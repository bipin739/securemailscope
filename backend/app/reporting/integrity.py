import json
import hashlib
from typing import Any, Dict, List, Tuple, Union, Optional
from pydantic import BaseModel

def _json_serializable(obj: Any) -> Any:
    """Helper to convert complex structures and Pydantic models into serializable python objects."""
    if isinstance(obj, BaseModel):
        return _json_serializable(obj.model_dump())
    elif isinstance(obj, dict):
        return {k: _json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [_json_serializable(v) for v in obj]
    elif hasattr(obj, "isoformat"):
        return obj.isoformat()
    elif isinstance(obj, float) and obj.is_integer():
        # JSON numbers have no int/float distinction in browsers. Preserve the
        # same digest when JSON.stringify turns 90.0 into 90 (including -0.0).
        return int(obj)
    return obj

def canonicalize_json(data: Any) -> bytes:
    """
    Serializes python objects to canonical UTF-8 JSON bytes with sorted keys
    and compact delimiters (no extraneous whitespace).
    """
    clean_data = _json_serializable(data)
    return json.dumps(
        clean_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

def hash_sha256(data: Union[bytes, str]) -> str:
    """Computes standard SHA-256 hex digest for given bytes or string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def compute_findings_digest(findings: List[Any]) -> str:
    """
    Computes deterministic SHA-256 digest over normalized security findings.
    Excludes ephemeral UI state while retaining complete logical evidence.
    """
    canonical_list = []
    for f in findings:
        f_dict = f.model_dump() if isinstance(f, BaseModel) else dict(f)
        
        # Canonicalize evidence items
        raw_ev = f_dict.get("evidence_items", [])
        norm_ev = []
        for ev in raw_ev:
            ev_d = ev if isinstance(ev, dict) else ev.model_dump() if isinstance(ev, BaseModel) else {}
            norm_ev.append({
                "type": ev_d.get("type"),
                "field": ev_d.get("field"),
                "value": str(ev_d.get("value")),
                "source": ev_d.get("source"),
                "description": ev_d.get("description"),
            })
        norm_ev.sort(key=lambda e: (e["type"] or "", e["field"] or "", e["source"] or ""))

        canonical_list.append({
            "rule_id": f_dict.get("rule_id"),
            "title": f_dict.get("title"),
            "severity": f_dict.get("severity"),
            "status": f_dict.get("status"),
            "confidence": f_dict.get("confidence"),
            "category": f_dict.get("category"),
            "location": f_dict.get("location"),
            "plain_explanation": f_dict.get("plain_explanation"),
            "why_it_matters": f_dict.get("why_it_matters"),
            "evidence": f_dict.get("evidence"),
            "recommendation": f_dict.get("recommendation"),
            "remediation": f_dict.get("remediation"),
            "references": sorted(f_dict.get("references") or []),
            "evidence_items": norm_ev,
        })

    canonical_list.sort(key=lambda item: (item["rule_id"] or "", item["location"] or "", item["title"] or ""))
    return hash_sha256(canonicalize_json(canonical_list))

def compute_replay_digest(replays: List[Any]) -> str:
    """
    Computes deterministic SHA-256 digest over security replay summaries.
    """
    canonical_list = []
    for r in replays:
        r_dict = r.model_dump() if isinstance(r, BaseModel) else dict(r)
        
        # Handle SecurityReplaySummaryItem vs full SessionReplay
        session_id = r_dict.get("session_id")
        protocol = r_dict.get("protocol")
        endpoints = r_dict.get("endpoints") or ""
        event_count = r_dict.get("event_count") or len(r_dict.get("events", []))
        highest_security_state = r_dict.get("highest_security_state")
        
        crit = r_dict.get("critical_moment")
        if isinstance(crit, dict):
            crit_title = crit.get("title") or crit.get("rule_id")
        elif isinstance(crit, str):
            crit_title = crit
        elif hasattr(crit, "title"):
            crit_title = getattr(crit, "title")
        else:
            crit_title = None

        if not highest_security_state and r_dict.get("summary"):
            s_sum = r_dict["summary"]
            highest_security_state = s_sum.get("highest_security_state")
            endpoints = f"{s_sum.get('client_endpoint', '')} → {s_sum.get('server_endpoint', '')}"
            event_count = s_sum.get("event_count", event_count)

        canonical_list.append({
            "session_id": session_id,
            "protocol": protocol,
            "endpoints": endpoints,
            "event_count": event_count,
            "highest_security_state": highest_security_state,
            "critical_moment": crit_title,
        })

    canonical_list.sort(key=lambda s: s["session_id"] or "")
    return hash_sha256(canonicalize_json(canonical_list))

def compute_discovery_digest(discovery_data: Any) -> str:
    """
    Computes deterministic SHA-256 digest over observed client inventory discovery summary.
    """
    if discovery_data is None:
        disc_d = {}
    elif isinstance(discovery_data, BaseModel):
        disc_d = discovery_data.model_dump()
    elif isinstance(discovery_data, dict):
        disc_d = discovery_data
    else:
        disc_d = {}

    canonical_obj = {
        "total_observed_clients": disc_d.get("total_observed_clients") or disc_d.get("observed_clients", 0),
        "modern_count": disc_d.get("modern_count") or disc_d.get("modern_clients", 0),
        "legacy_count": disc_d.get("legacy_count") or disc_d.get("legacy_clients", 0),
        "mixed_count": disc_d.get("mixed_count") or disc_d.get("mixed_clients", 0),
        "unknown_count": disc_d.get("unknown_count") or disc_d.get("unknown_clients", 0),
        "cleartext_clients_count": disc_d.get("cleartext_clients_count") or disc_d.get("cleartext_clients", 0),
        "clients_with_critical_findings": disc_d.get("clients_with_critical_findings", 0),
    }

    return hash_sha256(canonicalize_json(canonical_obj))

def compute_simulation_digest(hardening_data: Any) -> str:
    """
    Computes deterministic SHA-256 digest over hardening policy simulation results.
    """
    if hardening_data is None:
        hard_d = {}
    elif isinstance(hardening_data, BaseModel):
        hard_d = hardening_data.model_dump()
    elif isinstance(hardening_data, dict):
        hard_d = hardening_data
    else:
        hard_d = {}

    compat_overview = hard_d.get("client_compatibility_overview", {})
    if not compat_overview and ("compatible_count" in hard_d):
        compat_overview = {
            "COMPATIBLE": hard_d.get("compatible_count", 0),
            "WOULD_BREAK": hard_d.get("would_break_count", 0),
            "UNKNOWN": hard_d.get("unknown_count", 0),
        }

    canonical_obj = {
        "available_policies_count": hard_d.get("available_policies_count", 0),
        "tested_policies": sorted(hard_d.get("tested_policies", []) or hard_d.get("policy_ids", [])),
        "client_compatibility_overview": {
            "COMPATIBLE": compat_overview.get("COMPATIBLE", 0),
            "WOULD_BREAK": compat_overview.get("WOULD_BREAK", 0),
            "UNKNOWN": compat_overview.get("UNKNOWN", 0),
        },
    }

    return hash_sha256(canonicalize_json(canonical_obj))

def compute_merkle_evidence_root(
    capture_sha256: str,
    findings_digest: str,
    replay_digest: str,
    discovery_digest: str,
    simulation_digest: str,
) -> str:
    """
    Computes a deterministic pairwise Merkle Evidence Root combining capture identity
    and authoritative subsystem evidence digests.
    
    Structure:
      Leaves: [capture_hash, findings_digest, replay_digest, discovery_digest, simulation_digest]
      Tree reduction: Pairwise SHA-256 until root is reached.
    """
    leaves = [
        capture_sha256.lower().strip(),
        findings_digest.lower().strip(),
        replay_digest.lower().strip(),
        discovery_digest.lower().strip(),
        simulation_digest.lower().strip(),
    ]

    current_layer = [hash_sha256(leaf) for leaf in leaves]

    while len(current_layer) > 1:
        next_layer = []
        for i in range(0, len(current_layer), 2):
            left = current_layer[i]
            if i + 1 < len(current_layer):
                right = current_layer[i + 1]
            else:
                # Odd leaf duplicated for standard Merkle tree balance
                right = left
            combined = f"{left}:{right}"
            next_layer.append(hash_sha256(combined))
        current_layer = next_layer

    return current_layer[0]

def extract_canonical_report_payload(report_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts canonical logical components of an InvestigationReport,
    excluding self-referential manifest fields (report_digest and integrity_status).
    """
    manifest = report_dict.get("evidence_manifest", {})
    manifest_clean = {
        "schema_version": manifest.get("schema_version", "1.0.0"),
        "investigation_id": manifest.get("investigation_id"),
        "source_filename": manifest.get("source_filename"),
        "capture_sha256": manifest.get("capture_sha256"),
        "data_source": manifest.get("data_source"),
        "engine_version": manifest.get("engine_version"),
        "session_count": manifest.get("session_count"),
        "finding_count": manifest.get("finding_count"),
        "replay_count": manifest.get("replay_count"),
        "observed_client_count": manifest.get("observed_client_count"),
        "findings_digest": manifest.get("findings_digest"),
        "replay_digest": manifest.get("replay_digest"),
        "discovery_digest": manifest.get("discovery_digest"),
        "simulation_digest": manifest.get("simulation_digest"),
        "evidence_root": manifest.get("evidence_root"),
        "integrity_algorithm": manifest.get("integrity_algorithm", "SHA-256"),
    }

    return {
        "report_metadata": {
            "report_id": report_dict.get("report_metadata", {}).get("report_id"),
            "investigation_id": report_dict.get("report_metadata", {}).get("investigation_id"),
            "engine_version": report_dict.get("report_metadata", {}).get("engine_version"),
            "schema_version": report_dict.get("report_metadata", {}).get("schema_version"),
            "data_source": report_dict.get("report_metadata", {}).get("data_source"),
        },
        "executive_summary": report_dict.get("executive_summary"),
        "capture_origin": report_dict.get("capture_origin"),
        "fix_first": report_dict.get("fix_first"),
        "session_evidence": report_dict.get("session_evidence"),
        "capture_summary": report_dict.get("capture_summary"),
        "security_posture": report_dict.get("security_posture"),
        "deterministic_findings": report_dict.get("deterministic_findings"),
        "security_replay_summary": report_dict.get("security_replay_summary"),
        "hardening_impact_summary": report_dict.get("hardening_impact_summary"),
        "client_discovery_summary": report_dict.get("client_discovery_summary"),
        "ai_assisted_prioritization": report_dict.get("ai_assisted_prioritization"),
        "recommendations": report_dict.get("recommendations"),
        "limitations": report_dict.get("limitations"),
        "privacy_statement": report_dict.get("privacy_statement"),
        "evidence_manifest": manifest_clean,
    }

def compute_report_digest(report_dict: Dict[str, Any]) -> str:
    """Computes canonical SHA-256 digest over the logical report body."""
    canonical_payload = extract_canonical_report_payload(report_dict)
    return hash_sha256(canonicalize_json(canonical_payload))

def verify_report_manifest(report_data: Union[BaseModel, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Verifies the cryptographic integrity of an InvestigationReport against its EvidenceManifest.
    Recomputes component digests, Merkle Evidence Root, and report digest.
    
    Returns structured verification result with detailed mismatch reporting if tampered.
    """
    report_dict = report_data.model_dump() if isinstance(report_data, BaseModel) else dict(report_data)
    manifest = report_dict.get("evidence_manifest", {})
    if not manifest:
        return {
            "is_valid": False,
            "status": "UNVERIFIED",
            "message": "Report is missing evidence_manifest.",
            "mismatches": ["Missing evidence_manifest"],
        }

    mismatches = []

    # 1. Recompute findings digest
    findings = report_dict.get("deterministic_findings", [])
    expected_findings_digest = compute_findings_digest(findings)
    recorded_findings_digest = manifest.get("findings_digest", "")
    if expected_findings_digest != recorded_findings_digest:
        mismatches.append(
            f"Findings Digest mismatch: recorded {recorded_findings_digest[:12]}... vs computed {expected_findings_digest[:12]}..."
        )

    # 2. Recompute replay digest
    replays = report_dict.get("security_replay_summary", [])
    expected_replay_digest = compute_replay_digest(replays)
    recorded_replay_digest = manifest.get("replay_digest", "")
    if expected_replay_digest != recorded_replay_digest:
        mismatches.append(
            f"Replay Digest mismatch: recorded {recorded_replay_digest[:12]}... vs computed {expected_replay_digest[:12]}..."
        )

    # 3. Recompute discovery digest
    discovery_summary = report_dict.get("client_discovery_summary", {})
    expected_discovery_digest = compute_discovery_digest(discovery_summary)
    recorded_discovery_digest = manifest.get("discovery_digest", "")
    if expected_discovery_digest != recorded_discovery_digest:
        mismatches.append(
            f"Discovery Digest mismatch: recorded {recorded_discovery_digest[:12]}... vs computed {expected_discovery_digest[:12]}..."
        )

    # 4. Recompute simulation digest
    hardening_summary = report_dict.get("hardening_impact_summary", {})
    expected_simulation_digest = compute_simulation_digest(hardening_summary)
    recorded_simulation_digest = manifest.get("simulation_digest", "")
    if expected_simulation_digest != recorded_simulation_digest:
        mismatches.append(
            f"Simulation Digest mismatch: recorded {recorded_simulation_digest[:12]}... vs computed {expected_simulation_digest[:12]}..."
        )

    # 5. Check Merkle Evidence Root
    capture_sha256 = manifest.get("capture_sha256", "")
    expected_root = compute_merkle_evidence_root(
        capture_sha256=capture_sha256,
        findings_digest=expected_findings_digest,
        replay_digest=expected_replay_digest,
        discovery_digest=expected_discovery_digest,
        simulation_digest=expected_simulation_digest,
    )
    recorded_root = manifest.get("evidence_root", "")
    if expected_root != recorded_root:
        mismatches.append(
            f"Merkle Evidence Root mismatch: recorded {recorded_root[:12]}... vs computed {expected_root[:12]}..."
        )

    # 6. Check Report Digest
    expected_report_digest = compute_report_digest(report_dict)
    recorded_report_digest = manifest.get("report_digest", "")
    if expected_report_digest != recorded_report_digest:
        mismatches.append(
            f"Report Digest mismatch: recorded {recorded_report_digest[:12]}... vs computed {expected_report_digest[:12]}..."
        )

    is_valid = len(mismatches) == 0
    return {
        "is_valid": is_valid,
        "status": "VERIFIED" if is_valid else "TAMPERED",
        "verification_statement": "Evidence integrity verified against the report manifest." if is_valid else "Report evidence fails integrity verification.",
        "algorithm": manifest.get("integrity_algorithm", "SHA-256"),
        "evidence_root": expected_root,
        "report_digest": expected_report_digest,
        "mismatches": mismatches,
    }
