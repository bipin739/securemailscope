from typing import List, Dict, Any, Optional, Set, Tuple
from app.analysis.evidence import Evidence
from app.models import Investigation, NetworkConnection, SecurityFinding
from app.discovery.models import ObservedClientProfile, LegacyClassification
from app.discovery.indicators import (
    evaluate_client_indicators,
    WEAK_CIPHER_KEYWORDS,
    DEPRECATED_TLS_VERSIONS,
)

def classify_legacy_status(
    observed_tls: List[str],
    supported_tls: List[str],
    observed_ciphers: List[str],
    plaintext_count: int,
    tls_count: int,
    auth_before_tls_count: int,
    evidence_quality: str,
) -> LegacyClassification:
    """
    Classifies observed client endpoint cryptographic baseline into analyst-friendly categories:
    MODERN_OBSERVED, LEGACY_OBSERVED, MIXED, or UNKNOWN.
    Distinguishes negotiated behavior from supported capability.
    """
    has_legacy_negotiated = any(v in DEPRECATED_TLS_VERSIONS for v in observed_tls)
    has_weak_ciphers = any(
        any(k in c.upper() for k in WEAK_CIPHER_KEYWORDS) for c in observed_ciphers
    )
    has_modern_negotiated = any(v in ("TLS 1.2", "TLS 1.3") for v in observed_tls)
    has_modern_supported = any(v in ("TLS 1.2", "TLS 1.3") for v in supported_tls)

    # 1. Mixed Behavior: both plaintext and TLS, or negotiated legacy but proven modern capability
    if plaintext_count > 0 and tls_count > 0:
        return "MIXED"
    if has_legacy_negotiated and has_modern_supported:
        return "MIXED"
    if has_modern_negotiated and has_legacy_negotiated:
        return "MIXED"

    # 2. Legacy Observed: only legacy TLS, weak ciphers, or unencrypted with cleartext auth
    if has_legacy_negotiated or has_weak_ciphers:
        return "LEGACY_OBSERVED"
    if plaintext_count > 0 and auth_before_tls_count > 0:
        return "LEGACY_OBSERVED"

    # 3. Modern Observed: exclusively modern TLS 1.2/1.3 with standard ciphers
    if has_modern_negotiated and not has_weak_ciphers and plaintext_count == 0:
        return "MODERN_OBSERVED"

    # 4. Unknown: unencrypted without specific flags or insufficient cryptographic evidence
    if evidence_quality == "INSUFFICIENT" or (not observed_tls and not observed_ciphers):
        return "UNKNOWN"

    if plaintext_count > 0 and tls_count == 0:
        return "LEGACY_OBSERVED"

    return "UNKNOWN"

def build_client_inventory(investigation: Investigation) -> List[ObservedClientProfile]:
    """
    Constructs a comprehensive, privacy-safe client inventory by aggregating observed
    sessions, connections, deterministic findings, and replay identifiers.
    Never includes usernames, passwords, auth payloads, or message content.
    """
    # Build mapping of node IDs to IP addresses
    node_ip_map: Dict[str, str] = {}
    for node in investigation.nodes:
        node_ip_map[node.id] = node.ip_address

    # Map existing Phase 3 client capabilities by client_id if available
    cap_map: Dict[str, Any] = {}
    if hasattr(investigation, "observed_clients") and investigation.observed_clients:
        for cap in investigation.observed_clients:
            c_id = cap.client_id if hasattr(cap, "client_id") else cap.get("client_id")
            if c_id:
                cap_map[c_id] = cap

    # Group connections and metadata by (protocol, client_ip)
    client_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for conn in investigation.connections:
        # Resolve client IP
        client_ip = node_ip_map.get(
            conn.source_node_id,
            conn.source_label.split('(')[-1].replace(')', '').strip()
        )
        protocol = conn.protocol or "SMTP"
        key = (protocol, client_ip)

        if key not in client_groups:
            client_groups[key] = {
                "client_id": f"{protocol}:{client_ip}",
                "protocol": protocol,
                "observed_ip": client_ip,
                "session_count": 0,
                "first_seen": investigation.capture_date or "",
                "last_seen": investigation.capture_date or "",
                "transport_modes": set(),
                "observed_tls_versions": set(),
                "supported_tls_versions": set(),
                "observed_cipher_suites": set(),
                "offered_cipher_suites": set(),
                "starttls_advertised_count": 0,
                "starttls_used_count": 0,
                "plaintext_session_count": 0,
                "tls_session_count": 0,
                "auth_before_tls_count": 0,
                "weak_tls_count": 0,
                "weak_cipher_count": 0,
                "forward_secrecy_observed": False,
                "evidence_quality": "INSUFFICIENT",
                "finding_ids": set(),
                "replay_session_ids": set(),
                "ja3_fingerprint": None,
            }

        entry = client_groups[key]
        entry["session_count"] += 1

        # Transport mode
        if conn.transport_mode:
            entry["transport_modes"].add(conn.transport_mode)
            if "CLEARTEXT" in conn.transport_mode.upper():
                entry["plaintext_session_count"] += 1
            elif "TLS" in conn.transport_mode.upper():
                entry["tls_session_count"] += 1

        # TLS Version
        if conn.tls_version and conn.tls_version not in ("None", "NONE", "UNKNOWN"):
            entry["observed_tls_versions"].add(conn.tls_version)
            if conn.tls_version in DEPRECATED_TLS_VERSIONS:
                entry["weak_tls_count"] += 1

        # Cipher Suite
        if conn.cipher_suite and conn.cipher_suite not in (
            "NONE (Unencrypted / Plaintext)", "UNKNOWN / Not Captured", "None"
        ):
            entry["observed_cipher_suites"].add(conn.cipher_suite)
            if any(k in conn.cipher_suite.upper() for k in WEAK_CIPHER_KEYWORDS):
                entry["weak_cipher_count"] += 1

        # STARTTLS
        if conn.starttls_advertised:
            entry["starttls_advertised_count"] += 1
        if conn.starttls_used:
            entry["starttls_used_count"] += 1

        # Authentication
        if conn.auth_before_tls:
            entry["auth_before_tls_count"] += 1

        # Forward secrecy
        if conn.has_pfs:
            entry["forward_secrecy_observed"] = True

        # Replay mapping
        if conn.session_id:
            entry["replay_session_ids"].add(conn.session_id)

    # Link Phase 2 Deterministic Findings to relevant client endpoints
    for finding in investigation.findings:
        if finding.affected_connection_id:
            conn = next((c for c in investigation.connections if c.id == finding.affected_connection_id), None)
            if conn:
                client_ip = node_ip_map.get(
                    conn.source_node_id,
                    conn.source_label.split('(')[-1].replace(')', '').strip()
                )
                protocol = conn.protocol or "SMTP"
                key = (protocol, client_ip)
                if key in client_groups:
                    client_groups[key]["finding_ids"].add(finding.id)
        else:
            # Finding applies generally; if single client, attach
            if len(client_groups) == 1:
                for grp in client_groups.values():
                    grp["finding_ids"].add(finding.id)

    # Enrich from Phase 3 capabilities if present
    for key, entry in client_groups.items():
        c_id = entry["client_id"]
        if c_id in cap_map:
            cap = cap_map[c_id]
            supp_tls = getattr(cap, "supported_tls_versions", None) or (
                cap.get("supported_tls_versions") if isinstance(cap, dict) else []
            ) or []
            offered_ciphers = getattr(cap, "offered_cipher_suites", None) or (
                cap.get("offered_cipher_suites") if isinstance(cap, dict) else []
            ) or []
            ev_quality = getattr(cap, "evidence_quality", None) or (
                cap.get("evidence_quality") if isinstance(cap, dict) else "INSUFFICIENT"
            )
            for st in supp_tls:
                entry["supported_tls_versions"].add(st)
            for oc in offered_ciphers:
                entry["offered_cipher_suites"].add(oc)
            cap_sess = getattr(cap, "session_count", 0) or (
                cap.get("session_count", 0) if isinstance(cap, dict) else 0
            )
            if cap_sess > entry["session_count"]:
                entry["session_count"] = cap_sess
            if ev_quality:
                entry["evidence_quality"] = ev_quality

        # Baseline quality if not set
        if entry["evidence_quality"] == "INSUFFICIENT":
            if entry["supported_tls_versions"] or entry["offered_cipher_suites"]:
                entry["evidence_quality"] = "STRONG"
            elif entry["observed_tls_versions"] or entry["observed_cipher_suites"]:
                entry["evidence_quality"] = "PARTIAL"

    # Assemble initial ObservedClientProfile objects
    raw_profiles: List[ObservedClientProfile] = []
    for key, entry in client_groups.items():
        obs_tls = sorted(list(entry["observed_tls_versions"]))
        supp_tls = sorted(list(entry["supported_tls_versions"]))
        obs_ciphers = sorted(list(entry["observed_cipher_suites"]))
        off_ciphers = sorted(list(entry["offered_cipher_suites"]))
        transport_modes = sorted(list(entry["transport_modes"]))

        classification = classify_legacy_status(
            observed_tls=obs_tls,
            supported_tls=supp_tls,
            observed_ciphers=obs_ciphers,
            plaintext_count=entry["plaintext_session_count"],
            tls_count=entry["tls_session_count"],
            auth_before_tls_count=entry["auth_before_tls_count"],
            evidence_quality=entry["evidence_quality"],
        )

        hellos=[o for c in investigation.connections if c.session_id in entry['replay_session_ids'] for o in c.client_hello_offers]
        fingerprints=sorted({o['ja3_fingerprint'] for o in hellos if o.get('ja3_fingerprint')})
        ja3_evidence=[Evidence(type='OBSERVED',field='ja3_fingerprint',value=o['ja3_fingerprint'],source=f"ClientHello frame {o['frame']}",description='TShark JA3 handshake fingerprint; not a unique identity or proof of software.') for o in hellos if o.get('ja3_fingerprint')]
        if not fingerprints or len(hellos)<entry['session_count'] or any(not o.get('ja3_fingerprint') for o in hellos):
            ja3_evidence.append(Evidence(type='COVERAGE_GAP',field='ja3_fingerprint',value='UNKNOWN',source='ClientHello dissection',description='ClientHello or its JA3 field was not visible for one or more sessions. No fingerprint is inferred from ServerHello.'))
        profile = ObservedClientProfile(
            client_id=entry["client_id"],
            protocol=entry["protocol"],
            observed_ip=entry["observed_ip"],
            session_count=entry["session_count"],
            first_seen=entry["first_seen"],
            last_seen=entry["last_seen"],
            transport_modes=transport_modes,
            observed_tls_versions=obs_tls,
            supported_tls_versions=supp_tls,
            observed_cipher_suites=obs_ciphers,
            offered_cipher_suites=off_ciphers,
            client_hello_offers=[o for c in investigation.connections if c.session_id in entry["replay_session_ids"] for o in c.client_hello_offers],
            offered_groups=sorted({g for c in investigation.connections if c.session_id in entry["replay_session_ids"] for o in c.client_hello_offers for g in o["offered_groups"]}),
            starttls_advertised_count=entry["starttls_advertised_count"],
            starttls_used_count=entry["starttls_used_count"],
            plaintext_session_count=entry["plaintext_session_count"],
            tls_session_count=entry["tls_session_count"],
            auth_before_tls_count=entry["auth_before_tls_count"],
            weak_tls_count=entry["weak_tls_count"],
            weak_cipher_count=entry["weak_cipher_count"],
            forward_secrecy_observed=entry["forward_secrecy_observed"],
            evidence_quality=entry["evidence_quality"],
            legacy_classification=classification,
            deterministic_finding_ids=sorted(list(entry["finding_ids"])),
            replay_session_ids=sorted(list(entry["replay_session_ids"])),
            indicators=[],
            ja3_fingerprint=fingerprints[0] if len(fingerprints)==1 else None,
            ja3_fingerprints=fingerprints, ja3_evidence=ja3_evidence,
        )
        raw_profiles.append(profile)

    # Now evaluate deterministic indicators for all profiles with full population context
    final_profiles: List[ObservedClientProfile] = []
    for prof in raw_profiles:
        prof.indicators = evaluate_client_indicators(prof, raw_profiles)
        final_profiles.append(prof)

    return final_profiles
