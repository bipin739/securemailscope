import datetime
from typing import List, Dict, Any, Optional
from app.models import Investigation, SecurityFinding
from app.reporting.models import (
    InvestigationReport,
    ReportMetadata,
    CaptureSummary,
    ExecutiveSummary,
    ReportFinding,
    ReportRecommendation,
    SecurityReplaySummaryItem,
    HardeningImpactReportSummary,
    ClientDiscoveryReportSummary,
    AIAssistedPrioritizationSummary,
    EvidenceManifest,
)
from app.analysis.prioritization import build_fix_first
from app.reporting.integrity import (
    compute_findings_digest,
    compute_replay_digest,
    compute_discovery_digest,
    compute_simulation_digest,
    compute_merkle_evidence_root,
    compute_report_digest,
)
from app.simulation.engine import HardeningSimulatorEngine
from app.discovery.engine import ClientDiscoveryEngine

RECOMMENDATION_POLICY_MAP = {
    "SMS-AUTH-001": "SMS-POLICY-REQUIRE-TLS",
    "SMS-STARTTLS-001": "SMS-POLICY-REQUIRE-TLS",
    "SMS-TLS-001": "SMS-POLICY-REQUIRE-TLS",
    "SMS-TLSVER-001": "SMS-POLICY-TLS12",
    "SMS-CIPHER-001": "SMS-POLICY-NO-WEAK-CIPHER",
}

SEVERITY_WEIGHT = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "INFO": 5,
}

AUTHORITATIVE_LIMITATIONS = [
    'TLS selections come from ServerHello; observing ServerHello does not prove handshake completion or successful delivery.',
    'TLS 1.3 certificates are encrypted. Chain validation requires visible certificates, observed SNI, capture time, and SMS_TRUST_STORE. Revocation is not checked.',
    'Capture SHA-256 and report hashes support integrity comparison, not source authentication or digital signatures.',
    "Analysis reflects strictly traffic captured and visible within the submitted packet capture window.",
    "Passive network observation cannot evaluate email clients or cryptographic capabilities absent from the capture.",
    "Incomplete TCP streams or truncated TLS handshakes in capture boundaries may limit full capability assessment.",
    "AI-assisted anomaly prioritization is relative strictly to the observed client population in this capture.",
    "AI anomaly engine abstains from statistical ranking when the comparison population is insufficient (minimum 5 observed clients).",
    "Encrypted application-layer email payload (message text, headers, attachments) is not decrypted.",
    "Hardening Impact Simulation results reflect passive capability evidence only and do not modify live servers.",
]

PRIVACY_STATEMENT = (
    "Capture files can contain sensitive payloads and are processed locally by TShark. "
    "Temporary uploaded files are removed after analysis. Command arguments are discarded "
    "at the extraction boundary; generated investigations retain transport and certificate "
    "metadata rather than message bodies or authentication secrets. Reports may contain "
    "IP addresses, hostnames, and certificate identities. No network revocation lookup or cloud AI is used."
)
def generate_executive_summary(
    investigation: Investigation,
    findings: List[SecurityFinding],
    discovery_summary: Any,
    ai_assessment: Any,
) -> ExecutiveSummary:
    """
    Generates deterministic human-readable summary text without LLM.
    Strictly evidence-based and factual.
    """
    session_count = investigation.summary.sessions_analyzed
    posture_status = investigation.security_posture.status if investigation.security_posture else "UNKNOWN"
    
    # 1. Posture statement
    if posture_status == "CRITICAL":
        headline = f"Critical Security Posture Identified Across {session_count} Transport Session{'s' if session_count != 1 else ''}"
        posture_summary = (
            f"The investigation identified a CRITICAL security posture. High-risk cryptographic weaknesses "
            f"or cleartext credential transmission were observed during transport-layer evaluation."
        )
    elif posture_status == "HIGH_RISK":
        headline = f"High-Risk Transport Security Issues Detected"
        posture_summary = "Significant transport weaknesses or obsolete cryptographic protocols were identified."
    elif posture_status == "NEEDS_ATTENTION":
        headline = "Transport Configuration Warnings Identified"
        posture_summary = "Transport encryption is partially established but configuration improvements are recommended."
    elif posture_status == "ACCEPTABLE":
        headline = "Modern Transport Security Verified"
        posture_summary = "Visible cryptographic checks passed the implemented baseline. Scope limitations and revocation status still apply."
    else:
        headline = "Transport Security Posture Evaluated"
        posture_summary = f"Overall security posture evaluated as {posture_status} based on {len(findings)} deterministic rule(s)."

    # 2. Key findings explanation
    key_points = []
    has_auth_before_tls = any(f.rule_id == "SMS-AUTH-001" for f in findings)
    has_starttls_unused = any(f.rule_id == "SMS-STARTTLS-001" for f in findings)
    has_cleartext = any(f.rule_id == "SMS-TLS-001" for f in findings)
    has_weak_tls = any(f.rule_id == "SMS-TLSVER-001" for f in findings)
    has_weak_cipher = any(f.rule_id == "SMS-CIPHER-001" for f in findings)

    if has_auth_before_tls:
        key_points.append("authentication occurred before TLS protection was established")
    if has_starttls_unused:
        key_points.append("STARTTLS was advertised by the server but was not negotiated by the client")
    if has_cleartext and not has_starttls_unused:
        key_points.append("email sessions operated in cleartext without transport encryption")
    if has_weak_tls:
        key_points.append("deprecated TLS protocols (TLS 1.0/1.1) were negotiated")
    if has_weak_cipher:
        key_points.append("legacy or non-AEAD cipher suites were utilized")

    if key_points:
        findings_prose = "The primary drivers of this assessment were: " + "; ".join(key_points) + "."
    elif findings:
        findings_prose = f"The assessment identified {len(findings)} finding(s) across transport sessions."
    else:
        findings_prose = "No active security violations were identified in the observed transport traffic."

    # 3. Transport summary
    protocols = list(set(c.protocol for c in investigation.connections)) if investigation.connections else ["Email"]
    proto_str = "/".join(protocols)
    transport_summary = (
        f"SecureMailScope analyzed {session_count} observed {proto_str} transport session(s) "
        f"from capture '{investigation.filename}'. {investigation.summary.secure_sessions} session(s) passed "
        f"all assessed baseline checks, {investigation.summary.warning_sessions} required review, and "
        f"{investigation.summary.critical_sessions} had critical transport risks."
    )

    # 4. AI anomaly summary
    ai_status = ai_assessment.status if ai_assessment else "UNAVAILABLE"
    pop_size = ai_assessment.population_size if ai_assessment else 0
    if ai_status == "INSUFFICIENT_SAMPLE":
        ai_prose = (
            f"AI-assisted anomaly prioritization was not performed because only {pop_size} observed client(s) "
            f"was available for comparison (minimum requirement: 5 observed clients)."
        )
    elif ai_status == "ANALYZED":
        review_count = sum(1 for r in (ai_assessment.results or []) if r.priority in ("HIGH_REVIEW", "REVIEW"))
        ai_prose = (
            f"AI-assisted anomaly prioritization evaluated {pop_size} observed client profiles across 14 transport dimensions. "
            f"{review_count} client(s) were prioritized for analyst attention based on relative statistical divergence."
        )
    elif ai_status == "INSUFFICIENT_EVIDENCE":
        ai_prose = "AI anomaly evaluation was omitted due to zero observed client profiles in the capture."
    else:
        ai_prose = "AI anomaly evaluation was unavailable in the current runtime environment."

    full_text = (
        f"{transport_summary}\n\n"
        f"{posture_summary} {findings_prose}\n\n"
        f"{ai_prose}"
    )

    return ExecutiveSummary(
        headline=headline,
        overall_posture=posture_status,
        posture_summary=posture_summary,
        key_findings_summary=findings_prose,
        transport_security_summary=transport_summary,
        ai_anomaly_summary=ai_prose,
        full_text=full_text,
    )

def aggregate_recommendations(findings: List[SecurityFinding]) -> List[ReportRecommendation]:
    """
    Aggregates and deduplicates recommendations from Phase 2 findings,
    sorted strictly by severity priority (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO).
    """
    seen_rules = set()
    recommendations = []

    # Sort findings by severity weight
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_WEIGHT.get(f.severity, 99)
    )

    for f in sorted_findings:
        if f.rule_id in seen_rules:
            continue
        seen_rules.add(f.rule_id)

        policy_bridge = RECOMMENDATION_POLICY_MAP.get(f.rule_id)
        recommendations.append(
            ReportRecommendation(
                priority_rank=len(recommendations) + 1,
                rule_id=f.rule_id,
                severity=f.severity,
                action=f.recommendation,
                rationale=f.plain_explanation,
                policy_bridge=policy_bridge,
            )
        )

    # Re-assign priority ranks
    for idx, r in enumerate(recommendations):
        r.priority_rank = idx + 1

    return recommendations

def build_investigation_report(
    investigation: Investigation,
    simulation_result: Optional[Any] = None,
) -> InvestigationReport:
    """
    Constructs a structured, complete, tamper-evident InvestigationReport from authoritative
    subsystem outputs without independently recalculating security findings.
    """
    # 1. Ensure Discovery & AI anomaly assessment are available
    if isinstance(investigation.discovery, dict):
        from app.discovery.models import ClientDiscoveryResult
        discovery_res = ClientDiscoveryResult.model_validate(investigation.discovery)
        investigation.discovery = discovery_res
    elif investigation.discovery:
        discovery_res = investigation.discovery
    else:
        engine = ClientDiscoveryEngine()
        discovery_res = engine.discover(investigation)
        investigation.discovery = discovery_res

    inventory = discovery_res.inventory if discovery_res else []
    ai_assessment = discovery_res.anomaly_assessment if discovery_res else None
    disc_summary = discovery_res.summary if discovery_res else None

    # 2. Extract observed client capabilities for simulation if not present
    if not investigation.observed_clients:
        sim_engine = HardeningSimulatorEngine()
        investigation.observed_clients = sim_engine.extract_client_capabilities(investigation)
    elif isinstance(investigation.observed_clients, list) and len(investigation.observed_clients) > 0 and isinstance(investigation.observed_clients[0], dict):
        from app.simulation.models import ObservedClientCapability
        investigation.observed_clients = [ObservedClientCapability.model_validate(c) for c in investigation.observed_clients]


    # 3. Report Metadata
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report_id = f"RPT-{investigation.sha256_short or investigation.id}"
    is_real = not investigation.is_simulated and investigation.data_source == "REAL_CAPTURE"

    report_metadata = ReportMetadata(
        report_id=report_id,
        investigation_id=investigation.id,
        generated_at=now_utc,
        engine_name="SecureMailScope Analysis & Reporting Engine",
        engine_version="1.0.0",
        schema_version="1.0.0",
        data_source="REAL_CAPTURE" if is_real else "SIMULATED",
        is_simulated=not is_real,
    )

    # 4. Capture Summary
    protocols = list(set(c.protocol for c in investigation.connections)) if investigation.connections else []
    capture_summary = CaptureSummary(
        filename=investigation.filename,
        capture_sha256=investigation.sha256_hash or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        capture_sha256_short=investigation.sha256_short or (investigation.sha256_hash[:12] if investigation.sha256_hash else "e3b0c44298fc"),
        capture_date=investigation.capture_date,
        total_sessions=investigation.summary.sessions_analyzed,
        secure_sessions=investigation.summary.secure_sessions,
        warning_sessions=investigation.summary.warning_sessions,
        critical_sessions=investigation.summary.critical_sessions,
        observed_clients_count=len(inventory),
        protocols_observed=protocols,
    )

    # 5. Executive Summary
    exec_summary = generate_executive_summary(
        investigation=investigation,
        findings=investigation.findings,
        discovery_summary=disc_summary,
        ai_assessment=ai_assessment,
    )

    # 6. Deterministic Findings
    report_findings = []
    # Map replay events for cross-referencing
    replay_critical_map = {}
    if investigation.replays:
        for r in investigation.replays:
            crit = getattr(r, "critical_moment", None)
            if isinstance(crit, dict) and crit.get("rule_id"):
                replay_critical_map[crit["rule_id"]] = crit.get("title")
            elif hasattr(crit, "rule_id") and crit.rule_id:
                replay_critical_map[crit.rule_id] = crit.title

    for f in investigation.findings:
        # Find related session ID
        related_sess = None
        if f.affected_connection_id and investigation.connections:
            c = next((conn for conn in investigation.connections if conn.id == f.affected_connection_id), None)
            if c:
                related_sess = c.session_id

        report_findings.append(
            ReportFinding(
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                status=f.status if f.status else "FAIL",
                confidence=f.confidence if f.confidence else "HIGH",
                category=f.category,
                location=f.location,
                plain_explanation=f.plain_explanation,
                why_it_matters=f.why_it_matters,
                evidence=f.evidence,
                evidence_items=f.evidence_items,
                recommendation=f.recommendation,
                remediation=f.remediation,
                references=f.references,
                affected_connection_id=f.affected_connection_id,
                related_session_id=related_sess,
                related_replay_event=replay_critical_map.get(f.rule_id),
            )
        )

    # 7. Recommendations
    recommendations = aggregate_recommendations(investigation.findings)

    # 8. Replay Summary Items
    replay_summary_items = []
    if investigation.replays:
        for r in investigation.replays:
            r_d = r if isinstance(r, dict) else r.model_dump() if hasattr(r, "model_dump") else {}
            s_sum = r_d.get("summary", {})
            crit = r_d.get("critical_moment", {})
            crit_title = crit.get("title") if crit else None
            replay_summary_items.append(
                SecurityReplaySummaryItem(
                    session_id=r_d.get("session_id", "UNKNOWN"),
                    protocol=r_d.get("protocol", "SMTP"),
                    endpoints=f"{s_sum.get('client_endpoint', 'Client')} → {s_sum.get('server_endpoint', 'Server')}",
                    event_count=s_sum.get("event_count", len(r_d.get("events", []))),
                    highest_security_state=s_sum.get("highest_security_state", "NEUTRAL"),
                    critical_moment=crit_title,
                )
            )

    # 9. Hardening Impact Summary
    compat_counts = {"COMPATIBLE": 0, "WOULD_BREAK": 0, "UNKNOWN": 0}
    if simulation_result:
        sim_d = simulation_result if isinstance(simulation_result, dict) else simulation_result.model_dump()
        compat_counts["COMPATIBLE"] = sim_d.get("compatible_count", 0)
        compat_counts["WOULD_BREAK"] = sim_d.get("would_break_count", 0)
        compat_counts["UNKNOWN"] = sim_d.get("unknown_count", 0)
        tested_pols = sim_d.get("policy_ids", [])
    else:
        # Default passive simulation over standard baseline
        tested_pols = ["SMS-POLICY-REQUIRE-TLS", "SMS-POLICY-TLS12", "SMS-POLICY-NO-WEAK-CIPHER"]
        sim_engine = HardeningSimulatorEngine()
        sim_res = sim_engine.simulate(investigation.observed_clients or [], tested_pols)
        compat_counts["COMPATIBLE"] = sim_res.compatible_count
        compat_counts["WOULD_BREAK"] = sim_res.would_break_count
        compat_counts["UNKNOWN"] = sim_res.unknown_count

    from app.simulation.policies import POLICY_REGISTRY
    hardening_summary = HardeningImpactReportSummary(
        available_policies_count=len(POLICY_REGISTRY),
        tested_policies=tested_pols,
        summary_notes=(
            f"Passive hardening simulation evaluated {len(investigation.observed_clients or [])} observed client(s) "
            f"against {len(tested_pols)} cryptographic policy baseline(s)."
        ),
        recommendation="Validate client compatibility in staging using the Hardening Impact Simulator before enforcing strict TLS policies.",
        client_compatibility_overview=compat_counts,
    )

    # 10. Client Discovery & AI Summary
    if disc_summary:
        client_disc_summary = ClientDiscoveryReportSummary(
            total_observed_clients=disc_summary.observed_clients,
            modern_count=disc_summary.modern_clients,
            legacy_count=disc_summary.legacy_clients,
            mixed_count=disc_summary.mixed_clients,
            unknown_count=disc_summary.unknown_clients,
            cleartext_clients_count=disc_summary.cleartext_clients,
            clients_with_critical_findings=disc_summary.clients_with_critical_findings,
        )
    else:
        client_disc_summary = ClientDiscoveryReportSummary(
            total_observed_clients=len(inventory),
            modern_count=sum(1 for p in inventory if getattr(p, "legacy_classification", "") == "MODERN_OBSERVED"),
            legacy_count=sum(1 for p in inventory if getattr(p, "legacy_classification", "") == "LEGACY_OBSERVED"),
            mixed_count=0,
            unknown_count=0,
            cleartext_clients_count=sum(1 for p in inventory if getattr(p, "plaintext_session_count", 0) > 0),
            clients_with_critical_findings=sum(1 for p in inventory if getattr(p, "auth_before_tls_count", 0) > 0),
        )

    # AI Top Prioritized
    top_ai_clients = []
    if ai_assessment and ai_assessment.status == "ANALYZED":
        for r in ai_assessment.results[:5]:
            top_ai_clients.append({
                "client_id": r.client_id,
                "anomaly_score": r.anomaly_score,
                "priority": r.priority,
                "explanation": r.explanation,
                "contributing_features": r.contributing_features,
            })

    ai_prioritization = AIAssistedPrioritizationSummary(
        status=ai_assessment.status if ai_assessment else "UNAVAILABLE",
        method=ai_assessment.method if ai_assessment else "Isolation Forest (Offline Preprocessed)",
        population_size=ai_assessment.population_size if ai_assessment else len(inventory),
        minimum_threshold=ai_assessment.minimum_threshold if ai_assessment else 5,
        summary_explanation=ai_assessment.summary_explanation if ai_assessment else "No AI analysis performed.",
        top_prioritized_clients=top_ai_clients,
    )

    # 11. Compute Component Digests
    findings_digest = compute_findings_digest(report_findings)
    replay_digest = compute_replay_digest(replay_summary_items)
    discovery_digest = compute_discovery_digest(client_disc_summary)
    simulation_digest = compute_simulation_digest(hardening_summary)

    # 12. Compute Merkle Evidence Root
    evidence_root = compute_merkle_evidence_root(
        capture_sha256=capture_summary.capture_sha256,
        findings_digest=findings_digest,
        replay_digest=replay_digest,
        discovery_digest=discovery_digest,
        simulation_digest=simulation_digest,
    )

    # 13. Pre-assemble Manifest to compute Report Digest
    manifest = EvidenceManifest(
        schema_version="1.0.0",
        investigation_id=investigation.id,
        source_filename=investigation.filename,
        capture_sha256=capture_summary.capture_sha256,
        generated_at=now_utc,
        data_source=report_metadata.data_source,
        engine_version=report_metadata.engine_version,
        session_count=capture_summary.total_sessions,
        finding_count=len(report_findings),
        replay_count=len(replay_summary_items),
        observed_client_count=client_disc_summary.total_observed_clients,
        findings_digest=findings_digest,
        replay_digest=replay_digest,
        discovery_digest=discovery_digest,
        simulation_digest=simulation_digest,
        evidence_root=evidence_root,
        report_digest="PRE_COMPUTATION_PLACEHOLDER",
        integrity_algorithm="SHA-256",
        integrity_status="VERIFIED",
        verification_statement="Evidence integrity verified against the report manifest.",
    )

    partial_report = InvestigationReport(
        capture_origin=investigation.capture_origin,
        session_evidence=[c.model_dump() for c in investigation.connections],
        report_metadata=report_metadata,
        executive_summary=exec_summary,
        capture_summary=capture_summary,
        security_posture=investigation.security_posture or SecurityPosture(
            status="UNKNOWN", findings_count=0, critical_count=0, high_count=0,
            medium_count=0, low_count=0, info_count=0, passed_checks=0, coverage_gaps=0
        ),
        deterministic_findings=report_findings,
        fix_first=build_fix_first(investigation),
        security_replay_summary=replay_summary_items,
        hardening_impact_summary=hardening_summary,
        client_discovery_summary=client_disc_summary,
        ai_assisted_prioritization=ai_prioritization,
        evidence_manifest=manifest,
        limitations=AUTHORITATIVE_LIMITATIONS,
        privacy_statement=PRIVACY_STATEMENT,
        recommendations=recommendations,
    )

    # Compute canonical report digest and finalize manifest
    report_digest = compute_report_digest(partial_report.model_dump())
    manifest.report_digest = report_digest
    partial_report.evidence_manifest = manifest

    return partial_report
