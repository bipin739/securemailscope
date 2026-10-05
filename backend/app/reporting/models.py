from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field
from app.analysis.evidence import Evidence
from app.analysis.scoring import SecurityPosture

class ReportMetadata(BaseModel):
    report_id: str = Field(..., description="Unique report identifier")
    investigation_id: str = Field(..., description="Referenced investigation ID")
    generated_at: str = Field(..., description="UTC timestamp of report generation (ISO-8601)")
    engine_name: str = Field("SecureMailScope Analysis & Reporting Engine", description="Reporting engine name")
    engine_version: str = Field("1.0.0", description="Reporting engine version")
    schema_version: str = Field("1.0.0", description="Evidence report schema version")
    data_source: str = Field("REAL_CAPTURE", description="Provenance of analyzed data (REAL_CAPTURE or SIMULATED)")
    is_simulated: bool = Field(False, description="Flag indicating simulated demonstration data")

class CaptureSummary(BaseModel):
    filename: str = Field(..., description="Original capture file name")
    capture_sha256: str = Field(..., description="Full SHA-256 hash of network capture")
    capture_sha256_short: str = Field(..., description="Truncated 12-char SHA-256 hash")
    capture_date: str = Field(..., description="Capture analysis timestamp")
    total_sessions: int = Field(..., description="Total email transport sessions evaluated")
    secure_sessions: int = Field(..., description="Sessions with verified modern encryption")
    warning_sessions: int = Field(..., description="Sessions with configuration warnings")
    critical_sessions: int = Field(..., description="Sessions with high-risk transport vulnerabilities")
    observed_clients_count: int = Field(..., description="Number of distinct observed email clients")
    protocols_observed: List[str] = Field(default_factory=list, description="Observed email transport protocols")

class ExecutiveSummary(BaseModel):
    headline: str = Field(..., description="High-level executive takeaway")
    overall_posture: str = Field(..., description="Deterministic overall posture (CRITICAL, HIGH_RISK, NEEDS_ATTENTION, ACCEPTABLE, UNKNOWN)")
    posture_summary: str = Field(..., description="Summary of overall security posture evaluation")
    key_findings_summary: str = Field(..., description="Deterministic breakdown of key identified risks")
    transport_security_summary: str = Field(..., description="Transport layer cryptographic status summary")
    ai_anomaly_summary: str = Field(..., description="Summary of AI client behavioral outlier assessment or abstention reason")
    full_text: str = Field(..., description="Complete executive summary prose")

from app.analysis.remediation import Remediation

class ReportFinding(BaseModel):
    remediation: Remediation | None = None
    rule_id: str = Field(..., description="Deterministic security rule identifier")
    title: str = Field(..., description="Finding title")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = Field(..., description="Severity level")
    status: Literal["PASS", "WARN", "FAIL", "UNKNOWN"] = Field("FAIL", description="Rule evaluation status")
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field("HIGH", description="Confidence level")
    category: str = Field("Transport Cryptography", description="Finding category")
    location: str = Field(..., description="Observed path or network location")
    plain_explanation: str = Field(..., description="Clear explanation for administrators and non-cryptographers")
    why_it_matters: str = Field(..., description="Technical impact and threat context")
    evidence: str = Field(..., description="Concise summary of packet/session evidence")
    evidence_items: List[Evidence] = Field(default_factory=list, description="Structured evidence items")
    recommendation: str = Field(..., description="Actionable remediation steps")
    references: List[str] = Field(default_factory=list, description="Relevant RFC and cryptographic standards")
    affected_connection_id: Optional[str] = Field(None, description="Affected connection identifier")
    related_session_id: Optional[str] = Field(None, description="Related transport session identifier")
    related_replay_event: Optional[str] = Field(None, description="Related visual security replay event title or ID")

class ReportRecommendation(BaseModel):
    priority_rank: int = Field(..., description="1-based priority rank based on severity")
    rule_id: str = Field(..., description="Associated deterministic rule ID")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = Field(..., description="Severity level")
    action: str = Field(..., description="Remediation directive")
    rationale: str = Field(..., description="Technical justification for this remediation")
    policy_bridge: Optional[str] = Field(None, description="Related Hardening Simulator policy ID for pre-enforcement testing")

class SecurityReplaySummaryItem(BaseModel):
    session_id: str = Field(..., description="Transport session ID")
    protocol: str = Field(..., description="Email protocol (SMTP, IMAP, POP3)")
    endpoints: str = Field(..., description="Client -> Server endpoint path")
    event_count: int = Field(..., description="Total chronological security events")
    highest_security_state: str = Field(..., description="Highest severity reached in session")
    critical_moment: Optional[str] = Field(None, description="Critical moment title if present")

class HardeningImpactReportSummary(BaseModel):
    available_policies_count: int = Field(..., description="Count of registered deterministic hardening policies")
    tested_policies: List[str] = Field(default_factory=list, description="Policies evaluated against observed clients")
    summary_notes: str = Field(..., description="Summary explanation of passive compatibility testing")
    recommendation: str = Field(..., description="Simulation recommendation prior to server policy enforcement")
    client_compatibility_overview: Dict[str, int] = Field(default_factory=dict, description="Counts of COMPATIBLE, WOULD_BREAK, UNKNOWN outcomes")

class ClientDiscoveryReportSummary(BaseModel):
    total_observed_clients: int = Field(..., description="Total observed client endpoints")
    modern_count: int = Field(..., description="Clients negotiating modern TLS 1.3 / TLS 1.2 with PFS")
    legacy_count: int = Field(..., description="Clients using legacy TLS 1.0/1.1 or cleartext")
    mixed_count: int = Field(0, description="Clients exhibiting mixed transport security behavior")
    unknown_count: int = Field(0, description="Clients with incomplete capability observation")
    cleartext_clients_count: int = Field(..., description="Clients observed communicating over cleartext")
    clients_with_critical_findings: int = Field(..., description="Clients affected by CRITICAL findings")

class AIAssistedPrioritizationSummary(BaseModel):
    status: Literal["ANALYZED", "INSUFFICIENT_SAMPLE", "INSUFFICIENT_EVIDENCE", "UNAVAILABLE"] = Field(
        ..., description="AI anomaly engine evaluation status"
    )
    method: str = Field("Isolation Forest (Offline Preprocessed)", description="Offline ML algorithm used")
    population_size: int = Field(..., description="Observed client population size")
    minimum_threshold: int = Field(5, description="Minimum population required for relative outlier ranking")
    summary_explanation: str = Field(..., description="Deterministic explanation of AI outcome")
    top_prioritized_clients: List[Dict[str, Any]] = Field(default_factory=list, description="Ranked client outliers if analyzed")
    disclaimer: str = Field(
        "AI anomaly scores provide statistical prioritization relative to the observed capture fleet only. "
        "AI assessments never declare maliciousness or replace deterministic Phase 2 security findings.",
        description="Mandatory explainability and honesty disclaimer"
    )

class EvidenceManifest(BaseModel):
    schema_version: str = Field("1.0.0", description="Manifest schema version")
    investigation_id: str = Field(..., description="Source investigation ID")
    source_filename: str = Field(..., description="Source capture filename")
    capture_sha256: str = Field(..., description="SHA-256 fingerprint of the analyzed network capture")
    generated_at: str = Field(..., description="UTC timestamp of report generation")
    data_source: str = Field("REAL_CAPTURE", description="Data provenance (REAL_CAPTURE or SIMULATED)")
    engine_version: str = Field("1.0.0", description="SecureMailScope core engine version")
    session_count: int = Field(..., description="Number of sessions in capture")
    finding_count: int = Field(..., description="Number of security findings")
    replay_count: int = Field(..., description="Number of reconstructed session replays")
    observed_client_count: int = Field(..., description="Number of discovered client endpoints")
    findings_digest: str = Field(..., description="SHA-256 digest of canonical deterministic findings")
    replay_digest: str = Field(..., description="SHA-256 digest of canonical session replay events")
    discovery_digest: str = Field(..., description="SHA-256 digest of canonical client discovery inventory")
    simulation_digest: str = Field(..., description="SHA-256 digest of canonical client capability evidence")
    evidence_root: str = Field(..., description="Merkle Evidence Root combining capture and subsystem digests")
    report_digest: str = Field(..., description="Canonical SHA-256 digest over the logical report content")
    integrity_algorithm: str = Field("SHA-256", description="Cryptographic hash algorithm")
    integrity_status: Literal["VERIFIED", "TAMPERED", "UNVERIFIED"] = Field("VERIFIED", description="Evidence manifest integrity status")
    verification_statement: str = Field(
        "Evidence integrity verified against the report manifest.",
        description="Standardized integrity verification statement"
    )

class InvestigationReport(BaseModel):
    fix_first: dict = Field(default_factory=dict)
    capture_origin: str = 'UPLOADED_UNVERIFIED'
    session_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    report_metadata: ReportMetadata = Field(..., description="Report generation and system metadata")
    executive_summary: ExecutiveSummary = Field(..., description="Deterministic human-readable executive overview")
    capture_summary: CaptureSummary = Field(..., description="Summary of analyzed network capture file")
    security_posture: SecurityPosture = Field(..., description="Authoritative security posture scoring")
    deterministic_findings: List[ReportFinding] = Field(..., description="Evidence-backed deterministic findings")
    security_replay_summary: List[SecurityReplaySummaryItem] = Field(default_factory=list, description="Reconstructed session security timelines")
    hardening_impact_summary: HardeningImpactReportSummary = Field(..., description="Hardening policy impact evaluation")
    client_discovery_summary: ClientDiscoveryReportSummary = Field(..., description="Observed client inventory and classifications")
    ai_assisted_prioritization: AIAssistedPrioritizationSummary = Field(..., description="AI anomaly assessment summary")
    evidence_manifest: EvidenceManifest = Field(..., description="Cryptographic evidence manifest and Merkle Evidence Root")
    limitations: List[str] = Field(default_factory=list, description="Authoritative analysis limitations")
    privacy_statement: str = Field(..., description="Privacy & data handling statement")
    recommendations: List[ReportRecommendation] = Field(default_factory=list, description="Prioritized administrator recommendations")
