from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field
from app.analysis.evidence import Evidence

LegacyClassification = Literal["MODERN_OBSERVED", "LEGACY_OBSERVED", "MIXED", "UNKNOWN"]
IndicatorSeverity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
AnomalyPriority = Literal["NORMAL", "REVIEW", "HIGH_REVIEW"]
AnomalyStatus = Literal["ANALYZED", "INSUFFICIENT_SAMPLE", "INSUFFICIENT_EVIDENCE", "UNAVAILABLE"]

class ClientIndicator(BaseModel):
    """
    Deterministic, explainable security or behavioral indicator for an observed client.
    Derived purely from observed packet evidence without AI speculation.
    """
    indicator_id: str = Field(..., description="Unique indicator identifier code")
    title: str = Field(..., description="Human-readable indicator headline")
    severity: IndicatorSeverity = Field("INFO", description="Attention / severity level")
    description: str = Field(..., description="Clear explanation of the observed condition")
    evidence: str = Field(..., description="Supporting technical evidence from capture")
    related_rule_ids: List[str] = Field(default_factory=list, description="Associated Phase 2 security rule IDs")

class ObservedClientProfile(BaseModel):
    """
    Comprehensive, privacy-safe inventory record for an observed email client endpoint.
    Aggregates session parameters, capabilities, and deterministic risk indicators.
    Never contains usernames, passwords, emails, credentials, or message payloads.
    """
    client_id: str = Field(..., description="Observed client identity (e.g. 'SMTP:10.10.1.4')")
    protocol: str = Field("SMTP", description="Transport protocol (SMTP, IMAP, POP3)")
    observed_ip: str = Field(..., description="Source IP address of client endpoint")
    session_count: int = Field(0, description="Total sessions observed from this client")
    first_seen: str = Field("", description="Capture timestamp or time of first session")
    last_seen: str = Field("", description="Capture timestamp or time of last session")
    transport_modes: List[str] = Field(default_factory=list, description="Observed transport modes")
    observed_tls_versions: List[str] = Field(default_factory=list, description="Negotiated TLS versions")
    supported_tls_versions: List[str] = Field(default_factory=list, description="ClientHello offered TLS versions")
    observed_cipher_suites: List[str] = Field(default_factory=list, description="Negotiated cipher suites")
    client_hello_offers: List[dict] = Field(default_factory=list)
    offered_groups: List[str] = Field(default_factory=list)
    offered_cipher_suites: List[str] = Field(default_factory=list, description="ClientHello offered cipher suites")
    starttls_advertised_count: int = Field(0, description="Count of sessions where server offered STARTTLS")
    starttls_used_count: int = Field(0, description="Count of sessions where client requested STARTTLS")
    plaintext_session_count: int = Field(0, description="Count of unencrypted sessions")
    tls_session_count: int = Field(0, description="Count of TLS-protected sessions")
    auth_before_tls_count: int = Field(0, description="Count of sessions with cleartext authentication")
    weak_tls_count: int = Field(0, description="Count of sessions negotiating TLS 1.0 or 1.1")
    weak_cipher_count: int = Field(0, description="Count of sessions negotiating weak ciphers (RC4, 3DES)")
    forward_secrecy_observed: bool = Field(False, description="Whether Perfect Forward Secrecy was verified")
    evidence_quality: str = Field("INSUFFICIENT", description="Evidence quality (STRONG, PARTIAL, INSUFFICIENT)")
    legacy_classification: LegacyClassification = Field("UNKNOWN", description="Observed cryptographic baseline")
    deterministic_finding_ids: List[str] = Field(default_factory=list, description="Triggered security finding IDs")
    replay_session_ids: List[str] = Field(default_factory=list, description="Replay session IDs for this client")
    indicators: List[ClientIndicator] = Field(default_factory=list, description="Deterministic behavioral indicators")
    ja3_fingerprints: List[str] = Field(default_factory=list)
    ja3_evidence: List[Evidence] = Field(default_factory=list)
    ja3_fingerprint: Optional[str] = Field(None, description="Optional TLS ClientHello JA3 fingerprint if present")

class ClientAnomalyResult(BaseModel):
    """
    AI-assisted anomaly prioritization output for an individual observed client.
    Represents statistical distinctiveness relative to the current capture population.
    Never declares a client malicious or creates speculative vulnerability findings.
    """
    client_id: str = Field(..., description="Observed client identifier")
    anomaly_score: float = Field(0.0, description="Normalized relative anomaly attention score (0-100)")
    raw_decision_score: Optional[float] = Field(None, description="Raw Isolation Forest decision score")
    priority: AnomalyPriority = Field("NORMAL", description="Analyst review priority (NORMAL, REVIEW, HIGH_REVIEW)")
    explanation: str = Field(..., description="Plain-language justification derived from distinctive feature deviations")
    contributing_features: List[str] = Field(default_factory=list, description="Top feature dimensions driving divergence")
    deterministic_findings: List[str] = Field(default_factory=list, description="Authoritative Phase 2 findings for reference")
    disclaimer: str = Field(
        "AI ranking is relative to clients in this capture and indicates statistical outlier behavior, not maliciousness.",
        description="Mandatory analyst disclaimer"
    )

class AnomalyAssessment(BaseModel):
    """
    Complete output of the offline anomaly prioritization engine for the capture population.
    """
    status: AnomalyStatus = Field("ANALYZED", description="Anomaly analysis execution status")
    method: str = Field("Isolation Forest (Offline Preprocessed)", description="Statistical / ML algorithm used")
    population_size: int = Field(0, description="Number of observed client profiles compared")
    minimum_threshold: int = Field(5, description="Minimum population size required for statistical validity")
    results: List[ClientAnomalyResult] = Field(default_factory=list, description="Per-client anomaly evaluations")
    summary_explanation: str = Field("", description="Overview of population behavioral distribution")

class DiscoverySummary(BaseModel):
    """
    Aggregated inventory and posture metrics across all observed clients.
    """
    observed_clients: int = Field(0, description="Total observed unique client endpoints")
    modern_clients: int = Field(0, description="Clients exclusively using modern TLS 1.2+ with safe ciphers")
    legacy_clients: int = Field(0, description="Clients with confirmed legacy or weak transport behavior")
    mixed_clients: int = Field(0, description="Clients exhibiting mixed cleartext and encrypted behavior")
    unknown_clients: int = Field(0, description="Clients with insufficient cryptographic evidence")
    clients_with_critical_findings: int = Field(0, description="Clients triggering CRITICAL security findings")
    clients_with_high_findings: int = Field(0, description="Clients triggering HIGH security findings")
    cleartext_clients: int = Field(0, description="Clients with observed cleartext mail activity")
    needs_review_count: int = Field(0, description="Clients flagged by AI for analyst review")
    anomaly_analysis_status: AnomalyStatus = Field("ANALYZED", description="Status of ML anomaly analysis")

class ClientDiscoveryResult(BaseModel):
    """
    Top-level payload returned by the Observed Client Discovery subsystem.
    """
    inventory: List[ObservedClientProfile] = Field(default_factory=list, description="All observed client profiles")
    summary: DiscoverySummary = Field(..., description="High-level inventory summary")
    anomaly_assessment: AnomalyAssessment = Field(..., description="AI anomaly assessment results")
