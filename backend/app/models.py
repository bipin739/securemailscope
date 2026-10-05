from typing import List, Optional, Literal, Any
from pydantic import BaseModel, Field, model_validator
from app.analysis.remediation import Remediation, remediation_for
from app.analysis.evidence import Evidence
from app.analysis.scoring import SecurityPosture

class SummaryStats(BaseModel):
    sessions_analyzed: int = Field(..., description="Total email transport sessions analyzed")
    secure_sessions: int = Field(..., description="Sessions with modern, fully verified transport security")
    warning_sessions: int = Field(..., description="Sessions with configuration warnings or policy ambiguities")
    critical_sessions: int = Field(..., description="Sessions with deprecated TLS or high-risk vulnerabilities")

class NetworkNode(BaseModel):
    id: str = Field(..., description="Unique node identifier")
    label: str = Field(..., description="Human-readable display label")
    role: str = Field(..., description="Functional role in the email routing path")
    ip_address: str = Field(..., description="Simulated or observed IP address")
    hostname: str = Field(..., description="Simulated or observed FQDN hostname")
    is_external: bool = Field(False, description="Whether node resides outside security perimeter")
    security_posture: Literal["secure", "warning", "critical", "neutral"] = Field("neutral", description="Overall security evaluation of the node")

class ConnectionEvidence(BaseModel):
    session_id: str = Field(..., description="Session identifier")
    handshake_record: str = Field(..., description="TLS handshake or protocol command record")
    cipher_suite_hex: Optional[str] = Field(None, description="Hex code of negotiated cipher suite")
    protocol_version_hex: Optional[str] = Field(None, description="Hex code of negotiated protocol version")
    ports: str = Field("25 → 25", description="Source and destination TCP ports")
    packet_count: int = Field(..., description="Packet count in session")

class PlainLanguageExploration(BaseModel):
    headline: str = Field(..., description="Plain-language headline for non-cryptographers")
    summary: str = Field(..., description="High-level explanation of the security condition")
    why_it_matters: str = Field(..., description="Operational and threat impact")
    evidence_summary: str = Field(..., description="Key packet/session evidence")
    recommended_action: str = Field(..., description="Clear administrator remediation steps")

class NetworkConnection(BaseModel):
    id: str = Field(..., description="Unique connection identifier")
    source_node_id: str = Field(..., description="Source node ID")
    target_node_id: str = Field(..., description="Target node ID")
    source_label: str = Field(..., description="Source node label")
    target_label: str = Field(..., description="Target node label")
    protocol: str = Field("SMTP", description="Email transport protocol (SMTP, IMAP, POP3)")
    transport_mode: str = Field("STARTTLS", description="Transport security mode (STARTTLS, Implicit TLS, Plaintext)")
    tls_version: str = Field(..., description="Negotiated TLS version (e.g., TLS 1.3, TLS 1.2, TLS 1.0, None)")
    cipher_suite: str = Field(..., description="Negotiated cipher suite name")
    security_status: Literal["SECURE", "WARNING", "CRITICAL"] = Field(..., description="Transport security evaluation")
    session_id: str = Field(..., description="Session ID")
    has_pfs: bool = Field(True, description="Perfect Forward Secrecy present")
    has_aead: bool = Field(True, description="Authenticated Encryption with Associated Data cipher")
    starttls_advertised: bool = Field(False, description="Whether STARTTLS was advertised as a capability")
    starttls_used: bool = Field(False, description="Whether STARTTLS was successfully negotiated/used")
    auth_observed: bool = Field(False, description="Whether authentication command (e.g. AUTH) was observed")
    starttls_requested: bool = False
    starttls_accepted: bool = False
    server_key_share_group: Optional[str] = None
    quantum_readiness: dict = Field(default_factory=dict)
    client_hello_offers: list[dict] = Field(default_factory=list)
    certificates: list[dict] = Field(default_factory=list)
    server_hello_frame: Optional[str] = None
    capture_gaps: bool = False
    plaintext_observed: bool = False
    tls_observed: bool = False
    auth_before_tls: bool = Field(False, description="Whether authentication took place before establishing TLS")
    explanation: PlainLanguageExploration = Field(..., description="Plain language translation and impact")
    evidence: ConnectionEvidence = Field(..., description="Technical evidence supporting the finding")

class SecurityFinding(BaseModel):
    id: str = Field(..., description="Unique finding ID")
    title: str = Field(..., description="Finding title")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = Field(..., description="Severity level")
    category: str = Field("Transport Cryptography", description="Finding category")
    status: Literal["PASS", "WARN", "FAIL", "UNKNOWN"] = Field("FAIL", description="Deterministic rule evaluation status")
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field("HIGH", description="Evidence completeness confidence level")
    affected_connection_id: Optional[str] = Field(None, description="ID of the affected connection")
    location: str = Field(..., description="Path or node location of the issue")
    plain_explanation: str = Field(..., description="Clear plain-language explanation")
    why_it_matters: str = Field(..., description="Why this weakness is important")
    evidence: str = Field(..., description="Summary of packet/session evidence")
    evidence_items: List[Evidence] = Field(default_factory=list, description="Structured evidence items backing this finding")
    remediation: Remediation | None = None

    @model_validator(mode='after')
    def supply_remediation(self):
        if self.remediation is None:
            self.remediation = remediation_for(self.rule_id, self.status, self.recommendation)
        return self

    recommendation: str = Field(..., description="Remediation steps for administrator")
    rule_id: str = Field(..., description="Deterministic security rule identifier")
    references: List[str] = Field(default_factory=list, description="Relevant RFC and NIST cryptographic standards")

class Investigation(BaseModel):
    fix_first: dict = Field(default_factory=dict)
    capture_origin: str = "UPLOADED_UNVERIFIED"
    id: str = Field(..., description="Investigation identifier")
    filename: str = Field(..., description="Source network capture filename")
    capture_date: str = Field(..., description="Capture timestamp")
    status: Literal["completed", "processing", "failed"] = Field("completed", description="Analysis status")
    is_simulated: bool = Field(True, description="Honesty flag confirming mock/simulated prototype data")
    data_source: str = Field("SIMULATED", description="Data provenance (SIMULATED or REAL_CAPTURE)")
    sha256_hash: Optional[str] = Field(None, description="Full SHA-256 hash of the capture file")
    sha256_short: Optional[str] = Field(None, description="Shortened SHA-256 hash (12 chars) for capture identity")
    analysis_engine: str = Field("SecureMailScope Deterministic Rule Engine v0.3", description="Engine name")
    summary: SummaryStats = Field(..., description="Aggregate session security statistics")
    security_posture: Optional[SecurityPosture] = Field(None, description="Deterministic security posture summary")
    nodes: List[NetworkNode] = Field(..., description="Nodes involved in the email routing path")
    connections: List[NetworkConnection] = Field(..., description="Transport connections between nodes")
    findings: List[SecurityFinding] = Field(..., description="Security findings and recommendations")
    observed_clients: List[Any] = Field(default_factory=list, description="Aggregated observed client capability profiles")
    replays: List[Any] = Field(default_factory=list, description="Visual security session replays")
    discovery: Optional[Any] = Field(None, description="Observed client discovery and AI anomaly assessment result")

class HealthResponse(BaseModel):
    status: str = Field("ok", description="Service operational status")
    service: str = Field("SecureMailScope", description="Service identifier")
    version: str = Field("1.0.0", description="Service version")
    is_simulated_mode: bool = Field(False, description="Indicator for simulated prototype models")
    tshark_available: bool = Field(False, description="Whether TShark is detected in system PATH")
    tshark_version: Optional[str] = Field(None, description="TShark version string if detected")


