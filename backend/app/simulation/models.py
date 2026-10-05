from typing import List, Optional, Literal, Any
from pydantic import BaseModel, Field
from app.analysis.evidence import Evidence

EvidenceQuality = Literal["STRONG", "PARTIAL", "INSUFFICIENT"]
SimulationOutcome = Literal["COMPATIBLE", "WOULD_BREAK", "UNKNOWN"]
SimulationConfidence = Literal["HIGH", "MEDIUM", "LOW"]

class ObservedClientCapability(BaseModel):
    """
    Observed client cryptographic capabilities aggregated from packet capture evidence.
    Contains strictly protocol and capability metadata without sensitive user data.
    """
    client_id: str = Field(..., description="Unique client identifier (e.g. SMTP:10.10.1.4)")
    protocol: str = Field("SMTP", description="Transport protocol (SMTP, IMAP, POP3)")
    observed_ip: str = Field(..., description="Observed client source IP address")
    observed_tls_versions: List[str] = Field(default_factory=list, description="Negotiated TLS versions observed in sessions")
    supported_tls_versions: List[str] = Field(default_factory=list, description="Explicit TLS versions offered in ClientHello")
    observed_cipher_suites: List[str] = Field(default_factory=list, description="Negotiated cipher suites observed in sessions")
    client_hello_offers: List[dict] = Field(default_factory=list)
    offered_groups: List[str] = Field(default_factory=list)
    offered_cipher_suites: List[str] = Field(default_factory=list, description="Explicit cipher suites offered in ClientHello")
    starttls_observed: bool = Field(False, description="Whether STARTTLS was advertised to this client")
    starttls_used: bool = Field(False, description="Whether this client initiated STARTTLS upgrade")
    plaintext_observed: bool = Field(False, description="Whether unencrypted cleartext transport was observed")
    forward_secrecy_observed: bool = Field(False, description="Whether Perfect Forward Secrecy was observed or offered")
    evidence_quality: EvidenceQuality = Field("INSUFFICIENT", description="Quality of capability evidence: STRONG, PARTIAL, or INSUFFICIENT")
    evidence: List[Evidence] = Field(default_factory=list, description="Structured evidence items backing this client's profile")
    session_count: int = Field(1, description="Number of observed sessions for this client")

class HardeningPolicy(BaseModel):
    """
    Deterministic configuration object for a simulated hardening policy.
    """
    id: str = Field(..., description="Policy identifier (e.g. SMS-POLICY-TLS12)")
    name: str = Field(..., description="Human-readable policy name")
    description: str = Field(..., description="Policy objective description")
    requirements: List[str] = Field(default_factory=list, description="Specific cryptographic requirements")
    references: List[str] = Field(default_factory=list, description="Relevant RFC and NIST standards")

class ClientSimulationResult(BaseModel):
    """
    Passive simulation outcome for a single observed client against evaluated policies.
    """
    client_id: str = Field(..., description="Observed client ID")
    protocol: str = Field(..., description="Transport protocol")
    endpoint: str = Field(..., description="Observed client source IP or endpoint")
    outcome: SimulationOutcome = Field(..., description="Simulation outcome: COMPATIBLE, WOULD_BREAK, or UNKNOWN")
    confidence: SimulationConfidence = Field(..., description="Confidence level: HIGH, MEDIUM, or LOW")
    reason: str = Field(..., description="Plain-language explanation of the outcome rationale")
    evidence: List[Evidence] = Field(default_factory=list, description="Supporting evidence items")

class SimulationRequest(BaseModel):
    """
    Request model for running policy simulation. Supports either policies or policy_ids.
    """
    policies: Optional[List[str]] = Field(default_factory=list, description="List of policy IDs to evaluate (e.g. ['SMS-POLICY-TLS12'])")
    policy_ids: Optional[List[str]] = Field(default_factory=list, description="Alias for policies")
    investigation_id: Optional[str] = Field(None, description="Optional ID of investigation to simulate")
    investigation: Optional[Any] = Field(None, description="Optional embedded investigation object")

    def get_policy_ids(self) -> List[str]:
        if self.policies:
            return self.policies
        if self.policy_ids:
            return self.policy_ids
        return []

class SimulationResult(BaseModel):
    """
    Aggregate simulation report summarizing policy impact across all observed clients.
    """
    policy_ids: List[str] = Field(..., description="Evaluated policy identifiers")
    policy_names: List[str] = Field(..., description="Names of evaluated policies")
    total_observed_clients: int = Field(0, description="Total number of unique observed clients")
    compatible_count: int = Field(0, description="Number of clients confirmed COMPATIBLE")
    would_break_count: int = Field(0, description="Number of clients predicted to WOULD_BREAK")
    unknown_count: int = Field(0, description="Number of clients with UNKNOWN compatibility due to incomplete evidence")
    potential_security_improvement: str = Field(..., description="Plain-language description of security benefits")
    disclaimer: str = Field(
        "Simulation is based only on capabilities observed in this capture. "
        "UNKNOWN means the capture does not contain enough evidence to predict compatibility safely.",
        description="Standard evidentiary disclaimer"
    )
    clients: List[ClientSimulationResult] = Field(default_factory=list, description="Per-client simulation results")
