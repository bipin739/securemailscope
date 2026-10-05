from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field

SecurityState = Literal["NEUTRAL", "SECURE", "WARNING", "CRITICAL", "UNKNOWN"]
EventDirection = Literal["CLIENT_TO_SERVER", "SERVER_TO_CLIENT", "INTERNAL"]
TransportState = Literal[
    "CONNECTED_CLEAR",
    "TLS_AVAILABLE",
    "TLS_REQUESTED",
    "TLS_HANDSHAKE",
    "TLS_PROTECTED",
    "SESSION_ENDED",
]

class SecurityEvent(BaseModel):
    """
    Represents an observed, privacy-sanitized security event in the reconstructed email session.
    Never contains raw credentials, payloads, email addresses, or message content.
    """
    event_id: str = Field(..., description="Unique event identifier within session")
    session_id: str = Field(..., description="Parent session / stream identifier")
    timestamp: Optional[str] = Field(None, description="ISO timestamp or epoch time from capture")
    relative_time_ms: float = Field(0.0, description="Elapsed time in milliseconds from start of session")
    direction: EventDirection = Field("INTERNAL", description="Message direction")
    event_type: str = Field(..., description="Semantic event type classification")
    title: str = Field(..., description="Human-readable event title")
    description: str = Field(..., description="Privacy-safe description of the observed event")
    transport_state: str = Field("CONNECTED_CLEAR", description="Session transport security state at this moment")
    security_state: SecurityState = Field("NEUTRAL", description="Security assessment status for this event")
    evidence_source: str = Field(..., description="Frame number / protocol indicator backing this event")
    related_rule_ids: List[str] = Field(default_factory=list, description="IDs of related Phase 2 security findings")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe technical metadata (commands, codes, versions)")

class CriticalMoment(BaseModel):
    """
    Spotlights the pivotal security degradation or turning point in a session.
    """
    event_id: str = Field(..., description="ID of the critical event")
    title: str = Field(..., description="Brief headline of the critical moment")
    reason: str = Field(..., description="Detailed explanation of why this moment is critical")
    rule_id: str = Field(..., description="Deterministic security rule ID associated with this moment")
    severity: str = Field("CRITICAL", description="Severity level")

class ReplaySummary(BaseModel):
    """
    High-level overview of a reconstructed session replay.
    """
    session_id: str = Field(..., description="Session identifier")
    protocol: str = Field("SMTP", description="Transport protocol")
    client_endpoint: str = Field(..., description="Client IP:port")
    server_endpoint: str = Field(..., description="Server IP:port")
    started_at: str = Field(..., description="Capture timestamp of first event")
    duration_ms: float = Field(0.0, description="Total session duration in milliseconds")
    initial_transport: str = Field("CLEARTEXT", description="Starting transport state")
    final_transport: str = Field("CLEARTEXT", description="Ending transport state")
    event_count: int = Field(0, description="Total number of security events in sequence")
    highest_security_state: SecurityState = Field("NEUTRAL", description="Most severe security state observed")
    critical_event_id: Optional[str] = Field(None, description="Event ID of critical turning point if present")
    critical_event_title: Optional[str] = Field(None, description="Title of critical turning point if present")
    related_findings: List[str] = Field(default_factory=list, description="List of rule IDs triggered in this session")

class SessionReplay(BaseModel):
    """
    Complete visual security replay for a single email transport session.
    """
    session_id: str = Field(..., description="Session identifier")
    protocol: str = Field("SMTP", description="Transport protocol")
    summary: ReplaySummary = Field(..., description="Session replay summary")
    critical_moment: Optional[CriticalMoment] = Field(None, description="Pivotal security risk moment if present")
    events: List[SecurityEvent] = Field(default_factory=list, description="Chronological security events")
