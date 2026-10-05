from abc import ABC, abstractmethod
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, model_validator
from app.analysis.remediation import Remediation, remediation_for
from app.analysis.evidence import Evidence

RuleStatus = Literal["PASS", "WARN", "FAIL", "UNKNOWN"]
RuleSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RuleConfidence = Literal["HIGH", "MEDIUM", "LOW"]

class EmailSessionContext(BaseModel):
    """
    Extracted session context representing the observed state of an email transport connection.
    Contains only protocol metadata and cryptographic parameters without sensitive payloads.
    """
    stream_id: str
    protocol: str = "SMTP"
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    transport_mode: str
    tls_version: str = "None"
    cipher_suite: str = "NONE (Unencrypted / Plaintext)"
    raw_version: Optional[str] = None
    raw_cipher: Optional[str] = None
    sni: Optional[str] = None
    has_pfs: bool = False
    has_aead: bool = False
    packet_count: int = 0
    starttls_advertised: bool = False
    starttls_used: bool = False
    auth_observed: bool = False
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
    auth_before_tls: bool = False

class RuleEvaluationResult(BaseModel):
    """
    Deterministic result produced by evaluating a security rule against a session context.
    """
    rule_id: str
    title: str
    severity: RuleSeverity
    category: str
    status: RuleStatus
    confidence: RuleConfidence
    plain_explanation: str
    why_it_matters: str
    remediation: Remediation | None = None

    @model_validator(mode='after')
    def supply_remediation(self):
        if self.remediation is None:
            self.remediation = remediation_for(self.rule_id, self.status, self.recommendation)
        return self

    recommendation: str
    references: List[str] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    affected_connection_id: Optional[str] = None
    location: Optional[str] = None

class BaseSecurityRule(ABC):
    """
    Base class for all deterministic SecureMailScope security rules.
    """
    rule_id: str
    title: str
    category: str
    references: List[str]

    @abstractmethod
    def evaluate(self, session: EmailSessionContext) -> Optional[RuleEvaluationResult]:
        pass

# ----------------------------------------------------------------------
# RULE SMS-TLS-001: Cleartext Email Transport
# ----------------------------------------------------------------------
class CleartextTransportRule(BaseSecurityRule):
    rule_id = "SMS-TLS-001"
    title = "Cleartext Email Transport"
    category = "Transport Encryption"
    references = ["RFC 8314", "NIST SP 800-52 Rev. 2"]

    def evaluate(self, session: EmailSessionContext) -> Optional[RuleEvaluationResult]:
        # Triggers when email protocol session exists and no TLS protection was established
        is_cleartext = (
            session.protocol in ("SMTP", "IMAP", "POP3")
            and (session.tls_version == "None" or "CLEARTEXT" in session.transport_mode.upper())
        )
        if is_cleartext:
            evidence = [
                Evidence(
                    type="OBSERVED",
                    field="protocol",
                    value=session.protocol,
                    source=f"{session.protocol} Stream Analysis",
                    description=f"Identified {session.protocol} session on port {session.server_port}.",
                ),
                Evidence(
                    type="OBSERVED",
                    field="tls_version",
                    value=session.tls_version,
                    source="TCP Stream",
                    description="No TLS encryption handshake was negotiated for this session.",
                ),
                Evidence(
                    type="OBSERVED",
                    field="transport_mode",
                    value=session.transport_mode,
                    source="Transport Analysis",
                    description=f"Session operated in {session.transport_mode} mode.",
                ),
            ]
            return RuleEvaluationResult(
                rule_id=self.rule_id,
                title=self.title,
                severity="HIGH",
                category=self.category,
                status="FAIL",
                confidence="HIGH",
                plain_explanation="This email session continued without TLS protection, allowing application-layer traffic to traverse the observed network path without transport encryption.",
                why_it_matters="Cleartext email transport exposes message metadata, routing headers, and session contents to passive eavesdropping and traffic manipulation along the transit path.",
                recommendation="Enforce TLS encryption for all email communications using Direct TLS (e.g. port 465/993/995) or mandatory STARTTLS with strict rejection of unencrypted fallbacks.",
                references=self.references,
                evidence=evidence,
                affected_connection_id=f"conn-real-{session.stream_id}",
                location=f"{session.client_ip} → {session.server_ip}",
            )
        return None

# ----------------------------------------------------------------------
# RULE SMS-STARTTLS-001: STARTTLS Available But Not Used
# ----------------------------------------------------------------------
class StartTLSUnusedRule(BaseSecurityRule):
    rule_id = "SMS-STARTTLS-001"
    title = "STARTTLS Available But Not Used"
    category = "Opportunistic Encryption"
    references = ["RFC 3207", "RFC 8314"]

    def evaluate(self, session: EmailSessionContext) -> Optional[RuleEvaluationResult]:
        if session.starttls_advertised and not session.starttls_used and not session.starttls_requested and session.tls_version != 'UNKNOWN':
            evidence = [
                Evidence(
                    type="OBSERVED",
                    field="starttls_advertised",
                    value=True,
                    source=f"{session.protocol} EHLO/Greeting Response",
                    description="Server advertised STARTTLS capability.",
                ),
                Evidence(
                    type="OBSERVED",
                    field="starttls_used",
                    value=False,
                    source="TCP Stream",
                    description="No STARTTLS command or TLS handshake was observed.",
                ),
            ]
            return RuleEvaluationResult(
                rule_id=self.rule_id,
                title=self.title,
                severity="HIGH",
                category=self.category,
                status="FAIL",
                confidence="HIGH",
                plain_explanation="The server advertised STARTTLS, but the client continued the SMTP session without upgrading to TLS.",
                why_it_matters="Transport encryption was available from the server, but the client did not initiate an upgrade. Without mandatory TLS enforcement, the session continued unprotected over cleartext.",
                recommendation="Configure the client and server policy to require TLS for this mail flow and reject insecure fallback where operationally appropriate.",
                references=self.references,
                evidence=evidence,
                affected_connection_id=f"conn-real-{session.stream_id}",
                location=f"{session.client_ip} → {session.server_ip}",
            )
        return None

# ----------------------------------------------------------------------
# RULE SMS-AUTH-001: Authentication Before TLS
# ----------------------------------------------------------------------
class AuthenticationBeforeTLSRule(BaseSecurityRule):
    rule_id = "SMS-AUTH-001"
    title = "Authentication Before TLS"
    category = "Credential Protection"
    references = ["RFC 8314", "RFC 4954"]

    def evaluate(self, session: EmailSessionContext) -> Optional[RuleEvaluationResult]:
        if session.auth_observed and session.auth_before_tls:
            evidence = [
                Evidence(
                    type="OBSERVED",
                    field="auth_observed",
                    value=True,
                    source=f"{session.protocol} Command Metadata",
                    description=f"{session.protocol} authentication command (e.g. AUTH/LOGIN/USER) was observed on the wire.",
                ),
                Evidence(
                    type="OBSERVED",
                    field="auth_before_tls",
                    value=True,
                    source="Session Handshake Timeline",
                    description="Authentication occurred before TLS protection was established.",
                ),
            ]
            return RuleEvaluationResult(
                rule_id=self.rule_id,
                title=self.title,
                severity="CRITICAL",
                category=self.category,
                status="FAIL",
                confidence="HIGH",
                plain_explanation="Authentication occurred before TLS protection was established.",
                why_it_matters="Transmitting authentication credentials over an unencrypted cleartext session exposes account login data to passive network capture and credential theft.",
                recommendation="Configure the mail server to mandate STARTTLS before advertising or accepting AUTH commands.",
                references=self.references,
                evidence=evidence,
                affected_connection_id=f"conn-real-{session.stream_id}",
                location=f"{session.client_ip} → {session.server_ip}",
            )
        return None

# ----------------------------------------------------------------------
# RULE SMS-TLSVER-001: Deprecated TLS Version
# ----------------------------------------------------------------------
class DeprecatedTLSRule(BaseSecurityRule):
    rule_id = "SMS-TLSVER-001"
    title = "Deprecated TLS Version"
    category = "Protocol Version"
    references = ["RFC 8996", "NIST SP 800-52 Rev. 2"]

    DEPRECATED_VERSIONS = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

    def evaluate(self, session: EmailSessionContext) -> Optional[RuleEvaluationResult]:
        if session.tls_version in self.DEPRECATED_VERSIONS:
            evidence = [
                Evidence(
                    type="OBSERVED",
                    field="tls_version",
                    value=session.tls_version,
                    source="TLS Handshake ServerHello",
                    description=f"Server selected deprecated protocol version {session.tls_version}.",
                ),
            ]
            return RuleEvaluationResult(
                rule_id=self.rule_id,
                title=f"Deprecated TLS Version ({session.tls_version})",
                severity="HIGH",
                category=self.category,
                status="FAIL",
                confidence="HIGH",
                plain_explanation=f"Observed email session negotiated deprecated {session.tls_version} protocol, which is susceptible to known downgrade attacks and lacks modern authenticated encryption.",
                why_it_matters=f"{session.tls_version} is formally deprecated under RFC 8996 due to lack of modern cipher constructions, vulnerability to downgrade attacks, and security weaknesses.",
                recommendation=f"Disable {session.tls_version} on {session.server_ip} and configure the mail server to require TLS 1.2 or TLS 1.3 as the minimum acceptable protocol version.",
                references=self.references,
                evidence=evidence,
                affected_connection_id=f"conn-real-{session.stream_id}",
                location=f"{session.client_ip} → {session.server_ip}",
            )
        return None

# ----------------------------------------------------------------------
# RULE SMS-TLSVER-002: Modern TLS Version
# ----------------------------------------------------------------------
class ModernTLSRule(BaseSecurityRule):
    rule_id = "SMS-TLSVER-002"
    title = "Modern TLS Version"
    category = "Protocol Version"
    references = ["RFC 8446", "RFC 5246", "NIST SP 800-52 Rev. 2"]

    MODERN_VERSIONS = {"TLS 1.2", "TLS 1.3"}

    def evaluate(self, session: EmailSessionContext) -> Optional[RuleEvaluationResult]:
        if session.tls_version in self.MODERN_VERSIONS:
            ref = ["RFC 8446", "NIST SP 800-52 Rev. 2"] if "1.3" in session.tls_version else ["RFC 5246", "NIST SP 800-52 Rev. 2"]
            evidence = [
                Evidence(
                    type="OBSERVED",
                    field="tls_version",
                    value=session.tls_version,
                    source="TLS Handshake ServerHello",
                    description=f"Server negotiated modern protocol version {session.tls_version}.",
                ),
            ]
            return RuleEvaluationResult(
                rule_id=self.rule_id,
                title=f"Modern TLS Version ({session.tls_version})",
                severity="INFO",
                category=self.category,
                status="PASS",
                confidence="HIGH",
                plain_explanation=f"A currently accepted TLS protocol version ({session.tls_version}) was observed.",
                why_it_matters=f"{session.tls_version} conforms to modern transport security baselines and supports strong cryptographic primitives.",
                recommendation="Maintain current TLS version baseline and monitor for future cryptographic standard updates.",
                references=ref,
                evidence=evidence,
                affected_connection_id=f"conn-real-{session.stream_id}",
                location=f"{session.client_ip} → {session.server_ip}",
            )
        return None

# ----------------------------------------------------------------------
# RULE SMS-CIPHER-001: Weak / Deprecated Cipher
# ----------------------------------------------------------------------
class WeakCipherRule(BaseSecurityRule):
    rule_id = "SMS-CIPHER-001"
    title = "Weak / Deprecated Cipher Suite"
    category = "Cipher Suite Strength"
    references = ["RFC 7465", "RFC 7540", "NIST SP 800-52 Rev. 2"]

    WEAK_PATTERNS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "EXP", "MD5", "IDEA")

    def evaluate(self, session: EmailSessionContext) -> Optional[RuleEvaluationResult]:
        cipher = session.cipher_suite
        if not cipher or cipher in ("NONE (Unencrypted / Plaintext)", "UNKNOWN / Not Captured", "None"):
            return None

        cipher_upper = cipher.upper()
        if any(pat in cipher_upper for pat in self.WEAK_PATTERNS):
            evidence = [
                Evidence(
                    type="OBSERVED",
                    field="cipher_suite",
                    value=cipher,
                    source="TLS Handshake ServerHello",
                    description=f"Negotiated cipher suite identifier: {cipher}.",
                ),
            ]
            return RuleEvaluationResult(
                rule_id=self.rule_id,
                title=f"Weak / Deprecated Cipher Suite ({cipher})",
                severity="HIGH",
                category=self.category,
                status="FAIL",
                confidence="HIGH",
                plain_explanation=f"The session negotiated weak or deprecated cipher suite {cipher}, which is vulnerable to cryptanalytic attacks.",
                why_it_matters=f"The selected cipher suite ({cipher}) utilizes obsolete algorithms (such as 64-bit block ciphers like 3DES vulnerable to Sweet32, or stream ciphers like RC4) susceptible to practical collision or plaintext recovery attacks.",
                recommendation="Disable obsolete cipher suites (RC4, 3DES, DES, EXPORT, NULL) on the mail server and require modern AEAD suites (e.g., AES-GCM or ChaCha20-Poly1305).",
                references=self.references,
                evidence=evidence,
                affected_connection_id=f"conn-real-{session.stream_id}",
                location=f"{session.client_ip} → {session.server_ip}",
            )
        return None

# ----------------------------------------------------------------------
# RULE SMS-PFS-001: Forward Secrecy Assessment
# ----------------------------------------------------------------------
class ForwardSecrecyRule(BaseSecurityRule):
    rule_id = "SMS-PFS-001"
    title = "Forward Secrecy Assessment"
    category = "Key Exchange"
    references = ["RFC 8446", "NIST SP 800-52 Rev. 2"]

    def evaluate(self, session: EmailSessionContext) -> Optional[RuleEvaluationResult]:
        cipher = session.cipher_suite
        if not cipher or cipher in ("NONE (Unencrypted / Plaintext)", "UNKNOWN / Not Captured", "None"):
            return None

        cipher_upper = cipher.upper()
        has_ephemeral = session.has_pfs if session.tls_version == "TLS 1.3" else any(k in cipher_upper for k in ("ECDHE", "DHE"))
        is_static_rsa = ("RSA_WITH_" in cipher_upper or cipher_upper.startswith("TLS_RSA_")) and not has_ephemeral

        if has_ephemeral:
            evidence = [
                Evidence(
                    type="OBSERVED",
                    field="has_pfs",
                    value=True,
                    source="TLS ServerHello key_share" if session.tls_version == "TLS 1.3" else "TLS Handshake Cipher Suite",
                    description=(f"TLS 1.3 ServerHello key_share observed: {session.server_key_share_group or 'group unavailable'}."
                                 if session.tls_version == "TLS 1.3" else f"Negotiated cipher suite {cipher} includes ephemeral key exchange."),
                ),
            ]
            return RuleEvaluationResult(
                rule_id=self.rule_id,
                title="Forward Secrecy Supported",
                severity="INFO",
                category=self.category,
                status="PASS",
                confidence="HIGH",
                plain_explanation=("The TLS 1.3 ServerHello key_share indicates ephemeral key exchange; the cipher name alone does not establish this."
                                   if session.tls_version == "TLS 1.3" else "The negotiated cipher suite utilizes ephemeral key exchange (ECDHE/DHE), providing Perfect Forward Secrecy."),
                why_it_matters="Ephemeral key exchange ensures that recorded encrypted traffic cannot be decrypted retroactively even if server private keys are compromised at a later date.",
                recommendation="Continue enforcing ephemeral key exchanges (ECDHE) across all mail transport connections.",
                references=self.references,
                evidence=evidence,
                affected_connection_id=f"conn-real-{session.stream_id}",
                location=f"{session.client_ip} → {session.server_ip}",
            )
        elif is_static_rsa:
            evidence = [
                Evidence(
                    type="OBSERVED",
                    field="has_pfs",
                    value=False,
                    source="TLS Handshake Cipher Suite",
                    description=f"Negotiated cipher suite {cipher} uses static RSA key exchange without ephemeral parameters.",
                ),
            ]
            return RuleEvaluationResult(
                rule_id=self.rule_id,
                title="Static Key Exchange Without Forward Secrecy",
                severity="MEDIUM",
                category=self.category,
                status="WARN",
                confidence="HIGH",
                plain_explanation="The session negotiated a static RSA key exchange cipher suite lacking Perfect Forward Secrecy. Compromise of the server private key allows retroactive decryption of past sessions.",
                why_it_matters="Static key exchange allows an adversary who captures encrypted traffic to decrypt it retroactively if they acquire the server's private key in the future.",
                recommendation="Configure the mail server to disable static RSA key exchange suites and prioritize ECDHE key exchange.",
                references=self.references,
                evidence=evidence,
                affected_connection_id=f"conn-real-{session.stream_id}",
                location=f"{session.client_ip} → {session.server_ip}",
            )

        return None

# ----------------------------------------------------------------------
# RULE SMS-COVERAGE-001: Insufficient Cryptographic Evidence
# ----------------------------------------------------------------------
class CoverageGapRule(BaseSecurityRule):
    rule_id = "SMS-COVERAGE-001"
    title = "Insufficient Cryptographic Evidence"
    category = "Capture Coverage"
    references = ["SecureMailScope Evidence Guidelines"]

    def evaluate(self, session: EmailSessionContext) -> Optional[RuleEvaluationResult]:
        # Triggers when TLS traffic was observed (e.g. STARTTLS used or implicit TLS port), but cipher or handshake was incomplete
        tls_intended = session.starttls_used or session.server_port in {465, 993, 995} or (session.tls_version != "None" and session.tls_version != "UNKNOWN")
        cipher_missing = session.cipher_suite in ("UNKNOWN / Not Captured", "UNKNOWN", "")
        
        if (tls_intended and cipher_missing) or session.tls_version == "UNKNOWN":
            evidence = [
                Evidence(
                    type="COVERAGE_GAP",
                    field="cipher_suite",
                    value="UNKNOWN",
                    source="TCP Stream Handshake Window",
                    description="TLS traffic was observed, but the available capture does not contain sufficient handshake evidence to determine the negotiated cipher suite.",
                ),
            ]
            return RuleEvaluationResult(
                rule_id=self.rule_id,
                title=self.title,
                severity="INFO",
                category=self.category,
                status="UNKNOWN",
                confidence="LOW",
                plain_explanation="TLS traffic was observed, but the available capture does not contain sufficient handshake evidence to determine the negotiated cipher suite.",
                why_it_matters="Without complete ServerHello handshake frames in the capture window, cryptographic cipher strength and forward secrecy cannot be conclusively verified.",
                recommendation="Capture network traffic from the initiation of the TCP session to include complete ClientHello and ServerHello handshake frames.",
                references=self.references,
                evidence=evidence,
                affected_connection_id=f"conn-real-{session.stream_id}",
                location=f"{session.client_ip} → {session.server_ip}",
            )
        return None
