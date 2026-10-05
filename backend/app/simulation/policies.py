from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Tuple
from app.simulation.models import (
    HardeningPolicy,
    ObservedClientCapability,
    ClientSimulationResult,
    SimulationOutcome,
    SimulationConfidence,
)
from app.analysis.evidence import Evidence

WEAK_CIPHER_PATTERNS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "EXP", "MD5", "IDEA")

def is_cipher_weak(cipher_name: str) -> bool:
    """Returns True if the cipher belongs to an obsolete/deprecated cipher family."""
    if not cipher_name or cipher_name in ("NONE (Unencrypted / Plaintext)", "UNKNOWN / Not Captured", "None"):
        return False
    upper = cipher_name.upper()
    return any(pat in upper for pat in WEAK_CIPHER_PATTERNS)

def has_pfs_capability(cipher_name: str) -> bool:
    """Returns True if the cipher suite supports ephemeral key exchange (Forward Secrecy)."""
    if not cipher_name:
        return False
    upper = cipher_name.upper()
    return any(k in upper for k in ("ECDHE", "DHE", "TLS_AES_", "TLS_CHACHA20_"))

class BasePolicyEvaluator(ABC):
    """
    Abstract base evaluator for a deterministic hardening policy.
    """
    policy_id: str
    name: str
    description: str
    requirements: List[str]
    references: List[str]

    def get_policy(self) -> HardeningPolicy:
        return HardeningPolicy(
            id=self.policy_id,
            name=self.name,
            description=self.description,
            requirements=self.requirements,
            references=self.references,
        )

    @abstractmethod
    def evaluate_client(self, client: ObservedClientCapability) -> ClientSimulationResult:
        pass

# ----------------------------------------------------------------------
# POLICY SMS-POLICY-TLS12: Require TLS 1.2 or newer
# ----------------------------------------------------------------------
class RequireTLS12Policy(BasePolicyEvaluator):
    policy_id = "SMS-POLICY-TLS12"
    name = "Require TLS 1.2 or Newer"
    description = "Disables deprecated TLS 1.0 and TLS 1.1 protocols, requiring TLS 1.2 or TLS 1.3 as the minimum acceptable transport version."
    requirements = ["Prohibit TLS 1.0 and TLS 1.1", "Require TLS 1.2 or TLS 1.3"]
    references = ["RFC 8996", "NIST SP 800-52 Rev. 2"]

    def evaluate_client(self, client: ObservedClientCapability) -> ClientSimulationResult:
        evidence: List[Evidence] = []
        
        # 1. Check strong ClientHello capability data if available
        if client.supported_tls_versions:
            has_modern = any(v in ("TLS 1.2", "TLS 1.3") for v in client.supported_tls_versions)
            if has_modern:
                evidence.append(
                    Evidence(
                        type="OBSERVED",
                        field="supported_tls_versions",
                        value=client.supported_tls_versions,
                        source="TLS ClientHello supported_versions",
                        description="Client explicitly offered TLS 1.2+ in ClientHello capability list.",
                    )
                )
                return ClientSimulationResult(
                    client_id=client.client_id,
                    protocol=client.protocol,
                    endpoint=client.observed_ip,
                    outcome="COMPATIBLE",
                    confidence="HIGH",
                    reason="ClientHello capability evidence confirms support for modern TLS versions (TLS 1.2+).",
                    evidence=evidence,
                )
            elif all(v in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1") for v in client.supported_tls_versions):
                evidence.append(
                    Evidence(
                        type="OBSERVED",
                        field="supported_tls_versions",
                        value=client.supported_tls_versions,
                        source="TLS ClientHello supported_versions",
                        description="Client offered only deprecated TLS versions (< TLS 1.2) in ClientHello.",
                    )
                )
                return ClientSimulationResult(
                    client_id=client.client_id,
                    protocol=client.protocol,
                    endpoint=client.observed_ip,
                    outcome="WOULD_BREAK",
                    confidence="HIGH",
                    reason="Client capability evidence demonstrates support only for deprecated versions (TLS 1.0/1.1) and lacks TLS 1.2+.",
                    evidence=evidence,
                )

        # 3. No TLS evidence
        evidence.append(
            Evidence(
                type="COVERAGE_GAP",
                field="tls_version",
                value="NONE",
                source="Stream Inspection",
                description="ClientHello version offers are missing or unrecognized.",
            )
        )
        return ClientSimulationResult(
            client_id=client.client_id,
            protocol=client.protocol,
            endpoint=client.observed_ip,
            outcome="UNKNOWN",
            confidence="MEDIUM" if client.observed_tls_versions else "LOW",
            reason="The capture does not provide enough capability evidence: ClientHello offers are missing or unrecognized.",
            evidence=evidence,
        )

# ----------------------------------------------------------------------
# POLICY SMS-POLICY-NO-WEAK-CIPHER: Disable known weak cipher families
# ----------------------------------------------------------------------
class DisableWeakCiphersPolicy(BasePolicyEvaluator):
    policy_id = "SMS-POLICY-NO-WEAK-CIPHER"
    name = "Disable Weak Cipher Suites"
    description = "Prohibits obsolete cipher suites including RC4, 3DES, DES, NULL, and EXPORT families."
    requirements = ["Disable RC4 and 3DES/DES ciphers", "Disable NULL and EXPORT suites", "Require modern AEAD ciphers"]
    references = ["RFC 7465", "RFC 7540", "NIST SP 800-52 Rev. 2"]

    def evaluate_client(self, client: ObservedClientCapability) -> ClientSimulationResult:
        evidence: List[Evidence] = []

        # 1. Check strong ClientHello offered ciphers
        if client.offered_cipher_suites:
            allowed_ciphers = [c for c in client.offered_cipher_suites if not is_cipher_weak(c) and not c.startswith("UNKNOWN")]
            if allowed_ciphers:
                evidence.append(
                    Evidence(
                        type="OBSERVED",
                        field="offered_cipher_suites",
                        value=client.offered_cipher_suites,
                        source="TLS ClientHello ciphersuites",
                        description="Client offered modern, non-deprecated cipher suites in ClientHello.",
                    )
                )
                return ClientSimulationResult(
                    client_id=client.client_id,
                    protocol=client.protocol,
                    endpoint=client.observed_ip,
                    outcome="COMPATIBLE",
                    confidence="HIGH",
                    reason="Client capability evidence shows support for allowed modern cipher suites.",
                    evidence=evidence,
                )
            elif all(is_cipher_weak(c) for c in client.offered_cipher_suites):
                evidence.append(
                    Evidence(
                        type="OBSERVED",
                        field="offered_cipher_suites",
                        value=client.offered_cipher_suites,
                        source="TLS ClientHello ciphersuites",
                        description="Client offered exclusively weak/deprecated cipher suites.",
                    )
                )
                return ClientSimulationResult(
                    client_id=client.client_id,
                    protocol=client.protocol,
                    endpoint=client.observed_ip,
                    outcome="WOULD_BREAK",
                    confidence="HIGH",
                    reason="Client capability evidence shows support only for deprecated/weak cipher suites and no allowed modern options.",
                    evidence=evidence,
                )

        # 3. No cipher evidence
        evidence.append(
            Evidence(
                type="COVERAGE_GAP",
                field="cipher_suite",
                value="NONE",
                source="Stream Inspection",
                description="ClientHello cipher offers are missing or unrecognized.",
            )
        )
        return ClientSimulationResult(
            client_id=client.client_id,
            protocol=client.protocol,
            endpoint=client.observed_ip,
            outcome="UNKNOWN",
            confidence="MEDIUM" if client.observed_cipher_suites else "LOW",
            reason="The capture does not contain the complete ClientHello cipher list, or contains unrecognized suites.",
            evidence=evidence,
        )

# ----------------------------------------------------------------------
# POLICY SMS-POLICY-REQUIRE-TLS: Require encrypted email transport
# ----------------------------------------------------------------------
class RequireEncryptedTransportPolicy(BasePolicyEvaluator):
    policy_id = "SMS-POLICY-REQUIRE-TLS"
    name = "Require Encrypted Transport"
    description = "Mandates transport-layer encryption (Direct TLS or mandatory STARTTLS) for all email communications, rejecting unencrypted plaintext fallbacks."
    requirements = ["Enforce TLS on all mail connections", "Reject unencrypted plaintext fallback"]
    references = ["RFC 8314", "RFC 3207"]

    def evaluate_client(self, client: ObservedClientCapability) -> ClientSimulationResult:
        evidence: List[Evidence] = []

        # 1. If client used TLS in observed sessions -> COMPATIBLE
        if client.observed_tls_versions and any(v != "None" for v in client.observed_tls_versions):
            evidence.append(
                Evidence(
                    type="OBSERVED",
                    field="tls_version",
                    value=client.observed_tls_versions,
                    source="Transport Security Observation",
                    description="Client successfully established TLS encryption in observed traffic.",
                )
            )
            return ClientSimulationResult(
                client_id=client.client_id,
                protocol=client.protocol,
                endpoint=client.observed_ip,
                outcome="COMPATIBLE",
                confidence="HIGH",
                reason="Client demonstrated transport encryption capability in observed sessions.",
                evidence=evidence,
            )

        # 2. If client only had cleartext sessions
        if client.plaintext_observed:
            if client.starttls_observed and not client.starttls_used:
                evidence.append(
                    Evidence(
                        type="OBSERVED",
                        field="starttls_advertised",
                        value=True,
                        source="SMTP Capability Greeting",
                        description="Server advertised STARTTLS, but client continued without TLS upgrade.",
                    )
                )
                evidence.append(
                    Evidence(
                        type="COVERAGE_GAP",
                        field="client_tls_capability",
                        value="UNDETERMINED",
                        source="Session Observation",
                        description="Capture does not prove whether client is incapable of TLS or unconfigured.",
                    )
                )
                return ClientSimulationResult(
                    client_id=client.client_id,
                    protocol=client.protocol,
                    endpoint=client.observed_ip,
                    outcome="UNKNOWN",
                    confidence="MEDIUM",
                    reason="The server advertised STARTTLS, but the client continued without upgrading to TLS. The capture does not establish whether the client lacks TLS capability or was configured not to use it.",
                    evidence=evidence,
                )
            else:
                evidence.append(
                    Evidence(
                        type="OBSERVED",
                        field="transport_mode",
                        value="CLEARTEXT",
                        source="Session Observation",
                        description="Session was cleartext without server STARTTLS capability signaled.",
                    )
                )
                return ClientSimulationResult(
                    client_id=client.client_id,
                    protocol=client.protocol,
                    endpoint=client.observed_ip,
                    outcome="UNKNOWN",
                    confidence="LOW",
                    reason="The session was cleartext and the server did not advertise STARTTLS. Captured evidence is insufficient to determine whether the client supports TLS.",
                    evidence=evidence,
                )

        evidence.append(
            Evidence(
                type="COVERAGE_GAP",
                field="transport",
                value="UNKNOWN",
                source="Stream Inspection",
                description="Insufficient transport evidence.",
            )
        )
        return ClientSimulationResult(
            client_id=client.client_id,
            protocol=client.protocol,
            endpoint=client.observed_ip,
            outcome="UNKNOWN",
            confidence="LOW",
            reason="Insufficient session evidence to determine transport security compatibility.",
            evidence=evidence,
        )

# ----------------------------------------------------------------------
# POLICY SMS-POLICY-PFS: Require Forward Secrecy
# ----------------------------------------------------------------------
class RequireForwardSecrecyPolicy(BasePolicyEvaluator):
    policy_id = "SMS-POLICY-PFS"
    name = "Require Forward Secrecy (PFS)"
    description = "Mandates ephemeral key exchange (ECDHE / DHE) for all TLS connections to protect against retroactive bulk decryption."
    requirements = ["Require ephemeral key exchange (ECDHE / DHE)", "Prohibit static RSA key exchange"]
    references = ["RFC 8446", "NIST SP 800-52 Rev. 2"]

    def evaluate_client(self, client: ObservedClientCapability) -> ClientSimulationResult:
        evidence: List[Evidence] = []

        # 1. Check strong ClientHello offered ciphers
        if client.offered_cipher_suites:
            pfs_ciphers = [c for c in client.offered_cipher_suites if has_pfs_capability(c)]
            if pfs_ciphers:
                evidence.append(
                    Evidence(
                        type="OBSERVED",
                        field="offered_cipher_suites",
                        value=f"{len(pfs_ciphers)} PFS suites",
                        source="TLS ClientHello ciphersuites",
                        description="Client offered ephemeral key exchange (ECDHE/DHE) cipher suites.",
                    )
                )
                return ClientSimulationResult(
                    client_id=client.client_id,
                    protocol=client.protocol,
                    endpoint=client.observed_ip,
                    outcome="COMPATIBLE",
                    confidence="HIGH",
                    reason="Client capability evidence demonstrates support for ephemeral key exchange suites (ECDHE/DHE).",
                    evidence=evidence,
                )
            else:
                evidence.append(
                    Evidence(
                        type="OBSERVED",
                        field="offered_cipher_suites",
                        value=client.offered_cipher_suites,
                        source="TLS ClientHello ciphersuites",
                        description="Client offered only static RSA key exchange suites without PFS.",
                    )
                )
                return ClientSimulationResult(
                    client_id=client.client_id,
                    protocol=client.protocol,
                    endpoint=client.observed_ip,
                    outcome="WOULD_BREAK",
                    confidence="HIGH",
                    reason="Client capability evidence demonstrates support only for static RSA key exchange without Forward Secrecy.",
                    evidence=evidence,
                )

        # 2. Check negotiated session PFS
        if client.forward_secrecy_observed or any(has_pfs_capability(c) for c in client.observed_cipher_suites):
            evidence.append(
                Evidence(
                    type="OBSERVED",
                    field="forward_secrecy_observed",
                    value=True,
                    source="Negotiated TLS Session",
                    description="Session negotiated ephemeral Diffie-Hellman key exchange (PFS).",
                )
            )
            return ClientSimulationResult(
                client_id=client.client_id,
                protocol=client.protocol,
                endpoint=client.observed_ip,
                outcome="COMPATIBLE",
                confidence="HIGH",
                reason="Observed session negotiated an ephemeral key exchange cipher suite providing Perfect Forward Secrecy.",
                evidence=evidence,
            )

        if client.observed_cipher_suites and any(c != "NONE (Unencrypted / Plaintext)" for c in client.observed_cipher_suites):
            evidence.append(
                Evidence(
                    type="COVERAGE_GAP",
                    field="offered_cipher_suites",
                    value="UNKNOWN",
                    source="Negotiated TLS Session (Missing ClientHello list)",
                    description="Session negotiated static RSA, but complete ClientHello cipher list was uncaptured.",
                )
            )
            return ClientSimulationResult(
                client_id=client.client_id,
                protocol=client.protocol,
                endpoint=client.observed_ip,
                outcome="UNKNOWN",
                confidence="MEDIUM",
                reason="The session negotiated a static RSA key exchange cipher, but the capture does not contain the full ClientHello to determine if the client supports ephemeral key exchange.",
                evidence=evidence,
            )

        evidence.append(
            Evidence(
                type="COVERAGE_GAP",
                field="has_pfs",
                value="NONE",
                source="Stream Inspection",
                description="No cryptographic key exchange evidence was captured for this client.",
            )
        )
        return ClientSimulationResult(
            client_id=client.client_id,
            protocol=client.protocol,
            endpoint=client.observed_ip,
            outcome="UNKNOWN",
            confidence="LOW",
            reason="No cryptographic key exchange evidence was captured for this client.",
            evidence=evidence,
        )

# Registry of all built-in policies
POLICY_REGISTRY: Dict[str, BasePolicyEvaluator] = {
    RequireTLS12Policy.policy_id: RequireTLS12Policy(),
    DisableWeakCiphersPolicy.policy_id: DisableWeakCiphersPolicy(),
    RequireEncryptedTransportPolicy.policy_id: RequireEncryptedTransportPolicy(),
    RequireForwardSecrecyPolicy.policy_id: RequireForwardSecrecyPolicy(),
}
