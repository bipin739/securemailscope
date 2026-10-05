from typing import List, Dict, Any, Optional
from app.discovery.models import ClientIndicator, ObservedClientProfile

WEAK_CIPHER_KEYWORDS = ["3DES", "RC4", "DES", "EXPORT", "NULL", "MD5", "RC2"]
DEPRECATED_TLS_VERSIONS = ["TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0", "TLSv1.0", "TLSv1.1", "SSLv3"]

def evaluate_client_indicators(
    profile: ObservedClientProfile,
    population: Optional[List[ObservedClientProfile]] = None,
) -> List[ClientIndicator]:
    """
    Evaluates deterministic, explainable security and behavioral indicators for an observed client profile.
    Derives indicators strictly from observed packet and session evidence.
    """
    indicators: List[ClientIndicator] = []

    # 1. AUTH_BEFORE_TLS_OBSERVED
    if profile.auth_before_tls_count > 0:
        indicators.append(
            ClientIndicator(
                indicator_id="AUTH_BEFORE_TLS_OBSERVED",
                title="Authentication Before TLS",
                severity="CRITICAL",
                description="Client initiated authentication commands and credentials over an unencrypted channel before establishing TLS encryption.",
                evidence=f"{profile.auth_before_tls_count} session(s) transmitted authentication credentials in cleartext.",
                related_rule_ids=["SMS-AUTH-001"],
            )
        )

    # 2. CLEARTEXT_MAIL_OBSERVED
    has_cleartext = profile.plaintext_session_count > 0 or any("CLEARTEXT" in m.upper() for m in profile.transport_modes)
    if has_cleartext:
        indicators.append(
            ClientIndicator(
                indicator_id="CLEARTEXT_MAIL_OBSERVED",
                title="Cleartext Mail Transport",
                severity="HIGH",
                description="Email transport sessions transmitted protocol commands and message metadata without TLS encryption.",
                evidence=f"{profile.plaintext_session_count} unencrypted session(s) observed.",
                related_rule_ids=["SMS-TLS-001"],
            )
        )

    # 3. STARTTLS_AVAILABLE_BUT_UNUSED
    if profile.starttls_advertised_count > 0 and profile.starttls_used_count < profile.starttls_advertised_count:
        if profile.plaintext_session_count > 0 or any("CLEARTEXT" in m.upper() for m in profile.transport_modes):
            indicators.append(
                ClientIndicator(
                    indicator_id="STARTTLS_AVAILABLE_BUT_UNUSED",
                    title="STARTTLS Available But Not Used",
                    severity="HIGH",
                    description="Mail server advertised STARTTLS capability, but the client proceeded in plaintext without upgrading the channel.",
                    evidence=f"STARTTLS advertised in {profile.starttls_advertised_count} session(s), but only requested in {profile.starttls_used_count}.",
                    related_rule_ids=["SMS-STARTTLS-001"],
                )
            )

    # 4. LEGACY_TLS_OBSERVED
    has_legacy_tls = (
        profile.weak_tls_count > 0
        or any(v in DEPRECATED_TLS_VERSIONS for v in profile.observed_tls_versions)
    )
    if has_legacy_tls:
        leg_versions = [v for v in profile.observed_tls_versions if v in DEPRECATED_TLS_VERSIONS]
        indicators.append(
            ClientIndicator(
                indicator_id="LEGACY_TLS_OBSERVED",
                title="Legacy TLS Protocol Observed",
                severity="HIGH",
                description="Client negotiated deprecated TLS protocol versions lacking modern AEAD encryption and forward secrecy safeguards.",
                evidence=f"Negotiated legacy version(s): {', '.join(leg_versions) if leg_versions else 'TLS 1.0 / 1.1'}.",
                related_rule_ids=["SMS-TLSVER-001"],
            )
        )

    # 5. WEAK_CIPHER_OBSERVED
    has_weak_cipher = (
        profile.weak_cipher_count > 0
        or any(any(k in c.upper() for k in WEAK_CIPHER_KEYWORDS) for c in profile.observed_cipher_suites)
    )
    if has_weak_cipher:
        weak_ciphers = [
            c for c in profile.observed_cipher_suites
            if any(k in c.upper() for k in WEAK_CIPHER_KEYWORDS)
        ]
        indicators.append(
            ClientIndicator(
                indicator_id="WEAK_CIPHER_OBSERVED",
                title="Weak Cipher Suite Observed",
                severity="HIGH",
                description="Client negotiated obsolete or cryptographically weak cipher suites vulnerable to downgrade or cryptanalysis.",
                evidence=f"Negotiated weak cipher(s): {', '.join(weak_ciphers) if weak_ciphers else '3DES / RC4'}.",
                related_rule_ids=["SMS-CIPHER-001"],
            )
        )

    # 6. MIXED_TRANSPORT_BEHAVIOR
    if profile.plaintext_session_count > 0 and profile.tls_session_count > 0:
        indicators.append(
            ClientIndicator(
                indicator_id="MIXED_TRANSPORT_BEHAVIOR",
                title="Mixed Transport Behavior",
                severity="MEDIUM",
                description="Client endpoint exhibited mixed transport security, communicating via both encrypted TLS and unencrypted cleartext across sessions.",
                evidence=f"{profile.tls_session_count} TLS-encrypted session(s) and {profile.plaintext_session_count} cleartext session(s) observed.",
                related_rule_ids=["SMS-TLS-001", "SMS-STARTTLS-001"],
            )
        )

    # 7. INSUFFICIENT_CAPABILITY_EVIDENCE
    if profile.evidence_quality == "INSUFFICIENT" or (
        not profile.supported_tls_versions and not profile.offered_cipher_suites and not profile.observed_tls_versions
    ):
        indicators.append(
            ClientIndicator(
                indicator_id="INSUFFICIENT_CAPABILITY_EVIDENCE",
                title="Insufficient Capability Evidence",
                severity="INFO",
                description="Capture window did not record a complete TLS ClientHello handshake, limiting cryptographic capability verification.",
                evidence="No ClientHello extension list available in captured packets.",
                related_rule_ids=[],
            )
        )

    # 8. RARE_CLIENT_PROFILE (relative capture context)
    if population and len(population) >= 5:
        # Check if cipher or TLS configuration is uncommon in this capture (< 20% of population)
        same_proto_pop = [p for p in population if p.protocol == profile.protocol]
        if same_proto_pop:
            same_tls = [
                p for p in same_proto_pop
                if set(p.observed_tls_versions) == set(profile.observed_tls_versions)
            ]
            same_ciphers = [
                p for p in same_proto_pop
                if set(p.observed_cipher_suites) == set(profile.observed_cipher_suites)
            ]
            if len(same_tls) == 1 or (profile.observed_cipher_suites and len(same_ciphers) == 1):
                indicators.append(
                    ClientIndicator(
                        indicator_id="RARE_CLIENT_PROFILE",
                        title="Statistically Uncommon Configuration",
                        severity="INFO",
                        description="Observed cryptographic baseline is statistically uncommon among endpoints in this specific capture.",
                        evidence=f"Unique cryptographic combination observed for only {len(same_tls)} of {len(population)} client(s) in this capture.",
                        related_rule_ids=[],
                    )
                )

    return indicators
