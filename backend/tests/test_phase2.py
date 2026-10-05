import pytest
import os
import json
from app.analysis.evidence import Evidence
from app.analysis.normalization import normalize_tls_version, normalize_cipher_suite
from app.analysis.rules import (
    EmailSessionContext,
    CleartextTransportRule,
    StartTLSUnusedRule,
    AuthenticationBeforeTLSRule,
    DeprecatedTLSRule,
    ModernTLSRule,
    WeakCipherRule,
    ForwardSecrecyRule,
    CoverageGapRule,
)
from app.analysis.scoring import calculate_security_posture
from app.analysis.engine import SecurityAnalysisEngine
from app.parse.sessions import reconstruct_investigation_from_packets

# --- TEST A: SMTP cleartext, STARTTLS unavailable ---
def test_rule_cleartext_email_transport():
    session = EmailSessionContext(
        stream_id="0",
        protocol="SMTP",
        client_ip="192.168.1.10",
        client_port=50000,
        server_ip="10.0.0.1",
        server_port=25,
        transport_mode="CLEARTEXT",
        tls_version="None",
        cipher_suite="NONE (Unencrypted / Plaintext)",
        starttls_advertised=False,
        starttls_used=False,
    )
    rule = CleartextTransportRule()
    result = rule.evaluate(session)
    assert result is not None
    assert result.rule_id == "SMS-TLS-001"
    assert result.severity == "HIGH"
    assert result.status == "FAIL"
    assert "without TLS protection" in result.plain_explanation
    assert any(e.field == "tls_version" and e.type == "OBSERVED" for e in result.evidence)

# --- TEST B: SMTP STARTTLS advertised but unused ---
def test_rule_starttls_advertised_but_unused():
    session = EmailSessionContext(
        stream_id="1",
        protocol="SMTP",
        client_ip="10.10.1.4",
        client_port=1470,
        server_ip="74.53.140.153",
        server_port=25,
        transport_mode="CLEARTEXT (STARTTLS Offered but Not Used)",
        tls_version="None",
        cipher_suite="NONE (Unencrypted / Plaintext)",
        starttls_advertised=True,
        starttls_used=False,
    )
    rule = StartTLSUnusedRule()
    result = rule.evaluate(session)
    assert result is not None
    assert result.rule_id == "SMS-STARTTLS-001"
    assert result.severity == "HIGH"
    assert result.status == "FAIL"
    assert "stripping attack" not in result.plain_explanation.lower()
    assert any(e.field == "starttls_advertised" and e.value is True for e in result.evidence)
    assert any(e.field == "starttls_used" and e.value is False for e in result.evidence)

# --- TEST C: SMTP authentication before TLS ---
def test_rule_authentication_before_tls():
    session = EmailSessionContext(
        stream_id="2",
        protocol="SMTP",
        client_ip="10.10.1.4",
        client_port=1470,
        server_ip="74.53.140.153",
        server_port=25,
        transport_mode="CLEARTEXT",
        tls_version="None",
        cipher_suite="NONE (Unencrypted / Plaintext)",
        auth_observed=True,
        auth_before_tls=True,
    )
    rule = AuthenticationBeforeTLSRule()
    result = rule.evaluate(session)
    assert result is not None
    assert result.rule_id == "SMS-AUTH-001"
    assert result.severity == "CRITICAL"
    assert result.status == "FAIL"
    assert "Authentication occurred before TLS" in result.plain_explanation

# --- TEST D: Deprecated TLS 1.0 ---
def test_rule_deprecated_tls_1_0():
    session = EmailSessionContext(
        stream_id="3",
        protocol="SMTP",
        client_ip="10.240.12.5",
        client_port=38210,
        server_ip="10.240.12.88",
        server_port=25,
        transport_mode="STARTTLS",
        tls_version="TLS 1.0",
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
    )
    rule = DeprecatedTLSRule()
    result = rule.evaluate(session)
    assert result is not None
    assert result.rule_id == "SMS-TLSVER-001"
    assert result.severity == "HIGH"
    assert result.status == "FAIL"
    assert "TLS 1.0" in result.plain_explanation
    assert "RFC 8996" in result.references

# --- TEST E: Deprecated TLS 1.1 ---
def test_rule_deprecated_tls_1_1():
    session = EmailSessionContext(
        stream_id="4",
        protocol="IMAP",
        client_ip="192.168.1.50",
        client_port=55120,
        server_ip="192.168.1.1",
        server_port=993,
        transport_mode="Direct TLS (Implicit)",
        tls_version="TLS 1.1",
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
    )
    rule = DeprecatedTLSRule()
    result = rule.evaluate(session)
    assert result is not None
    assert result.rule_id == "SMS-TLSVER-001"
    assert result.severity == "HIGH"
    assert result.status == "FAIL"
    assert "TLS 1.1" in result.plain_explanation

# --- TEST F: Modern TLS 1.2 PASS ---
def test_rule_modern_tls_1_2():
    session = EmailSessionContext(
        stream_id="5",
        protocol="SMTP",
        client_ip="203.0.113.10",
        client_port=41908,
        server_ip="10.240.12.5",
        server_port=587,
        transport_mode="STARTTLS",
        tls_version="TLS 1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    )
    rule = ModernTLSRule()
    result = rule.evaluate(session)
    assert result is not None
    assert result.rule_id == "SMS-TLSVER-002"
    assert result.severity == "INFO"
    assert result.status == "PASS"
    assert "currently accepted TLS protocol version" in result.plain_explanation

# --- TEST G: Modern TLS 1.3 PASS ---
def test_rule_modern_tls_1_3():
    session = EmailSessionContext(
        stream_id="6",
        protocol="SMTP",
        client_ip="198.51.100.24",
        client_port=58412,
        server_ip="203.0.113.10",
        server_port=25,
        transport_mode="STARTTLS",
        tls_version="TLS 1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        has_pfs=True,
    )
    rule = ModernTLSRule()
    result = rule.evaluate(session)
    assert result is not None
    assert result.rule_id == "SMS-TLSVER-002"
    assert result.severity == "INFO"
    assert result.status == "PASS"
    assert "RFC 8446" in result.references

# --- TEST H: Weak Cipher RC4 ---
def test_rule_weak_cipher_rc4():
    session = EmailSessionContext(
        stream_id="7",
        protocol="SMTP",
        client_ip="192.168.1.100",
        client_port=49000,
        server_ip="10.0.0.5",
        server_port=25,
        transport_mode="Explicit TLS",
        tls_version="TLS 1.2",
        cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
        raw_cipher="0x0005",
    )
    rule = WeakCipherRule()
    result = rule.evaluate(session)
    assert result is not None
    assert result.rule_id == "SMS-CIPHER-001"
    assert result.severity == "HIGH"
    assert result.status == "FAIL"
    assert "TLS_RSA_WITH_RC4_128_SHA" in result.plain_explanation

# --- TEST I: Weak Cipher 3DES ---
def test_rule_weak_cipher_3des():
    session = EmailSessionContext(
        stream_id="8",
        protocol="SMTP",
        client_ip="192.168.1.100",
        client_port=49001,
        server_ip="10.0.0.5",
        server_port=25,
        transport_mode="Explicit TLS",
        tls_version="TLS 1.0",
        cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        raw_cipher="0x000a",
    )
    rule = WeakCipherRule()
    result = rule.evaluate(session)
    assert result is not None
    assert result.rule_id == "SMS-CIPHER-001"
    assert result.severity == "HIGH"
    assert result.status == "FAIL"
    assert "3DES" in result.plain_explanation

# --- TEST J: TLS observed but cipher unavailable (Coverage Gap) ---
def test_rule_coverage_gap_insufficient_evidence():
    session = EmailSessionContext(
        stream_id="9",
        protocol="SMTP",
        client_ip="192.168.1.100",
        client_port=49002,
        server_ip="10.0.0.5",
        server_port=465,
        transport_mode="Direct TLS (Implicit)",
        tls_version="TLS 1.2",
        cipher_suite="UNKNOWN / Not Captured",
        starttls_used=True,
    )
    rule = CoverageGapRule()
    result = rule.evaluate(session)
    assert result is not None
    assert result.rule_id == "SMS-COVERAGE-001"
    assert result.status == "UNKNOWN"
    assert any(e.type == "COVERAGE_GAP" for e in result.evidence)
    # Ensure weak cipher rule does NOT fabricate a finding
    weak_rule = WeakCipherRule()
    assert weak_rule.evaluate(session) is None

# --- TEST K: No email session in capture ---
def test_no_email_session_in_capture():
    packets = [
        {
            "frame.number": "1",
            "ip.src": "192.168.1.5",
            "ip.dst": "8.8.8.8",
            "tcp.srcport": "54321",
            "tcp.dstport": "53",
            "tcp.stream": "0",
            "_ws.col.Protocol": "DNS",
        }
    ]
    inv = reconstruct_investigation_from_packets("dns_capture.pcap", "abcdef000000", "abcdef000000", packets)
    assert inv.summary.sessions_analyzed == 0
    assert inv.security_posture is not None
    assert inv.security_posture.status == "UNKNOWN"
    assert len(inv.findings) == 1
    assert inv.findings[0].rule_id == "RULE-REAL-NO-MAIL-TRAFFIC"

# --- TEST L: Multiple sessions evaluated independently ---
def test_multiple_sessions_independent_evaluation():
    s1 = EmailSessionContext(
        stream_id="101",
        has_pfs=True,
        protocol="SMTP",
        client_ip="192.168.1.10",
        client_port=50001,
        server_ip="10.0.0.1",
        server_port=25,
        transport_mode="STARTTLS",
        tls_version="TLS 1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        starttls_advertised=True,
        starttls_used=True,
    )
    s2 = EmailSessionContext(
        stream_id="102",
        protocol="SMTP",
        client_ip="192.168.1.11",
        client_port=50002,
        server_ip="10.0.0.2",
        server_port=25,
        transport_mode="CLEARTEXT",
        tls_version="None",
        cipher_suite="NONE (Unencrypted / Plaintext)",
        auth_observed=True,
        auth_before_tls=True,
    )
    engine = SecurityAnalysisEngine()
    findings, posture = engine.analyze_sessions([s1, s2])
    
    stream_101_findings = [f for f in findings if f.affected_connection_id == "conn-real-101"]
    stream_102_findings = [f for f in findings if f.affected_connection_id == "conn-real-102"]

    # Stream 101 should have modern TLS PASS finding and forward secrecy PASS
    assert any(f.rule_id == "SMS-TLSVER-002" and f.status == "PASS" for f in stream_101_findings)
    assert any(f.rule_id == "SMS-PFS-001" and f.status == "PASS" for f in stream_101_findings)

    # Stream 102 should have CRITICAL auth finding and cleartext finding
    assert any(f.rule_id == "SMS-AUTH-001" and f.severity == "CRITICAL" for f in stream_102_findings)
    assert any(f.rule_id == "SMS-TLS-001" and f.severity == "HIGH" for f in stream_102_findings)

    # Overall posture must be CRITICAL due to Stream 102
    assert posture.status == "CRITICAL"
    assert posture.critical_count == 1

# --- TEST M: Sensitive values never exposed ---
def test_sensitive_values_not_exposed():
    engine = SecurityAnalysisEngine()
    session = EmailSessionContext(
        stream_id="0",
        protocol="SMTP",
        client_ip="10.10.1.4",
        client_port=1470,
        server_ip="74.53.140.153",
        server_port=25,
        transport_mode="CLEARTEXT",
        tls_version="None",
        cipher_suite="NONE (Unencrypted / Plaintext)",
        auth_observed=True,
        auth_before_tls=True,
    )
    findings, posture = engine.analyze_sessions([session])
    
    # Serialize to JSON string to inspect full payload
    serialized = json.dumps([f.model_dump() for f in findings])
    
    forbidden_terms = ["password", "secret", "base64", "LOGIN dXNlcg==", "dXNlcm5hbWU=", "cGFzc3dvcmQ="]
    for term in forbidden_terms:
        assert term.lower() not in serialized.lower(), f"Forbidden term {term} found in findings output!"

# --- TEST N: Forward Secrecy Evaluation (PFS PASS vs Static RSA WARN) ---
def test_forward_secrecy_evaluations():
    rule = ForwardSecrecyRule()

    # ECDHE -> PASS
    pfs_session = EmailSessionContext(
        stream_id="201",
        protocol="SMTP",
        client_ip="1.1.1.1",
        client_port=1000,
        server_ip="2.2.2.2",
        server_port=25,
        transport_mode="STARTTLS",
        tls_version="TLS 1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    )
    pfs_res = rule.evaluate(pfs_session)
    assert pfs_res is not None
    assert pfs_res.status == "PASS"
    assert pfs_res.severity == "INFO"

    # Static RSA -> WARN
    static_session = EmailSessionContext(
        stream_id="202",
        protocol="SMTP",
        client_ip="1.1.1.1",
        client_port=1000,
        server_ip="2.2.2.2",
        server_port=25,
        transport_mode="STARTTLS",
        tls_version="TLS 1.2",
        cipher_suite="TLS_RSA_WITH_AES_128_GCM_SHA256",
    )
    static_res = rule.evaluate(static_session)
    assert static_res is not None
    assert static_res.status == "WARN"
    assert static_res.severity == "MEDIUM"

# --- TEST O: Real smtp.pcap analysis (if present) ---
def test_real_smtp_pcap_analysis():
    pcap_path = r"C:\Users\LOQ\Downloads\smtp.pcap"
    if not os.path.exists(pcap_path):
        pytest.skip(f"Capture {pcap_path} not found on disk")

    from app.ingest.tshark import extract_packet_records
    from app.ingest.validator import validate_pcap_file

    with open(pcap_path, "rb") as f:
        file_bytes = f.read()

    validation = validate_pcap_file("smtp.pcap", file_bytes)
    assert validation.is_valid

    pkts = extract_packet_records(pcap_path)
    assert len(pkts) > 0

    inv = reconstruct_investigation_from_packets(
        "smtp.pcap",
        validation.sha256_full,
        validation.sha256_short,
        pkts,
    )

    assert inv.data_source == "REAL_CAPTURE"
    assert inv.summary.sessions_analyzed == 1
    assert inv.security_posture is not None
    assert inv.security_posture.status == "CRITICAL"

    rule_ids = {f.rule_id for f in inv.findings}
    assert "SMS-AUTH-001" in rule_ids
    assert "SMS-STARTTLS-001" in rule_ids
    assert "SMS-TLS-001" in rule_ids
    assert "SMS-TLSVER-001" not in rule_ids  # No TLS handshake
    assert "SMS-CIPHER-001" not in rule_ids  # No TLS handshake
