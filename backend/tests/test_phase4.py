import pytest
import os
import json
from app.replay.models import SecurityEvent, CriticalMoment, ReplaySummary, SessionReplay
from app.replay.builder import ReplayBuilder
from app.replay.sanitization import sanitize_smtp_command, sanitize_smtp_response
from app.models import SecurityFinding
from app.analysis.rules import EmailSessionContext
from app.ingest.validator import validate_pcap_file
from app.ingest.tshark import is_tshark_available, extract_packet_records
from app.parse.sessions import reconstruct_investigation_from_packets

REAL_PCAP_PATH = r"C:\Users\LOQ\Downloads\smtp.pcap"

def make_packet(frame_num: int, rel_time: float, src_ip: str, dst_ip: str, src_port: int, dst_port: int, **kwargs):
    pkt = {
        "frame.number": str(frame_num),
        "frame.time_epoch": str(1600000000.0 + rel_time),
        "frame.time_relative": str(rel_time),
        "ip.src": src_ip,
        "ip.dst": dst_ip,
        "tcp.srcport": str(src_port),
        "tcp.dstport": str(dst_port),
        "tcp.stream": "0",
        "tcp.flags.syn": "0",
        "_ws.col.Protocol": "SMTP",
    }
    pkt.update(kwargs)
    return pkt

# -----------------------------------------------------------------------------
# TEST A: SMTP cleartext basic sequence
# -----------------------------------------------------------------------------
def test_replay_smtp_cleartext_basic_sequence():
    pkts = [
        make_packet(1, 0.0, "10.0.0.1", "10.0.0.2", 1234, 25, **{"tcp.flags.syn": "1"}),
        make_packet(2, 0.05, "10.0.0.2", "10.0.0.1", 25, 1234, **{"smtp.response.code": "220", "smtp.response": "220 mail.example.com ESMTP"}),
        make_packet(3, 0.10, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "EHLO client.example.com"}),
        make_packet(4, 0.15, "10.0.0.2", "10.0.0.1", 25, 1234, **{"smtp.response.code": "250", "smtp.response": "250-mail.example.com\n250 HELP"}),
        make_packet(5, 0.20, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "MAIL FROM:<alice@example.com>"}),
        make_packet(6, 0.30, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "QUIT"}),
    ]
    ctx = EmailSessionContext(
        stream_id="0",
        protocol="SMTP",
        client_ip="10.0.0.1",
        client_port=1234,
        server_ip="10.0.0.2",
        server_port=25,
        transport_mode="CLEARTEXT",
        tls_version="None",
        cipher_suite="NONE (Unencrypted / Plaintext)",
        starttls_advertised=False,
        starttls_used=False,
    )
    finding = SecurityFinding(
        id="F-1", title="Cleartext", severity="HIGH", category="Transport", status="FAIL", confidence="HIGH",
        location="10.0.0.1 -> 10.0.0.2", plain_explanation="Cleartext", why_it_matters="No TLS", evidence="Stream 0",
        recommendation="Enable TLS", rule_id="SMS-TLS-001", affected_connection_id="conn-real-0"
    )

    builder = ReplayBuilder()
    replay = builder.build_replay("0", pkts, ctx, [finding])

    event_types = [e.event_type for e in replay.events]
    assert "TCP_CONNECTION_ESTABLISHED" in event_types
    assert "SERVER_GREETING" in event_types
    assert "CLIENT_GREETING" in event_types
    assert "MAIL_TRANSACTION_STARTED" in event_types
    assert "SESSION_TERMINATED" in event_types
    assert "TLS_ESTABLISHED" not in event_types
    assert "STARTTLS_REQUESTED" not in event_types
    assert replay.summary.final_transport == "CLEARTEXT"

# -----------------------------------------------------------------------------
# TEST B: SMTP STARTTLS advertised but unused
# -----------------------------------------------------------------------------
def test_replay_starttls_advertised_but_unused():
    pkts = [
        make_packet(1, 0.0, "10.0.0.1", "10.0.0.2", 1234, 25, **{"tcp.flags.syn": "1"}),
        make_packet(2, 0.05, "10.0.0.2", "10.0.0.1", 25, 1234, **{"smtp.response.code": "220", "smtp.response": "220 Ready"}),
        make_packet(3, 0.10, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "EHLO"}),
        make_packet(4, 0.15, "10.0.0.2", "10.0.0.1", 25, 1234, **{"smtp.rsp.parameter": "STARTTLS", "smtp.response": "250-STARTTLS"}),
        make_packet(5, 0.20, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "MAIL FROM:<bob@example.com>"}),
        make_packet(6, 0.30, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "QUIT"}),
    ]
    ctx = EmailSessionContext(
        stream_id="0",
        protocol="SMTP",
        client_ip="10.0.0.1",
        client_port=1234,
        server_ip="10.0.0.2",
        server_port=25,
        transport_mode="CLEARTEXT (STARTTLS Offered but Not Used)",
        tls_version="None",
        cipher_suite="NONE (Unencrypted / Plaintext)",
        starttls_advertised=True,
        starttls_used=False,
    )
    finding = SecurityFinding(
        id="F-STLS", title="STARTTLS Advertised But Not Used", severity="HIGH", category="Transport", status="FAIL",
        confidence="HIGH", location="10.0.0.1 -> 10.0.0.2", plain_explanation="STARTTLS unused", why_it_matters="No TLS",
        evidence="Stream 0", recommendation="Mandate TLS", rule_id="SMS-STARTTLS-001", affected_connection_id="conn-real-0"
    )

    builder = ReplayBuilder()
    replay = builder.build_replay("0", pkts, ctx, [finding])

    event_types = [e.event_type for e in replay.events]
    assert "STARTTLS_ADVERTISED" in event_types
    assert "STARTTLS_REQUESTED" not in event_types
    assert "TLS_ESTABLISHED" not in event_types
    
    stls_evt = next(e for e in replay.events if e.event_type == "STARTTLS_ADVERTISED")
    assert "SMS-STARTTLS-001" in stls_evt.related_rule_ids

# -----------------------------------------------------------------------------
# TEST C: Authentication before TLS
# -----------------------------------------------------------------------------
def test_replay_authentication_before_tls():
    pkts = [
        make_packet(1, 0.0, "10.0.0.1", "10.0.0.2", 1234, 25, **{"tcp.flags.syn": "1"}),
        make_packet(2, 0.05, "10.0.0.2", "10.0.0.1", 25, 1234, **{"smtp.response.code": "220"}),
        make_packet(3, 0.10, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "EHLO"}),
        make_packet(4, 0.15, "10.0.0.2", "10.0.0.1", 25, 1234, **{"smtp.rsp.parameter": "STARTTLS", "smtp.response": "250-STARTTLS"}),
        make_packet(5, 0.25, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "AUTH LOGIN"}),
        make_packet(6, 0.35, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "QUIT"}),
    ]
    ctx = EmailSessionContext(
        stream_id="0",
        protocol="SMTP",
        client_ip="10.0.0.1",
        client_port=1234,
        server_ip="10.0.0.2",
        server_port=25,
        transport_mode="CLEARTEXT",
        tls_version="None",
        cipher_suite="NONE (Unencrypted / Plaintext)",
        starttls_advertised=True,
        starttls_used=False,
        auth_observed=True,
        auth_before_tls=True,
    )
    finding = SecurityFinding(
        id="F-AUTH", title="Authentication Before TLS", severity="CRITICAL", category="Authentication", status="FAIL",
        confidence="HIGH", location="10.0.0.1 -> 10.0.0.2", plain_explanation="Auth unencrypted", why_it_matters="Credentials exposed",
        evidence="Stream 0", recommendation="Require TLS", rule_id="SMS-AUTH-001", affected_connection_id="conn-real-0"
    )

    builder = ReplayBuilder()
    replay = builder.build_replay("0", pkts, ctx, [finding])

    event_types = [e.event_type for e in replay.events]
    assert "AUTHENTICATION_ATTEMPT" in event_types
    assert "AUTHENTICATION_BEFORE_TLS" in event_types

    auth_evt = next(e for e in replay.events if e.event_type == "AUTHENTICATION_BEFORE_TLS")
    assert auth_evt.security_state == "CRITICAL"
    assert "SMS-AUTH-001" in auth_evt.related_rule_ids

    assert replay.summary.highest_security_state == "CRITICAL"
    assert replay.critical_moment is not None
    assert replay.critical_moment.rule_id == "SMS-AUTH-001"

# -----------------------------------------------------------------------------
# TEST D: Secure STARTTLS flow
# -----------------------------------------------------------------------------
def test_replay_secure_starttls_flow():
    pkts = [
        make_packet(1, 0.0, "10.0.0.1", "10.0.0.2", 1234, 25, **{"tcp.flags.syn": "1"}),
        make_packet(2, 0.05, "10.0.0.2", "10.0.0.1", 25, 1234, **{"smtp.response.code": "220"}),
        make_packet(3, 0.10, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "EHLO"}),
        make_packet(4, 0.15, "10.0.0.2", "10.0.0.1", 25, 1234, **{"smtp.rsp.parameter": "STARTTLS", "smtp.response": "250-STARTTLS"}),
        make_packet(5, 0.20, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "STARTTLS"}),
        make_packet(6, 0.25, "10.0.0.1", "10.0.0.2", 1234, 25, **{"tls.handshake.type": "1"}), # ClientHello
        make_packet(7, 0.30, "10.0.0.2", "10.0.0.1", 25, 1234, **{"tls.handshake.type": "2", "tls.handshake.version": "0x0303"}), # ServerHello
        make_packet(8, 0.40, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "AUTH PLAIN"}),
    ]
    ctx = EmailSessionContext(
        stream_id="0",
        protocol="SMTP",
        client_ip="10.0.0.1",
        client_port=1234,
        server_ip="10.0.0.2",
        server_port=25,
        transport_mode="STARTTLS (Explicit)",
        tls_version="TLS 1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        starttls_advertised=True,
        starttls_used=True,
        auth_observed=True,
        auth_before_tls=False,
    )
    builder = ReplayBuilder()
    replay = builder.build_replay("0", pkts, ctx, [])

    event_types = [e.event_type for e in replay.events]
    assert "STARTTLS_ADVERTISED" in event_types
    assert "STARTTLS_REQUESTED" in event_types
    assert "TLS_HANDSHAKE_STARTED" in event_types
    assert "TLS_ESTABLISHED" in event_types
    assert "AUTHENTICATION_BEFORE_TLS" not in event_types

    auth_evt = next(e for e in replay.events if e.event_type == "AUTHENTICATION_ATTEMPT")
    assert auth_evt.security_state == "SECURE"
    assert auth_evt.transport_state == "TLS_PROTECTED"

# -----------------------------------------------------------------------------
# TEST E: TLS 1.3 direct TLS
# -----------------------------------------------------------------------------
def test_replay_direct_tls_13():
    pkts = [
        make_packet(1, 0.0, "10.0.0.1", "10.0.0.2", 1234, 465, **{"tcp.flags.syn": "1"}),
        make_packet(2, 0.05, "10.0.0.1", "10.0.0.2", 1234, 465, **{"tls.handshake.type": "1"}),
        make_packet(3, 0.10, "10.0.0.2", "10.0.0.1", 465, 1234, **{"tls.handshake.type": "2", "tls.handshake.version": "0x0304"}),
    ]
    ctx = EmailSessionContext(
        stream_id="0",
        protocol="SMTP",
        client_ip="10.0.0.1",
        client_port=1234,
        server_ip="10.0.0.2",
        server_port=465,
        transport_mode="Direct TLS (Implicit)",
        tls_version="TLS 1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
    )
    builder = ReplayBuilder()
    replay = builder.build_replay("0", pkts, ctx, [])

    event_types = [e.event_type for e in replay.events]
    assert "STARTTLS_ADVERTISED" not in event_types
    assert "STARTTLS_REQUESTED" not in event_types
    assert "TLS_ESTABLISHED" in event_types
    assert replay.summary.final_transport == "TLS_PROTECTED"

# -----------------------------------------------------------------------------
# TEST F: Sensitive SMTP AUTH payload privacy
# -----------------------------------------------------------------------------
def test_replay_sensitive_auth_payload_not_exposed():
    cmd_title, cmd_desc, cmd_meta = sanitize_smtp_command("AUTH LOGIN dXNlckBleGFtcGxlLmNvbQ== cGFzc3dvcmQxMjM=", None)
    assert "dXNlckBleGFtcGxlLmNvbQ==" not in cmd_title
    assert "dXNlckBleGFtcGxlLmNvbQ==" not in cmd_desc
    assert "password123" not in cmd_desc
    assert "cGFzc3dvcmQxMjM=" not in str(cmd_meta)

# -----------------------------------------------------------------------------
# TEST G: MAIL FROM / RCPT TO / DATA privacy
# -----------------------------------------------------------------------------
def test_replay_mail_transaction_addresses_not_exposed():
    cmd_title, cmd_desc, cmd_meta = sanitize_smtp_command("MAIL FROM:<confidential-ceo@victim-corp.com>", None)
    assert "confidential-ceo@victim-corp.com" not in cmd_title
    assert "confidential-ceo@victim-corp.com" not in cmd_desc
    assert "confidential-ceo@victim-corp.com" not in str(cmd_meta)
    assert cmd_title == "Mail Transaction"

# -----------------------------------------------------------------------------
# TEST H: Multiple sessions
# -----------------------------------------------------------------------------
def test_replay_multiple_sessions():
    pkts1 = [make_packet(1, 0.0, "10.0.0.1", "10.0.0.2", 1234, 25, **{"tcp.flags.syn": "1"})]
    pkts2 = [make_packet(2, 0.0, "10.0.0.3", "10.0.0.2", 1235, 25, **{"tcp.flags.syn": "1"})]

    ctx1 = EmailSessionContext(stream_id="1", protocol="SMTP", client_ip="10.0.0.1", client_port=1234, server_ip="10.0.0.2", server_port=25, transport_mode="CLEARTEXT")
    ctx2 = EmailSessionContext(stream_id="2", protocol="SMTP", client_ip="10.0.0.3", client_port=1235, server_ip="10.0.0.2", server_port=25, transport_mode="CLEARTEXT")

    builder = ReplayBuilder()
    r1 = builder.build_replay("1", pkts1, ctx1, [])
    r2 = builder.build_replay("2", pkts2, ctx2, [])

    assert r1.session_id == "SMTP-STREAM-1"
    assert r2.session_id == "SMTP-STREAM-2"
    assert r1.summary.client_endpoint == "10.0.0.1:1234"
    assert r2.summary.client_endpoint == "10.0.0.3:1235"

# -----------------------------------------------------------------------------
# TEST I: Partial capture coverage gap
# -----------------------------------------------------------------------------
def test_replay_partial_capture_coverage_gap():
    # Packets starting mid-stream without SYN or greeting
    pkts = [
        make_packet(45, 10.5, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "NOOP"}),
        make_packet(46, 10.6, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "QUIT"}),
    ]
    ctx = EmailSessionContext(stream_id="5", protocol="SMTP", client_ip="10.0.0.1", client_port=1234, server_ip="10.0.0.2", server_port=25, transport_mode="CLEARTEXT")
    builder = ReplayBuilder()
    replay = builder.build_replay("5", pkts, ctx, [])

    assert len(replay.events) >= 1
    assert replay.events[0].event_type == "COVERAGE_GAP"
    assert replay.events[0].security_state == "UNKNOWN"

# -----------------------------------------------------------------------------
# TEST J: Finding bridge
# -----------------------------------------------------------------------------
def test_replay_finding_bridge():
    pkts = [
        make_packet(1, 0.0, "10.0.0.1", "10.0.0.2", 1234, 25, **{"tcp.flags.syn": "1"}),
        make_packet(2, 0.1, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "AUTH PLAIN"}),
    ]
    ctx = EmailSessionContext(
        stream_id="0", protocol="SMTP", client_ip="10.0.0.1", client_port=1234, server_ip="10.0.0.2", server_port=25,
        transport_mode="CLEARTEXT", tls_version="None", auth_observed=True, auth_before_tls=True
    )
    finding = SecurityFinding(
        id="F-AUTH-001", title="Authentication Before TLS", severity="CRITICAL", category="Authentication", status="FAIL",
        confidence="HIGH", location="10.0.0.1 -> 10.0.0.2", plain_explanation="Auth unencrypted", why_it_matters="Credentials exposed",
        evidence="Stream 0", recommendation="Require TLS", rule_id="SMS-AUTH-001", affected_connection_id="conn-real-0"
    )

    builder = ReplayBuilder()
    replay = builder.build_replay("0", pkts, ctx, [finding])

    matched_events = [e for e in replay.events if "SMS-AUTH-001" in e.related_rule_ids]
    assert len(matched_events) > 0
    assert replay.critical_moment is not None
    assert replay.critical_moment.rule_id == "SMS-AUTH-001"

# -----------------------------------------------------------------------------
# TEST K: Secure session has no fabricated critical moment
# -----------------------------------------------------------------------------
def test_replay_secure_session_no_fabricated_critical_moment():
    pkts = [
        make_packet(1, 0.0, "10.0.0.1", "10.0.0.2", 1234, 465, **{"tcp.flags.syn": "1"}),
        make_packet(2, 0.05, "10.0.0.1", "10.0.0.2", 1234, 465, **{"tls.handshake.type": "1"}),
        make_packet(3, 0.10, "10.0.0.2", "10.0.0.1", 465, 1234, **{"tls.handshake.type": "2", "tls.handshake.version": "0x0304"}),
    ]
    ctx = EmailSessionContext(
        stream_id="0", protocol="SMTP", client_ip="10.0.0.1", client_port=1234, server_ip="10.0.0.2", server_port=465,
        transport_mode="Direct TLS (Implicit)", tls_version="TLS 1.3", cipher_suite="TLS_AES_256_GCM_SHA384"
    )
    builder = ReplayBuilder()
    replay = builder.build_replay("0", pkts, ctx, [])

    assert replay.critical_moment is None
    assert replay.summary.highest_security_state == "SECURE"

# -----------------------------------------------------------------------------
# TEST L: Relative timestamps monotonic
# -----------------------------------------------------------------------------
def test_replay_relative_timestamps_monotonic():
    pkts = [
        make_packet(1, 0.0, "10.0.0.1", "10.0.0.2", 1234, 25, **{"tcp.flags.syn": "1"}),
        make_packet(2, 0.05, "10.0.0.2", "10.0.0.1", 25, 1234, **{"smtp.response.code": "220"}),
        make_packet(3, 0.12, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "EHLO"}),
        make_packet(4, 0.30, "10.0.0.1", "10.0.0.2", 1234, 25, **{"smtp.req.command": "QUIT"}),
    ]
    ctx = EmailSessionContext(stream_id="0", protocol="SMTP", client_ip="10.0.0.1", client_port=1234, server_ip="10.0.0.2", server_port=25, transport_mode="CLEARTEXT")
    builder = ReplayBuilder()
    replay = builder.build_replay("0", pkts, ctx, [])

    times = [e.relative_time_ms for e in replay.events]
    for i in range(1, len(times)):
        assert times[i] >= times[i - 1]

# -----------------------------------------------------------------------------
# TEST M: Real smtp.pcap Replay
# -----------------------------------------------------------------------------
def test_real_smtp_pcap_replay():
    if not os.path.isfile(REAL_PCAP_PATH):
        pytest.skip(f"Target PCAP file {REAL_PCAP_PATH} is not present in environment.")
    if not is_tshark_available():
        pytest.skip("TShark binary is not accessible.")

    with open(REAL_PCAP_PATH, "rb") as f:
        pcap_bytes = f.read()

    val = validate_pcap_file("smtp.pcap", pcap_bytes)
    assert val.is_valid is True

    pkts = extract_packet_records(REAL_PCAP_PATH)
    inv = reconstruct_investigation_from_packets("smtp.pcap", val.sha256_full, val.sha256_short, pkts)

    assert len(inv.replays) >= 1
    replay = inv.replays[0]

    assert replay.protocol == "SMTP"
    assert replay.summary.client_endpoint == "10.10.1.4:1470"
    assert replay.summary.server_endpoint == "74.53.140.153:25"
    assert replay.summary.highest_security_state == "CRITICAL"
    assert replay.critical_moment is not None
    assert replay.critical_moment.rule_id == "SMS-AUTH-001"

    event_types = [e.event_type for e in replay.events]
    assert "TCP_CONNECTION_ESTABLISHED" in event_types
    assert "SERVER_GREETING" in event_types
    assert "CLIENT_GREETING" in event_types
    assert "STARTTLS_ADVERTISED" in event_types
    assert "AUTHENTICATION_ATTEMPT" in event_types
    assert "AUTHENTICATION_BEFORE_TLS" in event_types
    assert "MAIL_TRANSACTION_STARTED" in event_types
    assert "SESSION_TERMINATED" in event_types

# -----------------------------------------------------------------------------
# TEST PRIVACY: Complete Serialization Absence of Sensitive Credentials
# -----------------------------------------------------------------------------
def test_privacy_serialized_investigation_and_replay():
    if not os.path.isfile(REAL_PCAP_PATH) or not is_tshark_available():
        pytest.skip("Skipping real pcap privacy serialization test.")

    with open(REAL_PCAP_PATH, "rb") as f:
        pcap_bytes = f.read()

    val = validate_pcap_file("smtp.pcap", pcap_bytes)
    pkts = extract_packet_records(REAL_PCAP_PATH)
    inv = reconstruct_investigation_from_packets("smtp.pcap", val.sha256_full, val.sha256_short, pkts)

    inv_json = inv.model_dump_json()

    # Sensitive strings that should NEVER appear in serialized investigation or replay
    FORBIDDEN_STRINGS = [
        "dXNlcm5hbWU=",
        "cGFzc3dvcmQ=",
        "password",
        "secret",
        "Authorization:",
        "Bearer ",
    ]
    for forbidden in FORBIDDEN_STRINGS:
        assert forbidden not in inv_json
