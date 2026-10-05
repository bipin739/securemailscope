import pytest
import os
import struct
import hashlib
from app.ingest.validator import validate_pcap_file, PCAP_MAGIC_BYTES
from app.parse.sessions import (
    normalize_tls_version,
    normalize_cipher_suite,
    reconstruct_investigation_from_packets,
)

def create_mock_pcap_header() -> bytes:
    """Creates a valid 24-byte PCAP global header."""
    magic = 0xa1b2c3d4
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # Ethernet
    return struct.pack("=IHHiIII", magic, version_major, version_minor, thiszone, sigfigs, snaplen, network)

def create_mock_pcapng_header() -> bytes:
    """Creates a valid PCAPNG Section Header Block."""
    block_type = 0x0a0d0d0a
    block_length = 28
    byte_order_magic = 0x1a2b3c4d
    major_version = 1
    minor_version = 0
    section_length = -1
    return struct.pack("=IIHHqI", block_type, block_length, major_version, minor_version, section_length, block_length)

# --- VALIDATOR TESTS ---

def test_validator_rejects_unsupported_extension():
    result = validate_pcap_file("test.txt", b"sample data")
    assert not result.is_valid
    assert result.format_detected == "UNSUPPORTED_EXTENSION"
    assert "Unsupported file extension" in (result.error_message or "")

def test_validator_rejects_empty_file():
    result = validate_pcap_file("empty.pcap", b"")
    assert not result.is_valid
    assert result.format_detected == "EMPTY"
    assert "empty" in (result.error_message or "")

def test_validator_rejects_invalid_magic_bytes():
    fake_pcap = b"This is plain text pretending to be a pcap"
    result = validate_pcap_file("fake.pcap", fake_pcap)
    assert not result.is_valid
    assert result.format_detected == "INVALID_MAGIC"
    assert "unrecognized" in (result.error_message or "")

def test_validator_accepts_valid_pcap_magic():
    header = create_mock_pcap_header()
    result = validate_pcap_file("valid.pcap", header)
    assert result.is_valid
    assert "PCAP (Microsecond" in result.format_detected
    assert len(result.sha256_full) == 64
    assert len(result.sha256_short) == 12

def test_validator_accepts_valid_pcapng_magic():
    header = create_mock_pcapng_header()
    result = validate_pcap_file("valid.pcapng", header)
    assert result.is_valid
    assert "PCAPNG" in result.format_detected

# --- NORMALIZATION TESTS ---

def test_normalize_tls_version():
    assert normalize_tls_version("0x0304") == "TLS 1.3"
    assert normalize_tls_version("TLS 1.3") == "TLS 1.3"
    assert normalize_tls_version("0x0303") == "TLS 1.2"
    assert normalize_tls_version("0x0301") == "TLS 1.0"
    assert normalize_tls_version(None) == "None"

def test_normalize_cipher_suite():
    assert normalize_cipher_suite("0x1302", "TLS 1.3") == "TLS_AES_256_GCM_SHA384"
    assert normalize_cipher_suite("0xc02f", "TLS 1.2") == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert normalize_cipher_suite("0x000a", "TLS 1.0") == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    assert normalize_cipher_suite(None, "None") == "NONE (Unencrypted / Plaintext)"

# --- SESSION RECONSTRUCTION TESTS ---

def test_reconstruction_no_mail_traffic():
    packets = [
        {
            "frame.number": "1",
            "frame.time_epoch": "1700000000.0",
            "ip.src": "192.168.1.5",
            "ip.dst": "8.8.8.8",
            "tcp.srcport": "54321",
            "tcp.dstport": "80",
            "tcp.stream": "0",
            "_ws.col.Protocol": "HTTP",
        }
    ]
    inv = reconstruct_investigation_from_packets("http_capture.pcap", "abcdef123456", "abcdef123456", packets)
    assert inv.data_source == "REAL_CAPTURE"
    assert inv.summary.sessions_analyzed == 0
    assert len(inv.findings) == 1
    assert inv.findings[0].title == "No Email Transport Sessions Identified"

def test_reconstruction_smtp_tls13():
    packets = [
        {
            "frame.number": "1",
            "frame.time_epoch": "1700000001.0",
            "ip.src": "192.168.1.10",
            "ip.dst": "10.0.0.25",
            "tcp.srcport": "49152",
            "tcp.dstport": "25",
            "tcp.stream": "1",
            "_ws.col.Protocol": "SMTP",
            "smtp.req.command": "STARTTLS",
        },
        {
            "frame.number": "2",
            "frame.time_epoch": "1700000002.0",
            "ip.src": "10.0.0.25",
            "ip.dst": "192.168.1.10",
            "tcp.srcport": "25",
            "tcp.dstport": "49152",
            "tcp.stream": "1",
            "_ws.col.Protocol": "TLSv1.3",
            "smtp.response.code": "220",
            "tls.handshake.type": "2",
            "tls.handshake.extensions_key_share_group": "29",
            "tls.handshake.version": "0x0304",
            "tls.handshake.ciphersuite": "0x1302",
            "tls.handshake.extensions_server_name": "mail.corp.lan",
        }
    ]
    inv = reconstruct_investigation_from_packets("smtp_tls13.pcap", "aabbccdd1122", "aabbccdd1122", packets)
    assert inv.data_source == "REAL_CAPTURE"
    assert inv.summary.sessions_analyzed == 1
    # TLS 1.3 hides certificates: selected parameters are known, trust is not.
    assert inv.summary.warning_sessions == 1
    assert len(inv.connections) == 1
    
    conn = inv.connections[0]
    assert conn.protocol == "SMTP"
    assert conn.tls_version == "TLS 1.3"
    assert conn.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert conn.security_status == "WARNING"
    assert conn.has_pfs is True
    assert conn.has_aead is True
    assert conn.starttls_used is True

def test_reconstruction_smtp_cleartext_without_starttls():
    packets = [
        {
            "frame.number": "1",
            "frame.time_epoch": "1700000001.0",
            "ip.src": "192.168.1.10",
            "ip.dst": "10.0.0.25",
            "tcp.srcport": "49152",
            "tcp.dstport": "25",
            "tcp.stream": "2",
            "_ws.col.Protocol": "SMTP",
            "smtp.req.command": "EHLO client.lan",
        },
        {
            "frame.number": "2",
            "frame.time_epoch": "1700000002.0",
            "ip.src": "192.168.1.10",
            "ip.dst": "10.0.0.25",
            "tcp.srcport": "49152",
            "tcp.dstport": "25",
            "tcp.stream": "2",
            "_ws.col.Protocol": "SMTP",
            "smtp.req.command": "MAIL FROM:<user@client.lan>",
        }
    ]
    inv = reconstruct_investigation_from_packets("smtp_plain.pcap", "112233445566", "112233445566", packets)
    assert inv.summary.sessions_analyzed == 1
    assert inv.summary.critical_sessions == 1
    conn = inv.connections[0]
    assert conn.tls_version == "None"
    assert "CLEARTEXT" in conn.transport_mode
    assert conn.security_status == "CRITICAL"

def test_reconstruction_smtp_starttls_offered_but_unused_with_auth():
    """
    Regression test for real-world SMTP capture where server advertises STARTTLS
    in EHLO response, but client never issues STARTTLS, issues AUTH LOGIN, and continues plaintext.
    """
    packets = [
        {
            "frame.number": "1",
            "ip.src": "10.10.1.4",
            "ip.dst": "74.53.140.153",
            "tcp.srcport": "1470",
            "tcp.dstport": "25",
            "tcp.stream": "0",
            "tcp.flags.syn": "1",
            "_ws.col.protocol": "TCP",
        },
        {
            "frame.number": "2",
            "ip.src": "74.53.140.153",
            "ip.dst": "10.10.1.4",
            "tcp.srcport": "25",
            "tcp.dstport": "1470",
            "tcp.stream": "0",
            "_ws.col.protocol": "SMTP",
            "smtp.response.code": "220",
            "smtp.response": "220-xc90.websitewelcome.com ESMTP Exim",
        },
        {
            "frame.number": "3",
            "ip.src": "10.10.1.4",
            "ip.dst": "74.53.140.153",
            "tcp.srcport": "1470",
            "tcp.dstport": "25",
            "tcp.stream": "0",
            "_ws.col.protocol": "SMTP",
            "smtp.req.command": "EHLO",
            "smtp.req.parameter": "GP",
        },
        {
            "frame.number": "4",
            "ip.src": "74.53.140.153",
            "ip.dst": "10.10.1.4",
            "tcp.srcport": "25",
            "tcp.dstport": "1470",
            "tcp.stream": "0",
            "_ws.col.protocol": "SMTP",
            "smtp.response.code": "250",
            "smtp.rsp.parameter": "Hello GP,SIZE 52428800,PIPELINING,AUTH PLAIN LOGIN,STARTTLS,HELP",
        },
        {
            "frame.number": "5",
            "ip.src": "10.10.1.4",
            "ip.dst": "74.53.140.153",
            "tcp.srcport": "1470",
            "tcp.dstport": "25",
            "tcp.stream": "0",
            "_ws.col.protocol": "SMTP",
            "smtp.req.command": "AUTH",
            "smtp.req.parameter": "LOGIN",
        },
        {
            "frame.number": "6",
            "ip.src": "10.10.1.4",
            "ip.dst": "74.53.140.153",
            "tcp.srcport": "1470",
            "tcp.dstport": "25",
            "tcp.stream": "0",
            "_ws.col.protocol": "SMTP",
            "smtp.req.command": "MAIL",
            "smtp.req.parameter": "FROM:<user@domain.lan>",
        },
    ]

    inv = reconstruct_investigation_from_packets("smtp_starttls_unused.pcap", "feedbeef1234", "feedbeef1234", packets)
    assert inv.summary.sessions_analyzed == 1
    assert inv.summary.critical_sessions == 1
    assert len(inv.connections) == 1

    conn = inv.connections[0]
    assert conn.protocol == "SMTP"
    assert conn.starttls_advertised is True
    assert conn.starttls_used is False
    assert conn.auth_observed is True
    assert conn.auth_before_tls is True
    assert conn.tls_version == "None"
    assert conn.transport_mode == "CLEARTEXT (STARTTLS Offered but Not Used)"
    assert conn.security_status == "CRITICAL"
    assert "Encryption was available, but session continued without upgrading to TLS" in conn.explanation.headline

    # Verify findings include Auth Before TLS and STARTTLS findings
    finding_titles = [f.title for f in inv.findings]
    assert any("Authentication" in t for t in finding_titles)
    assert any("STARTTLS" in t or "Encryption was available" in t for t in finding_titles)
