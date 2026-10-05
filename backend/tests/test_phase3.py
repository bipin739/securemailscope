import pytest
import os
import json
from app.simulation.models import (
    ObservedClientCapability,
    SimulationRequest,
    SimulationResult,
)
from app.simulation.policies import (
    RequireTLS12Policy,
    DisableWeakCiphersPolicy,
    RequireEncryptedTransportPolicy,
    RequireForwardSecrecyPolicy,
    POLICY_REGISTRY,
)
from app.simulation.engine import HardeningSimulatorEngine
from app.analysis.evidence import Evidence

# --- TEST A: Strong ClientHello evidence supports TLS 1.2+ -> COMPATIBLE ---
def test_sim_tls12_strong_modern_compatible():
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.1",
        protocol="SMTP",
        observed_ip="10.0.0.1",
        supported_tls_versions=["TLS 1.3", "TLS 1.2"],
        evidence_quality="STRONG",
    )
    pol = RequireTLS12Policy()
    res = pol.evaluate_client(client)
    assert res.outcome == "COMPATIBLE"
    assert res.confidence == "HIGH"
    assert "confirms support for modern TLS versions" in res.reason

# --- TEST B: Strong capability evidence proves only TLS 1.0/1.1 -> WOULD_BREAK ---
def test_sim_tls12_strong_legacy_would_break():
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.2",
        protocol="SMTP",
        observed_ip="10.0.0.2",
        supported_tls_versions=["TLS 1.0"],
        evidence_quality="STRONG",
    )
    pol = RequireTLS12Policy()
    res = pol.evaluate_client(client)
    assert res.outcome == "WOULD_BREAK"
    assert res.confidence == "HIGH"
    assert "deprecated versions" in res.reason

# --- TEST C: Only negotiated TLS 1.0 known, no capability list -> UNKNOWN ---
def test_sim_tls12_negotiated_only_unknown():
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.3",
        protocol="SMTP",
        observed_ip="10.0.0.3",
        observed_tls_versions=["TLS 1.0"],
        supported_tls_versions=[],
        evidence_quality="PARTIAL",
    )
    pol = RequireTLS12Policy()
    res = pol.evaluate_client(client)
    assert res.outcome == "UNKNOWN"
    assert res.confidence == "MEDIUM"
    assert "does not provide enough capability evidence" in res.reason

# --- TEST D: RC4 only capability evidence -> WOULD_BREAK ---
def test_sim_weak_cipher_strong_rc4_only_would_break():
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.4",
        protocol="SMTP",
        observed_ip="10.0.0.4",
        offered_cipher_suites=["TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_RC4_128_MD5"],
        evidence_quality="STRONG",
    )
    pol = DisableWeakCiphersPolicy()
    res = pol.evaluate_client(client)
    assert res.outcome == "WOULD_BREAK"
    assert res.confidence == "HIGH"
    assert "support only for deprecated/weak cipher suites" in res.reason

# --- TEST E: RC4 observed as negotiated but other capabilities unknown -> UNKNOWN ---
def test_sim_weak_cipher_negotiated_rc4_unknown():
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.5",
        protocol="SMTP",
        observed_ip="10.0.0.5",
        observed_cipher_suites=["TLS_RSA_WITH_RC4_128_SHA"],
        offered_cipher_suites=[],
        evidence_quality="PARTIAL",
    )
    pol = DisableWeakCiphersPolicy()
    res = pol.evaluate_client(client)
    assert res.outcome == "UNKNOWN"
    assert res.confidence == "MEDIUM"
    assert "does not contain the complete ClientHello cipher list" in res.reason

# --- TEST F: Allowed modern cipher capability -> COMPATIBLE ---
def test_sim_weak_cipher_modern_compatible():
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.6",
        protocol="SMTP",
        observed_ip="10.0.0.6",
        offered_cipher_suites=["TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
        evidence_quality="STRONG",
    )
    pol = DisableWeakCiphersPolicy()
    res = pol.evaluate_client(client)
    assert res.outcome == "COMPATIBLE"
    assert res.confidence == "HIGH"

# --- TEST G: ECDHE capability -> Require PFS -> COMPATIBLE ---
def test_sim_pfs_ecdhe_compatible():
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.7",
        protocol="SMTP",
        observed_ip="10.0.0.7",
        offered_cipher_suites=["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
        evidence_quality="STRONG",
    )
    pol = RequireForwardSecrecyPolicy()
    res = pol.evaluate_client(client)
    assert res.outcome == "COMPATIBLE"
    assert res.confidence == "HIGH"

# --- TEST H: Static RSA only, proven capability -> WOULD_BREAK ---
def test_sim_pfs_static_rsa_only_would_break():
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.8",
        protocol="SMTP",
        observed_ip="10.0.0.8",
        offered_cipher_suites=["TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"],
        evidence_quality="STRONG",
    )
    pol = RequireForwardSecrecyPolicy()
    res = pol.evaluate_client(client)
    assert res.outcome == "WOULD_BREAK"
    assert res.confidence == "HIGH"
    assert "static RSA key exchange without Forward Secrecy" in res.reason

# --- TEST I: PFS evidence incomplete -> UNKNOWN ---
def test_sim_pfs_incomplete_unknown():
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.9",
        protocol="SMTP",
        observed_ip="10.0.0.9",
        observed_cipher_suites=["TLS_RSA_WITH_AES_128_CBC_SHA"],
        offered_cipher_suites=[],
        evidence_quality="PARTIAL",
    )
    pol = RequireForwardSecrecyPolicy()
    res = pol.evaluate_client(client)
    assert res.outcome == "UNKNOWN"
    assert res.confidence == "MEDIUM"

# --- TEST J: Current real smtp.pcap + Require TLS -> UNKNOWN ---
def test_sim_real_smtp_pcap_require_tls_is_unknown():
    # Observed on smtp.pcap: 10.10.1.4, cleartext, STARTTLS offered, STARTTLS used: false
    client = ObservedClientCapability(
        client_id="SMTP:10.10.1.4",
        protocol="SMTP",
        observed_ip="10.10.1.4",
        starttls_observed=True,
        starttls_used=False,
        plaintext_observed=True,
        evidence_quality="INSUFFICIENT",
    )
    pol = RequireEncryptedTransportPolicy()
    res = pol.evaluate_client(client)
    assert res.outcome == "UNKNOWN"
    assert res.confidence == "MEDIUM"
    assert "does not establish whether the client lacks TLS capability" in res.reason
    assert res.outcome != "WOULD_BREAK"

# --- TEST K: Combined policy (TLS1.2+ + no weak cipher) with one break -> WOULD_BREAK ---
def test_sim_combined_policy_with_break():
    # Client supports TLS 1.2 (compatible with TLS12) but only offered RC4 (breaks weak cipher)
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.10",
        protocol="SMTP",
        observed_ip="10.0.0.10",
        supported_tls_versions=["TLS 1.2"],
        offered_cipher_suites=["TLS_RSA_WITH_RC4_128_SHA"],
        evidence_quality="STRONG",
    )
    engine = HardeningSimulatorEngine()
    sim_res = engine.simulate([client], ["SMS-POLICY-TLS12", "SMS-POLICY-NO-WEAK-CIPHER"])
    assert sim_res.would_break_count == 1
    assert sim_res.compatible_count == 0
    assert sim_res.clients[0].outcome == "WOULD_BREAK"

# --- TEST L: Combined policy with one compatible and one unknown -> UNKNOWN ---
def test_sim_combined_policy_with_unknown():
    # Client supports TLS 1.3 (compatible with TLS12), but cipher list is uncaptured (unknown weak cipher)
    client = ObservedClientCapability(
        client_id="SMTP:10.0.0.11",
        protocol="SMTP",
        observed_ip="10.0.0.11",
        supported_tls_versions=["TLS 1.3"],
        observed_cipher_suites=["TLS_RSA_WITH_RC4_128_SHA"],
        offered_cipher_suites=[],
        evidence_quality="PARTIAL",
    )
    engine = HardeningSimulatorEngine()
    sim_res = engine.simulate([client], ["SMS-POLICY-TLS12", "SMS-POLICY-NO-WEAK-CIPHER"])
    assert sim_res.unknown_count == 1
    assert sim_res.compatible_count == 0
    assert sim_res.clients[0].outcome == "UNKNOWN"

# --- TEST M: No clients -> counts all zero ---
def test_sim_no_clients():
    engine = HardeningSimulatorEngine()
    sim_res = engine.simulate([], ["SMS-POLICY-TLS12"])
    assert sim_res.total_observed_clients == 0
    assert sim_res.compatible_count == 0
    assert sim_res.would_break_count == 0
    assert sim_res.unknown_count == 0
    assert len(sim_res.clients) == 0

# --- TEST N: Sensitive data not exposed in simulation response ---
def test_sim_sensitive_data_not_exposed():
    client = ObservedClientCapability(
        client_id="SMTP:10.10.1.4",
        protocol="SMTP",
        observed_ip="10.10.1.4",
        starttls_observed=True,
        starttls_used=False,
        plaintext_observed=True,
    )
    engine = HardeningSimulatorEngine()
    sim_res = engine.simulate([client], list(POLICY_REGISTRY.keys()))
    serialized = sim_res.model_dump_json()

    forbidden_terms = ["password", "secret", "base64", "dXNlcg==", "cGFzc3dvcmQ="]
    for term in forbidden_terms:
        assert term.lower() not in serialized.lower()

# --- TEST O: Real smtp.pcap full pipeline simulation ---
def test_sim_real_smtp_pcap_pipeline():
    pcap_path = r"C:\Users\LOQ\Downloads\smtp.pcap"
    if not os.path.exists(pcap_path):
        pytest.skip(f"Capture {pcap_path} not found on disk")

    from app.ingest.tshark import extract_packet_records
    from app.ingest.validator import validate_pcap_file
    from app.parse.sessions import reconstruct_investigation_from_packets

    with open(pcap_path, "rb") as f:
        file_bytes = f.read()

    validation = validate_pcap_file("smtp.pcap", file_bytes)
    assert validation.is_valid

    pkts = extract_packet_records(pcap_path)
    inv = reconstruct_investigation_from_packets("smtp.pcap", validation.sha256_full, validation.sha256_short, pkts)

    assert len(inv.observed_clients) == 1
    client = inv.observed_clients[0]
    assert client.observed_ip == "10.10.1.4"
    assert client.protocol == "SMTP"
    assert client.starttls_observed is True
    assert client.starttls_used is False

    engine = HardeningSimulatorEngine()
    sim_res = engine.simulate(inv.observed_clients, ["SMS-POLICY-REQUIRE-TLS"])
    assert sim_res.total_observed_clients == 1
    assert sim_res.unknown_count == 1
    assert sim_res.would_break_count == 0
    assert sim_res.clients[0].outcome == "UNKNOWN"
