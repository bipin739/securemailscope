import os
import json
import pytest
from app.models import (
    Investigation,
    SummaryStats,
    NetworkNode,
    NetworkConnection,
    ConnectionEvidence,
    PlainLanguageExploration,
    SecurityFinding,
)
from app.analysis.evidence import Evidence
from app.analysis.scoring import SecurityPosture, calculate_security_posture
from app.discovery.models import (
    ObservedClientProfile,
    ClientDiscoveryResult,
    AnomalyAssessment,
)
from app.discovery.inventory import build_client_inventory, classify_legacy_status
from app.discovery.indicators import evaluate_client_indicators
from app.discovery.features import extract_client_features, build_feature_matrix
from app.discovery.anomaly import ClientAnomalyEngine
from app.discovery.engine import ClientDiscoveryEngine
from app.mock_data import DEMO_INVESTIGATION
from app.ingest.validator import validate_pcap_file
from app.ingest.tshark import extract_packet_records
from app.parse.sessions import reconstruct_investigation_from_packets

def create_mock_investigation(client_configs: list) -> Investigation:
    """Helper to build a mock Investigation with customized client configurations."""
    nodes = [
        NetworkNode(
            id="node-server",
            label="Mail Server (10.0.0.1)",
            role="Destination Mail Server",
            ip_address="10.0.0.1",
            hostname="mx.corp.lan",
            is_external=False,
            security_posture="secure",
        )
    ]
    connections = []
    findings = []

    for i, cfg in enumerate(client_configs):
        c_ip = cfg.get("ip", f"192.168.1.{i+10}")
        protocol = cfg.get("protocol", "SMTP")
        node_id = f"node-client-{i}"
        conn_id = f"conn-{i}"

        nodes.append(
            NetworkNode(
                id=node_id,
                label=f"Client ({c_ip})",
                role="Mail Client",
                ip_address=c_ip,
                hostname=f"client-{i}.lan",
                is_external=True,
                security_posture="secure",
            )
        )

        connections.append(
            NetworkConnection(
                id=conn_id,
                source_node_id=node_id,
                target_node_id="node-server",
                source_label=f"Client ({c_ip})",
                target_label="Mail Server (10.0.0.1)",
                protocol=protocol,
                transport_mode=cfg.get("transport_mode", "Explicit TLS / STARTTLS"),
                tls_version=cfg.get("tls_version", "TLS 1.3"),
                cipher_suite=cfg.get("cipher_suite", "TLS_AES_256_GCM_SHA384"),
                security_status=cfg.get("security_status", "SECURE"),
                session_id=f"STREAM-{i}",
                has_pfs=cfg.get("has_pfs", True),
                has_aead=cfg.get("has_aead", True),
                starttls_advertised=cfg.get("starttls_advertised", True),
                starttls_used=cfg.get("starttls_used", True),
                auth_observed=cfg.get("auth_observed", False),
                auth_before_tls=cfg.get("auth_before_tls", False),
                explanation=PlainLanguageExploration(
                    headline="Test",
                    summary="Test",
                    why_it_matters="Test",
                    evidence_summary="Test",
                    recommended_action="Test",
                ),
                evidence=ConnectionEvidence(
                    session_id=f"STREAM-{i}",
                    handshake_record="Test Handshake",
                    ports="50000 -> 25",
                    packet_count=10,
                ),
            )
        )

        if cfg.get("auth_before_tls"):
            findings.append(
                SecurityFinding(
                    id=f"FIND-AUTH-{i}",
                    title="Authentication Before TLS",
                    severity="CRITICAL",
                    category="Credential Protection",
                    status="FAIL",
                    confidence="HIGH",
                    affected_connection_id=conn_id,
                    location=f"Client {c_ip}",
                    plain_explanation="Cleartext authentication observed.",
                    why_it_matters="Credentials exposed.",
                    evidence="AUTH command before TLS",
                    recommendation="Mandate TLS",
                    rule_id="SMS-AUTH-001",
                )
            )
        if cfg.get("tls_version") in ("TLS 1.0", "TLS 1.1"):
            findings.append(
                SecurityFinding(
                    id=f"FIND-TLSVER-{i}",
                    title="Deprecated TLS Version",
                    severity="HIGH",
                    category="Protocol Deprecation",
                    status="FAIL",
                    confidence="HIGH",
                    affected_connection_id=conn_id,
                    location=f"Client {c_ip}",
                    plain_explanation="Deprecated TLS.",
                    why_it_matters="Cryptographic degradation.",
                    evidence=f"Negotiated {cfg.get('tls_version')}",
                    recommendation="Upgrade to TLS 1.2+",
                    rule_id="SMS-TLSVER-001",
                )
            )

    return Investigation(
        id="INV-TEST-001",
        filename="test.pcap",
        capture_date="2026-09-30 12:00:00 UTC",
        status="completed",
        is_simulated=True,
        data_source="SIMULATED",
        analysis_engine="SecureMailScope Deterministic Rule Engine v0.3",
        summary=SummaryStats(
            sessions_analyzed=len(connections),
            secure_sessions=sum(1 for c in connections if c.security_status == "SECURE"),
            warning_sessions=0,
            critical_sessions=sum(1 for c in connections if c.security_status == "CRITICAL"),
        ),
        security_posture=SecurityPosture(
            status="CRITICAL" if any(f.severity == "CRITICAL" for f in findings) else "HIGH_RISK" if any(f.severity == "HIGH" for f in findings) else "ACCEPTABLE",
            findings_count=len(findings),
            critical_count=sum(1 for f in findings if f.severity == "CRITICAL"),
            high_count=sum(1 for f in findings if f.severity == "HIGH"),
            medium_count=sum(1 for f in findings if f.severity == "MEDIUM"),
            low_count=0,
            info_count=0,
            passed_checks=1,
            coverage_gaps=0,
        ),
        nodes=nodes,
        connections=connections,
        findings=findings,
    )

def test_test_a_single_client_abstention():
    """TEST A: Single client -> inventory generated, AI status INSUFFICIENT_SAMPLE."""
    inv = create_mock_investigation([
        {"ip": "10.10.1.4", "transport_mode": "CLEARTEXT", "tls_version": "None", "cipher_suite": "NONE", "auth_before_tls": True}
    ])
    result = ClientDiscoveryEngine().discover(inv)

    assert len(result.inventory) == 1
    assert result.inventory[0].client_id == "SMTP:10.10.1.4"
    assert result.summary.observed_clients == 1
    assert result.anomaly_assessment.status == "INSUFFICIENT_SAMPLE"
    assert result.anomaly_assessment.population_size == 1
    assert "minimum 5 observed clients" in result.anomaly_assessment.summary_explanation.lower()
    # No fabricated anomaly score
    assert result.anomaly_assessment.results[0].anomaly_score == 0.0

def test_test_b_four_clients_abstention():
    """TEST B: Four clients -> AI status INSUFFICIENT_SAMPLE (threshold = 5)."""
    configs = [
        {"ip": f"192.168.1.{i}", "tls_version": "TLS 1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"}
        for i in range(1, 5)
    ]
    inv = create_mock_investigation(configs)
    result = ClientDiscoveryEngine().discover(inv)

    assert len(result.inventory) == 4
    assert result.anomaly_assessment.status == "INSUFFICIENT_SAMPLE"
    assert result.anomaly_assessment.population_size == 4

def test_test_c_sufficient_population_analyzed():
    """TEST C: Sufficient population (>= 5) -> AI status ANALYZED."""
    configs = [
        {"ip": f"192.168.1.{i}", "tls_version": "TLS 1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"}
        for i in range(1, 7)
    ]
    inv = create_mock_investigation(configs)
    result = ClientDiscoveryEngine().discover(inv)

    assert len(result.inventory) == 6
    assert result.anomaly_assessment.status == "ANALYZED"
    assert result.anomaly_assessment.population_size == 6
    assert len(result.anomaly_assessment.results) == 6

def test_test_d_reproducibility():
    """TEST D: Reproducibility -> Same feature data + same random state yields identical anomaly scores."""
    inv = DEMO_INVESTIGATION
    engine1 = ClientAnomalyEngine(random_state=42)
    engine2 = ClientAnomalyEngine(random_state=42)

    profiles = build_client_inventory(inv)
    res1 = engine1.analyze(profiles, inv)
    res2 = engine2.analyze(profiles, inv)

    assert res1.status == "ANALYZED"
    assert res2.status == "ANALYZED"
    assert len(res1.results) == len(res2.results)

    scores1 = [r.anomaly_score for r in res1.results]
    scores2 = [r.anomaly_score for r in res2.results]
    assert scores1 == scores2

def test_test_e_legacy_tls_indicator():
    """TEST E: Legacy TLS indicator -> LEGACY_TLS_OBSERVED."""
    inv = create_mock_investigation([
        {"ip": "10.0.0.5", "tls_version": "TLS 1.0", "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA"}
    ])
    profiles = build_client_inventory(inv)
    assert len(profiles) == 1
    ind_ids = [ind.indicator_id for ind in profiles[0].indicators]
    assert "LEGACY_TLS_OBSERVED" in ind_ids
    assert profiles[0].legacy_classification == "LEGACY_OBSERVED"

def test_test_f_weak_cipher_indicator():
    """TEST F: Weak cipher indicator -> WEAK_CIPHER_OBSERVED."""
    inv = create_mock_investigation([
        {"ip": "10.0.0.6", "tls_version": "TLS 1.2", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
    ])
    profiles = build_client_inventory(inv)
    assert len(profiles) == 1
    ind_ids = [ind.indicator_id for ind in profiles[0].indicators]
    assert "WEAK_CIPHER_OBSERVED" in ind_ids
    assert profiles[0].legacy_classification == "LEGACY_OBSERVED"

def test_test_g_cleartext_indicator():
    """TEST G: Cleartext indicator -> CLEARTEXT_MAIL_OBSERVED."""
    inv = create_mock_investigation([
        {"ip": "10.0.0.7", "transport_mode": "CLEARTEXT", "tls_version": "None", "cipher_suite": "NONE"}
    ])
    profiles = build_client_inventory(inv)
    assert len(profiles) == 1
    ind_ids = [ind.indicator_id for ind in profiles[0].indicators]
    assert "CLEARTEXT_MAIL_OBSERVED" in ind_ids

def test_test_h_auth_before_tls_indicator():
    """TEST H: Authentication-before-TLS indicator -> AUTH_BEFORE_TLS_OBSERVED."""
    inv = create_mock_investigation([
        {"ip": "10.10.1.4", "transport_mode": "CLEARTEXT", "tls_version": "None", "cipher_suite": "NONE", "auth_before_tls": True}
    ])
    profiles = build_client_inventory(inv)
    assert len(profiles) == 1
    ind_ids = [ind.indicator_id for ind in profiles[0].indicators]
    assert "AUTH_BEFORE_TLS_OBSERVED" in ind_ids

def test_test_i_mixed_transport_indicator():
    """TEST I: Mixed transport -> MIXED_TRANSPORT_BEHAVIOR."""
    # Build client with 1 TLS and 1 Cleartext connection
    client_ip = "10.240.14.90"
    nodes = [
        NetworkNode(id="node-client", label=f"Client ({client_ip})", role="Client", ip_address=client_ip, hostname="client.lan", is_external=False, security_posture="warning"),
        NetworkNode(id="node-server", label="Server (10.0.0.1)", role="Server", ip_address="10.0.0.1", hostname="server.lan", is_external=False, security_posture="secure"),
    ]
    connections = [
        NetworkConnection(
            id="conn-1",
            source_node_id="node-client",
            target_node_id="node-server",
            source_label=f"Client ({client_ip})",
            target_label="Server (10.0.0.1)",
            protocol="SMTP",
            transport_mode="Explicit TLS / STARTTLS",
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            security_status="SECURE",
            session_id="STREAM-1",
            has_pfs=True,
            has_aead=True,
            explanation=PlainLanguageExploration(headline="T", summary="T", why_it_matters="T", evidence_summary="T", recommended_action="T"),
            evidence=ConnectionEvidence(session_id="S-1", handshake_record="H", ports="5000->25", packet_count=10),
        ),
        NetworkConnection(
            id="conn-2",
            source_node_id="node-client",
            target_node_id="node-server",
            source_label=f"Client ({client_ip})",
            target_label="Server (10.0.0.1)",
            protocol="SMTP",
            transport_mode="CLEARTEXT",
            tls_version="None",
            cipher_suite="NONE",
            security_status="CRITICAL",
            session_id="STREAM-2",
            has_pfs=False,
            has_aead=False,
            explanation=PlainLanguageExploration(headline="T", summary="T", why_it_matters="T", evidence_summary="T", recommended_action="T"),
            evidence=ConnectionEvidence(session_id="S-2", handshake_record="H", ports="5001->25", packet_count=10),
        ),
    ]
    inv = Investigation(
        id="INV-MIXED",
        filename="mixed.pcap",
        capture_date="2026-09-30 12:00:00 UTC",
        status="completed",
        is_simulated=True,
        data_source="SIMULATED",
        analysis_engine="Test",
        summary=SummaryStats(sessions_analyzed=2, secure_sessions=1, warning_sessions=0, critical_sessions=1),
        nodes=nodes,
        connections=connections,
        findings=[],
    )

    profiles = build_client_inventory(inv)
    assert len(profiles) == 1
    assert profiles[0].legacy_classification == "MIXED"
    ind_ids = [ind.indicator_id for ind in profiles[0].indicators]
    assert "MIXED_TRANSPORT_BEHAVIOR" in ind_ids

def test_test_j_secure_unusual_client_no_fabricated_finding():
    """TEST J: Secure unusual client can receive AI REVIEW but MUST NOT receive fabricated vulnerability."""
    # 7 standard TLS 1.2 clients and 1 unusual TLS 1.3 ChaCha20 client
    configs = [
        {"ip": f"192.168.1.{i}", "tls_version": "TLS 1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
        for i in range(1, 8)
    ]
    # Unusual client
    configs.append({
        "ip": "192.0.2.77",
        "tls_version": "TLS 1.3",
        "cipher_suite": "TLS_CHACHA20_POLY1305_SHA256",
        "has_pfs": True,
        "has_aead": True,
    })

    inv = create_mock_investigation(configs)
    result = ClientDiscoveryEngine().discover(inv)

    unusual_client = next(p for p in result.inventory if p.observed_ip == "192.0.2.77")
    assert unusual_client.legacy_classification == "MODERN_OBSERVED"
    # No vulnerability findings attached to this secure client
    assert len(unusual_client.deterministic_finding_ids) == 0

def test_test_k_common_insecure_client_findings_intact():
    """TEST K: Common insecure client receives AI NORMAL/REVIEW, but deterministic findings remain unchanged."""
    # All 8 clients negotiate TLS 1.0 (common in this capture)
    configs = [
        {"ip": f"192.168.1.{i}", "tls_version": "TLS 1.0", "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA"}
        for i in range(1, 9)
    ]
    inv = create_mock_investigation(configs)
    result = ClientDiscoveryEngine().discover(inv)

    for prof in result.inventory:
        # Deterministic legacy classification and indicators remain active
        assert prof.legacy_classification == "LEGACY_OBSERVED"
        assert any(ind.indicator_id == "LEGACY_TLS_OBSERVED" for ind in prof.indicators)
        # Deterministic finding IDs remain present
        assert len(prof.deterministic_finding_ids) > 0

def test_test_l_sensitive_data_absence():
    """TEST L: Sensitive data absence in serialized inventory and AI results."""
    result = ClientDiscoveryEngine().discover(DEMO_INVESTIGATION)
    dump_str = result.model_dump_json().lower()

    sensitive_terms = ["password", "secret", "passwd", "base64", "dxnlsg==", "mail from: <", "rcpt to: <", "subject:"]
    for term in sensitive_terms:
        assert term not in dump_str, f"Found sensitive leak: {term}"

def test_test_m_real_smtp_pcap():
    """TEST M: Real smtp.pcap has 1 observed client, AI INSUFFICIENT_SAMPLE, Deterministic CRITICAL."""
    pcap_path = r"C:\Users\LOQ\Downloads\smtp.pcap"
    if not os.path.isfile(pcap_path):
        pytest.skip("Real smtp.pcap file not present on system.")

    with open(pcap_path, "rb") as f:
        file_bytes = f.read()

    validation = validate_pcap_file("smtp.pcap", file_bytes)
    assert validation.is_valid

    pkts = extract_packet_records(pcap_path)
    inv = reconstruct_investigation_from_packets("smtp.pcap", validation.sha256_full, validation.sha256_short, pkts)

    assert inv.discovery is not None
    assert len(inv.discovery.inventory) == 1
    assert inv.discovery.inventory[0].client_id == "SMTP:10.10.1.4"
    assert inv.discovery.anomaly_assessment.status == "INSUFFICIENT_SAMPLE"
    assert inv.security_posture.status == "CRITICAL"

    ind_ids = [ind.indicator_id for ind in inv.discovery.inventory[0].indicators]
    assert "AUTH_BEFORE_TLS_OBSERVED" in ind_ids
    assert "CLEARTEXT_MAIL_OBSERVED" in ind_ids
    assert "STARTTLS_AVAILABLE_BUT_UNUSED" in ind_ids

def test_test_n_finding_client_link():
    """TEST N: Finding -> Client linkage."""
    result = ClientDiscoveryEngine().discover(DEMO_INVESTIGATION)
    insecure_prof = next(p for p in result.inventory if p.observed_ip == "10.10.1.4")
    assert "FIND-005" in insecure_prof.deterministic_finding_ids
    assert "FIND-006" in insecure_prof.deterministic_finding_ids

def test_test_o_client_replay_link():
    """TEST O: Client -> Replay linkage."""
    result = ClientDiscoveryEngine().discover(DEMO_INVESTIGATION)
    insecure_prof = next(p for p in result.inventory if p.observed_ip == "10.10.1.4")
    assert "SMTP-STREAM-088" in insecure_prof.replay_session_ids

def test_test_p_client_simulator_link():
    """TEST P: Client capability extraction works seamlessly with simulator."""
    from app.simulation.engine import HardeningSimulatorEngine
    from app.simulation.models import ObservedClientCapability
    sim_engine = HardeningSimulatorEngine()
    caps = [ObservedClientCapability(**c) for c in DEMO_INVESTIGATION.observed_clients]
    assert len(caps) >= 4
    sim_res = sim_engine.simulate(caps, ["SMS-POLICY-TLS12", "SMS-POLICY-NO-WEAK-CIPHER"])
    assert sim_res.total_observed_clients == len(caps)
    assert sim_res.would_break_count > 0

def test_test_q_zero_observed_clients_empty_inventory():
    """TEST Q: Zero observed clients produces graceful empty inventory."""
    empty_inv = Investigation(
        id="INV-EMPTY",
        filename="empty.pcap",
        capture_date="2026-09-30 12:00:00 UTC",
        status="completed",
        is_simulated=True,
        data_source="SIMULATED",
        analysis_engine="Test",
        summary=SummaryStats(sessions_analyzed=0, secure_sessions=0, warning_sessions=0, critical_sessions=0),
        nodes=[],
        connections=[],
        findings=[],
    )
    result = ClientDiscoveryEngine().discover(empty_inv)
    assert len(result.inventory) == 0
    assert result.summary.observed_clients == 0
    assert result.anomaly_assessment.status in ("INSUFFICIENT_EVIDENCE", "INSUFFICIENT_SAMPLE")
