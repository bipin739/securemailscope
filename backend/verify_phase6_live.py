import os
import json
from app.ingest.validator import validate_pcap_file
from app.ingest.tshark import extract_packet_records
from app.parse.sessions import reconstruct_investigation_from_packets
from app.mock_data import DEMO_INVESTIGATION
from app.reporting import (
    build_investigation_report,
    verify_report_manifest,
    export_report_to_json,
    export_report_to_html,
)
from app.simulation.engine import HardeningSimulatorEngine

def run_phase6_live_verification():
    print("==================================================")
    print("SECUREMAILSCOPE PHASE 6 / V1.0 LIVE E2E VERIFICATION")
    print("==================================================")

    # 1. REAL PCAP E2E TEST (smtp.pcap)
    pcap_path = r"C:\Users\LOQ\Downloads\smtp.pcap"
    print(f"\n[STEP 1] Validating Real PCAP: {pcap_path}")
    assert os.path.exists(pcap_path), f"File {pcap_path} not found"

    with open(pcap_path, "rb") as f:
        file_bytes = f.read()

    validation = validate_pcap_file("smtp.pcap", file_bytes)
    assert validation.is_valid, f"PCAP validation failed: {validation.error_message}"
    print(f"  [OK] PCAP Magic & Format Valid (SHA-256: {validation.sha256_short})")

    pkts = extract_packet_records(pcap_path)
    real_inv = reconstruct_investigation_from_packets("smtp.pcap", validation.sha256_full, validation.sha256_short, pkts)

    print(f"  [OK] Reconstructed Sessions: {real_inv.summary.sessions_analyzed}")
    print(f"  [OK] Overall Posture: {real_inv.security_posture.status if real_inv.security_posture else 'N/A'}")
    assert real_inv.security_posture and real_inv.security_posture.status == "CRITICAL"

    finding_ids = [f.rule_id for f in real_inv.findings]
    print(f"  [OK] Findings: {finding_ids}")
    assert "SMS-AUTH-001" in finding_ids
    assert "SMS-STARTTLS-001" in finding_ids
    assert "SMS-TLS-001" in finding_ids

    # Check Replay Critical Moment
    assert len(real_inv.replays) == 1
    replay = real_inv.replays[0]
    crit = getattr(replay, "critical_moment", None)
    crit_title = crit.get("title") if isinstance(crit, dict) else getattr(crit, "title", None)
    print(f"  [OK] Replay Critical Moment: {crit_title}")
    assert "Authentication Before TLS" in (crit_title or "")

    # Check Simulator on Real PCAP
    sim_res = HardeningSimulatorEngine().simulate(real_inv.observed_clients or [], ["SMS-POLICY-REQUIRE-TLS"])
    print(f"  [OK] Simulator Outcome for Require TLS: {sim_res.clients[0].outcome} (Reason: {sim_res.clients[0].reason})")
    assert sim_res.clients[0].outcome == "UNKNOWN"

    # Check Client Discovery & AI Abstention
    disc = real_inv.discovery
    print(f"  [OK] Discovered Clients: {len(disc.inventory)} | AI Status: {disc.anomaly_assessment.status}")
    assert len(disc.inventory) == 1
    assert disc.anomaly_assessment.status == "INSUFFICIENT_SAMPLE"

    # Generate Report for Real PCAP
    real_report = build_investigation_report(real_inv)
    real_verify = verify_report_manifest(real_report)
    print(f"  [OK] Real PCAP Report Manifest Status: {real_verify['status']} (Merkle Root: {real_verify['evidence_root'][:16]}...)")
    assert real_verify["is_valid"] is True
    assert real_verify["status"] == "VERIFIED"

    # Export formats
    real_json = export_report_to_json(real_report)
    real_html = export_report_to_html(real_report)
    print(f"  [OK] Exports Generated — JSON: {len(real_json)} bytes | HTML: {len(real_html)} bytes")
    assert len(real_json) > 1000
    assert len(real_html) > 5000

    # 2. SIMULATED DEMO E2E TEST
    print("\n[STEP 2] Validating Simulated Demo Fleet")
    demo_report = build_investigation_report(DEMO_INVESTIGATION)
    demo_verify = verify_report_manifest(demo_report)
    print(f"  [OK] Demo Sessions: {DEMO_INVESTIGATION.summary.sessions_analyzed} | Observed Clients: {len(DEMO_INVESTIGATION.discovery.inventory)}")
    print(f"  [OK] Demo AI Status: {DEMO_INVESTIGATION.discovery.anomaly_assessment.status}")
    print(f"  [OK] Demo Report Manifest: {demo_verify['status']} (Merkle Root: {demo_verify['evidence_root'][:16]}...)")
    assert demo_verify["is_valid"] is True
    assert demo_verify["status"] == "VERIFIED"
    assert DEMO_INVESTIGATION.discovery.anomaly_assessment.status == "ANALYZED"

    # 3. TAMPER DETECTION TEST
    print("\n[STEP 3] Testing Cryptographic Tamper Evidence")
    tampered_dict = demo_report.model_dump()
    tampered_dict["deterministic_findings"][0]["plain_explanation"] = "Unauthorized modified finding text."
    tamper_res = verify_report_manifest(tampered_dict)
    print(f"  [OK] Modified finding verification: is_valid={tamper_res['is_valid']}, status={tamper_res['status']}")
    assert tamper_res["is_valid"] is False
    assert tamper_res["status"] == "TAMPERED"

    # 4. PRIVACY MASTER REGRESSION TEST
    print("\n[STEP 4] Testing Privacy Master Regression")
    SECRETS = ["phase6-secret-password-9281", "private.person@example.invalid", "U2VjdXJlTWFpbFNjb3BlU2VjcmV0"]
    full_dump = "\n".join([DEMO_INVESTIGATION.model_dump_json(), real_report.model_dump_json(), real_html])
    for s in SECRETS:
        assert s not in full_dump
    print("  [OK] Zero sensitive secret leakage detected across all serialized outputs.")

    print("\n==================================================")
    print("ALL PHASE 6 / V1.0 ACCEPTANCE CRITERIA PASS!")
    print("==================================================")

if __name__ == "__main__":
    run_phase6_live_verification()
