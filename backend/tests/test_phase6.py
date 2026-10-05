import json
import asyncio
import pytest
from app.models import Investigation, SummaryStats, SecurityFinding
from app.mock_data import DEMO_INVESTIGATION
from app.reporting.models import (
    InvestigationReport,
    EvidenceManifest,
    ReportFinding,
    ReportRecommendation,
)
from app.reporting.integrity import (
    canonicalize_json,
    hash_sha256,
    compute_findings_digest,
    compute_replay_digest,
    compute_discovery_digest,
    compute_simulation_digest,
    compute_merkle_evidence_root,
    compute_report_digest,
    verify_report_manifest,
)
from app.reporting.report_builder import (
    build_investigation_report,
    generate_executive_summary,
    aggregate_recommendations,
)
from app.reporting.exporters import export_report_to_json, export_report_to_html
from app.analysis.evidence import Evidence
from app.analysis.scoring import SecurityPosture
from app.routes.investigations import (
    get_demo_report,
    generate_investigation_report,
    verify_report_integrity,
    export_demo_report_json,
    export_demo_report_html,
)

# ==========================================
# 1. EVIDENCE MANIFEST & MERKLE ROOT TESTS
# ==========================================

def test_evidence_manifest_generation():
    """Verifies that an EvidenceManifest generates all required fields and SHA-256 digests."""
    report = build_investigation_report(DEMO_INVESTIGATION)
    manifest = report.evidence_manifest

    assert manifest.schema_version == "1.0.0"
    assert manifest.investigation_id == DEMO_INVESTIGATION.id
    assert manifest.engine_version == "1.0.0"
    assert manifest.integrity_algorithm == "SHA-256"
    assert manifest.integrity_status == "VERIFIED"
    assert len(manifest.capture_sha256) == 64
    assert len(manifest.findings_digest) == 64
    assert len(manifest.replay_digest) == 64
    assert len(manifest.discovery_digest) == 64
    assert len(manifest.simulation_digest) == 64
    assert len(manifest.evidence_root) == 64
    assert len(manifest.report_digest) == 64
    assert "Evidence integrity verified" in manifest.verification_statement

def test_merkle_evidence_root_determinism_and_sensitivity():
    """Verifies that Merkle Evidence Root is deterministic and sensitive to any single component change."""
    cap = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    d_find = hash_sha256("findings_sample_data")
    d_rep = hash_sha256("replay_sample_data")
    d_disc = hash_sha256("discovery_sample_data")
    d_sim = hash_sha256("simulation_sample_data")

    root1 = compute_merkle_evidence_root(cap, d_find, d_rep, d_disc, d_sim)
    root2 = compute_merkle_evidence_root(cap, d_find, d_rep, d_disc, d_sim)
    assert root1 == root2

    # Change findings digest -> root must change
    d_find_tampered = hash_sha256("findings_tampered_data")
    root_tampered = compute_merkle_evidence_root(cap, d_find_tampered, d_rep, d_disc, d_sim)
    assert root_tampered != root1

    # Change capture hash -> root must change
    root_cap_tampered = compute_merkle_evidence_root(hash_sha256("alt_cap"), d_find, d_rep, d_disc, d_sim)
    assert root_cap_tampered != root1

# ==========================================
# 2. REPORT GENERATION TESTS
# ==========================================

def test_report_generation_demo_investigation():
    """Tests comprehensive report generation for DEMO_INVESTIGATION."""
    report = build_investigation_report(DEMO_INVESTIGATION)

    assert report.report_metadata.report_id.startswith("RPT-")
    assert report.report_metadata.data_source == "SIMULATED"
    assert report.capture_summary.total_sessions == 104
    assert report.security_posture.status == "CRITICAL"
    assert len(report.deterministic_findings) > 0
    assert len(report.recommendations) > 0
    assert len(report.limitations) >= 5
    assert "processed locally by TShark" in report.privacy_statement

    # Check recommendations ordering: CRITICAL/HIGH first
    ranks = [r.priority_rank for r in report.recommendations]
    assert ranks == list(range(1, len(ranks) + 1))
    severities = [r.severity for r in report.recommendations]
    sev_weights = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
    weights = [sev_weights[s] for s in severities]
    assert weights == sorted(weights)

def test_executive_summary_synthesis():
    """Verifies deterministic rule-based executive summary without LLM."""
    exec_summary = generate_executive_summary(
        investigation=DEMO_INVESTIGATION,
        findings=DEMO_INVESTIGATION.findings,
        discovery_summary=DEMO_INVESTIGATION.discovery.summary if DEMO_INVESTIGATION.discovery else None,
        ai_assessment=DEMO_INVESTIGATION.discovery.anomaly_assessment if DEMO_INVESTIGATION.discovery else None,
    )

    assert exec_summary.overall_posture == "CRITICAL"
    assert "CRITICAL security posture" in exec_summary.posture_summary
    assert "AI-assisted anomaly prioritization" in exec_summary.ai_anomaly_summary
    assert len(exec_summary.full_text) > 100

# ==========================================
# 3. TAMPER EVIDENCE & INTEGRITY VERIFICATION
# ==========================================

def test_report_verification_success():
    """Verifies that an un-modified report passes cryptographic integrity verification."""
    report = build_investigation_report(DEMO_INVESTIGATION)
    result = verify_report_manifest(report)

    assert result["is_valid"] is True
    assert result["status"] == "VERIFIED"
    assert len(result["mismatches"]) == 0
    assert "Evidence integrity verified" in result["verification_statement"]

def test_tamper_detection_on_finding_modification():
    """Tampers with a finding in a report copy and verifies that integrity check FAILS."""
    report = build_investigation_report(DEMO_INVESTIGATION)
    report_dict = report.model_dump()

    # Modify one finding
    report_dict["deterministic_findings"][0]["plain_explanation"] = "Unauthorized altered finding text."

    result = verify_report_manifest(report_dict)
    assert result["is_valid"] is False
    assert result["status"] == "TAMPERED"
    assert len(result["mismatches"]) > 0
    assert any("Findings Digest mismatch" in m for m in result["mismatches"])

def test_tamper_detection_on_replay_modification():
    """Tampers with replay summary and verifies that integrity check FAILS."""
    report = build_investigation_report(DEMO_INVESTIGATION)
    report_dict = report.model_dump()

    # Tamper with replay event count
    report_dict["security_replay_summary"][0]["event_count"] = 9999

    result = verify_report_manifest(report_dict)
    assert result["is_valid"] is False
    assert result["status"] == "TAMPERED"
    assert any("Replay Digest mismatch" in m for m in result["mismatches"])

def test_tamper_detection_on_root_forgery():
    """Tampers with evidence_root in manifest and verifies that verification FAILS."""
    report = build_investigation_report(DEMO_INVESTIGATION)
    report_dict = report.model_dump()

    # Forge evidence root
    report_dict["evidence_manifest"]["evidence_root"] = "0000000000000000000000000000000000000000000000000000000000000000"

    result = verify_report_manifest(report_dict)
    assert result["is_valid"] is False
    assert result["status"] == "TAMPERED"
    assert any("Merkle Evidence Root mismatch" in m for m in result["mismatches"])

# ==========================================
# 4. EXPORTERS (JSON & HTML) TESTS
# ==========================================

def test_export_json():
    """Verifies that JSON export produces valid, complete structured report JSON."""
    report = build_investigation_report(DEMO_INVESTIGATION)
    json_str = export_report_to_json(report)

    parsed = json.loads(json_str)
    assert parsed["report_metadata"]["engine_version"] == "1.0.0"
    assert parsed["evidence_manifest"]["integrity_status"] == "VERIFIED"
    assert len(parsed["deterministic_findings"]) > 0

def test_export_html_security_and_completeness():
    """Verifies that HTML export is standalone, safe, contains no scripts, and has all sections."""
    report = build_investigation_report(DEMO_INVESTIGATION)
    html_str = export_report_to_html(report)

    assert "<!DOCTYPE html>" in html_str
    assert "SECUREMAILSCOPE" in html_str
    assert "Executive Summary" in html_str
    assert "Deterministic Security Findings" in html_str
    assert "Cryptographic Evidence Integrity" in html_str
    assert "Merkle Evidence Root" in html_str
    assert "Evidence integrity verified against the report manifest" in html_str
    assert "Privacy & Data Handling" in html_str

    # Ensure no executable script tags
    assert "<script" not in html_str.lower()
    # Ensure no external CDN dependencies (http/https links to external stylesheets/fonts)
    assert "http://fonts.googleapis.com" not in html_str
    assert "https://cdn." not in html_str

# ==========================================
# 5. PRIVACY MASTER REGRESSION TEST
# ==========================================

def test_privacy_master_regression_seeded_secrets():
    """
    CRITICAL PRIVACY TEST:
    Verifies that zero seeded sensitive secrets (passwords, usernames, AUTH base64 payloads,
    email addresses, attachments) leak into serialized Investigation, Findings, Replays,
    Discovery, AI outputs, Report, JSON export, or HTML export.
    """
    SEEDED_SECRETS = [
        "phase6-secret-password-9281",
        "super_private_admin_password_xyz",
        "private.person@example.invalid",
        "confidential_ceo@enterprise.org",
        "U2VjdXJlTWFpbFNjb3BlU2VjcmV0",
        "dXNlcm5hbWU6cGFzc3dvcmQxMjM=",
        "top_secret_financial_report.pdf",
        "Confidential Project Payload Text 12345",
    ]

    # Generate full report
    report = build_investigation_report(DEMO_INVESTIGATION)
    json_export = export_report_to_json(report)
    html_export = export_report_to_html(report)

    # Check against all serialized artifacts
    all_serialized_text = "\n".join([
        DEMO_INVESTIGATION.model_dump_json(),
        report.model_dump_json(),
        json_export,
        html_export,
    ])

    for secret in SEEDED_SECRETS:
        assert secret not in all_serialized_text, f"Privacy violation: seeded secret '{secret}' found in output!"

# ==========================================
# 6. REPORT API ENDPOINTS TESTS
# ==========================================

@pytest.mark.anyio
async def test_api_report_endpoints():
    """Tests GET /api/investigations/demo/report, POST /report, verify and exports."""
    # 1. GET demo report
    demo_report = await get_demo_report()
    assert demo_report.report_metadata.schema_version == "1.0.0"
    assert demo_report.evidence_manifest.integrity_status == "VERIFIED"

    # 2. POST report with custom investigation
    custom_report = await generate_investigation_report(investigation=DEMO_INVESTIGATION)
    assert custom_report.evidence_manifest.integrity_status == "VERIFIED"

    # 3. POST verify endpoint
    v_data = await verify_report_integrity(report=demo_report.model_dump())
    assert v_data["is_valid"] is True
    assert v_data["status"] == "VERIFIED"

    # 4. GET export JSON
    res_json = await export_demo_report_json()
    assert res_json.media_type == "application/json"
    assert "attachment" in res_json.headers["Content-Disposition"]
    assert len(res_json.body) > 0

    # 5. GET export HTML
    res_html = await export_demo_report_html()
    assert "text/html" in res_html.media_type
    assert b"SECUREMAILSCOPE" in res_html.body
