"""
SecureMailScope Reporting & Evidence Integrity Module
Phase 6 — Final Product Architecture
"""

from app.reporting.models import (
    InvestigationReport,
    ReportMetadata,
    CaptureSummary,
    ExecutiveSummary,
    ReportFinding,
    ReportRecommendation,
    EvidenceManifest,
)
from app.reporting.integrity import (
    canonicalize_json,
    hash_sha256,
    verify_report_manifest,
    compute_merkle_evidence_root,
)
from app.reporting.report_builder import build_investigation_report
from app.reporting.exporters import export_report_to_json, export_report_to_html

__all__ = [
    "InvestigationReport",
    "ReportMetadata",
    "CaptureSummary",
    "ExecutiveSummary",
    "ReportFinding",
    "ReportRecommendation",
    "EvidenceManifest",
    "canonicalize_json",
    "hash_sha256",
    "verify_report_manifest",
    "compute_merkle_evidence_root",
    "build_investigation_report",
    "export_report_to_json",
    "export_report_to_html",
]
