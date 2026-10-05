from typing import List, Literal
from pydantic import BaseModel, Field
from app.analysis.rules import RuleEvaluationResult

SecurityPostureStatus = Literal["CRITICAL", "HIGH_RISK", "NEEDS_ATTENTION", "ACCEPTABLE", "UNKNOWN"]

class SecurityPosture(BaseModel):
    """
    Deterministic security posture summary for an investigation.
    Derives overall status from the highest applicable severity without arbitrary scoring algorithms.
    """
    status: SecurityPostureStatus = Field(..., description="Deterministic overall posture: CRITICAL, HIGH_RISK, NEEDS_ATTENTION, ACCEPTABLE, or UNKNOWN")
    findings_count: int = Field(0, description="Total number of evaluated rule findings")
    critical_count: int = Field(0, description="Count of CRITICAL severity findings")
    high_count: int = Field(0, description="Count of HIGH severity findings")
    medium_count: int = Field(0, description="Count of MEDIUM severity findings")
    low_count: int = Field(0, description="Count of LOW severity findings")
    info_count: int = Field(0, description="Count of INFO severity findings")
    passed_checks: int = Field(0, description="Count of checks evaluated with PASS status")
    coverage_gaps: int = Field(0, description="Count of checks with UNKNOWN status or COVERAGE_GAP evidence")

def calculate_security_posture(evaluations: List[RuleEvaluationResult]) -> SecurityPosture:
    """
    Calculates deterministic posture counts and overall status from rule evaluation results.
    """
    critical_count = sum(1 for e in evaluations if e.severity == "CRITICAL" and e.status != "PASS")
    high_count = sum(1 for e in evaluations if e.severity == "HIGH" and e.status != "PASS")
    medium_count = sum(1 for e in evaluations if e.severity == "MEDIUM" and e.status != "PASS")
    low_count = sum(1 for e in evaluations if e.severity == "LOW" and e.status != "PASS")
    info_count = sum(1 for e in evaluations if e.severity == "INFO")
    passed_checks = sum(1 for e in evaluations if e.status == "PASS")
    coverage_gaps = sum(
        1 for e in evaluations
        if e.status == "UNKNOWN" or any(ev.type == "COVERAGE_GAP" for ev in e.evidence)
    )

    if critical_count > 0:
        overall_status: SecurityPostureStatus = "CRITICAL"
    elif high_count > 0:
        overall_status = "HIGH_RISK"
    elif medium_count > 0:
        overall_status = "NEEDS_ATTENTION"
    elif coverage_gaps > 0:
        overall_status = "UNKNOWN"
    elif passed_checks > 0 and (critical_count == 0 and high_count == 0 and medium_count == 0 and low_count == 0):
        overall_status = "ACCEPTABLE"
    else:
        overall_status = "UNKNOWN"

    return SecurityPosture(
        status=overall_status,
        findings_count=len(evaluations),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        passed_checks=passed_checks,
        coverage_gaps=coverage_gaps,
    )
