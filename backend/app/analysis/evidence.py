from typing import Any, Literal
from pydantic import BaseModel, Field

EvidenceType = Literal["OBSERVED", "RULE", "ASSUMPTION", "COVERAGE_GAP"]

class Evidence(BaseModel):
    """
    Structured evidence backing a security observation or rule finding.
    Distinguishes observed facts from rule inferences, assumptions, and coverage gaps.
    """
    type: EvidenceType = Field(..., description="Evidence category: OBSERVED, RULE, ASSUMPTION, or COVERAGE_GAP")
    field: str = Field(..., description="Observed or evaluated metadata field name")
    value: Any = Field(..., description="Extracted field value")
    source: str = Field(..., description="Capture source or protocol layer where evidence was observed")
    description: str = Field(..., description="Human-readable explanation of this specific evidence item")
