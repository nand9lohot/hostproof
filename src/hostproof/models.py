"""The data shapes passed between each stage."""

from typing import Any, Literal

from pydantic import BaseModel, Field

Status = Literal["affected", "not_affected", "under_investigation"]
Justification = Literal[
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
]
Confidence = Literal["low", "medium", "high"]
Exposure = Literal["network", "running", "local", "unknown", "enabled", "dormant", "none"]


class Finding(BaseModel):
    """One scanner finding. All of its text is untrusted."""

    vulnerability_id: str
    package: str
    installed_version: str = ""
    fixed_version: str = ""
    severity: str = "UNKNOWN"
    title: str = ""
    description: str = ""


class Evidence(BaseModel):
    """The result of one read-only check."""

    id: str
    check: str
    args: dict[str, str]
    status: Literal["ok", "unknown", "error", "rejected"]
    result: dict[str, Any] = Field(default_factory=dict)
    note: str = ""


class Decision(BaseModel):
    """A proposed verdict. It has no effect until the guard accepts it."""

    status: Status
    justification: Justification | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Confidence = "low"
    reason: str = Field(default="", max_length=1500)


class Verdict(BaseModel):
    """The final result for one finding on one host."""

    host: str
    finding: Finding
    status: Status
    justification: Justification | None = None
    confidence: Confidence
    reason: str
    exposure: Exposure
    evidence: list[Evidence]
    cited_evidence: list[str]
    decided_by: Literal["rules", "model", "guard", "person"]
    model_status: Status | None = None
    model_justification: Justification | None = None
    guard_violations: list[str] = Field(default_factory=list)
    review_required: bool = True
