"""Structured outputs for crew tasks (stable fields for downstream tasks and the report)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class IntakeReview(BaseModel):
    change_id: str
    summary: str = Field(description="One-paragraph plain-English summary of the requested access")
    missing_fields: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    clarifications_needed: list[str] = Field(default_factory=list, description="Questions to send back to the requester")


class ClauseMapping(BaseModel):
    check_id: str = Field(pattern=r"^RG-\d{3}$")
    clauses: list[str] = Field(description="Clause references exactly as returned by compliance_kb, e.g. 'SEC-STD-FW 2.2'")
    note: str


class ComplianceMapping(BaseModel):
    mappings: list[ClauseMapping] = Field(default_factory=list)
    compliance_sign_off_required: list[str] = Field(default_factory=list, description="Owners whose sign-off is required")
