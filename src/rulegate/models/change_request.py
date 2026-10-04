"""Vendor-neutral change request model."""

from __future__ import annotations

import datetime as dt
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from rulegate.models.normalized_rule import Vendor


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return list(v)


class Target(BaseModel):
    vendor: Vendor
    device_group: str | None = Field(None, description="Panorama device group (PAN) or access policy name (FTD)")


class RequestSpec(BaseModel):
    action: Literal["allow", "deny"] = "allow"
    source_zone: list[str] = Field(default_factory=lambda: ["any"])
    source: list[str] = Field(default_factory=lambda: ["any"])
    destination_zone: list[str] = Field(default_factory=lambda: ["any"])
    destination: list[str] = Field(default_factory=lambda: ["any"])
    application: list[str] = Field(default_factory=lambda: ["any"])
    service: list[str] = Field(default_factory=lambda: ["any"], description="e.g. tcp/443, udp/53, tcp/1000-2000, any, application-default")
    users: list[str] = Field(default_factory=list)
    logging: bool = True
    # PAN-OS inspection
    security_profile_group: str | None = None
    # FTD inspection / action
    intrusion_policy: str | None = None
    file_policy: str | None = None
    ftd_action: Literal["allow", "trust"] = "allow"
    prefilter_fastpath: bool = False
    # Where the requester wants the rule: top | bottom | before:<rule> | after:<rule>
    placement: str = "bottom"

    @field_validator("source_zone", "source", "destination_zone", "destination", "application", "service", "users", mode="before")
    @classmethod
    def _listify(cls, v):
        values = [str(x).strip() for x in _as_list(v) if str(x).strip()]
        return values

    @field_validator("source_zone", "source", "destination_zone", "destination", "application", "service", mode="after")
    @classmethod
    def _default_any(cls, v):
        return v or ["any"]

    @field_validator("placement")
    @classmethod
    def _check_placement(cls, v: str) -> str:
        v = (v or "bottom").strip()
        if v in ("top", "bottom") or v.startswith(("before:", "after:")):
            return v
        raise ValueError("placement must be top, bottom, before:<rule> or after:<rule>")


class NormalizedChangeRequest(BaseModel):
    change_id: str
    ticket_ref: str | None = None
    requester: str | None = None
    business_justification: str | None = None
    target: Target
    request: RequestSpec
    temporary: bool = False
    expiry: dt.date | None = None
    assumptions: list[str] = Field(default_factory=list, description="Fields the intake had to assume (free-text requests)")

    def missing_fields(self) -> list[str]:
        missing = []
        if not self.ticket_ref:
            missing.append("ticket_ref")
        if not self.requester:
            missing.append("requester")
        if not (self.business_justification or "").strip():
            missing.append("business_justification")
        if self.temporary and not self.expiry:
            missing.append("expiry")
        if self.request.service == ["any"]:
            missing.append("request.service (exact ports)")
        if not self.target.device_group:
            missing.append("target.device_group")
        return missing
