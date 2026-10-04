"""Deterministic review pipeline: load request + rulebase, run shadow analysis and risk checks.

Agents never compute facts; they read the ReviewContext through tools.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from rulegate.analysis import shadow
from rulegate.analysis.risk_rules import RiskPolicy, load_policy, scan
from rulegate.models.change_request import NormalizedChangeRequest
from rulegate.models.findings import RiskReport
from rulegate.models.normalized_rule import NormalizedRule
from rulegate.parsers import LOADERS

DEFAULT_RULEBASES = {
    "panos": ("RULEGATE_PANOS_RULEBASE", "samples/rulebases/panos_running.xml"),
    "ftd": ("RULEGATE_FMC_RULEBASE", "samples/rulebases/fmc_accessrules.json"),
}


def read_request_file(path: str | Path) -> NormalizedChangeRequest | str:
    """Return a validated request for YAML/JSON files, or the raw text for free-text requests."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml", ".json"):
        data = json.loads(text) if p.suffix.lower() == ".json" else yaml.safe_load(text)
        return NormalizedChangeRequest.model_validate(data)
    return text


def rulebase_path(vendor: str, override: str | Path | None = None) -> Path:
    if override:
        return Path(override)
    env, default = DEFAULT_RULEBASES[vendor]
    return Path(os.getenv(env) or default)


def load_rulebase(cr: NormalizedChangeRequest, override: str | Path | None = None) -> list[NormalizedRule]:
    if os.getenv("RULEGATE_MODE", "offline").lower() != "offline":
        raise NotImplementedError("Live read-only API mode is planned for Phase 4; set RULEGATE_MODE=offline.")
    return LOADERS[cr.target.vendor](rulebase_path(cr.target.vendor, override), cr.target.device_group)


@dataclass
class ReviewContext:
    """Everything the tools expose to agents for one change request."""

    request: NormalizedChangeRequest
    rules: list[NormalizedRule]
    policy: RiskPolicy
    shadow: shadow.ShadowReport = field(init=False)
    risk: RiskReport = field(init=False)

    def __post_init__(self) -> None:
        self.shadow = shadow.analyze(self.request, self.rules)
        self.risk = scan(self.request, self.shadow, self.policy)


def build_context(cr: NormalizedChangeRequest, rulebase: str | Path | None = None,
                  policy_path: str | Path | None = None) -> ReviewContext:
    return ReviewContext(request=cr, rules=load_rulebase(cr, rulebase), policy=load_policy(policy_path))
