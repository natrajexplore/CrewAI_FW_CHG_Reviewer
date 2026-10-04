"""Labeled scenarios: expected decision and expected check IDs for every sample change request.

The deterministic suite always runs. The LLM suite runs the full crew and is skipped unless
MODEL and a provider key are set (it costs tokens): `uv run pytest tests/scenarios -m llm`.
"""

import os

import pytest

from rulegate.pipeline import build_context, read_request_file

CR = "samples/change_requests/"

SCENARIOS = [
    # file, expected decision, expected check IDs (exact), needs human review
    ("cr-1001-panos-web-to-db.yaml", "APPROVE", set(), False),
    ("cr-1002-panos-duplicate.yaml", "REJECT_DUPLICATE", {"RG-005", "RG-013"}, False),
    ("cr-1003-panos-any-any.yaml", "REJECT", {"RG-001", "RG-002", "RG-005", "RG-006", "RG-015", "RG-016"}, False),
    ("cr-1004-panos-dmz-to-pci.yaml", "APPROVE_WITH_CONDITIONS", {"RG-014", "RG-016"}, False),
    ("cr-1005-panos-telnet-untrust.yaml", "APPROVE_WITH_CONDITIONS", {"RG-003", "RG-010", "RG-012"}, True),
    ("cr-1006-panos-ssh-no-justification.yaml", "APPROVE_WITH_CONDITIONS", {"RG-009", "RG-011", "RG-012"}, False),
    ("cr-2001-ftd-vendor-sftp.yaml", "APPROVE_WITH_CONDITIONS", {"RG-003", "RG-011"}, False),
    ("cr-2002-ftd-trust-bypass.yaml", "APPROVE", {"RG-008"}, False),
    ("cr-2003-ftd-pci-fastpath.yaml", "REJECT", {"RG-008", "RG-015", "RG-016"}, False),
    ("cr-2004-ftd-clean.yaml", "APPROVE", set(), False),
    ("cr-2005-ftd-duplicate.yaml", "REJECT_DUPLICATE", {"RG-013"}, False),
]


@pytest.mark.parametrize("file,decision,check_ids,review", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_deterministic_scenario(file, decision, check_ids, review):
    risk = build_context(read_request_file(CR + file)).risk
    assert risk.decision.value == decision
    assert risk.check_ids == check_ids
    assert risk.needs_human_review is review


def _llm_available() -> bool:
    return bool(os.getenv("MODEL")) and any(os.getenv(k) for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                                                                  "AZURE_API_KEY", "OLLAMA_API_BASE"))


@pytest.mark.llm
@pytest.mark.skipif(not _llm_available(), reason="MODEL and a provider API key are required")
@pytest.mark.parametrize("file,decision,check_ids,review", SCENARIOS[:3], ids=[s[0] for s in SCENARIOS[:3]])
def test_crew_end_to_end(file, decision, check_ids, review, tmp_path):
    from rulegate.main import main

    assert main(["review", CR + file, "--non-interactive", "--output-dir", str(tmp_path)]) == 0
    report = next(tmp_path.glob("*/review.md")).read_text(encoding="utf-8")
    assert f"Recommendation: {decision}" in report
    recall = sum(cid in report for cid in check_ids) / len(check_ids) if check_ids else 1.0
    assert recall == 1.0
