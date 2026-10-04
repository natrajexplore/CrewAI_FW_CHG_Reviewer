import json

import pytest

from rulegate.crew import check_narrative
from rulegate.pipeline import build_context, read_request_file
from rulegate.render import render
from rulegate.tools import (
    ComplianceKBTool,
    ConfigRendererTool,
    CRSchemaValidatorTool,
    RiskScannerTool,
    RulebaseLookupTool,
    ShadowAnalyzerTool,
)


@pytest.fixture
def ctx_1003():
    return build_context(read_request_file("samples/change_requests/cr-1003-panos-any-any.yaml"))


def test_tools_return_json(ctx_1003):
    assert json.loads(CRSchemaValidatorTool(ctx=ctx_1003).run())["normalized_request"]["change_id"] == "CR-1003"
    assert json.loads(RiskScannerTool(ctx=ctx_1003).run())["decision"] == "REJECT"
    assert json.loads(ShadowAnalyzerTool(ctx=ctx_1003).run())["deny_overrides"]
    assert "set device-group DC-Core" in json.loads(ConfigRendererTool(ctx=ctx_1003).run())["config"]


def test_rulebase_lookup(ctx_1003):
    by_ip = json.loads(RulebaseLookupTool(ctx=ctx_1003).run(query="10.40.10.16"))
    assert "Allow-App-to-DB-Postgres" in [r["name"] for r in by_ip["rules"]]
    by_zone = json.loads(RulebaseLookupTool(ctx=ctx_1003).run(query="pci-cde"))
    assert [r["name"] for r in by_zone["rules"]] == ["Deny-DMZ-to-PCI"]


def test_compliance_kb(ctx_1003):
    out = json.loads(ComplianceKBTool(ctx=ctx_1003).run(query="RG-016"))
    sections = {m["section"] for m in out["matches"]}
    assert any(s.startswith("SEC-STD-FW 4.1") for s in sections)


def test_no_write_paths_in_tools():
    import inspect

    import rulegate.tools as tools_pkg
    src = "".join(inspect.getsource(m) for m in (tools_pkg,) + tuple(
        __import__(f"rulegate.tools.{n}", fromlist=["x"]) for n in
        ("base", "rulebase_lookup_tool", "shadow_analyzer_tool", "risk_scanner_tool", "config_renderer_tool",
         "compliance_kb_tool", "cr_schema_validator_tool")))
    for forbidden in ("requests.post", "requests.put", "requests.delete", "httpx", "commit(", "paramiko"):
        assert forbidden not in src


def test_guardrail_accepts_faithful_narrative(ctx_1003):
    text = ("Recommendation: REJECT\n\nKey findings: RG-001, RG-002, RG-006, RG-015 (Block-DMZ-to-Mgmt) and RG-016.")
    ok, _ = check_narrative(text, ctx_1003)
    assert ok


@pytest.mark.parametrize("text,needle", [
    ("Recommendation: REJECT RG-001 RG-002 RG-006 RG-015 RG-016 RG-010", "no tool produced"),
    ("Recommendation: REJECT RG-001 RG-002", "missing"),
    ("Recommendation: APPROVE_WITH_CONDITIONS RG-001 RG-002 RG-006 RG-015 RG-016", "cannot be changed"),
])
def test_guardrail_rejects(ctx_1003, text, needle):
    ok, msg = check_narrative(text, ctx_1003)
    assert not ok and needle in msg


def test_ftd_payload_is_plain_json_after_comments():
    ctx = build_context(read_request_file("samples/change_requests/cr-2001-ftd-vendor-sftp.yaml"))
    staged = render(ctx)
    body = "\n".join(l for l in staged.config.splitlines() if not l.startswith("//"))
    payload = json.loads(body)
    assert payload["action"] == "ALLOW" and payload["ipsPolicy"]["name"]
    assert payload["destinationPorts"]["literals"] == [{"type": "PortLiteral", "protocol": "6", "port": "22"}]


def test_guardrail_rejects_unrelated_rules():
    ctx = build_context(read_request_file("samples/change_requests/cr-1001-panos-web-to-db.yaml"))
    ok, msg = check_narrative("Recommendation: APPROVE\nResolve Block-Quarantine and Allow-DNS-Out first.", ctx)
    assert not ok and "Block-Quarantine" in msg
    assert check_narrative("Recommendation: APPROVE\nConditions: standard change process only.", ctx)[0]


def test_strip_code_fence():
    from rulegate.flow import strip_code_fence

    assert strip_code_fence("```markdown\nRecommendation: APPROVE\n\nbody\n```") == "Recommendation: APPROVE\n\nbody"
    assert strip_code_fence("Recommendation: APPROVE\n```\nx\n```") == "Recommendation: APPROVE\n```\nx\n```"
