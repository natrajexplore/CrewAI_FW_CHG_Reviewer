"""Review console API: security controls and the end-to-end review/approval flow (deterministic mode)."""

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from rulegate.web.app import create_app
from rulegate.web.jobs import JobManager

TOKEN = "t" * 40
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def client(monkeypatch, tmp_path):
    for k in ("MODEL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    app = create_app(TOKEN, allowed_hosts=["testserver"], manager=JobManager(output_dir=str(tmp_path)), bridge=False)
    return TestClient(app)


def wait_for(client, job_id, statuses, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/reviews/{job_id}", headers=AUTH).json()
        if job["status"] in statuses:
            return job
        time.sleep(0.05)
    raise AssertionError(f"job did not reach {statuses}: {job['status']}")


# ---------------------------------------------------------------- authentication / transport

@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {TOKEN}"}])
def test_api_requires_valid_bearer_token(client, headers):
    assert client.get("/api/config", headers=headers).status_code == 401


def test_static_page_is_public_but_has_no_data(client):
    r = client.get("/")
    assert r.status_code == 200 and "RuleGate" in r.text
    assert TOKEN not in r.text


def test_untrusted_host_header_rejected(client):
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


def test_security_headers(client):
    r = client.get("/api/config", headers=AUTH)
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"
    assert "server" not in {k.lower() for k in r.headers if k.lower() == "server" and "uvicorn" in r.headers[k]}


def test_no_cors(client):
    r = client.options("/api/reviews", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in r.headers


def test_openapi_docs_disabled(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_config_never_returns_secrets(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-value")
    monkeypatch.setenv("MODEL", "openai/gpt-4o")
    body = client.get("/api/config", headers=AUTH).text
    assert "sk-secret-value" not in body and json.loads(body)["llm_configured"] is True


# ---------------------------------------------------------------- input validation

def test_body_size_limit(client):
    big = json.dumps({"source": "yaml", "content": "x" * 70_000, "use_llm": False})
    r = client.post("/api/reviews", content=big, headers={**AUTH, "Content-Type": "application/json"})
    assert r.status_code == 413


def test_json_content_type_required(client):
    r = client.post("/api/reviews", content="source=sample", headers={**AUTH, "Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415


def test_unknown_fields_rejected(client):
    r = client.post("/api/reviews", json={"source": "sample", "sample_id": "cr-1001-panos-web-to-db",
                                          "use_llm": False, "rulebase": "/etc/passwd"}, headers=AUTH)
    assert r.status_code == 422


@pytest.mark.parametrize("sample_id", ["../../pyproject", "..\\..\\.env", "does-not-exist"])
def test_samples_only_from_allowlist(client, sample_id):
    r = client.post("/api/reviews", json={"source": "sample", "sample_id": sample_id, "use_llm": False}, headers=AUTH)
    assert r.status_code in (404, 422)
    assert client.get(f"/api/samples/{sample_id}", headers=AUTH).status_code == 404


def test_invalid_yaml_reports_position_only(client):
    r = client.post("/api/reviews", json={"source": "yaml", "content": "a: [1, 2", "use_llm": False}, headers=AUTH)
    assert r.status_code == 422 and "line" in r.json()["detail"]


def test_yaml_schema_errors_do_not_echo_input(client):
    doc = "change_id: CR-1\ntarget: {vendor: panos}\nrequest: {service: ['<script>alert(1)</script>']}\n"
    r = client.post("/api/reviews", json={"source": "yaml", "content": doc, "use_llm": False}, headers=AUTH)
    assert r.status_code == 422
    assert "<script>" not in r.text


def test_change_id_path_traversal_rejected(client):
    doc = Path("samples/change_requests/cr-1001-panos-web-to-db.yaml").read_text().replace("CR-1001", "../../evil")
    r = client.post("/api/reviews", json={"source": "yaml", "content": doc, "use_llm": False}, headers=AUTH)
    assert r.status_code == 422
    assert any(e["field"] == "change_id" for e in r.json()["errors"])


def test_python_yaml_tags_not_executed(client):
    doc = "!!python/object/apply:os.system ['echo pwned']"
    r = client.post("/api/reviews", json={"source": "yaml", "content": doc, "use_llm": False}, headers=AUTH)
    assert r.status_code == 422


def test_llm_required_when_not_configured(client):
    r = client.post("/api/reviews", json={"source": "sample", "sample_id": "cr-1001-panos-web-to-db"}, headers=AUTH)
    assert r.status_code == 400
    r = client.post("/api/reviews", json={"source": "text", "content": "please allow web to db on 5432 now",
                                          "use_llm": False}, headers=AUTH)
    assert r.status_code == 400


# ---------------------------------------------------------------- review + approval flow

def test_low_risk_review_completes_without_gate(client, tmp_path):
    r = client.post("/api/reviews", json={"source": "sample", "sample_id": "cr-1001-panos-web-to-db", "use_llm": False},
                    headers=AUTH)
    assert r.status_code == 202
    job = wait_for(client, r.json()["id"], {"completed", "failed"})
    assert job["status"] == "completed" and job["decision"] == "APPROVE"
    res = job["result"]
    assert res["final"] and res["staged"]["filename"] == "staged_config.set"
    assert "Recommendation: APPROVE" in res["report_markdown"]
    assert (tmp_path / "CR-1001" / "review.md").exists()


def test_high_risk_review_pauses_for_approval(client):
    r = client.post("/api/reviews", json={"source": "sample", "sample_id": "cr-1003-panos-any-any", "use_llm": False},
                    headers=AUTH)
    job_id = r.json()["id"]
    job = wait_for(client, job_id, {"awaiting_approval"})
    assert job["decision"] == "REJECT" and job["approval_reason"]

    # one review at a time
    busy = client.post("/api/reviews", json={"source": "sample", "sample_id": "cr-1001-panos-web-to-db",
                                             "use_llm": False}, headers=AUTH)
    assert busy.status_code == 409

    # validation: override needs a justification, attestation required
    bad = client.post(f"/api/reviews/{job_id}/decision", headers=AUTH,
                      json={"action": "override", "reviewer": "CSO", "comment": "ok", "attested": True})
    assert bad.status_code == 422
    bad = client.post(f"/api/reviews/{job_id}/decision", headers=AUTH,
                      json={"action": "accept", "reviewer": "CSO", "attested": False})
    assert bad.status_code == 422

    ok = client.post(f"/api/reviews/{job_id}/decision", headers=AUTH,
                     json={"action": "accept", "reviewer": "Jane Doe\n| injected", "comment": "Agree\nwith reject",
                           "attested": True})
    assert ok.status_code == 200
    job = wait_for(client, job_id, {"completed"})
    assert job["gate"].startswith("ACCEPTED by Jane Doe / injected")
    assert "\n" not in job["gate"]

    again = client.post(f"/api/reviews/{job_id}/decision", headers=AUTH,
                        json={"action": "defer", "reviewer": "CSO", "attested": True})
    assert again.status_code == 409


def test_event_stream_replays_and_ends(client):
    r = client.post("/api/reviews", json={"source": "sample", "sample_id": "cr-2005-ftd-duplicate", "use_llm": False},
                    headers=AUTH)
    job_id = r.json()["id"]
    wait_for(client, job_id, {"completed"})
    with client.stream("GET", f"/api/reviews/{job_id}/events", headers=AUTH) as s:
        body = "".join(s.iter_text())
    kinds = [json.loads(line[6:])["kind"] for line in body.splitlines() if line.startswith("data: {\"seq")]
    assert kinds[0] == "intake_started" and "analysis_complete" in kinds and kinds[-1] == "completed"
    assert "event: end" in body
    # resume after a sequence number
    with client.stream("GET", f"/api/reviews/{job_id}/events", headers={**AUTH, "Last-Event-ID": "2"}) as s:
        resumed = [json.loads(line[6:])["seq"] for line in "".join(s.iter_text()).splitlines() if line.startswith("data: {\"seq")]
    assert resumed and resumed[0] == 3


def test_unknown_job_ids(client):
    for jid in ("0" * 32, "../etc", "zz"):
        assert client.get(f"/api/reviews/{jid}", headers=AUTH).status_code == 404


# ---------------------------------------------------------------- frontend hygiene

def test_frontend_has_no_unsafe_sinks_or_third_party_code():
    static = Path("src/rulegate/web/static")
    js = (static / "app.js").read_text(encoding="utf-8")
    html = (static / "index.html").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js, sink
    assert "style=" not in html, "inline styles would be blocked by the CSP"
    assert "<script>" not in html and "onclick" not in html.lower()
    for text in (js, html, (static / "app.css").read_text(encoding="utf-8")):
        assert "http://" not in text.replace("http://www.w3.org/2000/svg", "")
        assert "https://" not in text


def test_step_mapping_handles_templated_roles():
    from rulegate.web.jobs import _step

    assert _step(None, "Palo Alto PAN-OS Implementation Planner") == "implementation_task"
    assert _step(None, "Cisco FTD (FMC) Implementation Planner") == "implementation_task"
    assert _step(None, "CAB Report Writer") == "cab_report_task"
    assert _step(None, None, "risk_assessment_task") == "risk_assessment_task"


def test_approval_required_emitted_once(client):
    r = client.post("/api/reviews", json={"source": "sample", "sample_id": "cr-1003-panos-any-any", "use_llm": False},
                    headers=AUTH)
    job_id = r.json()["id"]
    wait_for(client, job_id, {"awaiting_approval"})
    job = client.app.state.manager.get(job_id)
    assert [e["kind"] for e in job.events_after(0)].count("approval_required") == 1
    client.post(f"/api/reviews/{job_id}/decision", headers=AUTH, json={"action": "defer", "reviewer": "QA", "attested": True})
    wait_for(client, job_id, {"completed"})


@pytest.mark.parametrize("value,expected", [
    ("INTERNAL USE ONLY · CONFIDENTIAL", "INTERNAL USE ONLY · CONFIDENTIAL"),
    ("", None),
    ("<script>alert(1)</script>", None),
    ("x" * 81, None),
    ("line one\nline two", None),
])
def test_ui_banner_validation(monkeypatch, value, expected):
    from rulegate.web.app import ui_banner

    monkeypatch.setenv("RULEGATE_UI_BANNER", value)
    assert ui_banner() == expected


def test_config_exposes_banner_and_weights(monkeypatch, tmp_path):
    monkeypatch.setenv("RULEGATE_UI_BANNER", "INTERNAL USE ONLY")
    app = create_app(TOKEN, allowed_hosts=["testserver"], manager=JobManager(output_dir=str(tmp_path)), bridge=False)
    cfg = TestClient(app).get("/api/config", headers=AUTH).json()
    assert cfg["banner"] == "INTERNAL USE ONLY"
    assert cfg["severity_weights"]["critical"] == 40 and cfg["severity_weights"]["info"] == 0


def test_job_summary_reports_free_text_flag(client):
    r = client.post("/api/reviews", json={"source": "sample", "sample_id": "cr-1001-panos-web-to-db", "use_llm": False},
                    headers=AUTH)
    assert r.json()["free_text"] is False
