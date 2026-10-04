"""RuleGate review console: FastAPI backend + static single-page UI.

Security controls (see README "Review console"):
* Bearer token on every /api route (per-launch random token unless RULEGATE_UI_TOKEN is set);
  constant-time comparison. A custom header also blocks cross-site request forgery: browsers
  cannot attach it cross-origin without a CORS preflight, and no CORS is enabled.
* Host header allowlist (blocks DNS-rebinding), loopback bind by default.
* Strict CSP and hardening headers; no third-party scripts, styles or fonts.
* Request body size cap, strict Pydantic schemas, samples chosen from a server-side allowlist
  (never a client-supplied path), YAML parsed with safe_load, change_id pattern-restricted.
* Error responses never include stack traces or secrets; the API never returns credentials.
* No endpoint changes any firewall: the backend only runs the read-only review pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
from pathlib import Path
from typing import Any, Literal

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError, model_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from rulegate.analysis.risk_rules import load_policy
from rulegate.models.change_request import NormalizedChangeRequest
from rulegate.web.jobs import BusyError, JobManager, JobStatus, StateError, install_event_bridge

log = logging.getLogger("rulegate.web")

STATIC = Path(__file__).parent / "static"
MAX_BODY_BYTES = 64 * 1024
MAX_CONTENT_CHARS = 32_000
SAMPLES_DIR = Path("samples/change_requests")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=()",
}


# ---------------------------------------------------------------------- request schemas

class ReviewRequest(BaseModel):
    model_config = {"extra": "forbid"}

    source: Literal["sample", "yaml", "text"]
    sample_id: str | None = Field(None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,80}$")
    content: str | None = Field(None, max_length=MAX_CONTENT_CHARS)
    use_llm: bool = True
    process: Literal["sequential", "hierarchical"] = "sequential"
    vendor_hint: Literal["panos", "ftd"] | None = None

    @model_validator(mode="after")
    def _check_source(self) -> "ReviewRequest":
        if self.source == "sample" and not self.sample_id:
            raise ValueError("sample_id is required when source is 'sample'")
        if self.source in ("yaml", "text") and not (self.content or "").strip():
            raise ValueError("content is required when source is 'yaml' or 'text'")
        if self.source == "text" and len(self.content.strip()) < 20:
            raise ValueError("free-text requests must be at least 20 characters")
        return self


class DecisionRequest(BaseModel):
    model_config = {"extra": "forbid"}

    action: Literal["accept", "override", "defer"]
    reviewer: str = Field(min_length=2, max_length=80)
    comment: str = Field("", max_length=500)
    attested: bool

    @model_validator(mode="after")
    def _check(self) -> "DecisionRequest":
        if not self.attested:
            raise ValueError("the reviewer must confirm they reviewed the evidence")
        if not self.reviewer.strip():
            raise ValueError("reviewer name is required")
        if self.action == "override" and len(self.comment.strip()) < 10:
            raise ValueError("an override needs a justification of at least 10 characters")
        return self


ACTION_LABEL = {"accept": "ACCEPTED", "override": "OVERRIDDEN", "defer": "DEFERRED"}


# ---------------------------------------------------------------------- helpers

def llm_configured() -> bool:
    keys = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_API_KEY", "GEMINI_API_KEY", "OLLAMA_API_BASE")
    return bool(os.getenv("MODEL")) and any(os.getenv(k) for k in keys)


BANNER_PATTERN = re.compile(r"^[A-Za-z0-9 .,:;/&()'\-·|]{1,80}$")


def ui_banner() -> str | None:
    """Optional organisation sensitivity banner (RULEGATE_UI_BANNER). Invalid values are ignored, not rendered."""
    value = (os.getenv("RULEGATE_UI_BANNER") or "").strip()
    if not value:
        return None
    if not BANNER_PATTERN.match(value):
        log.warning("Ignoring RULEGATE_UI_BANNER: use up to 80 letters, digits, spaces and basic punctuation")
        return None
    return value


def _validation_errors(exc: ValidationError) -> list[dict[str, str]]:
    # loc + msg only: never echo submitted values back
    def message(e: dict) -> str:
        if e["type"] == "string_pattern_mismatch":
            return "contains characters that are not allowed (letters, digits, '.', '_' and '-' only)"
        if e["type"] == "extra_forbidden":
            return "is not a recognised field (check the spelling)"
        return e["msg"].removeprefix("Value error, ")

    return [{"field": ".".join(str(p) for p in e["loc"]) or "request", "message": message(e)} for e in exc.errors()]


def load_samples() -> dict[str, dict[str, Any]]:
    """Server-side allowlist of sample requests, keyed by file stem."""
    samples: dict[str, dict[str, Any]] = {}
    for path in sorted(SAMPLES_DIR.glob("*")):
        if path.suffix.lower() not in (".yaml", ".yml", ".json", ".txt") or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        meta: dict[str, Any] = {"id": path.stem, "format": "text" if path.suffix == ".txt" else "yaml",
                                "content": text, "change_id": None, "vendor": None, "title": path.stem}
        if meta["format"] == "yaml":
            try:
                cr = NormalizedChangeRequest.model_validate(yaml.safe_load(text))
                meta.update(change_id=cr.change_id, vendor=cr.target.vendor,
                            title=cr.business_justification or cr.change_id, request=cr)
            except (ValidationError, yaml.YAMLError):
                log.warning("Skipping invalid sample %s", path.name)
                continue
        else:
            meta.update(title=text.strip().splitlines()[0][:120] if text.strip() else path.stem)
        samples[path.stem] = meta
    return samples


# ---------------------------------------------------------------------- app factory

def create_app(token: str, *, allowed_hosts: list[str] | None = None, manager: JobManager | None = None,
               bridge: bool = True) -> FastAPI:
    if len(token) < 24:
        raise ValueError("UI token must be at least 24 characters")
    manager = manager or JobManager()
    if bridge:
        install_event_bridge(manager)
    samples = load_samples()
    banner = ui_banner()
    policy = load_policy()

    app = FastAPI(title="RuleGate Review Console", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.manager = manager
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts or ["127.0.0.1", "localhost", "[::1]"])

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            length = request.headers.get("content-length")
            if length is None:
                return JSONResponse({"detail": "Content-Length required"}, status_code=411)
            if not length.isdigit() or int(length) > MAX_BODY_BYTES:
                return JSONResponse({"detail": "Request body too large"}, status_code=413)
            if not request.headers.get("content-type", "").startswith("application/json"):
                return JSONResponse({"detail": "Content-Type must be application/json"}, status_code=415)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/") or request.url.path == "/":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def on_validation(_: Request, exc: RequestValidationError):
        errors = [{"field": ".".join(str(p) for p in e["loc"] if p != "body") or "request",
                   "message": e["msg"].removeprefix("Value error, ")} for e in exc.errors()]
        return JSONResponse({"detail": "Invalid request", "errors": errors}, status_code=422)

    @app.exception_handler(Exception)
    async def on_error(_: Request, exc: Exception):
        ref = secrets.token_hex(4)
        log.exception("Unhandled error (ref %s)", ref)
        return JSONResponse({"detail": f"Internal error. Server log reference: {ref}."}, status_code=500)

    def require_token(request: Request) -> None:
        header = request.headers.get("authorization", "")
        scheme, _, supplied = header.partition(" ")
        if scheme.lower() != "bearer" or not secrets.compare_digest(supplied.encode(), token.encode()):
            raise HTTPException(status_code=401, detail="Missing or invalid access token",
                                headers={"WWW-Authenticate": "Bearer"})

    def job_or_404(job_id: str):
        if not (len(job_id) == 32 and all(c in "0123456789abcdef" for c in job_id)):
            raise HTTPException(status_code=404, detail="Review not found")
        job = manager.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Review not found")
        return job

    api = [Depends(require_token)]

    # ------------------------------------------------------------------ routes

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/api/config", dependencies=api)
    async def config():
        return {"llm_configured": llm_configured(), "model": os.getenv("MODEL") or None,
                "mode": os.getenv("RULEGATE_MODE", "offline"), "read_only": True,
                "approval_timeout_minutes": int(manager.approval_timeout // 60),
                "banner": banner,
                "severity_weights": {k.value: v for k, v in policy.severity_weights.items()}}

    @app.get("/api/samples", dependencies=api)
    async def list_samples():
        return [{k: s[k] for k in ("id", "format", "change_id", "vendor", "title")} for s in samples.values()]

    @app.get("/api/samples/{sample_id}", dependencies=api)
    async def get_sample(sample_id: str):
        s = samples.get(sample_id)
        if s is None:
            raise HTTPException(status_code=404, detail="Sample not found")
        return {"id": s["id"], "format": s["format"], "content": s["content"]}

    @app.post("/api/reviews", dependencies=api, status_code=202)
    async def start_review(body: ReviewRequest):
        if body.use_llm and not llm_configured():
            raise HTTPException(status_code=400, detail="No LLM is configured on the server (MODEL and an API key "
                                                        "in .env). Run with 'Deterministic only' instead.")
        if body.source == "sample":
            s = samples.get(body.sample_id)
            if s is None:
                raise HTTPException(status_code=404, detail="Sample not found")
            request: NormalizedChangeRequest | str = s.get("request") or s["content"]
            label = f"Sample {s['id']}"
        elif body.source == "yaml":
            try:
                data = yaml.safe_load(body.content)
            except yaml.YAMLError as exc:
                mark = getattr(exc, "problem_mark", None)
                where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
                raise HTTPException(status_code=422, detail=f"YAML could not be parsed{where}.") from None
            if not isinstance(data, dict):
                raise HTTPException(status_code=422, detail="YAML must describe a single change request mapping.")
            try:
                request = NormalizedChangeRequest.model_validate(data)
            except ValidationError as exc:
                return JSONResponse({"detail": "The change request is not valid",
                                     "errors": _validation_errors(exc)}, status_code=422)
            label = f"Pasted {request.change_id}"
        else:
            request, label = body.content.strip(), "Free-text request"
        if isinstance(request, str) and not body.use_llm:
            raise HTTPException(status_code=400, detail="Free-text requests need the LLM intake agent.")
        try:
            job = manager.start(request, label=label, use_llm=body.use_llm, process=body.process,
                                vendor_hint=body.vendor_hint)
        except BusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return job.summary()

    @app.get("/api/reviews", dependencies=api)
    async def list_reviews():
        return [j.summary() for j in manager.list()]

    @app.get("/api/reviews/{job_id}", dependencies=api)
    async def get_review(job_id: str):
        job = job_or_404(job_id)
        return {**job.summary(), "result": job.result}

    @app.get("/api/reviews/{job_id}/events", dependencies=api)
    async def review_events(job_id: str, request: Request, after: int = 0):
        job = job_or_404(job_id)
        last = request.headers.get("last-event-id", "")
        start = int(last) if last.isdigit() else max(after, 0)

        async def stream():
            seq, idle = start, 0.0
            while True:
                if await request.is_disconnected():
                    return
                events = job.events_after(seq)
                for ev in events:
                    seq = ev["seq"]
                    yield f"id: {seq}\ndata: {json.dumps(ev, default=str)}\n\n"
                if events:
                    idle = 0.0
                elif job.finished:
                    yield "event: end\ndata: {}\n\n"
                    return
                else:
                    idle += 0.3
                    if idle >= 15:
                        idle = 0.0
                        yield ": keep-alive\n\n"
                await asyncio.sleep(0.3)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @app.post("/api/reviews/{job_id}/decision", dependencies=api)
    async def submit_decision(job_id: str, body: DecisionRequest):
        job = job_or_404(job_id)
        if job.status != JobStatus.AWAITING_APPROVAL:
            raise HTTPException(status_code=409, detail="This review is not waiting for an approval decision.")
        try:
            job.submit_approval(ACTION_LABEL[body.action], body.reviewer, body.comment)
        except StateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return job.summary()

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
