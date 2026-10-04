"""CrewAI Flow: intake -> review crew -> severity router -> human gate / auto report."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

from crewai import Agent, Crew, Process, Task
from crewai.flow.flow import Flow, listen, router, start
from pydantic import BaseModel, PrivateAttr

from rulegate.crew import ReviewCrew, make_llm
from rulegate.models.change_request import NormalizedChangeRequest
from rulegate.models.findings import Severity
from rulegate.pipeline import ReviewContext, build_context, read_request_file
from rulegate.render import _env, render

VENDOR_LABEL = {"panos": "Palo Alto", "ftd": "Cisco FTD"}


class ReviewState(BaseModel):
    request_path: str = ""
    rulebase: str | None = None
    policy: str | None = None
    vendor_hint: str | None = None
    process: str = "sequential"
    use_llm: bool = True
    interactive: bool = True
    output_dir: str = "reports"
    change_id: str = ""
    decision: str = ""
    risk_score: int = 0
    gate: str = ""
    report_dir: str = ""


def strip_code_fence(text: str) -> str:
    """Remove a ```markdown fence wrapping the whole answer."""
    return re.sub(r"^```(?:markdown|md)?\s*\n(.*?)\n```\s*$", r"\1", text.strip(), flags=re.S)


def parse_free_text(text: str, vendor_hint: str | None) -> NormalizedChangeRequest:
    """Normalize a free-text request with a single intake agent. Assumed fields are listed, not hidden."""
    hint = f" The target vendor is {vendor_hint}." if vendor_hint else ""
    agent = Agent(
        role="Firewall Change Intake Parser",
        goal="Convert free-text firewall requests into the normalized change request schema without inventing facts.",
        backstory="You copy only what the requester wrote. Every value you had to infer is listed in assumptions.",
        llm=make_llm(0.0), allow_delegation=False, verbose=True)
    task = Task(
        description=(
            "Normalize this firewall change request into the schema.{hint}\n"
            "Rules: use 'any' only if the requester literally asked for any; if a zone, port or vendor is not stated, "
            "make the most conservative guess AND add a sentence to 'assumptions'. Use change_id 'CR-FREETEXT' if no ID "
            "is given. Services use the form tcp/<port> or udp/<port>.\n\nRequest:\n{text}").format(hint=hint, text=text),
        expected_output="A NormalizedChangeRequest object.",
        agent=agent, output_pydantic=NormalizedChangeRequest)
    result = Crew(agents=[agent], tasks=[task], process=Process.sequential).kickoff()
    return NormalizedChangeRequest.model_validate(result.pydantic.model_dump())


# approver(ctx, reason) -> gate text; notify(stage, data) -> None
Approver = Callable[[ReviewContext, str], str]
Notifier = Callable[[str, dict[str, Any]], None]


class ReviewFlow(Flow[ReviewState]):
    _ctx: ReviewContext | None = PrivateAttr(default=None)
    _narrative: str = PrivateAttr(default="")
    _request: NormalizedChangeRequest | str | None = PrivateAttr(default=None)
    _approver: Approver | None = PrivateAttr(default=None)
    _notify: Notifier | None = PrivateAttr(default=None)
    _report: str = PrivateAttr(default="")
    _staged: Any = PrivateAttr(default=None)

    def configure(self, *, request: NormalizedChangeRequest | str | None = None,
                  approver: Approver | None = None, notify: Notifier | None = None) -> "ReviewFlow":
        """Hooks for non-CLI callers (web UI): in-memory request, approval provider, stage notifications."""
        self._request, self._approver, self._notify = request, approver, notify
        return self

    def _emit(self, stage: str, **data: Any) -> None:
        if self._notify:
            self._notify(stage, data)

    @start()
    def intake(self):
        parsed = self._request if self._request is not None else read_request_file(self.state.request_path)
        self._emit("intake_started", free_text=isinstance(parsed, str))
        if isinstance(parsed, str):
            if not self.state.use_llm:
                raise SystemExit("Free-text requests need an LLM for intake; remove --no-llm or supply YAML/JSON.")
            parsed = parse_free_text(parsed, self.state.vendor_hint)
        self._ctx = build_context(parsed, self.state.rulebase, self.state.policy)
        self.state.change_id = parsed.change_id
        self.state.decision = self._ctx.risk.decision.value
        self.state.risk_score = self._ctx.risk.risk_score
        self._emit("analysis_complete", change_id=parsed.change_id)

    @listen(intake)
    def review(self):
        if not self.state.use_llm:
            self._narrative = (f"Recommendation: {self._ctx.risk.decision.value}\n\n"
                              "_LLM narrative skipped (--no-llm). Findings above are the deterministic results._")
            self._emit("crew_skipped")
            return
        self._emit("crew_started", process=self.state.process)
        crew = ReviewCrew(self._ctx, process=self.state.process)
        result = crew.crew().kickoff(inputs=crew.kickoff_inputs())
        # models sometimes wrap the whole answer in a ```markdown fence, which breaks the report layout
        self._narrative = strip_code_fence(result.raw)
        self._emit("crew_complete")

    @router(review)
    def route(self):
        risk = self._ctx.risk
        if risk.max_severity in (Severity.CRITICAL, Severity.HIGH) or risk.needs_human_review:
            return "needs_approval"
        return "low_risk"

    @listen("needs_approval")
    def human_gate(self):
        risk = self._ctx.risk
        reason = (f"{risk.max_severity.value if risk.max_severity else 'review'} findings"
                  + (" and items needing human review" if risk.needs_human_review else ""))
        if self._approver:
            self._emit("approval_required", reason=reason)
            self.state.gate = self._approver(self._ctx, reason)
            return self._write_report()
        if not (self.state.interactive and sys.stdin.isatty()):
            self.state.gate = f"PENDING human approval ({reason}); non-interactive run."
            return self._write_report()
        print(f"\n=== Human approval gate: {self.state.change_id} ===")
        print(f"Deterministic recommendation: {risk.decision.value} (risk {risk.risk_score}/100, {reason})")
        choice = input("Reviewer action - [a]ccept recommendation, [o]verride, [d]efer: ").strip().lower()[:1]
        reviewer = input("Reviewer name: ").strip() or "unknown"
        comment = input("Comment: ").strip()
        action = {"a": "ACCEPTED", "o": "OVERRIDDEN"}.get(choice, "DEFERRED")
        self.state.gate = f"{action} by {reviewer}" + (f" - {comment}" if comment else "")
        return self._write_report()

    @listen("low_risk")
    def auto_report(self):
        self.state.gate = "Not required (no Critical/High findings); queued for CAB."
        return self._write_report()

    def _write_report(self) -> str:
        ctx = self._ctx
        staged = render(ctx)
        base = Path(self.state.output_dir).resolve()
        out = (base / ctx.request.change_id).resolve()
        if out.parent != base:  # defence in depth; change_id is already pattern-restricted
            raise ValueError(f"Refusing to write report outside {base}")
        out.mkdir(parents=True, exist_ok=True)
        report = _env.get_template("cab_report.md.j2").render(
            cr=ctx.request, req=ctx.request.request, risk=ctx.risk, shadow=ctx.shadow, staged=staged,
            narrative=self._narrative, gate=self.state.gate, vendor_label=VENDOR_LABEL[ctx.request.target.vendor])
        self._report, self._staged = report, staged
        (out / "review.md").write_text(report, encoding="utf-8")
        (out / staged.filename).write_text(staged.config, encoding="utf-8")
        (out / "findings.json").write_text(json.dumps({
            "request": ctx.request.model_dump(mode="json"),
            "risk": ctx.risk.model_dump(mode="json"),
            "shadow": ctx.shadow.model_dump(mode="json"),
            "approval_gate": self.state.gate,
        }, indent=2), encoding="utf-8")
        self.state.report_dir = str(out)
        self._emit("report_written", gate=self.state.gate)
        return str(out)
