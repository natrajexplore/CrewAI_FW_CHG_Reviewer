"""Review jobs for the web UI: background execution, CrewAI event bridge, and the approval gate.

One review runs at a time. CrewAI's event bus is process-global, so serialising reviews keeps
every captured event attributable to exactly one job (and bounds LLM spend).
"""

from __future__ import annotations

import datetime as dt
import logging
import re
import threading
import uuid
from collections import OrderedDict
from enum import Enum
from typing import Any

from rulegate.flow import ReviewFlow
from rulegate.models.change_request import NormalizedChangeRequest

log = logging.getLogger("rulegate.web")

CLIP_SHORT = 600
CLIP_LONG = 6000
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")

# Task method names (crew.py) -> UI pipeline step
TASK_STEPS = {
    "intake_task": "intake_task",
    "rulebase_analysis_task": "rulebase_analysis_task",
    "risk_assessment_task": "risk_assessment_task",
    "compliance_task": "compliance_task",
    "implementation_task": "implementation_task",
    "cab_report_task": "cab_report_task",
}
ROLE_STEPS = {
    "Firewall Change Intake Parser": "intake_task",
    "Palo Alto and Cisco FTD Rulebase Analyst": "rulebase_analysis_task",
    "Firewall Change Risk Assessor": "risk_assessment_task",
    "Firewall Compliance Auditor (internal standard, PCI DSS, CIS)": "compliance_task",
    "CAB Report Writer": "cab_report_task",
}


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"


TERMINAL = {JobStatus.COMPLETED, JobStatus.FAILED}


class BusyError(RuntimeError):
    pass


class StateError(RuntimeError):
    pass


def clip(value: Any, limit: int) -> str:
    text = value if isinstance(value, str) else str(value)
    return text if len(text) <= limit else text[:limit] + f"\n… [truncated {len(text) - limit} characters]"


def single_line(value: str, limit: int) -> str:
    """Collapse control characters/newlines so user text cannot restructure the Markdown report."""
    return _CONTROL.sub(" ", value).replace("|", "/").strip()[:limit]


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


class Job:
    def __init__(self, label: str, use_llm: bool, process: str):
        self.id = uuid.uuid4().hex
        self.label = label
        self.use_llm = use_llm
        self.process = process
        self.created_at = _now()
        self.status = JobStatus.QUEUED
        self.change_id: str | None = None
        self.decision: str | None = None
        self.risk_score: int | None = None
        self.gate: str | None = None
        self.error: str | None = None
        self.approval_reason: str | None = None
        self.result: dict[str, Any] | None = None
        self._events: list[dict[str, Any]] = []
        self._cond = threading.Condition()
        self._approval_ready = threading.Event()
        self._approval: dict[str, str] | None = None

    # ------------------------------------------------------------------ events

    def push(self, kind: str, **data: Any) -> None:
        with self._cond:
            self._events.append({"seq": len(self._events) + 1, "ts": _now(), "kind": kind, **data})
            self._cond.notify_all()

    def events_after(self, seq: int) -> list[dict[str, Any]]:
        with self._cond:
            return self._events[seq:]

    @property
    def finished(self) -> bool:
        return self.status in TERMINAL

    # ------------------------------------------------------------------ approval

    def wait_for_approval(self, reason: str, timeout: float) -> str:
        self.status = JobStatus.AWAITING_APPROVAL
        self.approval_reason = reason  # the Flow emits the approval_required event itself
        if not self._approval_ready.wait(timeout):
            self.push("approval_timeout", minutes=int(timeout // 60))
            gate = f"DEFERRED - no reviewer decision within {int(timeout // 60)} minutes"
        else:
            a = self._approval
            gate = f"{a['action']} by {a['reviewer']} at {a['at']}" + (f" - {a['comment']}" if a["comment"] else "")
        self.status = JobStatus.RUNNING
        self.approval_reason = None
        return gate

    def submit_approval(self, action: str, reviewer: str, comment: str) -> None:
        if self.status != JobStatus.AWAITING_APPROVAL or self._approval_ready.is_set():
            raise StateError("This review is not waiting for an approval decision.")
        self._approval = {"action": action, "reviewer": single_line(reviewer, 80),
                          "comment": single_line(comment, 500), "at": _now()}
        self.push("approval_submitted", action=action, reviewer=self._approval["reviewer"])
        self._approval_ready.set()

    # ------------------------------------------------------------------ views

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id, "label": self.label, "status": self.status.value, "created_at": self.created_at,
            "use_llm": self.use_llm, "process": self.process, "change_id": self.change_id,
            "decision": self.decision, "risk_score": self.risk_score, "gate": self.gate,
            "error": self.error, "approval_reason": self.approval_reason,
        }


def build_result(flow: ReviewFlow, final: bool) -> dict[str, Any]:
    """JSON view of the decision package. Everything here comes from the deterministic pipeline,
    except ``narrative`` which is the guardrail-checked LLM text."""
    ctx = flow._ctx
    result: dict[str, Any] = {
        "request": ctx.request.model_dump(mode="json"),
        "missing_fields": ctx.request.missing_fields(),
        "risk": ctx.risk.model_dump(mode="json"),
        "shadow": ctx.shadow.model_dump(mode="json"),
        "final": final,
    }
    if final:
        staged = flow._staged
        result.update({
            "narrative": flow._narrative,
            "gate": flow.state.gate,
            "staged": staged.model_dump(mode="json"),
            "report_markdown": flow._report,
        })
    return result


class JobManager:
    def __init__(self, output_dir: str = "reports", approval_timeout: float = 1800, max_jobs: int = 25):
        self.output_dir = output_dir
        self.approval_timeout = approval_timeout
        self.max_jobs = max_jobs
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._lock = threading.Lock()
        self.active: Job | None = None

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        return list(reversed(self._jobs.values()))

    def start(self, request: NormalizedChangeRequest | str, *, label: str, use_llm: bool, process: str,
              vendor_hint: str | None) -> Job:
        with self._lock:
            if self.active is not None and not self.active.finished:
                raise BusyError("Another review is in progress. Wait for it to finish or complete its approval.")
            job = Job(label=label, use_llm=use_llm, process=process)
            self._jobs[job.id] = job
            while len(self._jobs) > self.max_jobs:
                self._jobs.popitem(last=False)
            self.active = job
        threading.Thread(target=self._run, args=(job, request, vendor_hint), name=f"review-{job.id[:8]}",
                         daemon=True).start()
        return job

    def _run(self, job: Job, request: NormalizedChangeRequest | str, vendor_hint: str | None) -> None:
        job.status = JobStatus.RUNNING
        flow = ReviewFlow()

        def notify(stage: str, data: dict[str, Any]) -> None:
            if stage == "analysis_complete":
                risk = flow._ctx.risk
                job.change_id, job.decision, job.risk_score = flow._ctx.request.change_id, risk.decision.value, risk.risk_score
                job.result = build_result(flow, final=False)
            if stage == "report_written":
                job.gate = flow.state.gate
                job.result = build_result(flow, final=True)
            job.push(stage, **data)

        flow.configure(request=request, notify=notify,
                       approver=lambda ctx, reason: job.wait_for_approval(reason, self.approval_timeout))
        try:
            flow.kickoff(inputs={"use_llm": job.use_llm, "process": job.process, "vendor_hint": vendor_hint,
                                 "interactive": False, "output_dir": self.output_dir})
            job.status = JobStatus.COMPLETED
            job.push("completed", decision=job.decision, gate=job.gate)
        except Exception as exc:  # noqa: BLE001 - report a safe message, keep details in the server log
            ref = uuid.uuid4().hex[:8]
            log.exception("Review %s failed (ref %s)", job.id, ref)
            job.error = f"The review failed ({type(exc).__name__}). Server log reference: {ref}."
            job.status = JobStatus.FAILED
            job.push("failed", error=job.error)


# ---------------------------------------------------------------------- CrewAI event bridge

def _step(task: Any, role: str | None, task_name: str | None = None) -> str | None:
    name = (getattr(task, "name", None) if task is not None else None) or task_name
    role = (role or "").strip()
    if role.endswith("Implementation Planner"):  # role is templated with the vendor name
        return "implementation_task"
    return TASK_STEPS.get(name or "") or ROLE_STEPS.get(role)


def _role(obj: Any) -> str | None:
    role = getattr(obj, "role", None)
    return role.strip() if isinstance(role, str) else None


def install_event_bridge(manager: JobManager) -> None:
    """Forward CrewAI agent/task/tool/guardrail events to the active job (registered once per process)."""
    from crewai.events import (
        LLMCallStartedEvent,
        LLMGuardrailCompletedEvent,
        TaskCompletedEvent,
        TaskFailedEvent,
        TaskStartedEvent,
        ToolUsageErrorEvent,
        ToolUsageFinishedEvent,
        ToolUsageStartedEvent,
        crewai_event_bus,
    )

    def active() -> Job | None:
        job = manager.active
        return job if job is not None and not job.finished else None

    def safe(fn):
        def handler(source, event):
            job = active()
            if job is None:
                return
            try:
                fn(job, event)
            except Exception:  # noqa: BLE001 - never let UI plumbing break a review
                log.exception("event bridge failed for %s", type(event).__name__)
        return handler

    @safe
    def on_task_started(job: Job, e) -> None:
        role = _role(getattr(e.task, "agent", None))
        job.push("task_started", step=_step(e.task, role), task=getattr(e.task, "name", None), agent=role)

    @safe
    def on_task_completed(job: Job, e) -> None:
        role = _role(getattr(e.task, "agent", None)) or getattr(e.output, "agent", None)
        job.push("task_completed", step=_step(e.task, role), task=getattr(e.task, "name", None), agent=role,
                 output=clip(getattr(e.output, "raw", ""), CLIP_LONG))

    @safe
    def on_task_failed(job: Job, e) -> None:
        role = _role(getattr(e.task, "agent", None))
        job.push("task_failed", step=_step(e.task, role), agent=role, error=clip(e.error, CLIP_SHORT))

    @safe
    def on_tool_started(job: Job, e) -> None:
        job.push("tool_started", step=_step(e.from_task, e.agent_role), agent=e.agent_role, tool=e.tool_name,
                 args=clip(e.tool_args, CLIP_SHORT))

    @safe
    def on_tool_finished(job: Job, e) -> None:
        ms = int((e.finished_at - e.started_at).total_seconds() * 1000) if e.started_at and e.finished_at else None
        job.push("tool_finished", step=_step(e.from_task, e.agent_role), agent=e.agent_role, tool=e.tool_name,
                 duration_ms=ms, output=clip(e.output, CLIP_LONG))

    @safe
    def on_tool_error(job: Job, e) -> None:
        job.push("tool_error", step=_step(e.from_task, e.agent_role), agent=e.agent_role, tool=e.tool_name,
                 error=clip(e.error, CLIP_SHORT))

    @safe
    def on_guardrail(job: Job, e) -> None:
        job.push("guardrail", step=_step(e.from_task, e.agent_role) or "cab_report_task", agent=e.agent_role,
                 success=bool(e.success), retry=e.retry_count, error=clip(e.error or "", CLIP_SHORT))

    @safe
    def on_llm_call(job: Job, e) -> None:
        role = e.agent_role or _role(e.from_agent)
        job.push("thinking", step=_step(e.from_task, role, e.task_name), agent=role)

    for event_type, handler in (
        (TaskStartedEvent, on_task_started), (TaskCompletedEvent, on_task_completed),
        (TaskFailedEvent, on_task_failed), (ToolUsageStartedEvent, on_tool_started),
        (ToolUsageFinishedEvent, on_tool_finished), (ToolUsageErrorEvent, on_tool_error),
        (LLMGuardrailCompletedEvent, on_guardrail), (LLMCallStartedEvent, on_llm_call),
    ):
        crewai_event_bus.on(event_type)(handler)
