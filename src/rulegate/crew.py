"""Review Crew: six specialist agents over one deterministic ReviewContext."""

# No `from __future__ import annotations`: CrewAI inspects the guardrail's real return annotation.
import os
import re
from typing import Any

from crewai import LLM, Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.tasks.task_output import TaskOutput

from rulegate.models.crew_outputs import ComplianceMapping, IntakeReview
from rulegate.models.findings import Severity
from rulegate.pipeline import ReviewContext
from rulegate.tools import (
    ComplianceKBTool,
    ConfigRendererTool,
    CRSchemaValidatorTool,
    RiskScannerTool,
    RulebaseLookupTool,
    ShadowAnalyzerTool,
)

_DECISION_LINE = re.compile(r"Recommendation:\s*\**\s*(APPROVE_WITH_CONDITIONS|REJECT_DUPLICATE|APPROVE|REJECT)\b")


def make_llm(temperature: float) -> LLM:
    model = os.getenv("MODEL")
    if not model:
        raise RuntimeError("Set MODEL in .env (e.g. MODEL=anthropic/claude-sonnet-5-5) and the matching API key.")
    return LLM(model=model, temperature=temperature)


def check_narrative(text: str, ctx: ReviewContext) -> tuple[bool, str]:
    """Evidence guardrail for the CAB narrative. Pure function so it is unit-testable."""
    risk = ctx.risk
    found = risk.check_ids
    cited = set(re.findall(r"RG-\d{3}", text))
    invented = cited - found
    if invented:
        return False, (f"The narrative cites {sorted(invented)}, which no tool produced. "
                       f"Cite only these check IDs: {sorted(found) or 'none'}.")
    required = {f.check_id for f in risk.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)}
    missing = required - cited
    if missing:
        return False, f"The narrative must reference every Critical/High finding; missing {sorted(missing)}."
    s = ctx.shadow
    relevant = {r.name for r in filter(None, [s.duplicate_of, s.shadowed_by])}
    relevant |= {r.name for r in s.deny_overrides + s.disabled_cleanup_candidates}
    relevant |= {n.rule.name for n in s.partial_overlaps + s.needs_review}
    if s.move_before:
        relevant.add(s.move_before)
    unrelated = sorted(r.name for r in ctx.rules
                       if r.name not in relevant and re.search(rf"(?<![\w-]){re.escape(r.name)}(?![\w-])", text))
    if unrelated:
        return False, (f"The narrative mentions rules {unrelated} that the rulebase analysis did not relate to this "
                       f"request. Only discuss these rules: {sorted(relevant) or 'none'}.")
    m = _DECISION_LINE.search(text)
    if not m or m.group(1) != risk.decision.value:
        return False, (f"The narrative must start with 'Recommendation: {risk.decision.value}' - the deterministic "
                       f"decision cannot be changed by the report writer.")
    return True, text


@CrewBase
class ReviewCrew:
    """RuleGate review crew bound to a single change request's ReviewContext."""

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    def __init__(self, ctx: ReviewContext, process: str = "sequential"):
        self.ctx = ctx
        self.process = process

    def kickoff_inputs(self) -> dict[str, Any]:
        cr, risk = self.ctx.request, self.ctx.risk
        return {
            "change_id": cr.change_id,
            "vendor": {"panos": "Palo Alto PAN-OS", "ftd": "Cisco FTD (FMC)"}[cr.target.vendor],
            "device_group": cr.target.device_group or "n/a",
            "decision": risk.decision.value,
            "risk_score": risk.risk_score,
            "check_ids": ", ".join(sorted(risk.check_ids)) or "none",
            "compliance_refs": ", ".join(sorted({c for f in risk.findings for c in f.compliance})) or "none",
        }

    # ------------------------------------------------------------------ agents

    def _agent(self, name: str, tools: list, temperature: float = 0.1) -> Agent:
        return Agent(config=self.agents_config[name], tools=tools, llm=make_llm(temperature),
                     allow_delegation=False, verbose=True)

    @agent
    def intake_parser(self) -> Agent:
        return self._agent("intake_parser", [CRSchemaValidatorTool(ctx=self.ctx)])

    @agent
    def rulebase_analyst(self) -> Agent:
        return self._agent("rulebase_analyst", [ShadowAnalyzerTool(ctx=self.ctx), RulebaseLookupTool(ctx=self.ctx)])

    @agent
    def risk_assessor(self) -> Agent:
        return self._agent("risk_assessor", [RiskScannerTool(ctx=self.ctx)])

    @agent
    def compliance_auditor(self) -> Agent:
        return self._agent("compliance_auditor", [ComplianceKBTool(ctx=self.ctx)])

    @agent
    def implementation_planner(self) -> Agent:
        return self._agent("implementation_planner", [ConfigRendererTool(ctx=self.ctx)])

    @agent
    def cab_report_writer(self) -> Agent:
        return self._agent("cab_report_writer", [], temperature=0.3)

    def lead_security_architect(self) -> Agent:
        # Manager for hierarchical mode; intentionally not an @agent so it is not a crew member.
        return Agent(config=self.agents_config["lead_security_architect"], llm=make_llm(0.1),
                     allow_delegation=True, verbose=True)

    # ------------------------------------------------------------------ tasks

    @task
    def intake_task(self) -> Task:
        return Task(config=self.tasks_config["intake_task"], output_pydantic=IntakeReview)

    @task
    def rulebase_analysis_task(self) -> Task:
        return Task(config=self.tasks_config["rulebase_analysis_task"])

    @task
    def risk_assessment_task(self) -> Task:
        return Task(config=self.tasks_config["risk_assessment_task"])

    @task
    def compliance_task(self) -> Task:
        return Task(config=self.tasks_config["compliance_task"], output_pydantic=ComplianceMapping)

    @task
    def implementation_task(self) -> Task:
        return Task(config=self.tasks_config["implementation_task"])

    @task
    def cab_report_task(self) -> Task:
        return Task(config=self.tasks_config["cab_report_task"], guardrail=self.cab_guardrail,
                    guardrail_max_retries=3)

    def cab_guardrail(self, output: TaskOutput) -> tuple[bool, Any]:
        return check_narrative(output.raw, self.ctx)

    # ------------------------------------------------------------------ crew

    @crew
    def crew(self) -> Crew:
        if self.process == "hierarchical":
            return Crew(agents=self.agents, tasks=self.tasks, process=Process.hierarchical,
                        manager_agent=self.lead_security_architect(), verbose=True)
        return Crew(agents=self.agents, tasks=self.tasks, process=Process.sequential, verbose=True)
