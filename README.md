# RuleGate — Multi-Agent Firewall Change Request Reviewer

> A CrewAI multi-agent system that reviews firewall change requests for **Palo Alto Networks (PAN-OS / Panorama)** and **Cisco Secure Firewall Threat Defense (FTD via FMC)** *before* they reach the CAB. It produces a risk-scored, evidence-backed review and a vendor-specific implementation plan.

RuleGate **never pushes configuration to a firewall**. It reads the current rulebase, analyzes the proposed change, and hands a human engineer a decision package with three parts: an approve, condition, or reject recommendation; a findings report; staged configuration; and a rollback plan.

---

## Table of Contents

1. [The Problem](#the-problem)
2. [What RuleGate Does](#what-rulegate-does)
3. [Architecture](#architecture)
4. [The Agent Crew](#the-agent-crew)
5. [Risk Check Catalog](#risk-check-catalog)
6. [Vendor Support Matrix](#vendor-support-matrix)
7. [Project Structure](#project-structure)
8. [Quick Start](#quick-start)
9. [Change Request Format](#change-request-format)
10. [Sample Output](#sample-output)
11. [Safety Model](#safety-model)
12. [Testing and Evaluation](#testing-and-evaluation)
13. [Roadmap](#roadmap)
14. [Using the Claude Skill](#using-the-claude-skill)

---

## The Problem

In most enterprises, firewall change requests follow a predictable pattern:

- Requesters ask for broader access than they need ("just open any/any for now").
- Reviewers rarely check whether the access **already exists** or whether the new rule will be **shadowed** by a rule above it.
- Security hygiene gets skipped under time pressure. Typical misses include missing App-ID or security profiles on Palo Alto, and missing intrusion or file policies on FTD.
- Multi-vendor estates double the review effort, because PAN-OS and FTD have different rule semantics (zones, NAT handling, inspection actions).
- CAB documentation (risk, rollback, test plan) is written by hand, inconsistently.

RuleGate automates the analysis that a senior firewall engineer does in their head. It then shows its work so that a human can approve with confidence.

---

## What RuleGate Does

| Step | Output |
|---|---|
| Parses a change request (YAML, JSON, or free text) | A vendor-neutral normalized request |
| Loads the current rulebase (offline export or read-only API) | Normalized rule model with resolved objects |
| Checks for duplicate, shadowed, and conflicting rules | Rulebase findings with rule IDs as evidence |
| Runs deterministic risk checks | Risk score with severity per finding |
| Maps findings to your security policy and compliance standard | Compliance findings with clause references |
| Generates vendor-specific staged config | PAN-OS `set` commands or an FMC REST API payload |
| Writes the CAB package | Markdown report: decision, findings, implementation, test, rollback |

---

## Architecture

```
                   ┌────────────────────────────┐
  Change Request ─►│  Flow @start: intake       │
  (YAML/JSON/text) └─────────────┬──────────────┘
                                 ▼
                   ┌────────────────────────────┐
                   │  Review Crew (sequential)  │
                   │                            │
                   │  1. Intake Parser          │──► NormalizedChangeRequest
                   │  2. Rulebase Analyst       │──► duplicate / shadow / conflict
                   │  3. Risk Assessor          │──► RG-xxx findings + score
                   │  4. Compliance Auditor     │──► policy clause mapping
                   │  5. Implementation Planner │──► staged config + rollback
                   │  6. CAB Report Writer      │──► final report
                   └─────────────┬──────────────┘
                                 ▼
                   ┌────────────────────────────┐
                   │  Flow @router: decision    │
                   └──────┬──────────┬──────────┘
                 CRITICAL │          │ LOW / MEDIUM
                 or HIGH  ▼          ▼
            Human approval gate    Auto-generate report
            (human_input=True)     for CAB queue
```

### Design principle: deterministic first, LLM second

LLMs are poor at CIDR math and port-range comparison. RuleGate therefore splits the work:

- **Python does the facts.** Subnet containment (`ipaddress`), port-range overlap, object resolution, rule-order shadow detection, and risk-check evaluation are all deterministic, unit-tested functions exposed to agents as **tools**.
- **Agents do the judgement.** They interpret business justification, weigh context, explain findings in plain English, choose rule placement, and write the CAB narrative.

Every finding must cite evidence, such as a rule name or UUID, an object name, or a check ID. An agent cannot invent a finding that a tool did not produce.

---

## The Agent Crew

| # | Agent | Responsibility | Key Tools |
|---|---|---|---|
| 1 | **Change Intake Parser** | Normalizes the request into the vendor-neutral schema. Flags missing fields (justification, owner, expiry, ticket ID). | `cr_schema_validator` |
| 2 | **Rulebase Analyst** | Finds existing rules that already permit the access, rules that would shadow the new rule, and deny rules the new rule would override. Recommends placement. | `rulebase_lookup`, `shadow_analyzer` |
| 3 | **Risk Assessor** | Runs the RG-xxx risk catalog and explains each finding in business terms. | `risk_scanner` |
| 4 | **Compliance Auditor** | Maps findings to the internal security standard and frameworks (e.g. PCI DSS Req. 1, CIS) loaded as CrewAI Knowledge. | `compliance_kb` (Knowledge source) |
| 5 | **Implementation Planner** | Produces vendor-specific staged config, a pre- and post-change test plan, and a rollback. | `config_renderer` (Jinja2 templates) |
| 6 | **CAB Report Writer** | Assembles the final decision package with a clear recommendation. | — |

**Process:** sequential by default, for reproducibility. A hierarchical mode with a *Lead Security Architect* manager is available via `--process hierarchical` for experimentation.

---

## Risk Check Catalog

Checks are deterministic Python functions in `src/rulegate/analysis/risk_rules.py`. Severity weights are configurable in `config/risk_policy.yaml`.

| ID | Check | Vendor | Default Severity |
|---|---|---|---|
| RG-001 | Source **any** and destination **any** on an allow rule | All | Critical |
| RG-002 | Service / port **any** on an allow rule | All | High |
| RG-003 | Untrust / outside source to internal destination | All | High |
| RG-004 | Overly broad CIDR (thresholds configurable) | All | Medium |
| RG-005 | Application `any`, or port-based rule where App-ID is possible | PAN-OS | Medium |
| RG-006 | Allow rule without a Security Profile Group | PAN-OS | High |
| RG-007 | Allow rule without an Intrusion Policy (and File Policy where relevant) | FTD | High |
| RG-008 | **Trust** action in ACP, or **Fastpath** in Prefilter (bypasses inspection) | FTD | Medium / High |
| RG-009 | Logging disabled (PAN `log-end` off; FTD end-of-connection logging off) | All | Medium |
| RG-010 | Cleartext or legacy protocols (telnet, FTP, HTTP, SMB from untrust) | All | High |
| RG-011 | Management ports (22, 3389, 443-mgmt, SNMP) from non-management zones | All | High |
| RG-012 | Missing business justification or expiry on a temporary request | All | Low |
| RG-013 | Requested access is **already permitted** by an existing rule | All | Info (recommend reject as duplicate) |
| RG-014 | New rule would be **shadowed** by a broader rule above it | All | High |
| RG-015 | New rule would **override an existing deny** | All | Critical |
| RG-016 | Crosses a sensitive zone (PCI / CDE / OT / management) | All | High + compliance |

### Decision logic

| Condition | Recommendation |
|---|---|
| Any **Critical** finding | `REJECT` (with a suggested narrower alternative) |
| Any **High** finding | `APPROVE_WITH_CONDITIONS`, which needs a human reviewer |
| Only Medium / Low / Info | `APPROVE` |
| RG-013 duplicate access | `REJECT_DUPLICATE` (no change needed) |

---

## Vendor Support Matrix

| Capability | Palo Alto (PAN-OS / Panorama) | Cisco FTD (via FMC) |
|---|---|---|
| Offline rulebase import | Running config XML | FMC access rules JSON (`expanded=true`) |
| Read-only live API | XML/REST API with a read-only admin role | FMC REST API with a read-only user role |
| Policy layers handled | Pre-rulebase, local, post-rulebase (Panorama) | Prefilter policy, then Access Control Policy (mandatory, then default section) |
| NAT semantics in rules | **Pre-NAT IP**, **post-NAT zone** | **Real (untranslated) IP** in access rules |
| Inspection check | Security Profile Group / profiles | Intrusion Policy, File Policy, Trust vs Allow |
| Staged config output | `set` commands + XML API payload | FMC REST `accessrules` JSON payload |
| Standalone FDM-managed FTD | — | Planned (Phase 4) |

> **FTD note:** FTD access policy is managed by FMC (or FDM), not by device CLI. RuleGate therefore generates FMC API payloads, not `configure terminal` commands.

---

## Project Structure

```
rulegate/
├── README.md
├── .claude/skills/firewall-change-reviewer/SKILL.md   # Claude skill for building/extending
├── pyproject.toml
├── .env.example
├── config/
│   └── risk_policy.yaml            # severity weights, CIDR thresholds, sensitive zones
├── src/rulegate/
│   ├── main.py                     # CLI entry point
│   ├── flow.py                     # CrewAI Flow: intake → crew → router → gate
│   ├── crew.py                     # @CrewBase crew definition
│   ├── config/
│   │   ├── agents.yaml             # role / goal / backstory per agent
│   │   └── tasks.yaml              # description / expected_output per task
│   ├── models/
│   │   ├── change_request.py       # Pydantic: NormalizedChangeRequest
│   │   ├── normalized_rule.py      # Pydantic: vendor-neutral rule
│   │   └── findings.py             # Pydantic: Finding, RiskReport, Decision
│   ├── parsers/
│   │   ├── panos.py                # PAN-OS XML / API → NormalizedRule
│   │   └── ftd_fmc.py              # FMC JSON / API → NormalizedRule
│   ├── analysis/
│   │   ├── address_math.py         # CIDR, ranges, object resolution
│   │   ├── shadow.py               # duplicate / shadow / conflict detection
│   │   └── risk_rules.py           # RG-001 … RG-016
│   ├── tools/
│   │   ├── rulebase_lookup_tool.py
│   │   ├── shadow_analyzer_tool.py
│   │   ├── risk_scanner_tool.py
│   │   └── config_renderer_tool.py
│   └── templates/
│       ├── panos_set.j2
│       ├── fmc_accessrule.json.j2
│       └── cab_report.md.j2
├── knowledge/
│   ├── security_policy_standard.md # your internal firewall standard
│   └── pci_dss_req1_summary.md
├── samples/
│   ├── change_requests/            # 10+ realistic CRs (good, risky, duplicate)
│   └── rulebases/
│       ├── panos_running.xml
│       └── fmc_accessrules.json
├── tests/
│   ├── unit/                       # address math, shadow logic, each RG check
│   └── scenarios/                  # end-to-end CRs with expected decisions
└── reports/                        # generated CAB packages
```

---

## Quick Start

### Prerequisites

- Python 3.10+ (check the CrewAI docs for the currently supported range)
- [`uv`](https://docs.astral.sh/uv/) (recommended) or pip
- An LLM API key (OpenAI, Anthropic, Azure OpenAI, or a local model via Ollama)

### Install

```bash
git clone https://github.com/natrajexplore/rulegate.git
cd rulegate
uv sync            # or: pip install -e .
cp .env.example .env
```

### Configure `.env`

```ini
# LLM
MODEL=anthropic/claude-sonnet-4-6
ANTHROPIC_API_KEY=sk-...

# Mode: offline (sample exports) or live (read-only APIs)
RULEGATE_MODE=offline

# Palo Alto — use a READ-ONLY admin role
PANOS_HOST=
PANOS_API_KEY=
PANOS_DEVICE_GROUP=

# Cisco FMC — use a READ-ONLY user role
FMC_HOST=
FMC_USERNAME=
FMC_PASSWORD=
FMC_DOMAIN_UUID=
FMC_ACCESS_POLICY=
```

### Run against sample data

```bash
# Palo Alto change request
uv run rulegate review samples/change_requests/cr-1001-panos-web-to-db.yaml

# FTD change request
uv run rulegate review samples/change_requests/cr-2001-ftd-vendor-sftp.yaml

# Hierarchical mode (manager agent delegates)
uv run rulegate review samples/change_requests/cr-1003-panos-any-any.yaml --process hierarchical
```

Reports are written to `reports/<CR-ID>/review.md`, alongside `staged_config.*` and `findings.json`.

---

## Change Request Format

```yaml
change_id: CR-1001
ticket_ref: CHG0045821
requester: app-team-payments
business_justification: "New payments API must query the transaction DB"
target:
  vendor: panos            # panos | ftd
  device_group: DC-Core    # Panorama DG (PAN) or access policy name (FTD)
request:
  action: allow
  source_zone: web-dmz
  source: ["10.20.30.0/27"]
  destination_zone: db-trust
  destination: ["10.40.10.15"]
  application: ["postgres"]     # PAN App-ID; ignored for FTD if not mapped
  service: ["tcp/5432"]
  logging: true
temporary: false
expiry: null
```

Free-text requests ("please allow the web servers to reach the DB on 5432") are also accepted. The Intake Parser normalizes them and lists any fields it had to assume.

---

## Sample Output

```markdown
# CAB Review — CR-1003 (Palo Alto, DC-Core)

## Recommendation: REJECT
Risk score: 92 / 100

## Findings
| ID | Severity | Finding | Evidence |
|---|---|---|---|
| RG-001 | Critical | Source any → destination any on allow | Request fields src/dst |
| RG-006 | High | No Security Profile Group | Request has no profile setting |
| RG-015 | Critical | Would override deny rule `Block-DMZ-to-Mgmt` | Rule #14, device group DC-Core |

## Suggested narrower alternative
Allow `web-dmz/10.20.30.0/27` → `db-trust/10.40.10.15` app `postgres`
(application-default), profile group `Strict-Inspection`, place above rule #22.

## Implementation (staged — not applied)
set device-group DC-Core pre-rulebase security rules CR-1003-web-to-db ...

## Test plan / Rollback
...
```

---

## Safety Model

RuleGate is built for production environments, so safety is enforced in code rather than by asking the LLM nicely.

1. **Read-only by design.** No tool contains a write, commit, or deploy function. Live mode requires read-only API roles, and the README and SKILL instruct users to create them.
2. **Staged config is text, not action.** Generated configuration is written to files for a human to review and apply through the normal change process.
3. **Evidence-bound findings.** Agents may only report findings that a tool produced. The CAB Writer task has a guardrail that rejects findings without a check ID or rule reference.
4. **Human gate on risk.** Critical and High decisions trigger `human_input=True` in the Flow.
5. **Secrets hygiene.** Credentials are loaded from `.env` only, never logged, and never included in prompts. Rulebase exports in `samples/` must be sanitized (no real public IPs or hostnames).
6. **Unresolvable objects are flagged, not guessed.** FQDN objects, dynamic address groups, EDLs, and user-based rules are marked `UNRESOLVED`. Results that depend on them are downgraded to "needs human review."

---

## Testing and Evaluation

```bash
uv run pytest tests/unit          # deterministic logic — must be 100% passing
uv run pytest tests/scenarios     # end-to-end crew runs against expected decisions
```

The scenario suite contains labeled change requests, each with an expected decision and expected check IDs. It covers:

| Scenario type | Examples |
|---|---|
| Clean, well-scoped request | Web tier → DB on a single port with App-ID |
| Overly permissive | any/any, broad /8 source, service any |
| Duplicate | Access already permitted by an existing rule |
| Shadowed | New rule placed below a broader allow |
| Deny override | New allow that bypasses an explicit block |
| Inspection bypass | FTD Trust action, Prefilter Fastpath, PAN rule without profiles |
| Compliance | Request crossing into a PCI / CDE zone |
| Ambiguous free text | Missing ports, unclear zones |

Track **decision accuracy** and **check recall** (expected RG IDs found) on every prompt or model change.

---

## Roadmap

- [x] **Phase 1:** Vendor-neutral models, PAN-OS and FMC offline parsers, address math, shadow analysis
- [ ] **Phase 2:** RG-001…RG-016 risk checks, crew with 6 agents, CAB report template
- [ ] **Phase 3:** Flow with severity routing and human approval gate, scenario evaluation suite
- [ ] **Phase 4:** Read-only live API mode (PAN-OS, FMC), FDM-managed FTD support
- [ ] **Phase 5:** NAT-aware analysis, ServiceNow / Jira intake, Slack notification
- [ ] **Phase 6:** Check Point and FortiGate parsers

---

## Using the Claude Skill

This repo includes a Claude skill at `.claude/skills/firewall-change-reviewer/SKILL.md`. It teaches Claude (in Claude Code or Claude.ai) the project's architecture, safety rules, vendor semantics, and conventions. With it, Claude can:

- add new risk checks in the correct RG-xxx format, with tests;
- extend parsers or add new vendors without breaking the normalized model;
- review a change request manually using the same methodology as the crew.

---

## License

MIT

## Author

**Nataraj Angappan**, Network Security Engineer (CCNP Security)
