---
name: firewall-change-reviewer
description: Build, extend, and operate RuleGate, a CrewAI multi-agent system that reviews firewall change requests for Palo Alto (PAN-OS/Panorama) and Cisco FTD (managed by FMC). Use this skill whenever the user works on the RuleGate codebase (agents, tasks, flows, tools, parsers, risk checks, templates, tests). Also use it when they ask to review a firewall rule or change request, check for shadowed, duplicate, or overly permissive rules, generate PAN-OS set commands or FMC access rule payloads, or write a CAB package for a firewall change, even if they don't mention RuleGate by name.
---

# Firewall Change Reviewer (RuleGate)

RuleGate reviews proposed firewall changes before they reach the Change Advisory Board. It reads the current rulebase, analyzes the proposed change with deterministic Python, uses CrewAI agents for judgement and explanation, and outputs a decision package. **It never changes a firewall.**

This skill covers three jobs:

1. **Building and extending the codebase** (most common)
2. **Reviewing a change request manually**, using the same methodology as the crew
3. **Generating vendor-specific staged config**, as text for human review only

---

## Non-negotiable rules

Follow these in every task. They exist because this tool runs against production security infrastructure.

1. **No write paths, ever.** Do not add code that commits, pushes, deploys, or POSTs to a firewall or manager API. Use only GET or read calls against PAN-OS and FMC. If the user asks for auto-apply, explain the risk and offer a staged-file plus human-apply workflow instead.
2. **Deterministic before LLM.** CIDR containment, port-range overlap, object resolution, rule-order evaluation, and every RG-xxx check must be pure Python functions with unit tests. Agents consume their results through tools. Never ask an LLM to decide whether `10.1.0.0/16` contains `10.1.4.0/24`.
3. **Evidence-bound findings.** Every finding needs a `check_id` and at least one piece of evidence (rule name/UUID, object name, or request field). Agents must not report findings that no tool produced.
4. **Flag, don't guess.** FQDN objects, dynamic address groups, EDLs, user/group-based rules, and URL categories cannot be fully resolved offline. Mark them `UNRESOLVED` and downgrade dependent conclusions to "needs human review."
5. **Read-only credentials.** Live-mode documentation and code must assume read-only API roles. Never log secrets or put them in prompts.
6. **Sanitized samples.** Sample data in `samples/` uses RFC 1918 / RFC 5737 addresses and fictional names only.

---

## Architecture at a glance

```
Flow (src/rulegate/flow.py)
  @start intake ─► Review Crew (src/rulegate/crew.py, sequential)
                     1 Intake Parser        → NormalizedChangeRequest
                     2 Rulebase Analyst     → duplicate / shadow / conflict findings
                     3 Risk Assessor        → RG-xxx findings + score
                     4 Compliance Auditor   → policy clause mapping (Knowledge)
                     5 Implementation Planner → staged config + test + rollback
                     6 CAB Report Writer    → reports/<CR-ID>/review.md
  @router decision ─► CRITICAL/HIGH → human_input gate
                   └► otherwise    → write report
```

Key directories:

| Path | Purpose |
|---|---|
| `src/rulegate/models/` | Pydantic models. **The vendor-neutral contract.** Change with care. |
| `src/rulegate/parsers/` | Vendor data → `NormalizedRule`. One module per vendor. |
| `src/rulegate/analysis/` | Deterministic logic: `address_math.py`, `shadow.py`, `risk_rules.py`. |
| `src/rulegate/tools/` | CrewAI tool wrappers. Thin: validate input, call analysis, return JSON. |
| `src/rulegate/config/` | `agents.yaml`, `tasks.yaml`. |
| `src/rulegate/templates/` | Jinja2 for PAN-OS set commands, FMC JSON, CAB report. |
| `config/risk_policy.yaml` | Severity weights, CIDR thresholds, sensitive zones. |
| `knowledge/` | Security standard and compliance docs loaded as CrewAI Knowledge. |
| `tests/unit/`, `tests/scenarios/` | Logic tests and labeled end-to-end cases. |

---

## The normalized rule model

Every vendor parser must produce this shape. Analysis code works **only** with normalized rules, never with vendor-specific structures.

```python
class NormalizedRule(BaseModel):
    vendor: Literal["panos", "ftd"]
    rule_id: str                 # PAN rule name / FMC rule UUID
    name: str
    position: int                # global evaluation order, 1-based
    layer: str                   # "pre" | "local" | "post" (PAN), "prefilter" | "mandatory" | "default" (FTD)
    action: Literal["allow", "deny", "drop", "reset", "trust", "fastpath", "monitor"]
    enabled: bool
    src_zones: list[str]         # ["any"] means any
    dst_zones: list[str]
    src_addrs: list[AddressEntry]   # resolved networks; AddressEntry.unresolved flags FQDN/DAG/EDL
    dst_addrs: list[AddressEntry]
    services: list[PortRange]       # protocol + start/end; "any" expanded explicitly
    applications: list[str]         # PAN App-ID; FTD application names
    app_default_service: bool       # PAN "application-default"
    users: list[str]                # non-empty → partial-resolution warning
    inspection: InspectionProfile   # PAN profile group / FTD intrusion + file policy
    log_at_end: bool
    raw_ref: str                    # pointer back to source object for evidence
```

When adding a field, update both parsers, the request model if relevant, the tests, and the README vendor matrix.

---

## Vendor semantics cheat sheet

Getting these wrong produces silently incorrect reviews. Check them whenever you touch parsers, shadow logic, or templates.

| Topic | Palo Alto PAN-OS | Cisco FTD (FMC-managed) |
|---|---|---|
| Evaluation order | Panorama pre-rules, then local rules, then Panorama post-rules, then intrazone/interzone defaults. First match wins. | Prefilter policy first (Fastpath/Block/Analyze), then ACP mandatory section, then default section, then default action. First match wins. |
| NAT in security rules | Uses **pre-NAT IP** and **post-NAT zone** | Uses **real (untranslated) IP** |
| App + port | `application-default` restricts to the app's standard ports. A port-based rule with app `any` is weaker. | Applications are matched by Snort/OpenAppID. Ports and apps are separate conditions. |
| Inspection | Security Profile Group (AV, AS, vuln, URL, file, WildFire) attached to allow | Intrusion policy and file policy attached to **Allow** only |
| Inspection bypass | Allow without profiles | **Trust** (no deep inspection) and Prefilter **Fastpath** (bypasses ACP entirely) |
| Logging | `log-end` (and optionally `log-start`) | Log at end of connection (and optionally beginning) |
| Config interface | XML API / `set` commands, device groups in Panorama | FMC REST API (`/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{id}/accessrules`). Not device CLI. |
| Objects | Address, address-group (static/dynamic), service, service-group, EDL | Network, network group, port objects, dynamic objects, SGT |

**Shadow analysis implication:** for FTD, evaluate Prefilter Fastpath and Block rules before ACP rules. A Prefilter Fastpath rule can make a later ACP rule irrelevant for that traffic.

---

## Shadow, duplicate, and conflict logic

Implemented in `analysis/shadow.py`. Rule A (earlier position) **covers** request R when, on every dimension, A's match set is a superset of R's:

- zones: A is `any`, or contains all of R's zones
- source and destination addresses: every R network is `subnet_of` some A network
- services: every R port range is inside some A port range for the same protocol
- applications: A is `any`, or contains R's applications (PAN)

The outcomes map as follows:

| Earlier covering rule's action | Request action | Result |
|---|---|---|
| allow / trust / fastpath | allow | **RG-013 Duplicate.** Access already exists. |
| deny / drop / reset | allow, placed below it | **RG-014 Shadowed.** The new rule would never match. |
| allow | deny | Deny would be shadowed (RG-014). |

A new allow placed **above** an existing deny it overlaps triggers **RG-015 Deny override** (Critical).

Partial overlap is not shadowing. Report it as Info with the overlapping dimensions listed. If any dimension involves an `UNRESOLVED` entry, the result is `NEEDS_HUMAN_REVIEW`, never a definitive shadow or duplicate.

---

## Adding a new risk check

Follow these steps in order.

1. Pick the next free ID (`RG-017`, …). Never reuse or renumber IDs, because reports and tests reference them.
2. Add a pure function in `analysis/risk_rules.py`:

```python
@register_check("RG-017", default_severity=Severity.MEDIUM, vendors={"panos", "ftd"})
def check_example(req: NormalizedChangeRequest, ctx: CheckContext) -> list[Finding]:
    """One-line description of what risky condition this detects and why it matters."""
    if <condition>:
        return [Finding(
            check_id="RG-017",
            severity=ctx.severity_for("RG-017"),
            title="Short title",
            detail="Plain-English explanation an engineer would accept.",
            evidence=[Evidence(kind="request_field", ref="service")],
            remediation="Concrete, narrower alternative.",
        )]
    return []
```

3. Make thresholds configurable in `config/risk_policy.yaml`. Do not hard-code CIDR prefixes, port lists, or zone names.
4. Add unit tests in `tests/unit/test_risk_rules.py`: at least one positive, one negative, and one edge case per vendor the check applies to.
5. Add or update a scenario in `tests/scenarios/` if the check changes any expected decision.
6. Add the row to the README's Risk Check Catalog table.

---

## Adding a new vendor parser

1. Create `parsers/<vendor>.py` exposing `load_offline(path) -> list[NormalizedRule]` and, optionally, `load_live(settings) -> list[NormalizedRule]` (read-only calls only).
2. Resolve objects and groups recursively, and detect cycles. Mark FQDN, dynamic, and EDL entries as `unresolved`.
3. Compute a **global** `position` across all layers in true evaluation order.
4. Map vendor actions onto the `action` literal. If a vendor action does not fit, extend the literal deliberately and update `shadow.py`.
5. Add a sanitized sample export to `samples/rulebases/` and parser tests that assert rule count, order, and a few fully resolved rules.
6. Add a staged-config template in `templates/` and a vendor column to the README matrix.

---

## Agents and tasks conventions

- Keep agents narrow. One role per agent, written as a specialist (`Palo Alto and FTD Rulebase Analyst`), not a generalist.
- Backstories describe judgement style, for example: "You never approve access you cannot trace to a business justification."
- Every task's `expected_output` specifies an exact structure, preferably a Pydantic model via `output_pydantic`, so that downstream tasks and the report template get stable fields.
- Use `context=[...]` to pass upstream task outputs explicitly. Do not rely on agents "remembering."
- The CAB Report Writer task gets a **guardrail** that fails if any finding lacks `check_id` or evidence.
- Default process is **sequential** for reproducibility. Hierarchical mode exists for experiments and must still pass the scenario suite.
- Set `temperature` low (≤ 0.2) for analysis agents. The report writer may go slightly higher.

---

## Staged config generation

Templates live in `templates/`. Output is **text written to `reports/<CR-ID>/`**, never sent to a device.

**PAN-OS (`panos_set.j2`):** emit `set device-group <DG> pre-rulebase security rules <name> ...` (or `set rulebase security rules ...` for a standalone firewall). Include `application`, `service application-default` when an App-ID is set, `profile-setting group <group>`, and `log-end yes`. Emit a `move ... before <rule>` line that reflects the Rulebase Analyst's placement recommendation. Rollback is `delete ...` for the same rule.

**FTD (`fmc_accessrule.json.j2`):** emit the JSON body for a POST to the FMC `accessrules` endpoint, with `action: "ALLOW"`, zone, network and port object references, `ipsPolicy`, `filePolicy` where relevant, `logEnd: true`, and the target section and `insertBefore` / `insertAfter` query parameters as a comment block. Include a note that the payload is for human review and deployment from FMC. Rollback is the DELETE of the created rule UUID followed by a policy deployment.

Always include a pre-change test (e.g. confirm current behavior with packet-tracer on FTD or `test security-policy-match` on PAN-OS) and the same test post-change.

---

## Reviewing a change request manually

When the user pastes a change request and asks for a review without running the crew, apply the same methodology:

1. Normalize the request and list any missing fields (justification, owner, ticket, expiry, exact ports).
2. If a rulebase is provided, check for duplicate, shadowed, and deny-override results using the logic above. If none is provided, say that rulebase checks were not possible.
3. Walk the RG-001…RG-016 catalog and report only what applies, with evidence.
4. Give a recommendation using the decision table: Critical → REJECT, High → APPROVE_WITH_CONDITIONS, else APPROVE, duplicate → REJECT_DUPLICATE.
5. Offer a narrower alternative rule and staged config for the target vendor.
6. End with a test plan and rollback.

Use this report structure:

```markdown
# Firewall Change Review — <CR-ID> (<vendor>, <device group / policy>)
## Recommendation: <DECISION>   Risk score: <n>/100
## Request summary
## Findings
| ID | Severity | Finding | Evidence | Remediation |
## Rulebase analysis (duplicate / shadow / conflict)
## Suggested alternative
## Staged configuration (not applied)
## Test plan
## Rollback
## Items needing human review
```

---

## Testing requirements

- `tests/unit` must pass at 100% before any agent or prompt change is considered done.
- When you change prompts, models, or task wiring, run `tests/scenarios` and report decision accuracy and check-ID recall. Do not merge a regression without saying so explicitly.
- Every bug fix in analysis logic gets a regression test that reproduces it first.

---

## Common pitfalls

- Treating `any` as a string in comparisons instead of expanding it to `0.0.0.0/0`, `::/0`, and `1-65535` per protocol.
- Forgetting IPv6, or comparing IPv4 and IPv6 networks directly. `ipaddress` raises `TypeError`, so group by version first.
- Ignoring disabled rules. They do not shadow anything, but report them as cleanup candidates (Info).
- Evaluating FTD ACP rules without the Prefilter policy first.
- Using post-NAT IPs for PAN-OS address matching, or pre-NAT IPs for FTD.
- Letting the LLM "fix" a finding's severity. Severity comes from `risk_policy.yaml`. Agents may add context but may not change the value.
