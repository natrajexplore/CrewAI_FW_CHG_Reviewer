"""RuleGate CLI: `rulegate review <change-request>`."""

from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    for stream in (sys.stdout, sys.stderr):  # CrewAI logs emoji; Windows consoles default to cp1252
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(prog="rulegate", description="Review firewall change requests (read-only).")
    sub = parser.add_subparsers(dest="command", required=True)
    rv = sub.add_parser("review", help="Review a change request (YAML, JSON, or free text)")
    rv.add_argument("request", help="Path to the change request file")
    rv.add_argument("--rulebase", help="Offline rulebase export (defaults to samples/ or RULEGATE_*_RULEBASE)")
    rv.add_argument("--policy", help="Risk policy YAML (default: config/risk_policy.yaml)")
    rv.add_argument("--vendor", choices=["panos", "ftd"], help="Vendor hint for free-text requests")
    rv.add_argument("--process", choices=["sequential", "hierarchical"], default="sequential")
    rv.add_argument("--no-llm", action="store_true", help="Deterministic analysis only; skip the agent crew")
    rv.add_argument("--non-interactive", action="store_true", help="Do not prompt at the human approval gate")
    rv.add_argument("--output-dir", default="reports")
    args = parser.parse_args(argv)

    from rulegate.flow import ReviewFlow  # imported late so --help stays fast

    flow = ReviewFlow()
    flow.kickoff(inputs={
        "request_path": args.request,
        "rulebase": args.rulebase,
        "policy": args.policy,
        "vendor_hint": args.vendor,
        "process": args.process,
        "use_llm": not args.no_llm,
        "interactive": not args.non_interactive,
        "output_dir": args.output_dir,
    })
    s = flow.state
    print(f"\n{s.change_id}: {s.decision} (risk {s.risk_score}/100)")
    print(f"Approval gate: {s.gate}")
    print(f"Report: {s.report_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
