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
    sv = sub.add_parser("serve", help="Start the review console (web UI) on localhost")
    sv.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--allow-remote", action="store_true",
                    help="Permit a non-loopback bind. Put a TLS reverse proxy in front; traffic is plain HTTP.")
    args = parser.parse_args(argv)

    if args.command == "serve":
        return serve(args.host, args.port, args.allow_remote)

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


def serve(host: str, port: int, allow_remote: bool) -> int:
    import ipaddress
    import os
    import secrets

    import uvicorn

    from rulegate.web.app import create_app

    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback and not allow_remote:
        print(f"Refusing to bind {host}: the console is local-only by default. "
              "Use --allow-remote behind a TLS reverse proxy if you really need it.", file=sys.stderr)
        return 2
    token = os.getenv("RULEGATE_UI_TOKEN") or secrets.token_urlsafe(32)
    if len(token) < 24:
        print("RULEGATE_UI_TOKEN must be at least 24 characters.", file=sys.stderr)
        return 2
    allowed = ["127.0.0.1", "localhost", "[::1]"] if loopback else [host]
    app = create_app(token, allowed_hosts=allowed)
    shown = "127.0.0.1" if loopback else host
    print("\nRuleGate review console (read-only: nothing is ever pushed to a firewall)")
    print(f"Open: http://{shown}:{port}/#token={token}")
    print("The token is read from the URL fragment (never sent to the server in the URL) and kept for this "
          "browser tab only. Anyone with the token can run reviews and approve them.\n")
    uvicorn.run(app, host=host, port=port, server_header=False, proxy_headers=False, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
