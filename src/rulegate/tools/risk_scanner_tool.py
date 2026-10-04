from rulegate.tools.base import ContextTool


class RiskScannerTool(ContextTool):
    name: str = "risk_scanner"
    description: str = ("Runs the deterministic RG-001..RG-016 risk catalog. Returns every finding with check_id, "
                        "severity (from risk_policy.yaml - do not change it), evidence and remediation, plus the risk "
                        "score and the decision computed by the decision table.")

    def _run(self) -> str:
        return self.ctx.risk.model_dump_json(indent=2)
