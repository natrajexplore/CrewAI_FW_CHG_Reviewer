from rulegate.tools.base import ContextTool


class ShadowAnalyzerTool(ContextTool):
    name: str = "shadow_analyzer"
    description: str = ("Deterministic duplicate / shadow / deny-override analysis of the requested rule against the "
                        "ordered rulebase. Returns covering rules, conflicting denies, partial overlaps, items that need "
                        "human review, and the recommended placement.")

    def _run(self) -> str:
        return self.ctx.shadow.model_dump_json(indent=2)
