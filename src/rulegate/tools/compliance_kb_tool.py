import json
import re
from pathlib import Path

from pydantic import BaseModel, Field

from rulegate.tools.base import ContextTool


class ComplianceQuery(BaseModel):
    query: str = Field(description="A check ID (e.g. RG-016), a zone name (e.g. pci-cde), or a keyword (e.g. logging)")


def _sections(knowledge_dir: Path) -> list[tuple[str, str, str]]:
    out = []
    for md in sorted(knowledge_dir.glob("*.md")):
        for block in re.split(r"(?m)^(?=## )", md.read_text(encoding="utf-8")):
            if block.startswith("## "):
                heading, _, body = block.partition("\n")
                out.append((md.name, heading[3:].strip(), body.strip()))
    return out


class ComplianceKBTool(ContextTool):
    name: str = "compliance_kb"
    description: str = ("Searches the internal firewall security standard and compliance summaries (knowledge/*.md) "
                        "and returns the matching clauses verbatim with their document and section reference.")
    args_schema: type[BaseModel] = ComplianceQuery
    knowledge_dir: Path = Path("knowledge")

    def _run(self, query: str) -> str:
        terms = [t for t in re.split(r"[\s,]+", query.lower()) if t]
        hits = [{"document": doc, "section": head, "text": body}
                for doc, head, body in _sections(self.knowledge_dir)
                if any(t in (head + " " + body).lower() for t in terms)]
        return json.dumps({"query": query, "matches": hits[:6], "total": len(hits)}, indent=2)
