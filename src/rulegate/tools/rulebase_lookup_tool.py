import ipaddress
import json

from pydantic import BaseModel, Field

from rulegate.analysis.address_math import addrs_overlap, parse_address_token
from rulegate.tools.base import ContextTool


class RulebaseQuery(BaseModel):
    query: str = Field(description="An IP/CIDR, a zone name, a rule name (substring), or 'all'")


class RulebaseLookupTool(ContextTool):
    name: str = "rulebase_lookup"
    description: str = ("Looks up existing rules in the current rulebase (read-only) by IP/CIDR overlap, zone, or rule "
                        "name. Returns rules in evaluation order with resolved objects; UNRESOLVED marks FQDN/DAG/EDL.")
    args_schema: type[BaseModel] = RulebaseQuery

    def _run(self, query: str) -> str:
        q = query.strip()
        rules = self.ctx.rules
        if q.lower() != "all":
            entries = []
            try:
                ipaddress.ip_network(q, strict=False)
                entries = parse_address_token(q)
            except ValueError:
                pass
            if entries:
                rules = [r for r in rules if addrs_overlap(r.src_addrs, entries) is not False
                         or addrs_overlap(r.dst_addrs, entries) is not False]
            else:
                ql = q.lower()
                rules = [r for r in rules if ql in r.name.lower() or ql == r.rule_id.lower()
                         or ql in [z.lower() for z in r.src_zones + r.dst_zones]]
        return json.dumps({"query": q, "count": len(rules), "rules": [r.summary() for r in rules[:30]],
                           "truncated": len(rules) > 30}, indent=2)
