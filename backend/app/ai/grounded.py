"""
Grounded (two-stage) LLM generation.

Free-form generation asked a 3B model to read raw events, infer facts and cite them. In the v2 benchmark
57% of its claims were unsafe and it invented ~7 citations per analysis. Grounded mode removes the parts
a small model is bad at:

  Stage 1 (deterministic): the deterministic analyst extracts candidate facts from the evidence, and the
          integrity engine keeps only those that verify (verified or correlation). They become a numbered
          fact table F1..Fn, each carrying its event citations.
  Stage 2 (model): the model sees only the fact table. It writes a summary and claims that reference facts
          by id ("F3"); it may add clearly hedged hypotheses with no facts.
  Stage 3 (deterministic): citations are *derived* from the referenced facts, so the model cannot invent a
          citation; unknown fact ids are dropped and reported. Every claim is then verified as usual, and
          claims that come out unsupported/contradictory are rejected by the pipeline (recorded) rather than
          left for the analyst to discover.

The model never sees raw log text, so prompt injection in telemetry cannot reach it through this path.
"""

import json
import re
from typing import Any

from app.ai import deterministic
from app.ai.schema import AnalysisOutput, ClaimOut
from app.integrity.scope import Scope
from app.integrity.validator import CORRELATION, VERIFIED, ClaimInput, validate_claim
from app.models import Investigation

GROUNDED_SYSTEM = """You write a security investigation summary from a FACT TABLE.
Rules:
1. Use only the facts in the FACT TABLE. Do not add hosts, users, IPs, counts, times or tools that are not in it.
2. Every claim that states something as true must list the ids of the facts it relies on (e.g. ["F2","F5"]).
   Restate the fact faithfully; you may combine facts, but do not add new details.
3. kind: "observation" when restating one fact; "correlation" when linking several facts;
   "hypothesis" for anything not in the facts, worded with "may", "might" or "likely", with fact_ids [].
4. Prefer fewer, accurate claims over many claims. Reply with JSON only."""

GROUNDED_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "claims": {"type": "array", "items": {"type": "object", "properties": {
            "text": {"type": "string"}, "kind": {"type": "string", "enum": ["observation", "correlation", "hypothesis"]},
            "fact_ids": {"type": "array", "items": {"type": "string"}}}, "required": ["text", "kind", "fact_ids"]}},
        "recommendations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "claims"],
}  # fmt: skip

_FACT_ID = re.compile(r"^F(\d{1,3})$")


def fact_table(scope: Scope, inv: Investigation) -> list[dict[str, Any]]:
    """Stage 1: deterministic candidate facts, kept only if the integrity engine verifies them."""
    out, _meta = deterministic.analyze(scope, inv)
    facts: list[dict[str, Any]] = []
    for c in out.claims:
        r = validate_claim(ClaimInput(c.text, c.kind, c.citations), scope)
        if r.verdict in (VERIFIED, CORRELATION):
            facts.append({"id": f"F{len(facts) + 1}", "text": c.text, "kind": c.kind, "citations": list(c.citations)})
    return facts


def build_grounded_prompt(inv: Investigation, facts: list[dict[str, Any]]) -> str:
    lines = [f"INVESTIGATION: {inv.title}", f"SEVERITY: {inv.severity}", "", "FACT TABLE (each fact is verified):"]
    lines += [f"{f['id']}: {f['text']}" for f in facts]
    lines += ["", "Write the JSON report now."]
    return "\n".join(lines)


def to_output(raw: str, facts: list[dict[str, Any]]) -> tuple[AnalysisOutput, dict[str, Any]]:
    """Stage 3a: parse, map fact ids to citations, drop unknown ids (counted, never trusted)."""
    data = json.loads(raw)
    by_id = {f["id"]: f for f in facts}
    claims: list[ClaimOut] = []
    unknown_ids = 0
    for c in (data.get("claims") or [])[:40]:
        if not isinstance(c, dict) or not str(c.get("text") or "").strip():
            continue
        ids = [str(x).strip().upper() for x in (c.get("fact_ids") or []) if isinstance(x, str | int)]
        ids = [i if i.startswith("F") else f"F{i}" for i in ids]
        known = [i for i in ids if _FACT_ID.match(i) and i in by_id]
        unknown_ids += len(ids) - len(known)
        cites = list(dict.fromkeys(e for i in known for e in by_id[i]["citations"]))
        claims.append(ClaimOut(text=str(c["text"])[:2000], kind=str(c.get("kind") or "observation"), citations=cites))
    out = AnalysisOutput(summary=str(data.get("summary") or "")[:6000], claims=claims,
                         recommendations=[str(r)[:500] for r in (data.get("recommendations") or [])[:10]])  # fmt: skip
    return out, {"facts": len(facts), "unknown_fact_ids": unknown_ids}
