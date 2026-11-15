"""
The analysis output contract shared by every generator (LLM, deterministic, pasted).

Parsing is tolerant of the ways small local models typically go wrong (markdown
fences, prose around the JSON, "E1, E2" as one string, integer refs, synonyms
for claim kinds) but strict about size, so a runaway generation cannot exhaust
memory or flood the UI.
"""

import json
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

MAX_CLAIMS = 40
MAX_TEXT = 2000

_KIND_SYNONYMS = {
    "observation": "observation", "fact": "observation", "finding": "observation", "verified": "observation",
    "correlation": "correlation", "inference": "correlation", "link": "correlation",
    "hypothesis": "hypothesis", "speculation": "hypothesis", "assessment": "hypothesis", "theory": "hypothesis",
}  # fmt: skip


class ClaimOut(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT)
    kind: str = "observation"
    citations: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("kind", mode="before")
    @classmethod
    def _kind(cls, v: Any) -> str:
        return _KIND_SYNONYMS.get(str(v or "observation").strip().lower(), "observation")

    @field_validator("citations", mode="before")
    @classmethod
    def _citations(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str | int):
            v = [v]
        out: list[str] = []
        for item in v if isinstance(v, list) else []:
            if isinstance(item, int):
                out.append(f"E{item}")
            elif isinstance(item, str):
                out.extend(x for x in re.split(r"[,\s]+", item.strip()) if x)
        return out


class AnalysisOutput(BaseModel):
    summary: str = Field(default="", max_length=6000)
    claims: list[ClaimOut] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    @field_validator("claims", mode="before")
    @classmethod
    def _cap_claims(cls, v: Any) -> Any:
        return v[:MAX_CLAIMS] if isinstance(v, list) else v

    @field_validator("recommendations", mode="before")
    @classmethod
    def _recs(cls, v: Any) -> list[str]:
        return [str(x)[:500] for x in v[:10]] if isinstance(v, list) else []


def parse_analysis_output(text: str) -> AnalysisOutput:
    """Extract and validate the JSON object from raw model output. Raises ValueError."""
    if len(text) > 500_000:
        raise ValueError("model output exceeds 500 KB")
    cleaned = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object found in model output")
    try:
        data = json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"model output is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError("model output must be a JSON object")
    # Drop empty / non-object claims instead of failing the whole analysis.
    if isinstance(data.get("claims"), list):
        data["claims"] = [c for c in data["claims"] if isinstance(c, dict) and str(c.get("text", "")).strip()]
    return AnalysisOutput.model_validate(data)


JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "claims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "kind": {"type": "string", "enum": ["observation", "correlation", "hypothesis"]},
                    "citations": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["text", "kind", "citations"],
            },
        },
        "recommendations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "claims"],
}
