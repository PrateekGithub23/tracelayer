"""
Analysis orchestration: choose a generator, validate every claim, persist, audit.

Engine selection
  "deterministic" -> template analyst, never touches the network
  "ollama"        -> local LLM; failure is an error (useful when you *want* to test the model)
  "auto"          -> try Ollama if reachable and the model is pulled, otherwise fall back.
                     The reason for any fallback is stored and shown in the UI.

Regardless of the generator, output goes through the same integrity validator,
and is stored as `pending_review` until an analyst approves it.
"""

import time
from typing import Any

from sqlalchemy.orm import Session

from app import audit
from app.ai import deterministic
from app.ai.ollama import OllamaClient, OllamaError
from app.ai.prompt import SYSTEM_PROMPT, build_prompt
from app.ai.schema import JSON_SCHEMA, AnalysisOutput, parse_analysis_output
from app.config import get_settings
from app.ids import new_id
from app.integrity.extract import extract
from app.integrity.provenance import sha256_hex
from app.integrity.scope import Scope, build_scope
from app.integrity.validator import ClaimInput, ClaimResult, validate_all
from app.models import AIAnalysis, Claim, Investigation


class AnalysisError(RuntimeError):
    pass


def ollama_client() -> OllamaClient:
    s = get_settings()
    return OllamaClient(s.ollama_url, s.ollama_model, s.ollama_timeout_s)


def summary_issues(summary: str, scope: Scope) -> list[str]:
    """The free-text summary is not a claim, but it must not smuggle in fabrications or dismissals."""
    a = extract(summary, scope)
    issues = [f"Summary names unknown entity {u}" for u in a.unknown_entities]
    in_scope_ips = {ip for e in scope.events.values() for ip in (e.src_ip, e.dst_ip) if ip}
    issues += [f"Summary mentions {ip}, which is not in this investigation" for ip in sorted(a.ips - in_scope_ips)]
    if a.dismissive and any(d.severity in ("high", "critical") for d in scope.detections):
        issues.append("Summary dismisses activity that has high/critical detections")
    return issues


def validate_output(output: AnalysisOutput, scope: Scope) -> tuple[list[ClaimResult], dict[str, Any]]:
    results, integrity = validate_all([ClaimInput(c.text, c.kind, c.citations) for c in output.claims], scope)
    integrity["summary_issues"] = summary_issues(output.summary, scope)
    return results, integrity


def _generate(scope: Scope, inv: Investigation, engine: str) -> dict[str, Any]:
    settings = get_settings()
    prompt, pack_sha, pack_meta = build_prompt(scope, inv, settings.llm_max_events)
    fallback_reason: str | None = None
    want_llm = engine == "ollama" or (engine == "auto" and settings.llm_mode != "deterministic")

    if want_llm:
        client = ollama_client()
        status = client.status()
        try:
            if not status["reachable"]:
                raise OllamaError(f"Ollama not reachable at {client.base_url} ({status['error']})")
            if not status["model_available"]:
                raise OllamaError(f"model '{client.model}' is not pulled (run: ollama pull {client.model})")
            content, meta = client.chat_json(SYSTEM_PROMPT, prompt, JSON_SCHEMA)
            try:
                output = parse_analysis_output(content)
            except ValueError as exc:
                raise OllamaError(f"model output rejected: {exc}") from exc
            return {"engine": "ollama", "model": client.model, "output": output, "raw": content,
                    "prompt_sha": sha256_hex(SYSTEM_PROMPT + prompt), "pack_sha": pack_sha,
                    "meta": {**meta, **pack_meta, "event_ids": None}, "fallback_reason": None}  # fmt: skip
        except OllamaError as exc:
            if engine == "ollama":
                raise AnalysisError(str(exc)) from exc
            fallback_reason = str(exc)

    output, meta = deterministic.analyze(scope, inv)
    return {"engine": "deterministic", "model": "templates-v1", "output": output, "raw": output.model_dump_json(),
            "prompt_sha": None, "pack_sha": sha256_hex(",".join(sorted(scope.events))), "meta": meta,
            "fallback_reason": fallback_reason}  # fmt: skip


def run_analysis(db: Session, investigation_id: str, engine: str = "auto", actor: str = "system") -> AIAnalysis:
    inv = db.get(Investigation, investigation_id)
    if inv is None:
        raise AnalysisError("investigation not found")
    scope = build_scope(db, investigation_id)
    if not scope.events:
        raise AnalysisError("investigation has no events in scope")

    t0 = time.perf_counter()
    gen = _generate(scope, inv, engine)
    t_gen = time.perf_counter()
    results, integrity = validate_output(gen["output"], scope)
    integrity["validation_ms"] = round((time.perf_counter() - t_gen) * 1000, 2)
    integrity["generation_ms"] = round((t_gen - t0) * 1000, 2)
    integrity["generator_meta"] = {k: v for k, v in gen["meta"].items() if k != "event_ids"}
    integrity["recommendations"] = gen["output"].recommendations

    analysis = AIAnalysis(
        id=new_id("ana"), investigation_id=inv.id, engine=gen["engine"], model=gen["model"],
        summary=gen["output"].summary, raw_output=gen["raw"][:200_000], prompt_sha256=gen["prompt_sha"],
        evidence_pack_sha256=gen["pack_sha"], fallback_reason=gen["fallback_reason"],
        latency_ms=round((time.perf_counter() - t0) * 1000, 2), integrity=integrity,
    )  # fmt: skip
    db.add(analysis)
    _attach_claims(analysis, results)
    audit.record(db, actor=actor, action="analysis.created", target_type="investigation", target_id=inv.id,
                 details={"analysis_id": analysis.id, "engine": analysis.engine, "model": analysis.model,
                          "integrity_score": integrity["integrity_score"],
                          "unsafe_claims": integrity["unsafe_claims"]})  # fmt: skip
    db.commit()
    return analysis


def _attach_claims(analysis: AIAnalysis, results: list[ClaimResult]) -> None:
    for i, r in enumerate(results):
        analysis.claims.append(Claim(
            id=new_id("clm"), ordinal=i, text=r.text, declared_kind=r.declared_kind, citations=r.citations,
            raw_citations=r.raw_citations, verdict=r.verdict, reasons=r.reasons, checks=r.checks,
        ))  # fmt: skip


def validate_external(db: Session, investigation_id: str, raw_output: str) -> dict[str, Any]:
    """Validate a pasted analysis (from any model or a human) without storing it."""
    scope = build_scope(db, investigation_id)
    output = parse_analysis_output(raw_output)
    results, integrity = validate_output(output, scope)
    return {
        "integrity": integrity,
        "claims": [
            {
                "text": r.text,
                "declared_kind": r.declared_kind,
                "verdict": r.verdict,
                "reasons": r.reasons,
                "citations": r.citations,
                "raw_citations": r.raw_citations,
                "checks": r.checks,
            }  # fmt: skip
            for r in results
        ],
    }
