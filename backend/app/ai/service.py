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

import threading
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
from app.integrity.validator import UNSAFE, ClaimInput, ClaimResult, validate_all
from app.models import AIAnalysis, Claim, Investigation


class AnalysisError(RuntimeError):
    pass


# One model generation at a time: a 3B model already saturates a laptop GPU, and this bounds the
# cost any user (including a demo account) can impose. Extra requests get HTTP 429, they do not queue.
_GENERATION_SLOT = threading.BoundedSemaphore(1)


class ModelBusy(AnalysisError):
    pass


def effective_llm(db: Session | None = None) -> tuple[str, str]:
    """(mode, model): admin overrides from app_settings take precedence over environment defaults."""
    s = get_settings()
    if db is None:
        return s.llm_mode, s.ollama_model
    from app.auth.users import get_setting

    return get_setting(db, "llm_mode", s.llm_mode), get_setting(db, "ollama_model", s.ollama_model)


def ollama_client(db: Session | None = None) -> OllamaClient:
    s = get_settings()
    return OllamaClient(s.ollama_url, effective_llm(db)[1], s.ollama_timeout_s)


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


def _generate(scope: Scope, inv: Investigation, engine: str, db: Session | None = None) -> dict[str, Any]:
    settings = get_settings()
    mode, _model = effective_llm(db)
    prompt, pack_sha, pack_meta = build_prompt(scope, inv, settings.llm_max_events)
    fallback_reason: str | None = None
    want_llm = engine in ("ollama", "grounded") or (engine == "auto" and mode != "deterministic")
    grounded = engine == "grounded" or (engine == "auto" and mode == "grounded")
    provenance: dict[str, Any] = {"requested_engine": engine, "configured_mode": mode, "llm_attempted": want_llm}

    if want_llm:
        client = ollama_client(db)
        status = client.status()
        provenance.update({"model": client.model, "model_digest": status.get("digest"),
                           "ollama_version": status.get("version"), "quantization": status.get("quantization"),
                           "parameter_size": status.get("parameter_size")})  # fmt: skip
        try:
            if not status["reachable"]:
                raise OllamaError(f"Ollama not reachable at {client.base_url} ({status['error']})")
            if not status["model_available"]:
                raise OllamaError(f"model '{client.model}' is not pulled (run: ollama pull {client.model})")
            if grounded:
                from app.ai.grounded import GROUNDED_SCHEMA, GROUNDED_SYSTEM, build_grounded_prompt, fact_table

                facts = fact_table(scope, inv)
                if not facts:
                    raise OllamaError("grounded mode found no verified facts to give the model")
                system, prompt, schema = GROUNDED_SYSTEM, build_grounded_prompt(inv, facts), GROUNDED_SCHEMA
            else:
                system, schema = SYSTEM_PROMPT, JSON_SCHEMA
            if not _GENERATION_SLOT.acquire(blocking=False):
                raise ModelBusy("the local model is busy with another analysis; try again shortly")
            try:
                content, meta = client.chat_json(system, prompt, schema)
            finally:
                _GENERATION_SLOT.release()
            provenance["model_latency_ms"] = meta.get("wall_ms")
            try:
                if grounded:
                    from app.ai.grounded import to_output

                    output, gmeta = to_output(content, facts)
                    provenance.update(gmeta)
                else:
                    output = parse_analysis_output(content)
                provenance["json_valid"] = True
            except ValueError as exc:
                provenance["json_valid"] = False
                raise OllamaError(f"model output rejected: {exc}") from exc
            used = "ollama-grounded" if grounded else "ollama"
            return {"engine": used, "model": client.model, "output": output, "raw": content,
                    "prompt_sha": sha256_hex(system + prompt), "pack_sha": pack_sha,
                    "meta": {**meta, **pack_meta, "event_ids": None}, "fallback_reason": None,
                    "provenance": {**provenance, "engine_used": used, "pipeline": "grounded" if grounded else "free-form"}}  # fmt: skip
        except OllamaError as exc:
            if engine == "ollama":
                raise AnalysisError(str(exc)) from exc
            fallback_reason = str(exc)

    output, meta = deterministic.analyze(scope, inv)
    # The fallback is recorded as what it is: engine "deterministic", with the reason the model was not used.
    return {"engine": "deterministic", "model": "templates-v1", "output": output, "raw": output.model_dump_json(),
            "prompt_sha": None, "pack_sha": sha256_hex(",".join(sorted(scope.events))), "meta": meta,
            "fallback_reason": fallback_reason,
            "provenance": {**provenance, "engine_used": "deterministic", "fallback": fallback_reason is not None}}  # fmt: skip


def run_analysis(db: Session, investigation_id: str, engine: str = "auto", actor: str = "system") -> AIAnalysis:
    inv = db.get(Investigation, investigation_id)
    if inv is None:
        raise AnalysisError("investigation not found")
    scope = build_scope(db, investigation_id)
    if not scope.events:
        raise AnalysisError("investigation has no events in scope")

    t0 = time.perf_counter()
    gen = _generate(scope, inv, engine, db)
    t_gen = time.perf_counter()
    results, integrity = validate_output(gen["output"], scope)
    integrity["validation_ms"] = round((time.perf_counter() - t_gen) * 1000, 2)
    integrity["generation_ms"] = round((t_gen - t0) * 1000, 2)
    integrity["generator_meta"] = {k: v for k, v in gen["meta"].items() if k != "event_ids"}
    integrity["recommendations"] = gen["output"].recommendations
    integrity["generation"] = gen["provenance"]
    integrity["claims_requiring_review"] = sum(1 for r in results if r.checks.get("requires_review"))

    analysis = AIAnalysis(
        id=new_id("ana"), investigation_id=inv.id, engine=gen["engine"], model=gen["model"],
        summary=gen["output"].summary, raw_output=gen["raw"][:200_000], prompt_sha256=gen["prompt_sha"],
        evidence_pack_sha256=gen["pack_sha"], fallback_reason=gen["fallback_reason"],
        latency_ms=round((time.perf_counter() - t0) * 1000, 2), integrity=integrity,
    )  # fmt: skip
    db.add(analysis)
    _attach_claims(analysis, results)
    if gen["engine"] == "ollama-grounded":
        # Stage 3b: the grounded pipeline rejects claims that fail verification instead of leaving them pending.
        # This is a recorded system decision (reason in the note); hypotheses and gaps still go to the analyst.
        for c in analysis.claims:
            if c.verdict in UNSAFE:
                c.review_status = "rejected"
                c.review_note = "Rejected automatically by the grounded pipeline: " + "; ".join(c.reasons)[:500]
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
