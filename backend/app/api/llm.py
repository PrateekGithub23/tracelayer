"""Local LLM status and a bounded connectivity test (model availability, version, latency)."""

import json
import time
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.ai.ollama import OllamaError
from app.ai.service import _GENERATION_SLOT, effective_llm, ollama_client
from app.api.deps import require
from app.auth.sessions import Principal
from app.config import get_settings
from app.db import get_db
from app.models import AIAnalysis

router = APIRouter(prefix="/api/llm", tags=["llm"])

_TEST_SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}, "word": {"type": "string"}},
                "required": ["ok", "word"]}  # fmt: skip


def _busy() -> bool:
    if _GENERATION_SLOT.acquire(blocking=False):
        _GENERATION_SLOT.release()
        return False
    return True


@router.get("/status")
def llm_status(db: Session = Depends(get_db), _: Principal = Depends(require("metrics:read"))) -> dict[str, Any]:
    s = get_settings()
    mode, model = effective_llm(db)
    st = ollama_client(db).status() if mode != "deterministic" else {"reachable": False, "model_available": False,
                                                                     "models": [], "error": "disabled (deterministic mode)"}  # fmt: skip
    usage = [{"engine": e, "count": n, "avg_ms": round(avg or 0, 1), "max_ms": round(mx or 0, 1)} for e, n, avg, mx in db.execute(
        select(AIAnalysis.engine, func.count(), func.avg(AIAnalysis.latency_ms), func.max(AIAnalysis.latency_ms))
        .group_by(AIAnalysis.engine))]  # fmt: skip
    fallbacks = (
        db.scalar(select(func.count()).select_from(AIAnalysis).where(AIAnalysis.fallback_reason.is_not(None))) or 0
    )
    return {
        **st,
        "mode": mode,
        "configured_model": model,
        "url": s.ollama_url,
        "timeout_s": s.ollama_timeout_s,
        "busy": _busy(),
        "usage": usage,
        "fallbacks": fallbacks,
    }


@router.post("/test")
def llm_test(db: Session = Depends(get_db), p: Principal = Depends(require("settings:manage"))) -> dict[str, Any]:
    """A tiny structured-output request with a short timeout: proves the model answers and returns valid JSON."""
    client = ollama_client(db)
    client.timeout_s = min(client.timeout_s, 60.0)
    t0 = time.perf_counter()
    out: dict[str, Any] = {"model": client.model}
    if not _GENERATION_SLOT.acquire(blocking=False):
        return {**out, "ok": False, "error": "model busy with an analysis"}
    try:
        content, meta = client.chat_json("Reply with JSON only.", 'Return {"ok": true, "word": "ready"}.', _TEST_SCHEMA)
        parsed = json.loads(content)
        out.update(ok=bool(parsed.get("ok")), json_valid=True, response=parsed, **meta)
    except (OllamaError, ValueError) as exc:
        out.update(ok=False, json_valid=False, error=str(exc)[:300])
    finally:
        _GENERATION_SLOT.release()
    out["round_trip_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    audit.record(db, actor=p.actor, action="llm.tested", target_type="system", target_id="llm",
                 details={k: out.get(k) for k in ("model", "ok", "json_valid", "round_trip_ms")})  # fmt: skip
    db.commit()
    return out
