"""
Background jobs, persisted in the `pipeline_runs` table.

Why not Celery/Redis? For a single-node, zero-cost deployment the only things
that need to run asynchronously are detection+correlation, the evaluation suite
and benchmarks. A small thread pool plus a durable status row gives the UI
progress/polling and an audit trail without adding two more services.
The trade-off (documented): queued jobs do not survive a process restart, and
runs are marked failed on startup if they were left 'running'.
"""

import logging
import secrets
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import session_scope
from app.ids import new_id
from app.models import PipelineRun, utcnow

log = logging.getLogger("tracelayer.jobs")
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="tl-job")
# Detection/correlation mutate shared state; running two at once would race on investigation assignment.
_PIPELINE_LOCK = threading.Lock()

JobFn = Callable[[Session, str], dict[str, Any]]


def submit(kind: str, fn: JobFn, params: dict[str, Any] | None = None) -> str:
    run_id = new_id("run")
    with session_scope() as db:
        db.add(PipelineRun(id=run_id, kind=kind, status="queued", params=params or {}))
    if get_settings().background_jobs:
        _executor.submit(_execute, run_id, fn)
    else:
        _execute(run_id, fn)
    return run_id


def _execute(run_id: str, fn: JobFn) -> None:
    with session_scope() as db:
        db.execute(update(PipelineRun).where(PipelineRun.id == run_id).values(status="running", started_at=utcnow()))
    try:
        with session_scope() as db:
            stats = fn(db, run_id)
        status, error = "succeeded", None
    except Exception as exc:  # noqa: BLE001 - job boundary: record any failure
        # The traceback goes to the server log only. Clients see the exception class and a correlation id,
        # never file paths, library internals, or data that may be embedded in an exception message.
        error_id = secrets.token_hex(6)
        log.exception("job %s failed (error id %s)", run_id, error_id)
        stats, status = {}, "failed"
        error = f"{type(exc).__name__} (error id {error_id}; see server log)"
    with session_scope() as db:
        db.execute(update(PipelineRun).where(PipelineRun.id == run_id)
                   .values(status=status, stats=stats, error=error, finished_at=utcnow()))  # fmt: skip


def detect_and_correlate(db: Session, run_id: str) -> dict[str, Any]:
    from app.correlation.engine import run_correlation
    from app.detection.engine import run_detection

    with _PIPELINE_LOCK:
        det = run_detection(db, run_id)
        db.flush()
        cor = run_correlation(db)
        total = det["timings_ms"]["load"] + det["timings_ms"]["rules"] + det["timings_ms"]["persist"] + cor["ms"]
        return {"detection": det, "correlation": cor, "total_ms": round(total, 2)}


def mark_interrupted_runs() -> None:
    """Called at startup: anything still 'running' died with the previous process."""
    with session_scope() as db:
        db.execute(update(PipelineRun).where(PipelineRun.status.in_(["queued", "running"]))
                   .values(status="failed", error="interrupted by restart", finished_at=utcnow()))  # fmt: skip
