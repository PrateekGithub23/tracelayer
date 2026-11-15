"""System status, dashboard metrics, performance data, ledger verification and background runs."""

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, func, select, text
from sqlalchemy.orm import Session

from app import __version__, audit, jobs, telemetry
from app.ai.service import ollama_client
from app.api.deps import analyst_name, require_writer
from app.audit import verify_audit_chain
from app.config import get_settings
from app.db import get_db
from app.db_utils import count_map
from app.ids import new_id
from app.integrity.ledger import verify_ledger
from app.models import (
    AIAnalysis,
    Claim,
    Detection,
    Event,
    IngestBatch,
    Investigation,
    PipelineRun,
    Report,
)
from app.schemas import BenchmarkRequest, ReportOut, RunOut

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "ok", "version": __version__}


@router.get("/system/status")
def system_status(db: Session = Depends(get_db)) -> dict[str, Any]:
    s = get_settings()
    llm = ollama_client().status() if s.llm_mode != "deterministic" else {"reachable": False, "disabled": True}
    return {
        "version": __version__,
        "database": db.get_bind().dialect.name,
        "auth_required": bool(s.api_token),
        "llm": {**llm, "mode": s.llm_mode, "url": s.ollama_url, "configured_model": s.ollama_model},
        "background_jobs": s.background_jobs,
    }


def _hour_bucket(db: Session) -> Any:
    if db.get_bind().dialect.name == "postgresql":
        return func.to_char(func.date_trunc("hour", Event.timestamp), 'YYYY-MM-DD"T"HH24:00:00')
    return func.strftime("%Y-%m-%dT%H:00:00", Event.timestamp)


@router.get("/metrics/overview")
def overview(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Every number on the dashboard is computed here from stored rows."""
    count = lambda model: db.scalar(select(func.count()).select_from(model)) or 0  # noqa: E731
    latest = db.scalar(select(func.max(Event.timestamp)))
    volume: list[dict[str, Any]] = []
    if latest:
        bucket = _hour_bucket(db).label("bucket")
        rows = db.execute(select(bucket, Event.event_type, func.count())
                          .where(Event.timestamp >= latest - timedelta(hours=24))
                          .group_by(bucket, Event.event_type).order_by(bucket)).all()  # fmt: skip
        by_bucket: dict[str, dict[str, Any]] = {}
        for b, t, n in rows:
            by_bucket.setdefault(b, {"bucket": b})[t] = n
        volume = list(by_bucket.values())

    dets_by_sev = count_map(db, select(Detection.severity, func.count()).group_by(Detection.severity))
    dets_by_rule = [{"rule_id": r, "rule_name": n, "count": c} for r, n, c in db.execute(
        select(Detection.rule_id, func.min(Detection.rule_name), func.count()).group_by(Detection.rule_id)
        .order_by(func.count().desc()))]  # fmt: skip
    inv_by_status = count_map(db, select(Investigation.status, func.count()).group_by(Investigation.status))
    inv_by_sev = count_map(db, select(Investigation.severity, func.count())
                                 .where(Investigation.status.in_(["open", "in_review"]))
                                 .group_by(Investigation.severity))  # fmt: skip
    verdicts = count_map(db, select(Claim.verdict, func.count()).group_by(Claim.verdict))
    analyses_by_status = count_map(db, select(AIAnalysis.status, func.count()).group_by(AIAnalysis.status))
    engines = count_map(db, select(AIAnalysis.engine, func.count()).group_by(AIAnalysis.engine))
    top_failed_sources = [{"ip": ip, "count": c} for ip, c in db.execute(
        select(Event.src_ip, func.count()).where(Event.event_type == "auth.login", Event.outcome == "failure",
                                                 Event.src_ip.is_not(None))
        .group_by(Event.src_ip).order_by(func.count().desc()).limit(5))]  # fmt: skip
    recent = [{"id": i.id, "title": i.title, "severity": i.severity, "score": i.score, "status": i.status,
               "last_seen": i.last_seen} for i in db.scalars(
        select(Investigation).order_by(Investigation.score.desc(), Investigation.updated_at.desc()).limit(6))]  # fmt: skip
    head = db.execute(select(IngestBatch.seq, IngestBatch.chain_hash).order_by(IngestBatch.seq.desc()).limit(1)).first()
    last_verify = db.scalar(select(Report).where(Report.kind == "verification").order_by(Report.created_at.desc()))
    tagged = db.scalar(
        select(func.count()).select_from(Event).where(cast(Event.tags, String).like("%llm_injection_suspected%"))
    )
    return {
        "totals": {"events": count(Event), "batches": count(IngestBatch), "detections": count(Detection),
                   "investigations": count(Investigation), "analyses": count(AIAnalysis), "claims": count(Claim),
                   "injection_tagged_events": tagged or 0,
                   "duplicates_rejected": db.scalar(select(func.coalesce(func.sum(IngestBatch.duplicate_count), 0)))},
        "event_volume": volume,
        "latest_event": latest,
        "detections_by_severity": dets_by_sev,
        "detections_by_rule": dets_by_rule,
        "investigations_by_status": inv_by_status,
        "open_investigations_by_severity": inv_by_sev,
        "claim_verdicts": verdicts,
        "analyses_by_status": analyses_by_status,
        "analyses_by_engine": engines,
        "top_failed_login_sources": top_failed_sources,
        "top_investigations": recent,
        "ledger": {"seq": head.seq if head else 0, "chain_head": head.chain_hash if head else None,
                   "last_verification": last_verify.payload | {"at": last_verify.created_at} if last_verify else None},
    }  # fmt: skip


@router.get("/metrics/performance")
def performance(db: Session = Depends(get_db)) -> dict[str, Any]:
    runs = list(db.scalars(select(PipelineRun).where(PipelineRun.kind == "detect_correlate")
                           .order_by(PipelineRun.created_at.desc()).limit(30)))  # fmt: skip
    batches = list(db.scalars(select(IngestBatch).order_by(IngestBatch.seq.desc()).limit(50)))
    analyses = db.execute(select(AIAnalysis.engine, func.count(), func.avg(AIAnalysis.latency_ms),
                                 func.max(AIAnalysis.latency_ms)).group_by(AIAnalysis.engine)).all()  # fmt: skip
    bench = db.scalar(select(Report).where(Report.kind == "benchmark").order_by(Report.created_at.desc()))
    evaluation = db.scalar(select(Report).where(Report.kind == "evaluation").order_by(Report.created_at.desc()))
    return {
        "pipeline_runs": [{"id": r.id, "status": r.status, "created_at": r.created_at,
                           "total_ms": r.stats.get("total_ms"), "events_scanned": r.stats.get("detection", {}).get("events_scanned"),
                           "timings": r.stats.get("detection", {}).get("timings_ms"),
                           "correlation_ms": r.stats.get("correlation", {}).get("ms")} for r in runs],
        "ingest_batches": [{"id": b.id, "seq": b.seq, "source": b.source, "accepted": b.accepted_count,
                            "duplicates": b.duplicate_count, "rejected": b.rejected_count, "ms": b.duration_ms,
                            "events_per_sec": round(b.accepted_count / (b.duration_ms / 1000), 1) if b.duration_ms else None,
                            "received_at": b.received_at} for b in batches],
        "analysis_latency": [{"engine": e, "count": n, "avg_ms": round(avg or 0, 1), "max_ms": round(mx or 0, 1)}
                             for e, n, avg, mx in analyses],
        "api_latency": telemetry.percentile_table(),
        "latest_benchmark": {"id": bench.id, "created_at": bench.created_at, **bench.payload} if bench else None,
        "latest_evaluation": {"id": evaluation.id, "created_at": evaluation.created_at,
                              "summary": evaluation.payload.get("summary")} if evaluation else None,
    }  # fmt: skip


# --------------------------------------------------------------------------- integrity ledger


@router.post("/integrity/verify", dependencies=[Depends(require_writer)])
def verify_all(db: Session = Depends(get_db), actor: str = Depends(analyst_name)) -> dict[str, Any]:
    ledger = verify_ledger(db)
    chain = verify_audit_chain(db)
    payload = {"ok": ledger["ok"] and chain["ok"], "ledger": ledger, "audit_chain": chain}
    db.add(Report(id=new_id("rep"), kind="verification", payload=payload))
    audit.record(db, actor=actor, action="integrity.verified", target_type="system", target_id="ledger",
                 details={"ok": payload["ok"], "events_checked": ledger["events_checked"],
                          "issues": len(ledger["issues"])})  # fmt: skip
    db.commit()
    return payload


# --------------------------------------------------------------------------- runs + reports


@router.post("/pipeline/runs", response_model=RunOut, dependencies=[Depends(require_writer)])
def start_pipeline(db: Session = Depends(get_db)) -> PipelineRun:
    run_id = jobs.submit("detect_correlate", jobs.detect_and_correlate)
    db.expire_all()
    return db.get(PipelineRun, run_id)  # type: ignore[return-value]


@router.get("/pipeline/runs", response_model=list[RunOut])
def list_runs(kind: str | None = None, limit: int = Query(default=30, ge=1, le=200),
              db: Session = Depends(get_db)) -> list[PipelineRun]:  # fmt: skip
    stmt = select(PipelineRun).order_by(PipelineRun.created_at.desc()).limit(limit)
    if kind:
        stmt = stmt.where(PipelineRun.kind == kind)
    return list(db.scalars(stmt))


@router.get("/pipeline/runs/{run_id}", response_model=RunOut)
def get_run(run_id: str, db: Session = Depends(get_db)) -> PipelineRun:
    run = db.get(PipelineRun, run_id)
    if not run:
        raise HTTPException(404, "run not found")
    return run


@router.get("/reports", response_model=list[ReportOut])
def list_reports(kind: str | None = None, limit: int = Query(default=20, ge=1, le=100),
                 db: Session = Depends(get_db)) -> list[Report]:  # fmt: skip
    stmt = select(Report).order_by(Report.created_at.desc()).limit(limit)
    if kind:
        stmt = stmt.where(Report.kind == kind)
    return list(db.scalars(stmt))


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(report_id: str, db: Session = Depends(get_db)) -> Report:
    rep = db.get(Report, report_id)
    if not rep:
        raise HTTPException(404, "report not found")
    return rep


def _store_report(kind: str, payload: dict[str, Any], db: Session) -> dict[str, Any]:
    rep = Report(id=new_id("rep"), kind=kind, payload=payload)
    db.add(rep)
    return {"report_id": rep.id, "summary": payload.get("summary")}


@router.post("/reports/evaluation", response_model=RunOut, dependencies=[Depends(require_writer)])
def run_evaluation(db: Session = Depends(get_db), actor: str = Depends(analyst_name)) -> PipelineRun:
    """Run the adversarial evaluation suite on an isolated in-memory database."""
    from app.evaluation.suite import run_suite

    run_id = jobs.submit("evaluation", lambda s, _rid: _store_report("evaluation", run_suite(), s))
    db.expire_all()
    return db.get(PipelineRun, run_id)  # type: ignore[return-value]


@router.post("/reports/benchmark", response_model=RunOut, dependencies=[Depends(require_writer)])
def run_benchmark(body: BenchmarkRequest, db: Session = Depends(get_db)) -> PipelineRun:
    """Measure ingest/detect/correlate/validate on an isolated temporary database."""
    from app.benchmarks.runner import run_benchmark as bench

    run_id = jobs.submit("benchmark", lambda s, _rid: _store_report("benchmark", bench(body.events), s),
                         {"events": body.events})  # fmt: skip
    db.expire_all()
    return db.get(PipelineRun, run_id)  # type: ignore[return-value]
