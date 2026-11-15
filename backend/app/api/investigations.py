"""
Investigation, detection and analysis endpoints, including the analyst approval workflow.

Approval workflow
-----------------
1. An analysis is created as `pending_review`.
2. The analyst reviews claims (accept / reject, with optional note).
3. The analysis can be approved only when every unsafe claim
   (unsupported or contradictory) has been explicitly rejected. Approving
   therefore always means "a human looked at every problem the engine found".
4. Approval records the analysis on the investigation; everything is audited.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app import audit
from app.ai.schema import parse_analysis_output
from app.ai.service import AnalysisError, run_analysis, validate_external
from app.api.deps import require
from app.auth.sessions import Principal
from app.db import get_db
from app.db_utils import count_map
from app.export import build_bundle, collect, render_csv, render_markdown
from app.graph import build_graph
from app.integrity.scope import build_scope, coverage_gaps
from app.integrity.validator import UNSAFE
from app.models import AIAnalysis, AuditEntry, Claim, Detection, Event, Investigation, InvestigationEvent, User, utcnow
from app.schemas import (
    AnalysisOut,
    AnalysisRequest,
    AnalysisReview,
    ClaimOutSchema,
    ClaimReview,
    DetectionOut,
    InvestigationDetail,
    InvestigationOut,
    ValidateRequest,
)

router = APIRouter(prefix="/api", tags=["investigations"])


def _inv(db: Session, inv_id: str) -> Investigation:
    inv = db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "investigation not found")
    return inv


def _analysis(db: Session, analysis_id: str) -> AIAnalysis:
    a = db.scalar(select(AIAnalysis).options(selectinload(AIAnalysis.claims)).where(AIAnalysis.id == analysis_id))
    if not a:
        raise HTTPException(404, "analysis not found")
    return a


# --------------------------------------------------------------------------- detections


@router.get("/detections", response_model=list[DetectionOut])
def list_detections(
    severity: str | None = None, rule_id: str | None = None, investigation_id: str | None = None,
    unassigned: bool = False, limit: int = Query(default=200, ge=1, le=1000), db: Session = Depends(get_db),
    _: Principal = Depends(require("detections:read")),
) -> list[Detection]:  # fmt: skip
    stmt = select(Detection).order_by(Detection.first_seen.desc()).limit(limit)
    if severity:
        stmt = stmt.where(Detection.severity == severity)
    if rule_id:
        stmt = stmt.where(Detection.rule_id == rule_id)
    if investigation_id:
        stmt = stmt.where(Detection.investigation_id == investigation_id)
    if unassigned:
        stmt = stmt.where(Detection.investigation_id.is_(None))
    return list(db.scalars(stmt))


@router.get("/rules")
def list_rules(_: Principal = Depends(require("detections:read"))) -> list[dict[str, Any]]:
    from app.detection.rules import ALL_RULES

    return [{"id": r.id, "name": r.name, "severity": r.severity, "tactic": r.tactic, "technique": r.technique,
             "description": r.description} for r in ALL_RULES]  # fmt: skip


# --------------------------------------------------------------------------- investigations


@router.get("/investigations/{inv_id}", response_model=InvestigationDetail)
def get_investigation(
    inv_id: str, db: Session = Depends(get_db), _: Principal = Depends(require("investigations:read"))
) -> InvestigationDetail:
    inv = _inv(db, inv_id)
    dets = list(
        db.scalars(select(Detection).where(Detection.investigation_id == inv.id).order_by(Detection.first_seen))
    )
    counts = count_map(db, select(InvestigationEvent.role, func.count())
                             .where(InvestigationEvent.investigation_id == inv.id)
                             .group_by(InvestigationEvent.role))  # fmt: skip
    analyses = db.scalars(select(AIAnalysis).where(AIAnalysis.investigation_id == inv.id)
                          .order_by(AIAnalysis.created_at.desc()))  # fmt: skip
    scope = build_scope(db, inv.id)
    names = {u.id: u.display_name for u in db.scalars(select(User).where(User.id.in_(
        [x for x in (inv.assignee_id, inv.reviewer_id) if x])))}  # fmt: skip
    return InvestigationDetail(
        **InvestigationOut.model_validate(inv).model_dump(exclude={"assignee_name", "reviewer_name"}),
        assignee_name=names.get(inv.assignee_id or ""),
        reviewer_name=names.get(inv.reviewer_id or ""),
        detections=[DetectionOut.model_validate(d) for d in dets],
        event_counts={"evidence": counts.get("evidence", 0), "context": counts.get("context", 0)},
        coverage_gaps=coverage_gaps(scope),
        analyses=[
            {
                "id": a.id,
                "engine": a.engine,
                "model": a.model,
                "status": a.status,
                "created_at": a.created_at,
                "integrity": a.integrity,
            }
            for a in analyses
        ],  # fmt: skip
    )


@router.get("/investigations/{inv_id}/timeline")
def timeline(
    inv_id: str, db: Session = Depends(get_db), _: Principal = Depends(require("investigations:read"))
) -> dict[str, Any]:
    inv = _inv(db, inv_id)
    rows = db.execute(
        select(Event.id, Event.timestamp, Event.event_type, Event.outcome, Event.host, Event.username, Event.src_ip,
               Event.dst_ip, Event.bytes_out, Event.process, Event.tags, InvestigationEvent.role)
        .join(InvestigationEvent, InvestigationEvent.event_id == Event.id)
        .where(InvestigationEvent.investigation_id == inv.id).order_by(Event.timestamp, Event.id).limit(5000)
    ).all()  # fmt: skip
    dets = db.scalars(select(Detection).where(Detection.investigation_id == inv.id).order_by(Detection.first_seen))
    return {
        "first_seen": inv.first_seen, "last_seen": inv.last_seen,
        # "ref" uses the same ordering as integrity.scope.build_scope, so E12 here is E12 to the validator.
        "events": [{"id": r.id, "ref": f"E{i}", "timestamp": r.timestamp, "event_type": r.event_type, "outcome": r.outcome,
                    "host": r.host, "username": r.username, "src_ip": r.src_ip, "dst_ip": r.dst_ip,
                    "bytes_out": r.bytes_out, "process": r.process, "tags": r.tags, "role": r.role} for i, r in enumerate(rows, start=1)],
        "detections": [{"id": d.id, "rule_id": d.rule_id, "rule_name": d.rule_name, "severity": d.severity,
                        "tactic": d.tactic, "first_seen": d.first_seen, "last_seen": d.last_seen,
                        "summary": d.summary} for d in dets],
    }  # fmt: skip


@router.get("/investigations/{inv_id}/graph")
def graph(
    inv_id: str, db: Session = Depends(get_db), _: Principal = Depends(require("investigations:read"))
) -> dict[str, Any]:
    _inv(db, inv_id)
    scope = build_scope(db, inv_id)
    flagged = {eid for d in scope.detections for eid in d.event_ids}
    return build_graph(scope, flagged)


@router.get("/investigations/{inv_id}/audit")
def investigation_audit(
    inv_id: str, db: Session = Depends(get_db), _: Principal = Depends(require("investigations:read"))
) -> list[dict[str, Any]]:
    _inv(db, inv_id)
    ids = [inv_id, *db.scalars(select(AIAnalysis.id).where(AIAnalysis.investigation_id == inv_id))]
    rows = db.scalars(select(AuditEntry).where(AuditEntry.target_id.in_(ids)).order_by(AuditEntry.id.desc()))
    return [{"id": e.id, "timestamp": e.timestamp, "actor": e.actor, "action": e.action, "target_type": e.target_type,
             "target_id": e.target_id, "details": e.details, "entry_hash": e.entry_hash} for e in rows]  # fmt: skip


@router.get("/investigations/{inv_id}/export")
def export(inv_id: str, format: str = Query(default="zip", pattern="^(zip|json|md|csv)$"),
           db: Session = Depends(get_db), p: Principal = Depends(require("export:create"))) -> Response:  # fmt: skip
    inv = _inv(db, inv_id)
    if format == "zip":
        payload, manifest = build_bundle(db, inv)
        media, ext, details = "application/zip", "zip", {"bundle_sha256": manifest["bundle_sha256"]}
    else:
        data = collect(db, inv)
        if format == "md":
            payload, media, ext = render_markdown(data).encode(), "text/markdown; charset=utf-8", "md"
        elif format == "csv":
            payload, media, ext = render_csv(data).encode(), "text/csv; charset=utf-8", "csv"
        else:
            import json

            payload, media, ext = json.dumps(data, indent=2, default=str).encode(), "application/json", "json"
        details = {}
    audit.record(db, actor=p.actor, action="investigation.exported", target_type="investigation", target_id=inv.id,
                 details={"format": format, "bytes": len(payload), **details})  # fmt: skip
    db.commit()
    return Response(payload, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="tracelayer-{inv.id}.{ext}"'})  # fmt: skip


# --------------------------------------------------------------------------- analyses


@router.post("/investigations/{inv_id}/analyses", response_model=AnalysisOut)
def create_analysis(inv_id: str, body: AnalysisRequest, db: Session = Depends(get_db),
                    p: Principal = Depends(require("analyses:create"))) -> AIAnalysis:  # fmt: skip
    _inv(db, inv_id)
    try:
        analysis = run_analysis(db, inv_id, body.engine, p.actor)
    except AnalysisError as exc:
        raise HTTPException(422, str(exc)) from exc
    return _analysis(db, analysis.id)


@router.get("/investigations/{inv_id}/analyses", response_model=list[AnalysisOut])
def list_analyses(
    inv_id: str, db: Session = Depends(get_db), _: Principal = Depends(require("analyses:read"))
) -> list[AIAnalysis]:
    _inv(db, inv_id)
    stmt = (select(AIAnalysis).options(selectinload(AIAnalysis.claims))
            .where(AIAnalysis.investigation_id == inv_id).order_by(AIAnalysis.created_at.desc()))  # fmt: skip
    return list(db.scalars(stmt))


@router.get("/analyses/{analysis_id}", response_model=AnalysisOut)
def get_analysis(
    analysis_id: str, db: Session = Depends(get_db), _: Principal = Depends(require("analyses:read"))
) -> AIAnalysis:
    return _analysis(db, analysis_id)


@router.post("/analyses/{analysis_id}/claims/{claim_id}/review", response_model=ClaimOutSchema)
def review_claim(analysis_id: str, claim_id: str, body: ClaimReview, db: Session = Depends(get_db),
                 p: Principal = Depends(require("claims:review"))) -> Claim:  # fmt: skip
    a = _analysis(db, analysis_id)
    if a.status != "pending_review":
        raise HTTPException(409, f"analysis is already {a.status}")
    claim = next((c for c in a.claims if c.id == claim_id), None)
    if not claim:
        raise HTTPException(404, "claim not found")
    if body.decision == "accept" and claim.verdict in UNSAFE and not (body.note or "").strip():
        # Overriding the engine on an unsafe claim is allowed, but must be justified in writing.
        raise HTTPException(422, "accepting an unsupported/contradictory claim requires a justification note")
    claim.review_status = {"accept": "accepted", "reject": "rejected", "pending": "pending"}[body.decision]
    claim.review_note = body.note
    audit.record(db, actor=p.actor, action=f"claim.{claim.review_status}", target_type="analysis", target_id=a.id,
                 details={"claim_id": claim.id, "verdict": claim.verdict, "note": body.note})  # fmt: skip
    db.commit()
    return claim


@router.post("/analyses/{analysis_id}/review", response_model=AnalysisOut)
def review_analysis(analysis_id: str, body: AnalysisReview, db: Session = Depends(get_db),
                    p: Principal = Depends(require("analyses:approve"))) -> AIAnalysis:  # fmt: skip
    a = _analysis(db, analysis_id)
    if a.status != "pending_review":
        raise HTTPException(409, f"analysis is already {a.status}")
    if body.decision == "approve":
        blocking = [c for c in a.claims if c.verdict in UNSAFE and c.review_status == "pending"]
        if blocking:
            raise HTTPException(409, {"message": "every unsupported or contradictory claim must be reviewed first",
                                      "blocking_claim_ids": [c.id for c in blocking]})  # fmt: skip
        for c in a.claims:
            if c.review_status == "pending":
                c.review_status = "accepted"
        a.status = "approved"
        inv = _inv(db, a.investigation_id)
        inv.approved_analysis_id = a.id
        inv.updated_at = utcnow()
    else:
        a.status = "rejected"
    a.reviewed_by, a.reviewed_at, a.review_note = p.user.email[:100], utcnow(), body.note
    audit.record(db, actor=p.actor, action=f"analysis.{a.status}", target_type="analysis", target_id=a.id,
                 details={"note": body.note, "investigation_id": a.investigation_id,
                          "claims": {c.id: c.review_status for c in a.claims}})  # fmt: skip
    db.commit()
    return _analysis(db, a.id)


@router.post("/integrity/validate")
def validate(
    body: ValidateRequest, db: Session = Depends(get_db), _: Principal = Depends(require("integrity:validate"))
) -> dict[str, Any]:
    """Validate any analysis JSON (another model, a human draft, an attack) without storing it."""
    _inv(db, body.investigation_id)
    try:
        parse_analysis_output(body.output)
        return validate_external(db, body.investigation_id, body.output)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
