"""
Event explorer endpoints.

Pagination is keyset-based (cursor = last timestamp + id), not OFFSET: deep
pages stay O(log n) via the timestamp index, and new events arriving while an
analyst scrolls do not shift rows between pages.
"""

import base64
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, and_, cast, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

from app.api.deps import require
from app.db import get_db
from app.integrity.ledger import verify_event
from app.models import Detection, DetectionEvent, Event, IngestBatch, Investigation, InvestigationEvent
from app.schemas import BatchOut, EventDetail, EventOut, EventPage

router = APIRouter(prefix="/api/events", tags=["events"], dependencies=[Depends(require("events:read"))])


def _like(term: str) -> str:
    # Escape LIKE wildcards so user input is matched literally.
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def apply_filters(
    stmt: Select[Any], *, q: str | None, event_type: list[str] | None, host: str | None, user: str | None,
    ip: str | None, outcome: str | None, tag: str | None, start: datetime | None, end: datetime | None,
    investigation_id: str | None, detection_id: str | None, role: str | None = None,
) -> Select[Any]:  # fmt: skip
    if q:
        pat = _like(q.strip()[:200])
        stmt = stmt.where(or_(*(c.ilike(pat, escape="\\") for c in (
            Event.command_line, Event.username, Event.host, Event.src_ip, Event.dst_ip, Event.message,
            Event.process, Event.id))))  # fmt: skip
    if event_type:
        stmt = stmt.where(Event.event_type.in_(event_type))
    if host:
        stmt = stmt.where(Event.host == host)
    if user:
        stmt = stmt.where(Event.username == user)
    if ip:
        stmt = stmt.where(or_(Event.src_ip == ip, Event.dst_ip == ip))
    if outcome:
        stmt = stmt.where(Event.outcome == outcome)
    if tag:
        stmt = stmt.where(cast(Event.tags, String).like(_like(f'"{tag}"'), escape="\\"))
    if start:
        stmt = stmt.where(Event.timestamp >= start)
    if end:
        stmt = stmt.where(Event.timestamp <= end)
    if investigation_id:
        sub = select(InvestigationEvent.event_id).where(InvestigationEvent.investigation_id == investigation_id)
        if role:
            sub = sub.where(InvestigationEvent.role == role)
        stmt = stmt.where(Event.id.in_(sub))
    if detection_id:
        stmt = stmt.where(
            Event.id.in_(select(DetectionEvent.event_id).where(DetectionEvent.detection_id == detection_id))
        )
    return stmt


def _encode(ts: datetime, eid: str) -> str:
    return base64.urlsafe_b64encode(f"{ts.isoformat()}|{eid}".encode()).decode()


def _decode(cursor: str) -> tuple[datetime, str]:
    try:
        ts, eid = base64.urlsafe_b64decode(cursor.encode()).decode().split("|", 1)
        return datetime.fromisoformat(ts), eid
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "invalid cursor") from exc


@router.get("", response_model=EventPage)
def list_events(
    q: str | None = None,
    event_type: list[str] | None = Query(default=None),
    host: str | None = None,
    user: str | None = None,
    ip: str | None = None,
    outcome: str | None = None,
    tag: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    investigation_id: str | None = None,
    detection_id: str | None = None,
    role: str | None = Query(default=None, pattern="^(evidence|context)$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = None,
    db: Session = Depends(get_db),
) -> EventPage:
    filters: dict[str, Any] = dict(q=q, event_type=event_type, host=host, user=user, ip=ip, outcome=outcome, tag=tag, start=start,
                   end=end, investigation_id=investigation_id, detection_id=detection_id, role=role)  # fmt: skip
    total = db.scalar(apply_filters(select(func.count()).select_from(Event), **filters)) or 0
    stmt = apply_filters(select(Event), **filters)
    if cursor:
        ts, eid = _decode(cursor)
        if order == "desc":
            stmt = stmt.where(or_(Event.timestamp < ts, and_(Event.timestamp == ts, Event.id < eid)))
        else:
            stmt = stmt.where(or_(Event.timestamp > ts, and_(Event.timestamp == ts, Event.id > eid)))
    sort = (Event.timestamp.desc(), Event.id.desc()) if order == "desc" else (Event.timestamp, Event.id)
    rows = list(db.scalars(stmt.order_by(*sort).limit(limit + 1)))
    more = len(rows) > limit
    rows = rows[:limit]
    return EventPage(items=[EventOut.model_validate(r) for r in rows], total=total,
                     next_cursor=_encode(rows[-1].timestamp, rows[-1].id) if more and rows else None)  # fmt: skip


@router.get("/facets")
def facets(investigation_id: str | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Top values per field, used to build filter dropdowns from real data."""
    out: dict[str, Any] = {}
    for name, col in (("event_type", Event.event_type), ("outcome", Event.outcome), ("host", Event.host),
                      ("username", Event.username), ("source", Event.source)):  # fmt: skip
        stmt = select(col, func.count()).where(col.is_not(None)).group_by(col).order_by(func.count().desc()).limit(50)
        if investigation_id:
            stmt = stmt.where(Event.id.in_(select(InvestigationEvent.event_id)
                                           .where(InvestigationEvent.investigation_id == investigation_id)))  # fmt: skip
        out[name] = [{"value": v, "count": c} for v, c in db.execute(stmt)]
    return out


@router.get("/{event_id}", response_model=EventDetail)
def get_event(event_id: str, db: Session = Depends(get_db)) -> EventDetail:
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(404, "event not found")
    batch = db.get(IngestBatch, ev.batch_id)
    dets = db.execute(select(Detection.id, Detection.rule_name, Detection.severity)
                      .join(DetectionEvent, DetectionEvent.detection_id == Detection.id)
                      .where(DetectionEvent.event_id == ev.id)).all()  # fmt: skip
    invs = db.execute(select(Investigation.id, Investigation.title, InvestigationEvent.role)
                      .join(InvestigationEvent, InvestigationEvent.investigation_id == Investigation.id)
                      .where(InvestigationEvent.event_id == ev.id)).all()  # fmt: skip
    return EventDetail(
        **EventOut.model_validate(ev).model_dump(), raw=ev.raw, ingested_at=ev.ingested_at,
        batch=BatchOut.model_validate(batch),
        detections=[{"id": i, "rule_name": n, "severity": s} for i, n, s in dets],
        investigations=[{"id": i, "title": t, "role": r} for i, t, r in invs],
    )  # fmt: skip


@router.get("/{event_id}/verify")
def verify(event_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(404, "event not found")
    check = verify_event(ev)
    return {"event_id": ev.id, "ok": check.ok, "issues": check.issues, "content_hash": ev.content_hash}
