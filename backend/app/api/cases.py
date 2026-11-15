"""
Case management endpoints: list views, versioned updates, assignment, comments and notes, pinned
evidence, activity timeline, team directory and saved filters.

The activity timeline is assembled from the hash-chained audit log (plus comment bodies), so there is
one source of truth for "who did what, when, and why", and it is covered by integrity verification.
"""

import hashlib
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from app import audit
from app.api.deps import require
from app.auth.rbac import has_permission
from app.auth.sessions import Principal
from app.cases import OPEN_STATUSES, REOPEN_FROM, WorkflowError, check_transition, may_modify
from app.db import get_db
from app.db_utils import count_map
from app.ids import new_id
from app.models import (
    AIAnalysis,
    AuditEntry,
    CaseComment,
    CaseEvidence,
    Detection,
    Event,
    Investigation,
    InvestigationEvent,
    SavedFilter,
    User,
    utcnow,
)  # fmt: skip
from app.schemas import InvestigationListItem, InvestigationOut, InvestigationPatch

router = APIRouter(prefix="/api", tags=["cases"])

View = Literal["all", "open", "mine", "needs_review", "unassigned", "recent"]


class CommentBody(BaseModel):
    kind: Literal["comment", "note"] = "comment"
    body: str = Field(min_length=1, max_length=10_000)


class CommentEdit(BaseModel):
    body: str = Field(min_length=1, max_length=10_000)


class PinBody(BaseModel):
    event_id: str = Field(min_length=4, max_length=24)
    note: str | None = Field(default=None, max_length=2000)


class FilterBody(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    scope: Literal["investigations", "events"]
    params: dict[str, Any]


def _inv(db: Session, inv_id: str) -> Investigation:
    inv = db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "investigation not found")
    return inv


def _names(db: Session, ids: set[str | None]) -> dict[str, str]:
    real = {i for i in ids if i}
    if not real:
        return {}
    return {uid: name for uid, name in db.execute(select(User.id, User.display_name).where(User.id.in_(real)))}


def _out(inv: Investigation, names: dict[str, str]) -> dict[str, Any]:
    d = InvestigationOut.model_validate(inv).model_dump(mode="json")  # JSON-safe: also used inside 409 bodies
    d["assignee_name"] = names.get(inv.assignee_id or "")
    d["reviewer_name"] = names.get(inv.reviewer_id or "")
    return d


# --------------------------------------------------------------------------- list + views


@router.get("/investigations", response_model=list[InvestigationListItem])
def list_investigations(
    view: View = "all", status: str | None = Query(default=None, max_length=20),
    severity: str | None = Query(default=None, max_length=10), priority: str | None = Query(default=None, max_length=2),
    q: str | None = Query(default=None, max_length=100), assignee_id: str | None = Query(default=None, max_length=24),
    sort: Literal["score", "updated", "created", "priority"] = "score",
    db: Session = Depends(get_db), p: Principal = Depends(require("investigations:read")),
) -> list[dict[str, Any]]:  # fmt: skip
    stmt = select(Investigation)
    if view == "open":
        stmt = stmt.where(Investigation.status.in_(OPEN_STATUSES))
    elif view == "mine":
        stmt = stmt.where(Investigation.assignee_id == p.user.id, Investigation.status.in_(OPEN_STATUSES))
    elif view == "needs_review":
        stmt = stmt.where(Investigation.reviewer_id == p.user.id, Investigation.status == "awaiting_review")
    elif view == "unassigned":
        stmt = stmt.where(Investigation.assignee_id.is_(None), Investigation.status.in_(OPEN_STATUSES))
    elif view == "recent":
        sort = "updated"
    if status:
        stmt = stmt.where(Investigation.status == status)
    if severity:
        stmt = stmt.where(Investigation.severity == severity)
    if priority:
        stmt = stmt.where(Investigation.priority == priority)
    if assignee_id:
        stmt = stmt.where(Investigation.assignee_id == assignee_id)
    if q:
        stmt = stmt.where(Investigation.title.ilike("%" + q.replace("%", r"\%").replace("_", r"\_") + "%", escape="\\"))
    order = {"score": (Investigation.score.desc(), Investigation.created_at.desc()),
             "updated": (Investigation.updated_at.desc(),), "created": (Investigation.created_at.desc(),),
             "priority": (Investigation.priority, Investigation.score.desc())}[sort]  # fmt: skip
    invs = list(db.scalars(stmt.order_by(*order).limit(50 if view == "recent" else 500)))
    ids = [i.id for i in invs]
    det_counts = count_map(db, select(Detection.investigation_id, func.count()).where(
        Detection.investigation_id.in_(ids)).group_by(Detection.investigation_id))  # fmt: skip
    ev_counts = count_map(db, select(InvestigationEvent.investigation_id, func.count()).where(
        InvestigationEvent.investigation_id.in_(ids)).group_by(InvestigationEvent.investigation_id))  # fmt: skip
    names = _names(db, {i.assignee_id for i in invs} | {i.reviewer_id for i in invs})
    return [{**_out(i, names), "detection_count": det_counts.get(i.id, 0), "event_count": ev_counts.get(i.id, 0)}
            for i in invs]  # fmt: skip


@router.get("/queues")
def my_queue_counts(
    db: Session = Depends(get_db), p: Principal = Depends(require("investigations:read"))
) -> dict[str, int]:
    """Badge counts for the sidebar and the investigations tabs."""
    open_ = Investigation.status.in_(OPEN_STATUSES)
    c = lambda *w: db.scalar(select(func.count()).select_from(Investigation).where(*w)) or 0  # noqa: E731
    return {"open": c(open_), "mine": c(open_, Investigation.assignee_id == p.user.id),
            "needs_review": c(Investigation.status == "awaiting_review", Investigation.reviewer_id == p.user.id),
            "unassigned": c(open_, Investigation.assignee_id.is_(None))}  # fmt: skip


# --------------------------------------------------------------------------- updates


def _assignable(db: Session, user_id: str, what: str) -> User:
    u = db.get(User, user_id)
    if not u or u.status != "active" or not has_permission(u.role, "investigations:write"):
        raise HTTPException(422, f"{what} must be an active analyst or administrator")
    return u


@router.patch("/investigations/{inv_id}")
def update_case(inv_id: str, body: InvestigationPatch, db: Session = Depends(get_db),
                p: Principal = Depends(require("investigations:write"))) -> dict[str, Any]:  # fmt: skip
    inv = _inv(db, inv_id)
    if body.expected_version != inv.version:
        raise HTTPException(409, {"message": "this case was changed by someone else; reload and try again",
                                  "current_version": inv.version, "current": _out(inv, _names(db, {inv.assignee_id}))})  # fmt: skip
    manage_any = has_permission(p.user.role, "investigations:manage_any")
    if not may_modify(actor_id=p.user.id, can_manage_any=manage_any, assignee_id=inv.assignee_id,
                      reviewer_id=inv.reviewer_id, status=inv.status):  # fmt: skip
        raise HTTPException(403, "this case is assigned to someone else; ask them or an administrator")
    reason = (body.reason or "").strip()
    changes: dict[str, Any] = {}

    # Assignment and reviewer first, so a single request can "assign reviewer + request review".
    if body.assignee_id is not None and (body.assignee_id or None) != inv.assignee_id:
        new = body.assignee_id or None
        if inv.assignee_id and inv.assignee_id != p.user.id and not manage_any:
            raise HTTPException(403, "only an administrator can take a case from another analyst")
        if new:
            _assignable(db, new, "assignee")
        changes["assignee_id"] = [inv.assignee_id, new]
        inv.assignee_id = new
    if body.reviewer_id is not None and (body.reviewer_id or None) != inv.reviewer_id:
        new = body.reviewer_id or None
        if new:
            _assignable(db, new, "reviewer")
        changes["reviewer_id"] = [inv.reviewer_id, new]
        inv.reviewer_id = new
    if body.priority and body.priority != inv.priority:
        changes["priority"] = [inv.priority, body.priority]
        inv.priority = body.priority

    if body.status and body.status != inv.status:
        if len(reason) < 3:
            raise HTTPException(422, "say why the status is changing (reason, at least 3 characters)")
        try:
            check_transition(inv.status, body.status, resolution=body.resolution or inv.resolution,
                             reviewer_id=inv.reviewer_id, assignee_id=inv.assignee_id)  # fmt: skip
        except WorkflowError as exc:
            raise HTTPException(exc.status_code, exc.message) from exc
        # Segregation of duties: leaving review is the reviewer's decision, not the assignee's.
        if inv.status == "awaiting_review" and not manage_any and p.user.id != inv.reviewer_id:
            raise HTTPException(403, "only the assigned reviewer can complete or return a review")
        now = utcnow()
        if body.status == "resolved":
            inv.resolution, inv.resolved_at = body.resolution or inv.resolution, now
        if body.status == "closed":
            inv.closed_at = now
        if body.status == "investigating" and inv.status in REOPEN_FROM:
            inv.reopen_count += 1
            inv.resolved_at = inv.closed_at = None
            changes["reopened"] = True
        changes["status"] = [inv.status, body.status]
        inv.status = body.status
    elif body.resolution and inv.status == "resolved" and body.resolution != inv.resolution:
        changes["resolution"] = [inv.resolution, body.resolution]
        inv.resolution = body.resolution

    if not changes:
        return _out(inv, _names(db, {inv.assignee_id, inv.reviewer_id}))
    inv.updated_at = utcnow()
    try:
        db.flush()  # the versioned UPDATE: fails if anyone committed in between
    except StaleDataError as exc:
        db.rollback()
        raise HTTPException(409, {"message": "this case was changed by someone else; reload and try again"}) from exc
    action = (
        "case.reopened" if changes.get("reopened") else "case.status_changed" if "status" in changes else "case.updated"
    )
    audit.record(db, actor=p.actor, action=action, target_type="investigation", target_id=inv.id,
                 details={"changes": changes, "reason": reason or None, "version": inv.version})  # fmt: skip
    db.commit()
    return _out(inv, _names(db, {inv.assignee_id, inv.reviewer_id}))


@router.post("/investigations/{inv_id}/assign-to-me")
def assign_to_me(inv_id: str, expected_version: int = Query(ge=1), db: Session = Depends(get_db),
                 p: Principal = Depends(require("investigations:write"))) -> dict[str, Any]:  # fmt: skip
    body = InvestigationPatch(expected_version=expected_version, assignee_id=p.user.id)
    return update_case(inv_id, body, db, p)


# --------------------------------------------------------------------------- comments + notes


def _comment_out(c: CaseComment, names: dict[str, str]) -> dict[str, Any]:
    return {"id": c.id, "kind": c.kind, "author_id": c.author_id, "author_name": names.get(c.author_id),
            "body": None if c.deleted_at else c.body, "created_at": c.created_at, "edited_at": c.edited_at,
            "deleted": c.deleted_at is not None}  # fmt: skip


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@router.get("/investigations/{inv_id}/comments")
def list_comments(inv_id: str, db: Session = Depends(get_db),
                  _: Principal = Depends(require("investigations:read"))) -> list[dict[str, Any]]:  # fmt: skip
    _inv(db, inv_id)
    rows = list(
        db.scalars(select(CaseComment).where(CaseComment.investigation_id == inv_id).order_by(CaseComment.created_at))
    )
    names = _names(db, {c.author_id for c in rows})
    return [_comment_out(c, names) for c in rows]


@router.post("/investigations/{inv_id}/comments", status_code=201)
def add_comment(inv_id: str, body: CommentBody, db: Session = Depends(get_db),
                p: Principal = Depends(require("comments:write"))) -> dict[str, Any]:  # fmt: skip
    _inv(db, inv_id)
    c = CaseComment(
        id=new_id("cmt"), investigation_id=inv_id, author_id=p.user.id, kind=body.kind, body=body.body.strip()
    )
    db.add(c)
    # The audit entry stores a hash of the text, so later edits or deletions remain provable.
    audit.record(db, actor=p.actor, action=f"{body.kind}.added", target_type="investigation", target_id=inv_id,
                 details={"comment_id": c.id, "sha256": _digest(c.body)})  # fmt: skip
    db.commit()
    return _comment_out(c, {p.user.id: p.user.display_name})


def _own_comment(db: Session, inv_id: str, comment_id: str, p: Principal) -> CaseComment:
    c = db.get(CaseComment, comment_id)
    if not c or c.investigation_id != inv_id or c.deleted_at:
        raise HTTPException(404, "comment not found")
    if c.author_id != p.user.id:  # horizontal escalation guard: admins included, history is personal
        raise HTTPException(403, "you can only change your own comments")
    return c


@router.patch("/investigations/{inv_id}/comments/{comment_id}")
def edit_comment(inv_id: str, comment_id: str, body: CommentEdit, db: Session = Depends(get_db),
                 p: Principal = Depends(require("comments:write"))) -> dict[str, Any]:  # fmt: skip
    c = _own_comment(db, inv_id, comment_id, p)
    before = _digest(c.body)
    c.body, c.edited_at = body.body.strip(), utcnow()
    audit.record(db, actor=p.actor, action=f"{c.kind}.edited", target_type="investigation", target_id=inv_id,
                 details={"comment_id": c.id, "previous_sha256": before, "sha256": _digest(c.body)})  # fmt: skip
    db.commit()
    return _comment_out(c, {p.user.id: p.user.display_name})


@router.delete("/investigations/{inv_id}/comments/{comment_id}")
def delete_comment(inv_id: str, comment_id: str, db: Session = Depends(get_db),
                   p: Principal = Depends(require("comments:write"))) -> dict[str, bool]:  # fmt: skip
    c = _own_comment(db, inv_id, comment_id, p)
    c.deleted_at = utcnow()
    audit.record(db, actor=p.actor, action=f"{c.kind}.deleted", target_type="investigation", target_id=inv_id,
                 details={"comment_id": c.id, "sha256": _digest(c.body)})  # fmt: skip
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- pinned evidence


@router.get("/investigations/{inv_id}/evidence")
def list_pins(inv_id: str, db: Session = Depends(get_db),
              _: Principal = Depends(require("investigations:read"))) -> list[dict[str, Any]]:  # fmt: skip
    _inv(db, inv_id)
    rows = db.execute(select(CaseEvidence, Event.event_type, Event.timestamp, Event.host, Event.username, Event.content_hash)
                      .join(Event, Event.id == CaseEvidence.event_id).where(CaseEvidence.investigation_id == inv_id)
                      .order_by(Event.timestamp)).all()  # fmt: skip
    names = _names(db, {r[0].added_by for r in rows})
    return [{"event_id": pin.event_id, "note": pin.note, "added_by": names.get(pin.added_by), "created_at": pin.created_at,
             "event_type": et, "timestamp": ts, "host": host, "username": user, "content_hash": h}
            for pin, et, ts, host, user, h in rows]  # fmt: skip


@router.post("/investigations/{inv_id}/evidence", status_code=201)
def pin_evidence(inv_id: str, body: PinBody, db: Session = Depends(get_db),
                 p: Principal = Depends(require("evidence:pin"))) -> dict[str, bool]:  # fmt: skip
    _inv(db, inv_id)
    ev = db.get(Event, body.event_id)
    if not ev:
        raise HTTPException(404, "event not found")
    if db.get(CaseEvidence, (inv_id, ev.id)):
        raise HTTPException(409, "event is already pinned to this case")
    db.add(CaseEvidence(investigation_id=inv_id, event_id=ev.id, added_by=p.user.id, note=body.note))
    audit.record(db, actor=p.actor, action="evidence.pinned", target_type="investigation", target_id=inv_id,
                 details={"event_id": ev.id, "content_hash": ev.content_hash, "note": body.note})  # fmt: skip
    db.commit()
    return {"ok": True}


@router.delete("/investigations/{inv_id}/evidence/{event_id}")
def unpin_evidence(inv_id: str, event_id: str, db: Session = Depends(get_db),
                   p: Principal = Depends(require("evidence:pin"))) -> dict[str, bool]:  # fmt: skip
    pin = db.get(CaseEvidence, (inv_id, event_id))
    if not pin:
        raise HTTPException(404, "pin not found")
    db.delete(pin)  # removes the *reference* only; the event itself is immutable
    audit.record(db, actor=p.actor, action="evidence.unpinned", target_type="investigation", target_id=inv_id,
                 details={"event_id": event_id})  # fmt: skip
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- activity timeline


@router.get("/investigations/{inv_id}/activity")
def activity(inv_id: str, db: Session = Depends(get_db),
             _: Principal = Depends(require("investigations:read"))) -> list[dict[str, Any]]:  # fmt: skip
    """Everything that happened to a case, newest first: workflow, reviews, comments, pins, exports."""
    _inv(db, inv_id)
    ids = [inv_id, *db.scalars(select(AIAnalysis.id).where(AIAnalysis.investigation_id == inv_id))]
    entries = list(
        db.scalars(select(AuditEntry).where(AuditEntry.target_id.in_(ids)).order_by(AuditEntry.id.desc()).limit(500))
    )
    comment_ids = [e.details.get("comment_id") for e in entries if e.details.get("comment_id")]
    live = select(CaseComment.id, CaseComment.body).where(
        CaseComment.id.in_(comment_ids), CaseComment.deleted_at.is_(None)
    )
    bodies: dict[str, str] = {cid: body for cid, body in db.execute(live)}
    return [{"id": e.id, "timestamp": e.timestamp, "actor": e.actor, "action": e.action, "target_id": e.target_id,
             "details": e.details, "comment": bodies.get(e.details.get("comment_id", "")),
             "entry_hash": e.entry_hash} for e in entries]  # fmt: skip


# --------------------------------------------------------------------------- team directory + saved filters


@router.get("/users/directory")
def directory(
    db: Session = Depends(get_db), _: Principal = Depends(require("investigations:read"))
) -> list[dict[str, Any]]:
    """Names for assignment pickers. No emails, no status details beyond 'can be assigned'."""
    rows = db.scalars(select(User).where(User.status == "active").order_by(User.display_name))
    return [{"id": u.id, "display_name": u.display_name, "role": u.role,
             "assignable": has_permission(u.role, "investigations:write")} for u in rows]  # fmt: skip


@router.get("/filters")
def list_filters(scope: str | None = Query(default=None, max_length=20), db: Session = Depends(get_db),
                 p: Principal = Depends(require("filters:own"))) -> list[dict[str, Any]]:  # fmt: skip
    stmt = select(SavedFilter).where(SavedFilter.user_id == p.user.id).order_by(SavedFilter.created_at)
    if scope:
        stmt = stmt.where(SavedFilter.scope == scope)
    return [{"id": f.id, "name": f.name, "scope": f.scope, "params": f.params, "created_at": f.created_at}
            for f in db.scalars(stmt)]  # fmt: skip


@router.post("/filters", status_code=201)
def save_filter(
    body: FilterBody, db: Session = Depends(get_db), p: Principal = Depends(require("filters:own"))
) -> dict[str, Any]:
    if len(str(body.params)) > 4000:
        raise HTTPException(422, "filter is too large")
    if (db.scalar(select(func.count()).select_from(SavedFilter).where(SavedFilter.user_id == p.user.id)) or 0) >= 50:
        raise HTTPException(422, "you can save at most 50 filters")
    params = {str(k)[:40]: v for k, v in body.params.items() if isinstance(v, str | int | float | bool | list | None)}
    f = SavedFilter(id=new_id("flt"), user_id=p.user.id, name=body.name.strip(), scope=body.scope, params=params)
    db.add(f)
    db.commit()
    return {"id": f.id, "name": f.name, "scope": f.scope, "params": f.params, "created_at": f.created_at}


@router.delete("/filters/{filter_id}")
def delete_filter(
    filter_id: str, db: Session = Depends(get_db), p: Principal = Depends(require("filters:own"))
) -> dict[str, bool]:
    f = db.get(SavedFilter, filter_id)
    if not f or f.user_id != p.user.id:  # another user's filter looks exactly like a missing one
        raise HTTPException(404, "filter not found")
    db.delete(f)
    db.commit()
    return {"ok": True}
