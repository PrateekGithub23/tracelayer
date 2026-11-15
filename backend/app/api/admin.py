"""
Administrator endpoints: users and roles, invitations, recovery codes, application settings, audit log.

Guard rails enforced here (and tested):
  * the last active administrator cannot be demoted or disabled (no accidental lock-out);
  * an administrator cannot disable their own account or remove their own admin role;
  * disabling a user or changing their role revokes all of their sessions immediately, so a role
    downgrade takes effect on the next request rather than at session expiry;
  * invitation tokens and recovery codes are shown exactly once and stored only as SHA-256.
"""

from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.api.auth import INVITE_TTL, RESET_CODE_TTL, user_out
from app.api.deps import require
from app.auth.passwords import digest, new_secret
from app.auth.sessions import Principal, revoke_all
from app.auth.users import AccountError, active_admin_count, create_user, get_setting, normalize_email, set_setting
from app.config import get_settings
from app.db import get_db
from app.ids import new_id
from app.models import AuditEntry, Invitation, LoginEvent, PasswordResetCode, User, UserSession, utcnow

router = APIRouter(prefix="/api/admin", tags=["admin"])
Role = Literal["admin", "analyst", "viewer"]


class CreateUserBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    display_name: str | None = Field(default=None, max_length=100)
    role: Role
    password: str = Field(min_length=1, max_length=256)
    must_change_password: bool = True


class PatchUserBody(BaseModel):
    role: Role | None = None
    status: Literal["active", "disabled"] | None = None
    display_name: str | None = Field(default=None, min_length=1, max_length=100)


class InviteBody(BaseModel):
    email: str | None = Field(default=None, max_length=254)
    role: Role = "viewer"


class SettingsBody(BaseModel):
    registration_mode: Literal["disabled", "invite", "open"] | None = None
    llm_mode: Literal["auto", "ollama", "deterministic"] | None = None
    ollama_model: str | None = Field(default=None, max_length=100, pattern=r"^[A-Za-z0-9_.:\-/]+$")


def _user(db: Session, user_id: str) -> User:
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "user not found")
    return u


@router.get("/users")
def list_users(_: Principal = Depends(require("users:manage")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    users = list(db.scalars(select(User).order_by(User.created_at)))
    active: dict[str, int] = {uid: n for uid, n in db.execute(select(UserSession.user_id, func.count()).where(
        UserSession.revoked_at.is_(None), UserSession.expires_at > utcnow()).group_by(UserSession.user_id))}  # fmt: skip
    since = utcnow() - timedelta(hours=24)
    failed: dict[str, int] = {uid: n for uid, n in db.execute(
        select(LoginEvent.user_id, func.count()).where(LoginEvent.success.is_(False), LoginEvent.created_at >= since)
        .group_by(LoginEvent.user_id)) if uid}  # fmt: skip
    return [
        {**user_out(u), "active_sessions": active.get(u.id, 0), "failed_logins_24h": failed.get(u.id, 0)} for u in users
    ]


@router.post("/users", status_code=201)
def admin_create_user(body: CreateUserBody, p: Principal = Depends(require("users:manage")),
                      db: Session = Depends(get_db)) -> dict[str, Any]:  # fmt: skip
    try:
        u = create_user(db, email=body.email, password=body.password, role=body.role, display_name=body.display_name,
                        created_by=p.user.id, must_change_password=body.must_change_password)  # fmt: skip
    except AccountError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit.record(db, actor=p.actor, action="user.created", target_type="user", target_id=u.id,
                 details={"email": u.email, "role": u.role})  # fmt: skip
    db.commit()
    return user_out(u)


@router.patch("/users/{user_id}")
def patch_user(user_id: str, body: PatchUserBody, p: Principal = Depends(require("users:manage")),
               db: Session = Depends(get_db)) -> dict[str, Any]:  # fmt: skip
    u = _user(db, user_id)
    changes: dict[str, Any] = {}
    removing_admin = u.role == "admin" and u.status == "active" and (
        (body.role and body.role != "admin") or body.status == "disabled")  # fmt: skip
    if removing_admin and u.id == p.user.id:
        raise HTTPException(409, "you cannot remove your own administrator access")
    if removing_admin and active_admin_count(db) <= 1:
        raise HTTPException(409, "cannot demote or disable the last active administrator")
    if u.is_demo and (body.role or body.status):
        raise HTTPException(409, "demo accounts are managed by the demo seeder")
    if body.role and body.role != u.role:
        changes["role"] = [u.role, body.role]
        u.role = body.role
    if body.status and body.status != u.status:
        changes["status"] = [u.status, body.status]
        u.status = body.status
    if body.display_name and body.display_name != u.display_name:
        changes["display_name"] = [u.display_name, body.display_name]
        u.display_name = body.display_name
    revoked = 0
    if "role" in changes or "status" in changes:
        revoked = revoke_all(db, u.id, "role_or_status_changed")
    if changes:
        audit.record(db, actor=p.actor, action="user.updated", target_type="user", target_id=u.id,
                     details={"changes": changes, "sessions_revoked": revoked})  # fmt: skip
        db.commit()
    return user_out(u)


@router.post("/users/{user_id}/revoke-sessions")
def admin_revoke_sessions(user_id: str, p: Principal = Depends(require("users:manage")),
                          db: Session = Depends(get_db)) -> dict[str, int]:  # fmt: skip
    u = _user(db, user_id)
    n = revoke_all(db, u.id, "revoked_by_admin")
    audit.record(db, actor=p.actor, action="user.sessions_revoked", target_type="user", target_id=u.id,
                 details={"count": n})  # fmt: skip
    db.commit()
    return {"revoked": n}


@router.post("/users/{user_id}/recovery-code")
def issue_recovery_code(user_id: str, p: Principal = Depends(require("users:manage")),
                        db: Session = Depends(get_db)) -> dict[str, Any]:  # fmt: skip
    """One-time code the admin passes to the user out of band. Shown once; only its hash is stored."""
    u = _user(db, user_id)
    if u.is_demo:
        raise HTTPException(409, "demo accounts cannot be recovered")
    code = new_secret()
    row = PasswordResetCode(id=new_id("rst"), user_id=u.id, code_hash=digest(code), created_by=p.user.id,
                            expires_at=utcnow() + RESET_CODE_TTL)  # fmt: skip
    db.add(row)
    audit.record(db, actor=p.actor, action="user.recovery_code_issued", target_type="user", target_id=u.id,
                 details={"code_id": row.id, "expires_at": row.expires_at.isoformat()})  # fmt: skip
    db.commit()
    return {"code": code, "expires_at": row.expires_at, "email": u.email}


@router.get("/users/{user_id}/login-history")
def user_login_history(user_id: str, _: Principal = Depends(require("users:manage")),
                       db: Session = Depends(get_db)) -> list[dict[str, Any]]:  # fmt: skip
    _user(db, user_id)
    rows = db.scalars(
        select(LoginEvent).where(LoginEvent.user_id == user_id).order_by(LoginEvent.created_at.desc()).limit(100)
    )
    return [{"id": r.id, "created_at": r.created_at, "success": r.success, "reason": r.reason, "ip": r.ip,
             "user_agent": r.user_agent} for r in rows]  # fmt: skip


@router.get("/users/{user_id}/activity")
def user_activity(user_id: str, _: Principal = Depends(require("users:manage")),
                  db: Session = Depends(get_db)) -> list[dict[str, Any]]:  # fmt: skip
    from app.api.auth import activity_for

    _user(db, user_id)
    return activity_for(db, user_id)


# --------------------------------------------------------------------------- invitations


@router.get("/invitations")
def list_invitations(
    _: Principal = Depends(require("users:manage")), db: Session = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.scalars(select(Invitation).order_by(Invitation.created_at.desc()).limit(100))
    now = utcnow()
    return [{"id": i.id, "email": i.email, "role": i.role, "created_at": i.created_at, "expires_at": i.expires_at,
             "used_at": i.used_at, "revoked_at": i.revoked_at,
             "state": "used" if i.used_at else "revoked" if i.revoked_at else "expired" if i.expires_at <= now else "pending"}
            for i in rows]  # fmt: skip


@router.post("/invitations", status_code=201)
def create_invitation(body: InviteBody, p: Principal = Depends(require("users:manage")),
                      db: Session = Depends(get_db)) -> dict[str, Any]:  # fmt: skip
    try:
        email = normalize_email(body.email) if body.email else None
    except AccountError as exc:
        raise HTTPException(422, str(exc)) from exc
    token = new_secret()
    inv = Invitation(id=new_id("inv"), token_hash=digest(token), email=email, role=body.role, created_by=p.user.id,
                     expires_at=utcnow() + INVITE_TTL)  # fmt: skip
    db.add(inv)
    audit.record(db, actor=p.actor, action="invitation.created", target_type="invitation", target_id=inv.id,
                 details={"email": email, "role": body.role})  # fmt: skip
    db.commit()
    return {"id": inv.id, "token": token, "email": email, "role": inv.role, "expires_at": inv.expires_at}


@router.delete("/invitations/{invitation_id}")
def revoke_invitation(invitation_id: str, p: Principal = Depends(require("users:manage")),
                      db: Session = Depends(get_db)) -> dict[str, bool]:  # fmt: skip
    inv = db.get(Invitation, invitation_id)
    if not inv:
        raise HTTPException(404, "invitation not found")
    if not inv.used_at and not inv.revoked_at:
        inv.revoked_at = utcnow()
        audit.record(db, actor=p.actor, action="invitation.revoked", target_type="invitation", target_id=inv.id)
        db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- settings + audit


def effective_settings(db: Session) -> dict[str, Any]:
    s = get_settings()
    return {"registration_mode": get_setting(db, "registration_mode", s.registration_mode),
            "llm_mode": get_setting(db, "llm_mode", s.llm_mode),
            "ollama_model": get_setting(db, "ollama_model", s.ollama_model),
            "ollama_url": s.ollama_url, "ollama_timeout_s": s.ollama_timeout_s,
            "session_idle_minutes": s.session_idle_minutes, "session_absolute_hours": s.session_absolute_hours,
            "cookie_secure": s.cookie_secure, "allow_synthetic": s.allow_synthetic, "env": s.env}  # fmt: skip


@router.get("/settings")
def get_app_settings(
    _: Principal = Depends(require("settings:manage")), db: Session = Depends(get_db)
) -> dict[str, Any]:
    return effective_settings(db)


@router.patch("/settings")
def patch_app_settings(body: SettingsBody, p: Principal = Depends(require("settings:manage")),
                       db: Session = Depends(get_db)) -> dict[str, Any]:  # fmt: skip
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        set_setting(db, k, v, p.user.id)
    if changes:
        audit.record(db, actor=p.actor, action="settings.updated", target_type="system", target_id="settings",
                     details={"changes": changes})  # fmt: skip
        db.commit()
    return effective_settings(db)


@router.get("/audit")
def audit_log(before_id: int | None = None, action: str | None = Query(default=None, max_length=60),
              limit: int = Query(default=100, ge=1, le=500), _: Principal = Depends(require("audit:read")),
              db: Session = Depends(get_db)) -> dict[str, Any]:  # fmt: skip
    stmt = select(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit)
    if before_id:
        stmt = stmt.where(AuditEntry.id < before_id)
    if action:
        stmt = stmt.where(AuditEntry.action.startswith(action))
    rows = list(db.scalars(stmt))
    return {"items": [{"id": e.id, "timestamp": e.timestamp, "actor": e.actor, "action": e.action,
                       "target_type": e.target_type, "target_id": e.target_id, "details": e.details,
                       "prev_hash": e.prev_hash, "entry_hash": e.entry_hash} for e in rows],
            "next_before_id": rows[-1].id if len(rows) == limit else None}  # fmt: skip
