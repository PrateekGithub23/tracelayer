"""
Authentication endpoints: login, logout, current user, password change, sessions, login history,
invitation-based registration and admin-issued recovery codes.

Uniform failures: unknown email, wrong password and disabled account all return the same 401 body,
and the unknown-email path still runs an Argon2 verification so timing does not reveal which case
occurred. The reason is recorded server-side in login_events for the account owner and admins.
"""

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import client_ip, current_principal, require
from app.auth import ratelimit
from app.auth.passwords import digest, hash_password, needs_rehash, policy_errors, verify_password
from app.auth.rbac import PERMISSIONS
from app.auth.sessions import (
    Principal,
    cookie_name,
    create_session,
    effective_expiry,
    resolve,
    revoke,
    revoke_all,
)  # fmt: skip
from app.auth.users import AccountError, create_user, get_setting, normalize_email
from app.config import get_settings
from app.db import get_db
from app.models import Invitation, LoginEvent, PasswordResetCode, User, UserSession, utcnow

router = APIRouter(prefix="/api/auth", tags=["auth"])

INVALID_CREDENTIALS = "invalid email or password"


class LoginBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class PasswordBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class ProfileBody(BaseModel):
    display_name: str = Field(min_length=1, max_length=100)


class RegisterBody(BaseModel):
    invite_token: str | None = Field(default=None, max_length=128)
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class RecoverBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    code: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=1, max_length=256)


def _limit(key: str, rule: tuple[int, int]) -> None:
    wait = ratelimit.limiter.check(key, *rule)
    if wait is not None:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts; try again later",
                            headers={"Retry-After": str(int(wait) + 1)})  # fmt: skip


def _set_cookie(response: Response, secret: str) -> None:
    s = get_settings()
    response.set_cookie(cookie_name(), secret, max_age=s.session_absolute_hours * 3600, httponly=True,
                        secure=s.cookie_secure, samesite="lax", path="/")  # fmt: skip


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(cookie_name(), path="/", secure=get_settings().cookie_secure, httponly=True,
                           samesite="lax")  # fmt: skip


def user_out(u: User) -> dict[str, Any]:
    return {"id": u.id, "email": u.email, "display_name": u.display_name, "role": u.role, "status": u.status,
            "must_change_password": u.must_change_password, "is_demo": u.is_demo, "created_at": u.created_at,
            "last_login_at": u.last_login_at, "password_changed_at": u.password_changed_at}  # fmt: skip


def _me(p: Principal) -> dict[str, Any]:
    return {"user": user_out(p.user), "permissions": sorted(PERMISSIONS[p.user.role]),
            "csrf_token": p.session.csrf_token,
            "session": {"id": p.session.id, "created_at": p.session.created_at,
                        "expires_at": effective_expiry(p.session), "absolute_expires_at": p.session.expires_at}}  # fmt: skip


def _record_login(db: Session, request: Request, email: str, user: User | None, ok: bool, reason: str) -> None:
    db.add(LoginEvent(user_id=user.id if user else None, email_attempted=email[:254], success=ok, reason=reason,
                      ip=client_ip(request), user_agent=(request.headers.get("user-agent") or "")[:255] or None))  # fmt: skip


@router.get("/config")
def auth_config(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Public: what the login page needs to render (no secrets, no user data)."""
    s = get_settings()
    return {"registration_mode": get_setting(db, "registration_mode", s.registration_mode),
            "has_users": db.scalar(select(User.id).limit(1)) is not None,
            "cookie_secure": s.cookie_secure}  # fmt: skip


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response, db: Session = Depends(get_db)) -> dict[str, Any]:
    ip = client_ip(request) or "unknown"
    email = body.email.strip().lower()
    _limit(f"login-ip:{ip}", ratelimit.LOGIN_PER_IP)
    _limit(f"login-acct:{email}", ratelimit.LOGIN_PER_ACCOUNT)
    user = db.scalar(select(User).where(User.email == email))
    ok = verify_password(user.password_hash if user else None, body.password)
    if not user or not ok or user.status != "active":
        reason = "unknown_user" if not user else ("bad_password" if not ok else f"account_{user.status}")
        _record_login(db, request, email, user, False, reason)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)

    # Session fixation defence: whatever session the browser presented is revoked; a fresh one is issued.
    old, _ = resolve(db, request.cookies.get(cookie_name()))
    if old:
        revoke(db, old.session, "replaced_by_login")
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    sess, secret = create_session(db, user, ip, request.headers.get("user-agent"))
    user.last_login_at = utcnow()
    _record_login(db, request, email, user, True, "ok")
    audit.record(db, actor=f"{user.email} ({user.id})", action="auth.login", target_type="user", target_id=user.id,
                 details={"session_id": sess.id, "ip": ip})  # fmt: skip
    db.commit()
    _set_cookie(response, secret)
    return _me(Principal(user=user, session=sess))


@router.post("/logout")
def logout(
    response: Response, p: Principal = Depends(current_principal), db: Session = Depends(get_db)
) -> dict[str, bool]:
    sess = db.get(UserSession, p.session.id)
    if sess:
        revoke(db, sess, "logout")
    audit.record(db, actor=p.actor, action="auth.logout", target_type="user", target_id=p.user.id,
                 details={"session_id": p.session.id})  # fmt: skip
    db.commit()
    _clear_cookie(response)
    return {"ok": True}


@router.get("/me")
def me(p: Principal = Depends(current_principal)) -> dict[str, Any]:
    return _me(p)


@router.patch("/me")
def update_profile(body: ProfileBody, p: Principal = Depends(require("account:own")),
                   db: Session = Depends(get_db)) -> dict[str, Any]:  # fmt: skip
    user = db.get(User, p.user.id)
    assert user
    user.display_name = body.display_name.strip()
    db.commit()
    return user_out(user)


@router.post("/password")
def change_password(body: PasswordBody, request: Request, response: Response,
                    p: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> dict[str, Any]:  # fmt: skip
    _limit(f"sensitive-ip:{client_ip(request)}", ratelimit.SENSITIVE_PER_IP)
    user = db.get(User, p.user.id)
    assert user
    if user.is_demo:
        raise HTTPException(403, "demo accounts cannot change their password")
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(400, "current password is incorrect")
    if errs := policy_errors(body.new_password, user.email):
        raise HTTPException(422, "new password " + "; ".join(errs))
    if verify_password(user.password_hash, body.new_password):
        raise HTTPException(422, "new password must differ from the current one")
    user.password_hash, user.password_changed_at, user.must_change_password = (
        hash_password(body.new_password),
        utcnow(),
        False,
    )
    # Every session (including this one) is revoked; the caller gets a fresh session: rotation on privilege change.
    revoked = revoke_all(db, user.id, "password_changed")
    sess, secret = create_session(db, user, client_ip(request), request.headers.get("user-agent"))
    audit.record(db, actor=p.actor, action="auth.password_changed", target_type="user", target_id=user.id,
                 details={"sessions_revoked": revoked})  # fmt: skip
    db.commit()
    _set_cookie(response, secret)
    return _me(Principal(user=user, session=sess))


def _session_out(s: UserSession, current_id: str) -> dict[str, Any]:
    return {"id": s.id, "created_at": s.created_at, "last_seen_at": s.last_seen_at, "expires_at": effective_expiry(s),
            "revoked_at": s.revoked_at, "revoked_reason": s.revoked_reason, "ip": s.ip, "user_agent": s.user_agent,
            "current": s.id == current_id,
            "active": s.revoked_at is None and effective_expiry(s) > utcnow()}  # fmt: skip


@router.get("/sessions")
def my_sessions(p: Principal = Depends(require("account:own")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.scalars(select(UserSession).where(UserSession.user_id == p.user.id)
                      .order_by(UserSession.created_at.desc()).limit(50))  # fmt: skip
    return [_session_out(s, p.session.id) for s in rows]


@router.delete("/sessions/{session_id}")
def revoke_my_session(session_id: str, p: Principal = Depends(require("account:own")),
                      db: Session = Depends(get_db)) -> dict[str, bool]:  # fmt: skip
    sess = db.get(UserSession, session_id)
    # IDOR defence: someone else's session id is indistinguishable from a non-existent one.
    if not sess or sess.user_id != p.user.id:
        raise HTTPException(404, "session not found")
    revoke(db, sess, "revoked_by_user")
    audit.record(db, actor=p.actor, action="auth.session_revoked", target_type="user", target_id=p.user.id,
                 details={"session_id": session_id})  # fmt: skip
    db.commit()
    return {"ok": True}


@router.post("/sessions/revoke-others")
def revoke_other_sessions(
    p: Principal = Depends(require("account:own")), db: Session = Depends(get_db)
) -> dict[str, int]:
    n = revoke_all(db, p.user.id, "revoked_by_user", except_id=p.session.id)
    audit.record(db, actor=p.actor, action="auth.sessions_revoked", target_type="user", target_id=p.user.id,
                 details={"count": n})  # fmt: skip
    db.commit()
    return {"revoked": n}


@router.get("/login-history")
def login_history(
    p: Principal = Depends(require("account:own")), db: Session = Depends(get_db)
) -> list[dict[str, Any]]:
    rows = db.scalars(select(LoginEvent).where(LoginEvent.user_id == p.user.id)
                      .order_by(LoginEvent.created_at.desc()).limit(50))  # fmt: skip
    return [{"id": r.id, "created_at": r.created_at, "success": r.success, "reason": r.reason, "ip": r.ip,
             "user_agent": r.user_agent} for r in rows]  # fmt: skip


@router.post("/register", status_code=201)
def register(body: RegisterBody, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    _limit(f"sensitive-ip:{client_ip(request)}", ratelimit.SENSITIVE_PER_IP)
    mode = get_setting(db, "registration_mode", get_settings().registration_mode)
    if mode == "disabled":
        raise HTTPException(403, "registration is disabled; ask an administrator for an account")
    role, invite = "viewer", None
    if mode == "invite":
        invite = db.scalar(select(Invitation).where(Invitation.token_hash == digest(body.invite_token or "")))
        if (not invite or invite.used_at or invite.revoked_at or invite.expires_at <= utcnow()
                or (invite.email and invite.email != body.email.strip().lower())):  # fmt: skip
            raise HTTPException(400, "invitation is invalid, expired or already used")
        role = invite.role
    try:
        user = create_user(db, email=body.email, password=body.password, role=role, display_name=body.display_name,
                           created_by=invite.created_by if invite else None)  # fmt: skip
    except AccountError as exc:
        # Same message for "exists" as for other failures would hurt usability more than it helps here:
        # registration is invite-only by default, so the invite token already gates enumeration.
        raise HTTPException(422, str(exc)) from exc
    if invite:
        invite.used_at, invite.used_by = utcnow(), user.id
    audit.record(db, actor=f"{user.email} ({user.id})", action="auth.registered", target_type="user",
                 target_id=user.id, details={"role": role, "invitation_id": invite.id if invite else None})  # fmt: skip
    db.commit()
    return {"user": user_out(user)}


@router.post("/recover")
def recover(body: RecoverBody, request: Request, db: Session = Depends(get_db)) -> dict[str, bool]:
    """Redeem an admin-issued one-time recovery code. Uniform failure message for every invalid case."""
    _limit(f"sensitive-ip:{client_ip(request)}", ratelimit.SENSITIVE_PER_IP)
    try:
        email = normalize_email(body.email)
    except AccountError:
        email = ""
    _limit(f"recover-acct:{email}", ratelimit.LOGIN_PER_ACCOUNT)
    user = db.scalar(select(User).where(User.email == email)) if email else None
    code = db.scalar(select(PasswordResetCode).where(PasswordResetCode.code_hash == digest(body.code)))
    if (not user or not code or code.user_id != user.id or code.used_at or code.expires_at <= utcnow()
            or user.status != "active"):  # fmt: skip
        raise HTTPException(400, "recovery code is invalid or expired")
    if errs := policy_errors(body.new_password, user.email):
        raise HTTPException(422, "new password " + "; ".join(errs))
    user.password_hash, user.password_changed_at, user.must_change_password = (
        hash_password(body.new_password),
        utcnow(),
        False,
    )
    code.used_at = utcnow()
    revoked = revoke_all(db, user.id, "password_recovered")
    audit.record(db, actor=f"{user.email} ({user.id})", action="auth.password_recovered", target_type="user",
                 target_id=user.id, details={"code_id": code.id, "sessions_revoked": revoked})  # fmt: skip
    db.commit()
    return {"ok": True}


RESET_CODE_TTL = timedelta(minutes=60)
INVITE_TTL = timedelta(days=7)
