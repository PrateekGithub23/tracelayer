"""
Server-side sessions.

* The cookie carries a 256-bit random secret; the database stores only its SHA-256 (token_hash).
* Every login creates a brand-new session (session-fixation defence); any session cookie presented at
  login is revoked first.
* Sessions expire after `session_idle_minutes` of inactivity or `session_absolute_hours` after creation,
  whichever comes first, and can be revoked individually, per user, or on password change.
* Each session has its own CSRF token (synchronizer-token pattern), returned by /api/auth/me and required
  in the X-CSRF-Token header for every state-changing request.
"""

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.auth.passwords import digest, new_secret
from app.config import get_settings
from app.ids import new_id
from app.models import User, UserSession, utcnow

COOKIE_NAME = "tl_session"
SECURE_COOKIE_NAME = "__Host-tl_session"  # __Host- prefix: Secure, Path=/, no Domain; cannot be set by subdomains
_TOUCH_EVERY = timedelta(seconds=60)


def cookie_name() -> str:
    return SECURE_COOKIE_NAME if get_settings().cookie_secure else COOKIE_NAME


@dataclass
class Principal:
    user: User
    session: UserSession

    @property
    def actor(self) -> str:
        """Audit-log identity: stable id plus a readable label."""
        return f"{self.user.email} ({self.user.id})"


def create_session(db: Session, user: User, ip: str | None, user_agent: str | None) -> tuple[UserSession, str]:
    s = get_settings()
    secret = new_secret()
    now = utcnow()
    sess = UserSession(
        id=new_id("ses"), token_hash=digest(secret), csrf_token=secrets.token_urlsafe(32), user_id=user.id,
        created_at=now, last_seen_at=now, expires_at=now + timedelta(hours=s.session_absolute_hours),
        ip=ip, user_agent=(user_agent or "")[:255] or None,
    )  # fmt: skip
    db.add(sess)
    return sess, secret


def idle_deadline(sess: UserSession) -> datetime:
    return sess.last_seen_at + timedelta(minutes=get_settings().session_idle_minutes)


def effective_expiry(sess: UserSession) -> datetime:
    return min(sess.expires_at, idle_deadline(sess))


def resolve(db: Session, secret: str | None) -> tuple[Principal | None, str | None]:
    """Look up a live session. Returns (principal, None) or (None, reason) where reason is safe to show."""
    if not secret or len(secret) > 128:
        return None, "missing"
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == digest(secret)))
    if sess is None:
        return None, "invalid"
    now = utcnow()
    if sess.revoked_at is not None:
        return None, "revoked"
    if now >= effective_expiry(sess):
        sess.revoked_at, sess.revoked_reason = now, "expired"
        db.commit()
        return None, "expired"
    user = db.get(User, sess.user_id)
    if user is None or user.status != "active":
        return None, "invalid"
    if now - sess.last_seen_at >= _TOUCH_EVERY:  # sliding expiry without a write on every request
        sess.last_seen_at = now
        db.commit()
    return Principal(user=user, session=sess), None


def revoke(db: Session, sess: UserSession, reason: str) -> None:
    if sess.revoked_at is None:
        sess.revoked_at, sess.revoked_reason = utcnow(), reason[:60]


def revoke_all(db: Session, user_id: str, reason: str, except_id: str | None = None) -> int:
    stmt = (update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
            .values(revoked_at=utcnow(), revoked_reason=reason[:60]))  # fmt: skip
    if except_id:
        stmt = stmt.where(UserSession.id != except_id)
    return db.execute(stmt).rowcount or 0  # type: ignore[attr-defined]
