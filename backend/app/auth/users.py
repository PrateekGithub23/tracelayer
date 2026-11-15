"""Account operations shared by the API, the CLI and bootstrap."""

import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password, policy_errors
from app.auth.rbac import ROLES
from app.ids import new_id
from app.models import AppSetting, User, utcnow

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,63}$")


class AccountError(ValueError):
    pass


def normalize_email(email: str) -> str:
    e = email.strip().lower()
    if not _EMAIL_RE.match(e):
        raise AccountError("invalid email address")
    return e


def create_user(db: Session, *, email: str, password: str, role: str, display_name: str | None = None,
                created_by: str | None = None, must_change_password: bool = False, is_demo: bool = False) -> User:  # fmt: skip
    email = normalize_email(email)
    if role not in ROLES:
        raise AccountError(f"role must be one of {', '.join(ROLES)}")
    if errs := policy_errors(password, email):
        raise AccountError("password " + "; ".join(errs))
    if db.scalar(select(User.id).where(User.email == email)):
        raise AccountError("an account with this email already exists")
    name = (display_name or email.split("@")[0]).strip()[:100] or email
    user = User(id=new_id("usr"), email=email, display_name=name, password_hash=hash_password(password), role=role,
                status="active", must_change_password=must_change_password, is_demo=is_demo, created_by=created_by,
                password_changed_at=utcnow())  # fmt: skip
    db.add(user)
    db.flush()
    return user


def active_admin_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.status == "active")) or 0


def get_setting(db: Session, key: str, default: Any) -> Any:
    row = db.get(AppSetting, key)
    return row.value.get("v", default) if row else default


def set_setting(db: Session, key: str, value: Any, user_id: str | None) -> None:
    row = db.get(AppSetting, key)
    if row:
        row.value, row.updated_by = {"v": value}, user_id
    else:
        db.add(AppSetting(key=key, value={"v": value}, updated_by=user_id))
