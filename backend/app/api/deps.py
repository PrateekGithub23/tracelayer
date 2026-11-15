"""
Shared API dependencies: authentication and analyst identity.

Auth model (deliberately simple for a self-hosted, single-team tool):
  * If TRACELAYER_API_TOKEN is set, every state-changing request must present
    `Authorization: Bearer <token>`. Comparison is constant-time.
  * Read-only requests are open on the local network; put the stack behind a
    reverse proxy with SSO for anything multi-user (documented in SECURITY.md).
  * The analyst name (X-Analyst header) is recorded in the audit log. It is an
    attribution label, not an authentication factor.
"""

import hmac
import re

from fastapi import Header, HTTPException, status

from app.config import get_settings

_ANALYST_RE = re.compile(r"^[\w .@\-]{1,100}$")


def require_writer(authorization: str | None = Header(default=None)) -> None:
    token = get_settings().api_token
    if not token:
        return
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing or invalid API token",
                            headers={"WWW-Authenticate": "Bearer"})  # fmt: skip


def analyst_name(x_analyst: str | None = Header(default=None)) -> str:
    name = (x_analyst or "analyst").strip()
    if not _ANALYST_RE.match(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid X-Analyst header")
    return name
