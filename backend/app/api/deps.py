"""
Shared API dependencies: authentication, CSRF, and permission checks.

Every router declares its permission with `Depends(require("perm"))`. There is no other way to reach a
handler: tests/test_rbac_matrix.py walks all registered routes and fails if one is reachable without a
session (apart from the explicit PUBLIC_ROUTES allow-list below).

Auth model (v2):
  * Identity comes from a server-side session referenced by an HttpOnly cookie. Nothing secret is
    readable from JavaScript, and the v1 `X-Analyst` header and shared API token are gone.
  * State-changing requests (POST/PUT/PATCH/DELETE) must also send `X-CSRF-Token`, which must equal the
    session's own CSRF token. A cross-site page can make the browser send the cookie, but it cannot read
    the token, so it cannot forge the header.
  * If an `Origin` header is present on a state-changing request, it must be one of `cors_origins` or
    the API's own origin (defence in depth for browsers that send it).
"""

import hmac
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.rbac import has_permission
from app.auth.sessions import Principal, cookie_name, resolve
from app.config import get_settings
from app.db import get_db

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Reachable without a session. Everything else requires one (enforced by the matrix test).
PUBLIC_ROUTES = frozenset({
    "GET /api/health",
    "GET /api/auth/config",
    "POST /api/auth/login",
    "POST /api/auth/register",
    "POST /api/auth/recover",
})  # fmt: skip


def client_ip(request: Request) -> str | None:
    """Socket peer, or the Nth-from-right X-Forwarded-For entry when N trusted proxies are configured."""
    hops = get_settings().trusted_proxies
    if hops > 0:
        chain = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if len(chain) >= hops:
            return chain[-hops][:45]
    return request.client.host[:45] if request.client else None


def check_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin or request.method not in UNSAFE_METHODS:
        return
    own = f"{request.url.scheme}://{request.url.netloc}"
    if origin != own and origin not in get_settings().cors_origins:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cross-origin request rejected")


def _unauthorized(reason: str) -> HTTPException:
    # `reason` is one of missing | invalid | expired | revoked: safe to expose, and lets the UI show
    # "your session expired" instead of a generic error.
    return HTTPException(status.HTTP_401_UNAUTHORIZED, {"message": "authentication required", "reason": reason})


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    check_origin(request)
    principal, reason = resolve(db, request.cookies.get(cookie_name()))
    if principal is None:
        raise _unauthorized(reason or "missing")
    if request.method in UNSAFE_METHODS:
        supplied = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(supplied.encode(), principal.session.csrf_token.encode()):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "missing or invalid CSRF token")
    if principal.user.must_change_password and request.url.path not in (
        "/api/auth/me", "/api/auth/password", "/api/auth/logout",
    ):  # fmt: skip
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"message": "password change required",
                                                        "reason": "must_change_password"})  # fmt: skip
    request.state.principal = principal
    return principal


def require(permission: str) -> Callable[..., Principal]:
    """Dependency factory: authenticated *and* holding `permission`."""

    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not has_permission(principal.user.role, permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"your role ({principal.user.role}) cannot do this")
        return principal

    dependency.__name__ = f"require_{permission.replace(':', '_')}"
    dependency.permission = permission  # type: ignore[attr-defined]  # read by the RBAC matrix test
    return dependency
