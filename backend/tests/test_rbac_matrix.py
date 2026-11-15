"""
Authorization matrix: every API route x {anonymous, viewer, analyst, admin}.

The route list is discovered from the application itself, so a newly added endpoint is covered
automatically. A route that is neither in PUBLIC_ROUTES nor guarded by `require(...)` /
`current_principal` fails `test_every_route_is_guarded`.

For roles *without* the permission we assert 403. For roles *with* it we only assert "not 401/403":
the request uses placeholder ids and deliberately invalid bodies, so allowed calls typically end in
404/422 without side effects. That is exactly the point: authorization is decided before any handler
logic or body validation can run, so a crafted frontend request cannot get past it.
"""

from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.deps import PUBLIC_ROUTES, current_principal
from app.auth.rbac import PERMISSIONS
from app.main import create_app
from tests.conftest import PASSWORDS, login, make_user


def _permission(route: APIRoute) -> str | None:
    """'' = authenticated (any role), a string = permission required, None = no auth dependency found."""
    stack: list[Any] = [route.dependant]
    found: str | None = None
    while stack:
        dep = stack.pop()
        call = getattr(dep, "call", None)
        if call is not None and hasattr(call, "permission"):
            return str(call.permission)
        if call is current_principal:
            found = ""
        stack.extend(dep.dependencies)
    return found


def _routes() -> list[tuple[str, str, str | None]]:
    from fastapi.routing import iter_route_contexts

    out = []
    for ctx in iter_route_contexts(create_app().routes):  # flattens included routers (FastAPI >= 0.16x)
        r = ctx.route
        if isinstance(r, APIRoute) and ctx.path.startswith("/api"):
            for m in sorted(set(ctx.methods or ()) - {"HEAD", "OPTIONS"}):
                out.append((m, ctx.path, _permission(r)))
    return out


ROUTES = _routes()


def _url(path: str) -> str:
    # Placeholder ids: handlers that are reached return 404 rather than touching real objects.
    import re

    return re.sub(r"\{[^}]+\}", "zz_nonexistent", path)


def _call(c: TestClient, method: str, path: str) -> int:
    url = _url(path)
    if method in ("POST", "PATCH", "PUT"):
        # An invalid body: allowed requests stop at validation (422) or not-found (404).
        return c.request(method, url, json={"__invalid__": True}).status_code
    return c.request(method, url).status_code


def test_route_inventory_is_nonempty_and_matches_policy() -> None:
    assert len(ROUTES) >= 55
    perms = {p for _, _, p in ROUTES if p}
    every_known = set().union(*PERMISSIONS.values())
    assert perms <= every_known, f"routes reference unknown permissions: {perms - every_known}"


def test_every_route_is_guarded() -> None:
    unguarded = [f"{m} {p}" for m, p, perm in ROUTES if perm is None and f"{m} {p}" not in PUBLIC_ROUTES]
    assert unguarded == [], f"routes without an auth dependency: {unguarded}"


def test_anonymous_gets_401_everywhere_except_public(anon_client: TestClient) -> None:
    failures = []
    for m, p, _perm in ROUTES:
        key = f"{m} {p}"
        code = _call(anon_client, m, p)
        if key in PUBLIC_ROUTES:
            if code in (401, 403):
                failures.append(f"{key} public but returned {code}")
        elif code != 401:
            failures.append(f"{key} returned {code} without a session")
    assert failures == []


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_role_matrix(role: str, db_url: str) -> None:
    with TestClient(create_app()) as c:
        make_user(role)
        login(c, f"{role}@example.test", PASSWORDS[role])
        failures = []
        for m, p, perm in ROUTES:
            key = f"{m} {p}"
            if key in PUBLIC_ROUTES or key in ("POST /api/auth/logout", "POST /api/auth/password"):
                continue  # logout would end the test session; password change is covered in test_auth
            code = _call(c, m, p)
            allowed = perm == "" or (perm is not None and perm in PERMISSIONS[role])
            if allowed and code in (401, 403):
                failures.append(f"{key} ({perm}) should be allowed for {role}, got {code}")
            if not allowed and code != 403:
                failures.append(f"{key} ({perm}) should be forbidden for {role}, got {code}")
        assert failures == []


def test_viewer_cannot_change_findings_even_with_crafted_requests(db_url: str) -> None:
    """The frontend hides these buttons for viewers; the server must refuse them regardless."""
    with TestClient(create_app()) as c:
        make_user("viewer")
        login(c, "viewer@example.test", PASSWORDS["viewer"])
        attempts = [
            ("PATCH", "/api/investigations/x", {"status": "closed", "expected_version": 1, "reason": "x"}),
            ("POST", "/api/analyses/x/review", {"decision": "approve"}),
            ("POST", "/api/analyses/x/claims/y/review", {"decision": "accept", "note": "ok"}),
            ("POST", "/api/investigations/x/analyses", {"engine": "deterministic"}),
            ("POST", "/api/ingest/events", {"source": "x", "records": []}),
            ("POST", "/api/admin/users", {"email": "e@x.io", "role": "admin", "password": "Aa1-long-enough-pw"}),
            ("PATCH", "/api/admin/settings", {"registration_mode": "open"}),
        ]
        for method, url, body in attempts:
            assert c.request(method, url, json=body).status_code == 403, (method, url)


def test_expensive_jobs_cannot_stack_and_validator_input_is_bounded(admin_client: TestClient) -> None:
    """Audit findings M2 and M8."""
    from app.db import session_scope
    from app.ids import new_id
    from app.models import PipelineRun

    with session_scope() as s:
        s.add(PipelineRun(id=new_id("run"), kind="benchmark", status="running", params={}))
    r = admin_client.post("/api/reports/benchmark", json={"events": 1000})
    assert r.status_code == 409 and "already" in r.json()["detail"]
    big = admin_client.post("/api/integrity/validate", json={"investigation_id": "x", "output": "x" * 70_000})
    assert big.status_code == 422
