"""
FastAPI application factory.

Cross-cutting concerns handled here:
  * migrations on startup (opt-out via TRACELAYER_AUTO_MIGRATE=false)
  * refuses to start in production with insecure settings
  * optional one-time administrator bootstrap when the users table is empty
  * request-body size cap enforced before any parsing (ASGI level)
  * CORS restricted to configured origins
  * security headers on every response (strict CSP for the JSON API, HSTS when cookies are Secure)
  * per-route latency telemetry for the performance dashboard
  * uniform JSON errors: no stack traces, and validation errors never echo submitted input
"""

import logging
import os
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app import __version__, jobs, telemetry
from app.api import admin, auth, cases, datasets, events, ingest, investigations, llm, system
from app.config import get_settings
from app.db import init_engine, session_scope
from app.migrate import upgrade

log = logging.getLogger("tracelayer")


class InsecureConfiguration(RuntimeError):
    pass


def check_configuration() -> None:
    s = get_settings()
    if s.env != "production":
        return
    problems = []
    if not s.cookie_secure:
        problems.append("TRACELAYER_COOKIE_SECURE must be true (sessions over HTTPS only)")
    if s.registration_mode == "open":
        problems.append("TRACELAYER_REGISTRATION_MODE=open is not allowed in production")
    if s.expose_docs:
        problems.append("TRACELAYER_EXPOSE_DOCS must be false in production")
    if s.bootstrap_admin_password:
        problems.append("unset TRACELAYER_BOOTSTRAP_ADMIN_PASSWORD after the first start")
    if problems:
        raise InsecureConfiguration("; ".join(problems))


def bootstrap_admin() -> None:
    """Create the first administrator from env vars, only if no user exists yet. Logged without the password."""
    from app.auth.users import create_user
    from app.models import User

    s = get_settings()
    if not (s.bootstrap_admin_email and s.bootstrap_admin_password):
        return
    with session_scope() as db:
        if db.scalar(select(User.id).limit(1)):
            return
        user = create_user(db, email=s.bootstrap_admin_email, password=s.bootstrap_admin_password, role="admin",
                           must_change_password=True)  # fmt: skip
        log.warning("bootstrapped administrator %s; the password must be changed at first login", user.email)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    check_configuration()
    if os.environ.get("TRACELAYER_AUTO_MIGRATE", "true").lower() != "false":
        upgrade(os.environ.get("TRACELAYER_MIGRATION_DATABASE_URL") or settings.database_url)
    init_engine(settings.database_url)
    jobs.mark_interrupted_runs()
    bootstrap_admin()
    yield


class BodySizeLimit:
    """Reject bodies over `max_request_bytes` while streaming, so oversized uploads never reach the parser."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = get_settings().max_request_bytes
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            await JSONResponse({"detail": "request body too large"}, status_code=413)(scope, receive, send)
            return
        seen = 0

        async def limited_receive() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise _TooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _TooLarge:
            await JSONResponse({"detail": "request body too large"}, status_code=413)(scope, receive, send)


class _TooLarge(Exception):
    pass


API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"


def create_app() -> FastAPI:
    settings = get_settings()
    docs = settings.expose_docs
    app = FastAPI(title="TraceLayer", version=__version__, lifespan=lifespan,
                  description="Evidence-driven security investigation platform",
                  docs_url="/docs" if docs else None, redoc_url=None,
                  openapi_url="/openapi.json" if docs else None)  # fmt: skip
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token"],
    )  # fmt: skip

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Field locations and messages only: never echo the submitted value back (it may be a password).
        detail = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", "invalid"), "type": e.get("type", "")}
                  for e in exc.errors()][:20]  # fmt: skip
        return JSONResponse({"detail": detail}, status_code=422)

    @app.exception_handler(jobs.JobAlreadyRunning)
    async def job_running(_request: Request, exc: jobs.JobAlreadyRunning) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.middleware("http")
    async def instrument(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        t0 = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001 - last-resort handler; details go to the server log only
            log.exception("unhandled error on %s %s", request.method, request.url.path)
            response = JSONResponse({"detail": "internal server error"}, status_code=500)
        route = request.scope.get("route")
        # Use the route *template* (/api/events/{event_id}) so metrics are not split per id.
        name = f"{request.method} {getattr(route, 'path', request.url.path)}"
        if request.url.path.startswith("/api"):
            telemetry.observe(name, (time.perf_counter() - t0) * 1000, response.status_code)
        h: Any = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        if not (docs and request.url.path.startswith("/docs")):
            h["Content-Security-Policy"] = API_CSP
        if settings.cookie_secure:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        h["Cache-Control"] = h.get("Cache-Control", "no-store")
        return response

    for r in (system.router, auth.router, admin.router, ingest.router, events.router, investigations.router,
              cases.router, datasets.router, llm.router):  # fmt: skip
        app.include_router(r)
    app.add_middleware(BodySizeLimit)
    return app


app = create_app()
