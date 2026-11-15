"""
FastAPI application factory.

Cross-cutting concerns handled here:
  * migrations on startup (opt-out via TRACELAYER_AUTO_MIGRATE=false)
  * CORS restricted to configured origins
  * security headers on every response
  * per-route latency telemetry for the performance dashboard
  * uniform JSON error for unexpected exceptions (no stack traces to clients)
"""

import logging
import os
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__, jobs, telemetry
from app.api import events, ingest, investigations, system
from app.config import get_settings
from app.db import init_engine
from app.migrate import upgrade

log = logging.getLogger("tracelayer")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if os.environ.get("TRACELAYER_AUTO_MIGRATE", "true").lower() != "false":
        upgrade(settings.database_url)
    init_engine(settings.database_url)
    jobs.mark_interrupted_runs()
    if not settings.api_token:
        log.warning("TRACELAYER_API_TOKEN is not set: write endpoints are unauthenticated (local dev only)")
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="TraceLayer", version=__version__, lifespan=lifespan,
                  description="Evidence-driven security investigation platform")  # fmt: skip
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"], allow_headers=["Authorization", "Content-Type", "X-Analyst"],
    )  # fmt: skip

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
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = response.headers.get("Cache-Control", "no-store")
        return response

    for r in (system.router, ingest.router, events.router, investigations.router):
        app.include_router(r)
    return app


app = create_app()
