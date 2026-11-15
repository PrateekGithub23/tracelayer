"""
Test fixtures.

Each test module gets a fresh SQLite file built by running the real Alembic
migrations, so tests exercise the same schema production uses. Background jobs
run inline (TRACELAYER_BACKGROUND_JOBS=false) for determinism, and the LLM is
disabled unless a test mocks it explicitly.
"""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

os.environ["TRACELAYER_BACKGROUND_JOBS"] = "false"
os.environ["TRACELAYER_LLM_MODE"] = "deterministic"
os.environ["TRACELAYER_ENV"] = "test"
# Real Argon2id, but with cheap parameters so the suite stays fast. Production uses the RFC 9106 profile.
os.environ["TRACELAYER_ARGON2_TIME_COST"] = "1"
os.environ["TRACELAYER_ARGON2_MEMORY_KIB"] = "8192"
os.environ["TRACELAYER_ARGON2_PARALLELISM"] = "1"

from fastapi.testclient import TestClient  # noqa: E402

from app.auth.ratelimit import limiter  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.db import init_engine, session_factory  # noqa: E402
from app.ingestion.pipeline import ingest_records  # noqa: E402
from app.migrate import upgrade  # noqa: E402
from app.synthetic.generator import Scenario, generate  # noqa: E402


@pytest.fixture()
def db_url(tmp_path: Path) -> str:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    os.environ["TRACELAYER_DATABASE_URL"] = url
    get_settings.cache_clear()
    upgrade(url)
    init_engine(url)
    return url


@pytest.fixture()
def db(db_url: str) -> Iterator[Session]:
    s = session_factory()()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture(scope="session")
def scenario() -> Scenario:
    return generate(seed=7, background_events=1500)


def ingest_scenario(db: Session, sc: Scenario) -> None:
    for recs, parser in ((sc.native, "native"), (sc.sshd, "sshd"), (sc.winsec, "winsec")):
        ingest_records(db, recs, source=f"synthetic-{parser}", parser_name=parser, options={"year": 2026})


@pytest.fixture()
def loaded_db(db: Session, scenario: Scenario) -> Session:
    """Database with the scenario ingested, detected and correlated."""
    from app.correlation.engine import run_correlation
    from app.detection.engine import run_detection

    ingest_scenario(db, scenario)
    run_detection(db)
    db.flush()
    run_correlation(db)
    db.commit()
    return db


# --------------------------------------------------------------------------- authenticated clients

PASSWORDS = {"admin": "Kestrel-orbit-4471", "analyst": "Granite-violet-9023", "viewer": "Harbor-lantern-5568"}


@pytest.fixture(autouse=True)
def _reset_rate_limits() -> Iterator[None]:
    limiter.reset()
    yield
    limiter.reset()


def make_user(role: str, email: str | None = None, password: str | None = None, **kw: object) -> str:
    from app.auth.users import create_user
    from app.db import session_scope

    with session_scope() as s:
        u = create_user(s, email=email or f"{role}@example.test", password=password or PASSWORDS[role], role=role, **kw)  # type: ignore[arg-type]
        return u.id


def login(client: TestClient, email: str, password: str) -> dict[str, object]:
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    body = r.json()
    client.headers["X-CSRF-Token"] = body["csrf_token"]
    return body


@pytest.fixture()
def app_factory(db_url: str):  # type: ignore[no-untyped-def]
    from app.main import create_app

    return create_app


def _client_for(role: str, db_url: str) -> Iterator[TestClient]:
    from app.main import create_app

    with TestClient(create_app()) as c:
        make_user(role)
        login(c, f"{role}@example.test", PASSWORDS[role])
        yield c


@pytest.fixture()
def admin_client(db_url: str) -> Iterator[TestClient]:
    yield from _client_for("admin", db_url)


@pytest.fixture()
def anon_client(db_url: str) -> Iterator[TestClient]:
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c
