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
os.environ.pop("TRACELAYER_API_TOKEN", None)

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
