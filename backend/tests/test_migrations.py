"""The Alembic migrations must produce exactly the schema the ORM models describe."""

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from app.db import get_engine
from app.models import Base


def test_migrations_match_models(db_url: str) -> None:
    with get_engine().connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


def test_case_migration_preserves_v1_data(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """0003 must map v1 statuses forward, keep the free-text assignee, and round-trip on downgrade."""
    from alembic import command
    from sqlalchemy import create_engine, text

    from app.migrate import alembic_config

    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "0002")
    eng = create_engine(url)
    rows = [("inv_a", "open", "critical", "dana"), ("inv_b", "in_review", "high", None),
            ("inv_c", "closed", "medium", "lee"), ("inv_d", "false_positive", "low", None)]  # fmt: skip
    with eng.begin() as c:
        for i, st, sev, who in rows:
            c.execute(text("INSERT INTO investigations (id, title, status, severity, score, score_breakdown, first_seen,"
                           " last_seen, entities, tactics, assignee, created_at, updated_at) VALUES (:i, 't', :st, :sev,"
                           " 1, '{}', '2026-01-01', '2026-01-01', '[]', '[]', :who, '2026-01-01', '2026-01-02')"),
                      {"i": i, "st": st, "sev": sev, "who": who})  # fmt: skip
    command.upgrade(cfg, "head")
    with eng.connect() as c:
        got = {r[0]: r[1:] for r in c.execute(text(
            "SELECT id, status, priority, legacy_assignee, resolution, version FROM investigations"))}  # fmt: skip
    assert got["inv_a"] == ("new", "P1", "dana", None, 1)
    assert got["inv_b"] == ("awaiting_review", "P2", None, None, 1)
    assert got["inv_c"][:4] == ("closed", "P3", "lee", "unspecified")
    assert got["inv_d"][:4] == ("closed", "P4", None, "false_positive")
    command.downgrade(cfg, "0002")
    with eng.connect() as c:
        back = dict(c.execute(text("SELECT id, status FROM investigations")).all())
        who = dict(c.execute(text("SELECT id, assignee FROM investigations")).all())
    assert back == {"inv_a": "open", "inv_b": "in_review", "inv_c": "closed", "inv_d": "false_positive"}
    assert who["inv_a"] == "dana" and who["inv_c"] == "lee"
