"""Small dialect-portable query helpers."""

from typing import Any

from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

CHUNK = 1000


def count_map(db: Session, stmt: Any) -> dict[Any, int]:
    """Run a `SELECT key, count(*) ... GROUP BY key` query and return {key: count}."""
    return {key: int(n) for key, n in db.execute(stmt)}


def insert_ignore(db: Session, model: Any, rows: list[dict[str, Any]], index_elements: list[str]) -> None:
    """Bulk INSERT ... ON CONFLICT DO NOTHING for PostgreSQL and SQLite."""
    if not rows:
        return
    dialect = db.get_bind().dialect.name
    # Insert against the Core Table, not the ORM entity: the ORM bulk path emitted and compiled one
    # statement per row (~14k for a 20k batch, found by profiling). The Core path is a single
    # executemany / "insertmanyvalues" batch and still applies column types (e.g. UTCDateTime).
    table = model.__table__
    ins = (postgresql.insert if dialect == "postgresql" else sqlite.insert)(table)
    stmt = ins.on_conflict_do_nothing(index_elements=index_elements)
    conn = db.connection()
    for i in range(0, len(rows), CHUNK):
        conn.execute(stmt, rows[i : i + CHUNK])
