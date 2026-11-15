"""evidence tables immutable for runtime role

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-15 00:32:56.299631
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_IMMUTABLE = ("events", "ingest_batches", "audit_log")


def _app_role_exists() -> bool:
    bind = op.get_bind()
    return bind.dialect.name == "postgresql" and bool(
        bind.execute(sa.text("SELECT 1 FROM pg_roles WHERE rolname = 'tracelayer_app'")).scalar()
    )


def upgrade() -> None:
    """Evidence immutability enforced by PostgreSQL itself, not only by application code.

    The runtime role keeps SELECT/INSERT on evidence tables but loses UPDATE, DELETE and TRUNCATE, so a
    compromised API process cannot rewrite or erase ingested events, ledger batches or the audit log.
    The migration (owner) role is unaffected. No-op on SQLite or when the runtime role does not exist.
    """
    if not _app_role_exists():
        return
    for table in _IMMUTABLE:
        op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM tracelayer_app")
    op.execute("REVOKE ALL ON alembic_version FROM tracelayer_app")
    op.execute("GRANT SELECT ON alembic_version TO tracelayer_app")


def downgrade() -> None:
    if not _app_role_exists():
        return
    for table in _IMMUTABLE:
        op.execute(f"GRANT UPDATE, DELETE ON {table} TO tracelayer_app")
