"""The Alembic migrations must produce exactly the schema the ORM models describe."""

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from app.db import get_engine
from app.models import Base


def test_migrations_match_models(db_url: str) -> None:
    with get_engine().connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []
