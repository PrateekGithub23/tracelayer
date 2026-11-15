"""
Alembic environment.

The URL is taken from (in order) an explicit `sqlalchemy.url` set by the caller
(app.migrate / tests) or TRACELAYER_DATABASE_URL, so migrations always target
the same database as the application.
"""

from alembic import context
from sqlalchemy.engine import Connection

from app.config import get_settings
from app.db import make_engine
from app.models import Base

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    return config.get_main_option("sqlalchemy.url") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = config.attributes.get("connection")
    if connectable is None:
        engine = make_engine(_url())
        with engine.connect() as connection:
            _run(connection)
        engine.dispose()
    else:
        _run(connectable)


def _run(connection: Connection) -> None:
    # render_as_batch lets ALTER TABLE migrations work on SQLite too.
    context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
