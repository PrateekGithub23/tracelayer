"""Run Alembic migrations programmatically (used at startup, by the CLI and by tests)."""

from pathlib import Path

from alembic import command
from alembic.config import Config


def alembic_config(url: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    if url:
        cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def upgrade(url: str | None = None) -> None:
    command.upgrade(alembic_config(url), "head")
