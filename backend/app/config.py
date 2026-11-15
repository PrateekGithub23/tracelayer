"""
Runtime configuration.

All settings are read from environment variables prefixed with TRACELAYER_
(or a local .env file). The same code therefore runs unchanged on a laptop
with SQLite, under Docker Compose with PostgreSQL, and in CI.
"""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRACELAYER_", env_file=".env", extra="ignore")

    # SQLite is the zero-setup default; Docker Compose overrides this with PostgreSQL.
    database_url: str = "sqlite:///./tracelayer.db"

    # When set, every state-changing request must send `Authorization: Bearer <token>`.
    # Left unset for local single-user development (a warning is logged at startup).
    api_token: str | None = None

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]

    # Local LLM (Ollama). "auto" tries Ollama and silently falls back to the
    # deterministic analyst; "deterministic" never touches the network.
    llm_mode: Literal["auto", "ollama", "deterministic"] = "auto"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    ollama_timeout_s: float = 180.0
    # Caps the evidence handed to a small model so prompts fit an 8k context window.
    llm_max_events: int = 60

    # Input limits: protect the API from oversized payloads.
    max_ingest_records: int = 50_000
    max_upload_bytes: int = 25 * 1024 * 1024

    # False in tests so background jobs run inline and deterministically.
    background_jobs: bool = True

    # Correlation tuning.
    correlation_window_minutes: int = 120
    context_padding_minutes: int = 30
    max_context_events: int = 1500


@lru_cache
def get_settings() -> Settings:
    return Settings()
