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

    # "development" allows plain-HTTP cookies; "production" refuses to start with insecure settings.
    env: Literal["development", "production", "test"] = "development"

    # ---- authentication (v2). The v1 shared API token was removed: see docs/AUTHENTICATION.md.
    # Secure cookies are required over HTTPS. Local HTTP development needs False (the default).
    cookie_secure: bool = False
    session_idle_minutes: int = 8 * 60  # sliding inactivity timeout
    session_absolute_hours: int = 7 * 24  # hard cap, regardless of activity
    # Argon2id parameters (RFC 9106 "second recommended" profile). Tests lower them for speed.
    argon2_time_cost: int = 3
    argon2_memory_kib: int = 64 * 1024
    argon2_parallelism: int = 4
    # Registration: "disabled" (admin creates accounts), "invite" (admin-issued links), "open" (local labs only).
    registration_mode: Literal["disabled", "invite", "open"] = "invite"
    # Optional one-time bootstrap: create this admin on startup if the users table is empty.
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None
    # Number of trusted reverse proxies in front of the API (0 = use the socket peer address).
    trusted_proxies: int = 0
    # Allow the synthetic scenario generator to write into this database (admin only either way).
    allow_synthetic: bool = True
    # Interactive API docs at /docs. Off by default so a public deployment does not advertise its surface.
    expose_docs: bool = False
    # Where downloaded public datasets are cached (gitignored). Downloads happen only on an explicit admin
    # action, only from catalogued URLs, and only if the SHA-256 matches the pinned value.
    data_dir: str = "./data"
    allow_dataset_download: bool = True

    # Hard cap on any request body, enforced in ASGI middleware before parsing.
    max_request_bytes: int = 30 * 1024 * 1024

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]

    # Local LLM (Ollama). "auto" tries Ollama and silently falls back to the
    # deterministic analyst; "deterministic" never touches the network.
    llm_mode: Literal["auto", "grounded", "ollama", "deterministic"] = "grounded"  # v3 benchmark: 96% fewer unsafe claims
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
