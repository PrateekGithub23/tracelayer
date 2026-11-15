"""
SQLAlchemy ORM models.

Design notes
------------
* Types are kept portable (String ids, JSON, a UTC datetime decorator) so the
  identical schema runs on PostgreSQL in Docker and SQLite in tests.
* Events are immutable evidence. Their id is derived from a SHA-256 of the raw
  record, which gives deduplication and tamper detection from one mechanism.
* Ingest batches form a hash chain (a lightweight append-only ledger) so the
  history of what was ingested, and in what order, can be verified later.
* Analyst actions go to a separate hash-chained audit log.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Always store UTC and always return timezone-aware UTC datetimes.

    SQLite has no timezone support, so we store naive UTC there and re-attach
    the tzinfo on load. Naive inputs are rejected to avoid silent local-time bugs.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not allowed; use timezone-aware UTC")
        value = value.astimezone(UTC)
        return value if dialect.name == "postgresql" else value.replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


# --------------------------------------------------------------------------- ingestion


class IngestBatch(Base):
    """One ingestion request. Batches are chained: chain_hash = H(prev_chain_hash | batch facts)."""

    __tablename__ = "ingest_batches"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, unique=True, index=True)  # position in the ledger
    source: Mapped[str] = mapped_column(String(100))
    parser: Mapped[str] = mapped_column(String(50))
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    accepted_count: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0)
    merkle_root: Mapped[str] = mapped_column(String(64))
    prev_chain_hash: Mapped[str] = mapped_column(String(64))
    chain_hash: Mapped[str] = mapped_column(String(64))
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    errors: Mapped[list[Any]] = mapped_column(JSON, default=list)


class Event(Base):
    """A normalised security event plus the raw record it was derived from."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)  # "evt_" + 20 hex of content_hash
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("ingest_batches.id"), index=True)
    source: Mapped[str] = mapped_column(String(100))
    parser: Mapped[str] = mapped_column(String(50))
    event_type: Mapped[str] = mapped_column(String(50))
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime())
    host: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    process: Mapped[str | None] = mapped_column(String(255))
    command_line: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(String(20), default="unknown")
    bytes_out: Mapped[int | None] = mapped_column(BigInteger)
    country: Mapped[str | None] = mapped_column(String(2))
    message: Mapped[str | None] = mapped_column(Text)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON)
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    __table_args__ = (
        # Composite indexes match the access patterns of the detection rules and the event explorer.
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_type_ts", "event_type", "timestamp"),
        Index("ix_events_user_ts", "username", "timestamp"),
        Index("ix_events_host_ts", "host", "timestamp"),
        Index("ix_events_src_ts", "src_ip", "timestamp"),
        Index("ix_events_dst_ts", "dst_ip", "timestamp"),
    )


# --------------------------------------------------------------------------- detection


class DetectionEvent(Base):
    """Association: which events are evidence for which detection."""

    __tablename__ = "detection_events"

    detection_id: Mapped[str] = mapped_column(ForeignKey("detections.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), primary_key=True, index=True)


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    dedup_key: Mapped[str] = mapped_column(String(255), unique=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_name: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    tactic: Mapped[str] = mapped_column(String(40))
    technique: Mapped[str] = mapped_column(String(20))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    entities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(Text)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    run_id: Mapped[str | None] = mapped_column(String(40))
    investigation_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="SET NULL"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    investigation: Mapped["Investigation | None"] = relationship(back_populates="detections")


# --------------------------------------------------------------------------- investigations


class InvestigationEvent(Base):
    """Events in an investigation's scope. role = 'evidence' (from detections) or 'context'."""

    __tablename__ = "investigation_events"

    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), primary_key=True, index=True)
    role: Mapped[str] = mapped_column(String(10))


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    # new | triaged | investigating | awaiting_review | resolved | closed  (see app/cases.py)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    priority: Mapped[str] = mapped_column(String(2), default="P3", index=True)  # P1 (urgent) .. P4
    score: Mapped[float] = mapped_column(Float)
    score_breakdown: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    entities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    tactics: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # v1 stored a free-text assignee name; kept (read-only) so the migration never discards data.
    legacy_assignee: Mapped[str | None] = mapped_column(String(100))
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    reviewer_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    resolution: Mapped[str | None] = mapped_column(String(30))
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    reopen_count: Mapped[int] = mapped_column(Integer, default=0)
    approved_analysis_id: Mapped[str | None] = mapped_column(String(24))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow, index=True)
    # Optimistic locking: every UPDATE is "... WHERE id = :id AND version = :seen", so concurrent writers
    # cannot silently overwrite each other (SQLAlchemy raises StaleDataError; the API returns 409).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")

    detections: Mapped[list[Detection]] = relationship(back_populates="investigation")

    __mapper_args__ = {"version_id_col": version}


# --------------------------------------------------------------------------- AI + integrity


class AIAnalysis(Base):
    """One AI (or deterministic) analysis of an investigation, with its integrity verdicts."""

    __tablename__ = "ai_analyses"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    engine: Mapped[str] = mapped_column(String(20))  # "ollama" | "deterministic" | "external"
    model: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="pending_review")
    summary: Mapped[str] = mapped_column(Text)
    raw_output: Mapped[str] = mapped_column(Text)
    prompt_sha256: Mapped[str | None] = mapped_column(String(64))
    evidence_pack_sha256: Mapped[str] = mapped_column(String(64))
    fallback_reason: Mapped[str | None] = mapped_column(Text)
    latency_ms: Mapped[float] = mapped_column(Float)
    integrity: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    reviewed_by: Mapped[str | None] = mapped_column(String(100))
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    review_note: Mapped[str | None] = mapped_column(Text)

    claims: Mapped[list["Claim"]] = relationship(
        back_populates="analysis", order_by="Claim.ordinal", cascade="all, delete-orphan"
    )


class Claim(Base):
    """A single statement made by an analysis, with the integrity engine's verdict."""

    __tablename__ = "claims"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("ai_analyses.id", ondelete="CASCADE"), index=True)
    ordinal: Mapped[int] = mapped_column(Integer)
    text: Mapped[str] = mapped_column(Text)
    declared_kind: Mapped[str] = mapped_column(String(20))
    citations: Mapped[list[Any]] = mapped_column(JSON, default=list)  # resolved event ids
    raw_citations: Mapped[list[Any]] = mapped_column(JSON, default=list)  # as emitted by the model
    verdict: Mapped[str] = mapped_column(String(30), index=True)
    reasons: Mapped[list[Any]] = mapped_column(JSON, default=list)
    checks: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    review_status: Mapped[str] = mapped_column(String(20), default="pending")
    review_note: Mapped[str | None] = mapped_column(Text)

    analysis: Mapped[AIAnalysis] = relationship(back_populates="claims")


# --------------------------------------------------------------------------- operations


class AuditEntry(Base):
    """Append-only, hash-chained record of every analyst/system decision."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(60))
    target_type: Mapped[str] = mapped_column(String(30))
    target_id: Mapped[str] = mapped_column(String(40), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


class PipelineRun(Base):
    """Background job record (detection + correlation, evaluation, benchmark)."""

    __tablename__ = "pipeline_runs"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    kind: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(15), index=True)  # queued|running|succeeded|failed
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class Report(Base):
    """Measured results from the evaluation suite and benchmarks (never hand-written)."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    kind: Mapped[str] = mapped_column(String(20), index=True)  # "evaluation" | "benchmark"
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


# --------------------------------------------------------------------------- identity and access (v2)


class User(Base):
    """A human account. Passwords are Argon2id hashes; the plaintext never touches the database or logs."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)  # stored lower-cased
    display_name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20))  # admin | analyst | viewer
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)  # active | disabled
    must_change_password: Mapped[bool] = mapped_column(default=False)
    is_demo: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    password_changed_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(24))


class UserSession(Base):
    """Server-side session. Only the SHA-256 of the bearer secret is stored, so a DB read cannot hijack sessions."""

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)  # public handle shown on the sessions page
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())  # absolute lifetime
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    revoked_reason: Mapped[str | None] = mapped_column(String(60))
    ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))


class LoginEvent(Base):
    """Every sign-in attempt (success or failure) for login history and abuse investigation."""

    __tablename__ = "login_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    email_attempted: Mapped[str] = mapped_column(String(254))
    success: Mapped[bool] = mapped_column()
    reason: Mapped[str] = mapped_column(String(40))
    ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)


class Invitation(Base):
    """Admin-issued, single-use, expiring registration token (only its hash is stored)."""

    __tablename__ = "invitations"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str | None] = mapped_column(String(254))
    role: Mapped[str] = mapped_column(String(20))
    created_by: Mapped[str] = mapped_column(String(24))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    used_by: Mapped[str | None] = mapped_column(String(24))
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class PasswordResetCode(Base):
    """Admin-issued one-time recovery code (no email infrastructure needed). Hash only; 60-minute lifetime."""

    __tablename__ = "password_reset_codes"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[str] = mapped_column(String(24))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class AppSetting(Base):
    """Admin-editable runtime settings (registration mode, LLM selection). Env vars provide defaults."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(60), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(24))


# --------------------------------------------------------------------------- case collaboration (v2)


class CaseComment(Base):
    """Analyst discussion (kind=comment) and longer-lived investigation notes (kind=note)."""

    __tablename__ = "case_comments"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(10))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    edited_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime())  # soft delete; the audit log keeps a hash


class CaseEvidence(Base):
    """An analyst-pinned reference from a case to an event (does not alter the event or the case scope)."""

    __tablename__ = "case_evidence"

    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), primary_key=True)
    added_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class SavedFilter(Base):
    """A user's private saved search over investigations or events."""

    __tablename__ = "saved_filters"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    scope: Mapped[str] = mapped_column(String(20))  # investigations | events
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class DatasetImport(Base):
    """One import of a catalogued public dataset, with its measured processing and evaluation results."""

    __tablename__ = "dataset_imports"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    dataset_id: Mapped[str] = mapped_column(String(60), index=True)
    status: Mapped[str] = mapped_column(String(20))  # running | succeeded | failed
    archive_sha256: Mapped[str | None] = mapped_column(String(64))
    imported_by: Mapped[str | None] = mapped_column(String(160))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    records: Mapped[int] = mapped_column(Integer, default=0)
    accepted: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    processing_ms: Mapped[float | None] = mapped_column(Float)
    batch_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    results: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
