"""
API request/response models.

Responses are explicit Pydantic models (not raw ORM objects) so the API
contract is typed, documented in OpenAPI at /docs, and cannot accidentally
leak columns that were added to the database later.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- ingestion


class IngestRequest(BaseModel):
    source: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:\-]+$")
    parser: Literal["native", "sshd", "winsec"] = "native"
    records: list[Any] = Field(min_length=1)
    options: dict[str, Any] = Field(default_factory=dict)


class IngestResponse(BaseModel):
    batch_id: str
    seq: int
    accepted: int
    duplicates: int
    rejected: int
    merkle_root: str
    chain_hash: str
    duration_ms: float
    errors: list[dict[str, Any]]


class BatchOut(ORM):
    id: str
    seq: int
    source: str
    parser: str
    received_at: datetime
    accepted_count: int
    duplicate_count: int
    rejected_count: int
    merkle_root: str
    prev_chain_hash: str
    chain_hash: str
    duration_ms: float


class SyntheticRequest(BaseModel):
    seed: int = Field(default=7, ge=0, le=2**31)
    background_events: int = Field(default=3000, ge=0, le=200_000)
    anchor: Literal["fixed", "now"] = "now"
    run_pipeline: bool = True


# --------------------------------------------------------------------------- events


class EventOut(ORM):
    id: str
    timestamp: datetime
    event_type: str
    outcome: str
    host: str | None
    username: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    process: str | None
    command_line: str | None
    bytes_out: int | None
    country: str | None
    message: str | None
    attributes: dict[str, Any]
    tags: list[str]
    source: str
    parser: str
    batch_id: str
    content_hash: str


class EventDetail(EventOut):
    raw: dict[str, Any]
    ingested_at: datetime
    batch: BatchOut
    detections: list[dict[str, Any]]
    investigations: list[dict[str, Any]]


class EventPage(BaseModel):
    items: list[EventOut]
    total: int
    next_cursor: str | None


# --------------------------------------------------------------------------- detections / investigations


class DetectionOut(ORM):
    id: str
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    tactic: str
    technique: str
    first_seen: datetime
    last_seen: datetime
    entities: list[dict[str, Any]]
    summary: str
    evidence_count: int
    investigation_id: str | None
    created_at: datetime


class InvestigationOut(ORM):
    id: str
    title: str
    status: str
    severity: str
    score: float
    score_breakdown: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    entities: list[dict[str, Any]]
    tactics: list[str]
    assignee: str | None
    approved_analysis_id: str | None
    created_at: datetime
    updated_at: datetime


class InvestigationListItem(InvestigationOut):
    detection_count: int
    event_count: int


class InvestigationDetail(InvestigationOut):
    detections: list[DetectionOut]
    event_counts: dict[str, int]
    coverage_gaps: list[dict[str, Any]]
    analyses: list[dict[str, Any]]


class InvestigationPatch(BaseModel):
    status: Literal["open", "in_review", "closed", "false_positive"] | None = None
    assignee: str | None = Field(default=None, max_length=100)
    note: str | None = Field(default=None, max_length=2000)


# --------------------------------------------------------------------------- analyses


class ClaimOutSchema(ORM):
    id: str
    ordinal: int
    text: str
    declared_kind: str
    citations: list[str]
    raw_citations: list[str]
    verdict: str
    reasons: list[str]
    checks: dict[str, Any]
    review_status: str
    review_note: str | None


class AnalysisOut(ORM):
    id: str
    investigation_id: str
    engine: str
    model: str
    status: str
    summary: str
    prompt_sha256: str | None
    evidence_pack_sha256: str
    fallback_reason: str | None
    latency_ms: float
    integrity: dict[str, Any]
    created_at: datetime
    reviewed_by: str | None
    reviewed_at: datetime | None
    review_note: str | None
    claims: list[ClaimOutSchema]


class AnalysisRequest(BaseModel):
    engine: Literal["auto", "ollama", "deterministic"] = "auto"


class ClaimReview(BaseModel):
    decision: Literal["accept", "reject", "pending"]
    note: str | None = Field(default=None, max_length=2000)


class AnalysisReview(BaseModel):
    decision: Literal["approve", "reject"]
    note: str | None = Field(default=None, max_length=2000)


class ValidateRequest(BaseModel):
    investigation_id: str
    output: str = Field(min_length=2, max_length=500_000)


class RunOut(ORM):
    id: str
    kind: str
    status: str
    params: dict[str, Any]
    stats: dict[str, Any]
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ReportOut(ORM):
    id: str
    kind: str
    created_at: datetime
    payload: dict[str, Any]


class BenchmarkRequest(BaseModel):
    events: int = Field(default=20_000, ge=1000, le=200_000)
