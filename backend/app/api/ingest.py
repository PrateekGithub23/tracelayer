"""Ingestion endpoints: JSON batches, file uploads, synthetic scenarios, and the batch ledger."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, jobs
from app.api.deps import analyst_name, require_writer
from app.config import get_settings
from app.db import get_db
from app.ingestion.parsers import ParseError
from app.ingestion.pipeline import IngestResult, ingest_records
from app.models import IngestBatch
from app.schemas import BatchOut, IngestRequest, IngestResponse, SyntheticRequest
from app.synthetic.generator import generate

router = APIRouter(prefix="/api", tags=["ingestion"])


def _response(r: IngestResult) -> IngestResponse:
    return IngestResponse(batch_id=r.batch_id, seq=r.seq, accepted=r.accepted, duplicates=r.duplicates,
                          rejected=r.rejected, merkle_root=r.merkle_root, chain_hash=r.chain_hash,
                          duration_ms=r.duration_ms, errors=r.errors)  # fmt: skip


def _ingest(db: Session, records: list[Any], source: str, parser: str, options: dict[str, Any]) -> IngestResponse:
    limit = get_settings().max_ingest_records
    if len(records) > limit:
        raise HTTPException(413, f"batch has {len(records)} records; the limit is {limit}")
    try:
        return _response(ingest_records(db, records, source=source, parser_name=parser, options=options))
    except ParseError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/ingest/events", response_model=IngestResponse, dependencies=[Depends(require_writer)])
def ingest_events(body: IngestRequest, db: Session = Depends(get_db)) -> IngestResponse:
    return _ingest(db, body.records, body.source, body.parser, body.options)


def parse_upload(content: bytes, parser: str) -> list[Any]:
    """NDJSON or a JSON array for JSON parsers; one record per line for sshd."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "file must be UTF-8 text") from exc
    if parser == "sshd":
        return [line for line in text.splitlines() if line.strip()]
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise HTTPException(400, f"invalid JSON array: {exc.msg} (line {exc.lineno})") from exc
        if not isinstance(data, list):
            raise HTTPException(400, "expected a JSON array of records")
        return data
    records = []
    for n, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise HTTPException(400, f"invalid NDJSON on line {n}: {exc.msg}") from exc
    return records


@router.post("/ingest/file", response_model=IngestResponse, dependencies=[Depends(require_writer)])
async def ingest_file(
    file: UploadFile = File(...),
    source: str = Form(..., min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:\-]+$"),
    parser: str = Form("native", pattern=r"^(native|sshd|winsec)$"),
    year: int | None = Form(None, ge=1990, le=2100),
    db: Session = Depends(get_db),
) -> IngestResponse:
    limit = get_settings().max_upload_bytes
    content = await file.read(limit + 1)  # read one byte past the limit to detect oversize files
    if len(content) > limit:
        raise HTTPException(413, f"file exceeds {limit // (1024 * 1024)} MB")
    records = parse_upload(content, parser)
    if not records:
        raise HTTPException(400, "file contains no records")
    return _ingest(db, records, source, parser, {"year": year} if year else {})


@router.post("/synthetic/generate", dependencies=[Depends(require_writer)])
def synthetic(body: SyntheticRequest, db: Session = Depends(get_db),
              actor: str = Depends(analyst_name)) -> dict[str, Any]:  # fmt: skip
    """Generate the seeded attack scenario and ingest it through the real parsers."""
    start = None
    if body.anchor == "now":
        # Anchor the 10-hour scenario so it ends roughly now; dashboards then look "live".
        start = (datetime.now(UTC) - timedelta(hours=11)).replace(second=0, microsecond=0)
    sc = generate(seed=body.seed, background_events=body.background_events, start=start)
    year = int(sc.truth["start"][:4])
    batches = {}
    for records, parser in ((sc.native, "native"), (sc.sshd, "sshd"), (sc.winsec, "winsec")):
        if records:
            batches[parser] = _ingest(db, records, f"synthetic-{parser}", parser, {"year": year}).model_dump()
    audit.record(db, actor=actor, action="synthetic.generated", target_type="system", target_id="synthetic",
                 details={"seed": body.seed, "records": sc.total_records})  # fmt: skip
    db.commit()
    run_id = jobs.submit("detect_correlate", jobs.detect_and_correlate) if body.run_pipeline else None
    return {"batches": batches, "truth": sc.truth, "pipeline_run_id": run_id}


@router.get("/ingest/batches", response_model=list[BatchOut])
def list_batches(limit: int = 100, db: Session = Depends(get_db)) -> list[IngestBatch]:
    stmt = select(IngestBatch).order_by(IngestBatch.seq.desc()).limit(min(max(limit, 1), 1000))
    return list(db.scalars(stmt))
