"""
Ingestion pipeline: records -> raw + hash -> normalise -> dedup -> ledger batch -> bulk insert.

Deduplication happens at three levels:
  1. inside the batch (same record sent twice in one request),
  2. against the database (hash lookup before insert), and
  3. by the UNIQUE(content_hash) constraint with ON CONFLICT DO NOTHING as the
     final safety net if two writers race.

Ledger appends are serialised: a process-wide lock for SQLite/single worker
and a PostgreSQL transaction-scoped advisory lock for multi-worker setups.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.db_utils import insert_ignore
from app.ids import new_id
from app.ingestion.parsers import ParseError, get_parser
from app.integrity.provenance import GENESIS_HASH, batch_chain_hash, merkle_root, record_hash
from app.models import Event, IngestBatch, utcnow

_LEDGER_LOCK = threading.Lock()
_LEDGER_ADVISORY_KEY = 0x7472_6163  # arbitrary constant: "trac"
_MAX_REPORTED_ERRORS = 50
_ANALYZE_THRESHOLD = 5000


@dataclass
class IngestResult:
    batch_id: str
    seq: int
    accepted: int
    duplicates: int
    rejected: int
    merkle_root: str
    chain_hash: str
    duration_ms: float
    errors: list[dict[str, Any]] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)


def _existing_hashes(db: Session, hashes: list[str]) -> set[str]:
    found: set[str] = set()
    for i in range(0, len(hashes), 500):  # chunked to stay under bind-parameter limits
        chunk = hashes[i : i + 500]
        found.update(db.scalars(select(Event.content_hash).where(Event.content_hash.in_(chunk))))
    return found


def ingest_records(
    db: Session,
    records: list[Any],
    *,
    source: str,
    parser_name: str,
    options: dict[str, Any] | None = None,
) -> IngestResult:
    """Ingest a list of records in a single ledger batch. Commits on success."""
    started = time.perf_counter()
    parser = get_parser(parser_name)
    options = options or {}

    parsed: dict[str, tuple[dict[str, Any], Any]] = {}
    errors: list[dict[str, Any]] = []
    rejected = 0
    in_batch_dups = 0

    for index, record in enumerate(records):
        try:
            raw = parser.to_raw(record, options)
            digest = record_hash(source, raw)
            if digest in parsed:
                in_batch_dups += 1
                continue
            parsed[digest] = (raw, parser.parse(raw))
        except ParseError as exc:
            rejected += 1
            if len(errors) < _MAX_REPORTED_ERRORS:
                errors.append({"index": index, "error": str(exc)[:300]})

    with _LEDGER_LOCK:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LEDGER_ADVISORY_KEY})
        # The dedup lookup must happen *inside* the lock: otherwise two concurrent batches could
        # both claim the same new event in their Merkle roots while only one row is inserted.
        existing = _existing_hashes(db, list(parsed))
        new_hashes = [h for h in parsed if h not in existing]
        duplicates = in_batch_dups + len(existing)

        head = db.execute(
            select(IngestBatch.seq, IngestBatch.chain_hash).order_by(IngestBatch.seq.desc()).limit(1)
        ).first()
        prev_chain, seq = (head.chain_hash, head.seq + 1) if head else (GENESIS_HASH, 1)

        batch_id = new_id("bat")
        received_at = utcnow()
        root = merkle_root(new_hashes)
        chain = batch_chain_hash(
            prev_chain, seq, batch_id, source, parser.name, root, len(new_hashes), received_at.isoformat()
        )
        batch = IngestBatch(
            id=batch_id, seq=seq, source=source, parser=parser.name, received_at=received_at,
            accepted_count=len(new_hashes), duplicate_count=duplicates, rejected_count=rejected,
            merkle_root=root, prev_chain_hash=prev_chain, chain_hash=chain, errors=errors,
        )  # fmt: skip
        db.add(batch)
        db.flush()

        now = utcnow()
        rows = []
        for h in new_hashes:
            raw, ev = parsed[h]
            rows.append({
                "id": f"evt_{h[:20]}", "content_hash": h, "batch_id": batch_id, "source": source,
                "parser": parser.name, "raw": raw, "ingested_at": now, **ev.columns(),
            })  # fmt: skip
        insert_ignore(db, Event, rows, ["content_hash"])
        batch.duration_ms = round((time.perf_counter() - started) * 1000, 2)
        db.commit()

    # After a large bulk load PostgreSQL's planner statistics are stale (it still believes the table is
    # tiny) and dedup lookups degrade to sequential scans: measured 167 records/s on a 100k replay.
    # Refreshing statistics here is cheap relative to the load and fixes that.
    if len(new_hashes) >= _ANALYZE_THRESHOLD and db.get_bind().dialect.name == "postgresql":
        db.execute(text("ANALYZE events"))
        db.commit()

    return IngestResult(
        batch_id=batch_id, seq=seq, accepted=len(new_hashes), duplicates=duplicates, rejected=rejected,
        merkle_root=root, chain_hash=chain, duration_ms=batch.duration_ms, errors=errors,
        event_ids=[r["id"] for r in rows],
    )  # fmt: skip


def event_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(Event)) or 0
