"""
Ledger and event verification.

`verify_ledger` re-derives everything that can be re-derived:
  * each event's content hash from its stored source + raw record,
  * each event's normalised columns by re-running the original parser on raw,
  * each batch's Merkle root from the hashes of the events that belong to it,
  * each batch's chain hash from the previous batch's chain hash.

Any mismatch is reported with the specific object and field, which is what an
analyst needs in order to decide whether evidence can still be trusted.
"""

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ingestion.parsers import ParseError, get_parser
from app.integrity.provenance import GENESIS_HASH, batch_chain_hash, merkle_root, record_hash
from app.models import Event, IngestBatch

# Columns that the parser derives from raw and that verification re-checks.
DERIVED_COLUMNS = [
    "event_type", "timestamp", "host", "username", "src_ip", "dst_ip", "dst_port", "process",
    "command_line", "outcome", "bytes_out", "country", "message", "attributes", "tags",
]  # fmt: skip


@dataclass
class EventCheck:
    event_id: str
    ok: bool
    issues: list[str] = field(default_factory=list)


def verify_event(ev: Event) -> EventCheck:
    issues: list[str] = []
    recomputed = record_hash(ev.source, ev.raw)
    if recomputed != ev.content_hash:
        issues.append("raw record does not match its content hash (raw was modified)")
    if ev.id != f"evt_{ev.content_hash[:20]}":
        issues.append("event id does not match its content hash")
    try:
        norm = get_parser(ev.parser).parse(ev.raw).columns()
        for col in DERIVED_COLUMNS:
            if norm[col] != getattr(ev, col):
                issues.append(f"normalised field '{col}' differs from re-parsed raw record")
    except ParseError as exc:
        issues.append(f"raw record no longer parses: {exc}")
    return EventCheck(event_id=ev.id, ok=not issues, issues=issues)


def verify_ledger(db: Session, max_issues: int = 200) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    batches_checked = events_checked = 0
    prev = GENESIS_HASH
    expected_seq = 1

    def report(kind: str, target: str, detail: str) -> None:
        if len(issues) < max_issues:
            issues.append({"kind": kind, "target": target, "detail": detail})

    for batch in db.scalars(select(IngestBatch).order_by(IngestBatch.seq)):
        batches_checked += 1
        if batch.seq != expected_seq:
            report("ledger_gap", batch.id, f"expected seq {expected_seq}, found {batch.seq}")
        expected_seq = batch.seq + 1
        if batch.prev_chain_hash != prev:
            report("chain_break", batch.id, "prev_chain_hash does not match previous batch")

        hashes: list[str] = []
        for ev in db.scalars(select(Event).where(Event.batch_id == batch.id).execution_options(yield_per=1000)):
            events_checked += 1
            hashes.append(ev.content_hash)
            check = verify_event(ev)
            for issue in check.issues:
                report("event_tampered", ev.id, issue)

        root = merkle_root(hashes)
        if root != batch.merkle_root:
            report("merkle_mismatch", batch.id, "batch contents changed (events added or removed)")
        if len(hashes) != batch.accepted_count:
            report("count_mismatch", batch.id, f"ledger says {batch.accepted_count}, found {len(hashes)}")
        chain = batch_chain_hash(
            batch.prev_chain_hash, batch.seq, batch.id, batch.source, batch.parser,
            batch.merkle_root, batch.accepted_count, batch.received_at.isoformat(),
        )  # fmt: skip
        if chain != batch.chain_hash:
            report("chain_hash_mismatch", batch.id, "batch metadata was modified")
        prev = batch.chain_hash

    return {
        "ok": not issues,
        "batches_checked": batches_checked,
        "events_checked": events_checked,
        "chain_head": prev,
        "issues": issues,
    }
