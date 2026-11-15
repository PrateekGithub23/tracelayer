"""
Re-derive normalised fields for existing events with a newer parser version (e.g. otrf_windows -> .v3).

What changes: the parser name and the derived columns (event_type, host, username, ..., attributes, tags).
What never changes: the raw record, its content hash, the event id, the batch and the ledger chain.
Integrity verification re-runs the parser recorded on each event, so after this the event verifies
against the new version, and an audit entry records exactly what was re-normalised.

On PostgreSQL this must run with the owner role: the runtime role cannot UPDATE events, by design.
"""

from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.ingestion.parsers import get_parser
from app.integrity.ledger import DERIVED_COLUMNS
from app.models import Event

UPGRADES = {"otrf_windows": "otrf_windows.v3"}


def renormalize(db: Session, source: str, *, actor: str = "cli", dry_run: bool = False) -> dict[str, Any]:
    events = list(db.scalars(select(Event).where(Event.source == source, Event.parser.in_(list(UPGRADES)))))
    if not events:
        return {"source": source, "events": 0, "changed": 0}
    before: Counter[str] = Counter(e.event_type for e in events)
    after: Counter[str] = Counter()
    changed = 0
    for ev in events:
        target = UPGRADES[ev.parser]
        cols = get_parser(target).parse(ev.raw).columns()
        after[cols["event_type"]] += 1
        if not dry_run:
            for c in DERIVED_COLUMNS:
                setattr(ev, c, cols[c])
            ev.parser = target
        changed += 1
    result = {"source": source, "events": len(events), "changed": changed, "to": sorted(set(UPGRADES.values())),
              "event_types_before": dict(before), "event_types_after": dict(after), "dry_run": dry_run}  # fmt: skip
    if not dry_run:
        audit.record(db, actor=actor, action="dataset.renormalized", target_type="dataset", target_id=source[:40],
                     details={k: v for k, v in result.items() if k != "event_types_before"})  # fmt: skip
        db.commit()
    return result
