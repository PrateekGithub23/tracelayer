"""
Detection engine: load events once, run every rule, persist idempotently.

Re-running detection over the same data never creates duplicates: a detection's
id is derived from its dedup key (rule + entity + burst start). If a later run
finds more evidence for an existing detection (e.g. a burst that kept going),
the new evidence is attached and `last_seen` is extended.
"""

import time
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db_utils import insert_ignore
from app.detection.base import Candidate, EventView
from app.detection.rules import ALL_RULES, Rule
from app.ids import content_id
from app.models import Detection, DetectionEvent, Event

_VIEW_COLUMNS = (
    Event.id, Event.timestamp, Event.event_type, Event.host, Event.username, Event.src_ip, Event.dst_ip,
    Event.dst_port, Event.process, Event.command_line, Event.outcome, Event.bytes_out, Event.country,
    Event.attributes, Event.tags,
)  # fmt: skip


def load_event_views(
    db: Session, event_types: set[str] | None = None, start: datetime | None = None, end: datetime | None = None
) -> list[EventView]:
    stmt = select(*_VIEW_COLUMNS).order_by(Event.timestamp, Event.id)
    if event_types:
        stmt = stmt.where(Event.event_type.in_(sorted(event_types)))
    if start:
        stmt = stmt.where(Event.timestamp >= start)
    if end:
        stmt = stmt.where(Event.timestamp <= end)
    return [EventView(*row) for row in db.execute(stmt.execution_options(yield_per=5000))]


def run_rules(events: list[EventView], rules: list[Rule] | None = None) -> tuple[list[Candidate], dict[str, Any]]:
    """Pure function: events in, candidates out (used directly by unit tests and benchmarks)."""
    rules = rules or ALL_RULES
    candidates: list[Candidate] = []
    per_rule: dict[str, Any] = {}
    for rule in rules:
        t0 = time.perf_counter()
        subset = [e for e in events if e.event_type in rule.event_types]
        found = rule.evaluate(subset)
        per_rule[rule.id] = {"candidates": len(found), "ms": round((time.perf_counter() - t0) * 1000, 2)}
        candidates.extend(found)
    return candidates, per_rule


def persist_candidates(db: Session, candidates: list[Candidate], run_id: str | None) -> dict[str, int]:
    created = updated = 0
    if not candidates:
        return {"created": 0, "updated": 0}
    ids = {c.dedup_key: content_id("det", c.dedup_key) for c in candidates}
    existing = {d.id: d for d in db.scalars(select(Detection).where(Detection.id.in_(list(ids.values()))))}

    links: list[dict[str, str]] = []
    for c in candidates:
        det_id = ids[c.dedup_key]
        det = existing.get(det_id)
        if det is None:
            det = Detection(
                id=det_id, dedup_key=c.dedup_key, rule_id=c.rule_id, rule_name=c.rule_name, severity=c.severity,
                confidence=c.confidence, tactic=c.tactic, technique=c.technique, first_seen=c.first_seen,
                last_seen=c.last_seen, entities=c.entities, summary=c.summary,
                evidence_count=len(c.event_ids), run_id=run_id,
            )  # fmt: skip
            db.add(det)
            existing[det_id] = det
            created += 1
        else:
            known = set(db.scalars(select(DetectionEvent.event_id).where(DetectionEvent.detection_id == det_id)))
            fresh = [e for e in c.event_ids if e not in known]
            if not fresh:
                continue
            det.last_seen = max(det.last_seen, c.last_seen)
            det.evidence_count = len(known) + len(fresh)
            det.summary = c.summary
            updated += 1
        links.extend({"detection_id": det_id, "event_id": eid} for eid in c.event_ids)

    db.flush()
    insert_ignore(db, DetectionEvent, links, ["detection_id", "event_id"])
    return {"created": created, "updated": updated}


def run_detection(db: Session, run_id: str | None = None) -> dict[str, Any]:
    t0 = time.perf_counter()
    needed = set().union(*(r.event_types for r in ALL_RULES))
    events = load_event_views(db, needed)
    t_load = time.perf_counter()
    candidates, per_rule = run_rules(events)
    t_rules = time.perf_counter()
    persisted = persist_candidates(db, candidates, run_id)
    t_end = time.perf_counter()
    return {
        "events_scanned": len(events),
        "candidates": len(candidates),
        **persisted,
        "per_rule": per_rule,
        "timings_ms": {
            "load": round((t_load - t0) * 1000, 2),
            "rules": round((t_rules - t_load) * 1000, 2),
            "persist": round((t_end - t_rules) * 1000, 2),
        },
    }
