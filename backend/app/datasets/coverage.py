"""
Telemetry normalisation coverage: how much of what was ingested became typed, queryable, detectable data.

Status per event (see app/ingestion/windows_v3.py for the criteria):
  full / partial / raw_only   recorded by schema-v3 parsers in attributes.norm
  typed_unassessed            typed by an older parser that did not record completeness (v1/v2 sources)
Rejected records are not events; they are counted from ingest batches.

Nothing here hides unsupported data: raw-only events are listed with the reason they were not normalised.
"""

from collections import Counter, defaultdict
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Event, IngestBatch

STATUSES = ("full", "partial", "raw_only", "typed_unassessed")


def classify(event_type: str, attributes: dict[str, Any]) -> tuple[str, list[str], str | None]:
    norm = attributes.get("norm") if isinstance(attributes, dict) else None
    if isinstance(norm, dict) and norm.get("status") in ("full", "partial", "raw_only"):
        return norm["status"], list(norm.get("missing") or []), norm.get("reason")
    if event_type == "other":
        return "raw_only", [], "no typed mapping in this parser version"
    return "typed_unassessed", [], None


def coverage(db: Session, source: str | None = None) -> dict[str, Any]:
    stmt = select(Event.source, Event.parser, Event.event_type, Event.attributes)
    if source:
        stmt = stmt.where(Event.source == source)
    by_source: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    statuses: Counter[str] = Counter()
    types: Counter[str] = Counter()
    missing: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    raw_only_sources: Counter[str] = Counter()
    for src, parser, etype, attrs in db.execute(stmt):
        status, miss, reason = classify(etype, attrs or {})
        statuses[status] += 1
        by_source[(src, parser)][status] += 1
        types[etype] += 1
        for m in miss:
            missing[f"{etype}.{m}"] += 1
        if status == "raw_only":
            reasons[reason or "unknown"] += 1
            raw_only_sources[f"{(attrs or {}).get('channel', '?')} {(attrs or {}).get('event_id', '?')}"] += 1
        elif status == "partial":
            reasons[reason or "unknown"] += 1
    total = sum(statuses.values())
    bq = select(IngestBatch.source, func.sum(IngestBatch.rejected_count), func.sum(IngestBatch.accepted_count))
    if source:
        bq = bq.where(IngestBatch.source == source)
    rejected = {s: int(r or 0) for s, r, _a in db.execute(bq.group_by(IngestBatch.source))}
    pct = lambda n: round(100 * n / total, 2) if total else None  # noqa: E731
    return {
        "total_events": total,
        "rejected_records": sum(rejected.values()),
        "statuses": {s: statuses.get(s, 0) for s in STATUSES},
        "percent": {s: pct(statuses.get(s, 0)) for s in STATUSES},
        "event_types": dict(types.most_common()),
        "fields_missing": [{"field": k, "count": v} for k, v in missing.most_common(20)],
        "reasons": [{"reason": k, "count": v} for k, v in reasons.most_common(20)],
        "unsupported_source_types": [{"source_type": k, "count": v} for k, v in raw_only_sources.most_common(20)],
        "by_source": [
            {
                "source": s,
                "parser": p,
                "total": sum(c.values()),
                **{st: c.get(st, 0) for st in STATUSES},
                "rejected": rejected.get(s, 0),
            }
            for (s, p), c in sorted(by_source.items(), key=lambda kv: -sum(kv[1].values()))
        ],  # fmt: skip
    }
