"""
Investigation scope: the evidence a claim is allowed to rely on.

The scope is the set of events attached to an investigation (detection evidence
plus correlated context), the detections themselves, and lookups into the global
event store so the validator can distinguish:
  * a citation to an event in scope                     -> usable evidence
  * a citation to a real event outside this investigation -> out of scope
  * a citation to an event that does not exist            -> fabricated

Events get short, stable reference labels (E1..En in time order). Small local
models copy "E17" far more reliably than a 24-character id, and because labels
are derived deterministically from the scope they never need to be stored.
"""

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from sqlalchemy import exists, or_, select
from sqlalchemy.orm import Session

from app.detection.base import EventView
from app.detection.engine import _VIEW_COLUMNS
from app.models import Detection, DetectionEvent, Event, InvestigationEvent

TELEMETRY_TYPES = ["auth.login", "process.start", "network.flow", "iam.change", "dns.query", "file.access",
                   "log.cleared"]  # fmt: skip


@dataclass
class DetectionRef:
    id: str
    ref: str
    rule_id: str
    rule_name: str
    severity: str
    tactic: str
    summary: str
    event_ids: list[str]


@dataclass
class Scope:
    investigation_id: str
    events: dict[str, EventView]
    roles: dict[str, str]
    ref_map: dict[str, str]  # "E1" -> event id
    detections: list[DetectionRef]
    vocab_users: set[str]
    vocab_hosts: set[str]
    event_exists: Callable[[str], bool]
    entity_exists: Callable[[str, str], bool]
    id_to_ref: dict[str, str] = field(default_factory=dict)

    def ordered(self) -> list[EventView]:
        return sorted(self.events.values(), key=lambda e: (e.timestamp, e.id))

    def types_by_host(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = defaultdict(set)
        for e in self.events.values():
            if e.host:
                out[e.host].add(e.event_type)
        return out


def build_scope(db: Session, investigation_id: str) -> Scope:
    rows = db.execute(
        select(*_VIEW_COLUMNS, InvestigationEvent.role)
        .join(InvestigationEvent, InvestigationEvent.event_id == Event.id)
        .where(InvestigationEvent.investigation_id == investigation_id)
        .order_by(Event.timestamp, Event.id)
    ).all()
    events = {r[0]: EventView(*r[:-1]) for r in rows}
    roles = {r[0]: r[-1] for r in rows}
    ref_map = {f"E{i}": eid for i, eid in enumerate(events, start=1)}

    dets = []
    for i, d in enumerate(db.scalars(
        select(Detection).where(Detection.investigation_id == investigation_id).order_by(Detection.first_seen)
    ), start=1):  # fmt: skip
        ev_ids = list(db.scalars(select(DetectionEvent.event_id).where(DetectionEvent.detection_id == d.id)))
        dets.append(DetectionRef(d.id, f"D{i}", d.rule_id, d.rule_name, d.severity, d.tactic, d.summary, ev_ids))

    # Global vocabularies let the validator recognise entity names and detect fabricated ones.
    users = {u.lower() for u in db.scalars(select(Event.username).distinct()) if u}
    hosts = {h.lower() for h in db.scalars(select(Event.host).distinct()) if h}

    @lru_cache(maxsize=4096)
    def event_exists(eid: str) -> bool:
        return bool(db.scalar(select(exists().where(Event.id == eid))))

    @lru_cache(maxsize=4096)
    def entity_exists(kind: str, value: str) -> bool:
        if kind == "user":
            return value.lower() in users
        if kind == "host":
            return value.lower() in hosts
        cond = or_(Event.src_ip == value, Event.dst_ip == value)
        return bool(db.scalar(select(exists().where(cond))))

    return Scope(
        investigation_id=investigation_id, events=events, roles=roles, ref_map=ref_map, detections=dets,
        vocab_users=users, vocab_hosts=hosts, event_exists=event_exists, entity_exists=entity_exists,
        id_to_ref={v: k for k, v in ref_map.items()},
    )  # fmt: skip


def coverage_gaps(scope: Scope) -> list[dict[str, Any]]:
    """Which core telemetry types are missing for each host in scope.

    A host that shows logons but no process telemetry is a blind spot: whatever
    happened after the logon cannot be verified. These gaps are surfaced as
    explicit 'missing evidence' instead of letting anyone assume nothing happened.
    """
    core = ["auth.login", "process.start", "network.flow"]
    gaps = []
    for host, types in sorted(scope.types_by_host().items()):
        missing = [t for t in core if t not in types]
        if missing and "auth.login" in types:
            gaps.append({"host": host, "present": sorted(types), "missing": missing})
    return gaps
