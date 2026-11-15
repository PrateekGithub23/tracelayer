"""
Shared types for detection rules.

Rules receive lightweight `EventView` tuples rather than ORM objects: loading
100k ORM instances is several times slower and the rules only read fields.
"""

import ipaddress
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any

SEVERITY_WEIGHT = {"low": 20, "medium": 45, "high": 70, "critical": 90}
SEVERITY_ORDER = ["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class EventView:
    id: str
    timestamp: datetime
    event_type: str
    host: str | None
    username: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    process: str | None
    command_line: str | None
    outcome: str
    bytes_out: int | None
    country: str | None
    attributes: dict[str, Any]
    tags: list[str]


@dataclass
class Candidate:
    """A detection produced by a rule, before persistence."""

    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    tactic: str
    technique: str
    dedup_key: str
    first_seen: datetime
    last_seen: datetime
    summary: str
    event_ids: list[str]
    entities: list[dict[str, str]] = field(default_factory=list)


class Rule:
    """Base class. Subclasses set metadata and implement `evaluate`."""

    id: str = ""
    name: str = ""
    severity: str = "medium"
    tactic: str = ""
    technique: str = ""
    description: str = ""
    event_types: frozenset[str] = frozenset()

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        raise NotImplementedError

    def candidate(self, *, key: str, events: list[EventView], summary: str, entities: list[dict[str, str]],
                  severity: str | None = None, confidence: float = 0.8) -> Candidate:  # fmt: skip
        return Candidate(
            rule_id=self.id, rule_name=self.name, severity=severity or self.severity,
            confidence=round(confidence, 2), tactic=self.tactic, technique=self.technique,
            dedup_key=f"{self.id}|{key}", first_seen=events[0].timestamp, last_seen=events[-1].timestamp,
            summary=summary, event_ids=[e.id for e in events], entities=dedupe_entities(entities),
        )  # fmt: skip


def dedupe_entities(entities: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out = []
    for e in entities:
        k = (e["type"], e["value"])
        if e["value"] and k not in seen:
            seen.add(k)
            out.append(e)
    return out


def ent(kind: str, value: str | None) -> list[dict[str, str]]:
    return [{"type": kind, "value": value}] if value else []


# RFC 5737 documentation ranges. Python's ipaddress classifies them as "private", but the
# synthetic data uses them for internet-facing attacker infrastructure (they are guaranteed
# never to be real hosts), so TraceLayer treats them as external.
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@lru_cache(maxsize=65536)
def is_external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(addr in net for net in _DOC_NETS):
        return True
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)


def bursts(events: list[EventView], max_gap: timedelta) -> Iterator[list[EventView]]:
    """Split time-ordered events into runs where consecutive events are <= max_gap apart."""
    run: list[EventView] = []
    for ev in events:
        if run and ev.timestamp - run[-1].timestamp > max_gap:
            yield run
            run = []
        run.append(ev)
    if run:
        yield run


def sliding_segments(
    events: list[EventView], window: timedelta, threshold: float, weight: Callable[[EventView], float] = lambda e: 1.0
) -> list[list[EventView]]:
    """Maximal runs of time-ordered events where some `window`-long span reaches `threshold`.

    Two-pointer sliding window, O(n). Unlike gap-based bursts, a window is bounded in time, so a
    slow trickle (a user's occasional typo, routine downloads) can never accumulate into an alert
    just because the gaps between events stay short. Overlapping qualifying windows are merged.
    """
    segments: list[list[int]] = []
    total = 0.0
    left = 0
    for right, ev in enumerate(events):
        total += weight(ev)
        while ev.timestamp - events[left].timestamp > window:
            total -= weight(events[left])
            left += 1
        if total >= threshold:
            if segments and left <= segments[-1][1]:
                segments[-1][1] = right
            else:
                segments.append([left, right])
    return [events[a : b + 1] for a, b in segments]


def bucket(ts: datetime, minutes: int = 60) -> str:
    """Stable time bucket used inside dedup keys."""
    epoch_min = int(ts.timestamp() // 60)
    return str(epoch_min - epoch_min % minutes)
