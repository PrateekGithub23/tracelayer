"""
Correlation engine: detections -> investigations.

Algorithm
---------
1. Candidate detections = unassigned detections + detections already in an
   investigation that is still open/in review (so late evidence can join it).
2. Build an entity index (user / host / ip -> detections).
3. "Ubiquitous" entities (seen in > 30% of a large candidate set, e.g. a DNS
   server or a shared jump host) are excluded from linking; otherwise a single
   noisy entity would merge unrelated incidents into one giant cluster.
4. For each entity, sort its detections by time and union consecutive ones whose
   time intervals are within the correlation window. Linking only *consecutive*
   detections is enough for connectivity and keeps this O(n log n) instead of
   O(n^2) pairwise comparison.
5. Each connected component becomes (or extends) an investigation. Existing
   investigations are never destroyed or re-numbered, because analysts may
   already have reviewed them.
6. Investigation scope = evidence events (from detections) + context events that
   share an entity and fall inside the padded time range.

Scoring is additive and returned as a breakdown, so the UI can explain it.
"""

import time
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from app.cases import OPEN_STATUSES, SEVERITY_PRIORITY
from app.config import get_settings
from app.db_utils import insert_ignore
from app.detection.base import SEVERITY_ORDER, SEVERITY_WEIGHT
from app.ids import new_id
from app.models import Detection, DetectionEvent, Event, Investigation, InvestigationEvent, utcnow

KILL_CHAIN = [
    "credential-access", "initial-access", "discovery", "execution", "privilege-escalation",
    "defense-evasion", "lateral-movement", "exfiltration",
]  # fmt: skip
LINKABLE = {"user", "host", "ip"}
# Resolved and closed cases are never extended (app.cases.OPEN_STATUSES): closing freezes the evidence scope.


class UnionFind:
    def __init__(self, items: list[str]) -> None:
        self.parent = {i: i for i in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]  # path halving
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def cluster_detections(
    dets: list[Detection], window: timedelta, ubiquity_ratio: float = 0.3, min_for_suppression: int = 20
) -> tuple[list[list[Detection]], list[str]]:
    """Pure clustering step (unit-tested directly). Returns clusters and suppressed entities."""
    index: dict[tuple[str, str], list[Detection]] = defaultdict(list)
    for d in dets:
        for e in d.entities:
            if e["type"] in LINKABLE:
                index[(e["type"], e["value"])].append(d)

    suppressed: list[str] = []
    if len(dets) >= min_for_suppression:
        limit = ubiquity_ratio * len(dets)
        for key, members in list(index.items()):
            if len(members) > limit:
                suppressed.append(f"{key[0]}:{key[1]}")
                del index[key]

    uf = UnionFind([d.id for d in dets])
    for members in index.values():
        members.sort(key=lambda d: d.first_seen)
        group_end = members[0].last_seen
        for prev, cur in zip(members, members[1:], strict=False):
            if cur.first_seen - group_end <= window:
                uf.union(prev.id, cur.id)
                group_end = max(group_end, cur.last_seen)
            else:
                group_end = cur.last_seen  # gap too large: start a new chain for this entity

    by_root: dict[str, list[Detection]] = defaultdict(list)
    for d in dets:
        by_root[uf.find(d.id)].append(d)
    clusters = sorted(by_root.values(), key=lambda c: min(d.first_seen for d in c))
    return clusters, suppressed


def score_cluster(dets: list[Detection]) -> dict[str, Any]:
    tactics = sorted({d.tactic for d in dets}, key=lambda t: KILL_CHAIN.index(t) if t in KILL_CHAIN else 99)
    base = max(SEVERITY_WEIGHT[d.severity] for d in dets)
    stage_bonus = min(32, 8 * (len(tactics) - 1))
    volume_bonus = min(10, 2 * (len(dets) - 1))
    confidence = sum(d.confidence for d in dets) / len(dets)
    score = round(min(100.0, (base + stage_bonus + volume_bonus) * (0.7 + 0.3 * confidence)), 1)
    by_score = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"
    max_det = max((d.severity for d in dets), key=SEVERITY_ORDER.index)
    severity = max(by_score, max_det, key=SEVERITY_ORDER.index)
    return {
        "score": score,
        "severity": severity,
        "tactics": tactics,
        "breakdown": {
            "max_severity_weight": base,
            "kill_chain_stage_bonus": stage_bonus,
            "volume_bonus": volume_bonus,
            "mean_confidence": round(confidence, 3),
            "formula": "(base + stages + volume) * (0.7 + 0.3 * conf)",
        },  # fmt: skip
    }


def _title(dets: list[Detection], tactics: list[str]) -> str:
    users = Counter(e["value"] for d in dets for e in d.entities if e["type"] == "user")
    hosts = Counter(e["value"] for d in dets for e in d.entities if e["type"] == "host")
    ips = Counter(e["value"] for d in dets for e in d.entities if e["type"] == "ip")
    focus = users.most_common(1)[0][0] if users else (ips.most_common(1)[0][0] if ips else "unknown")
    where = f" on {hosts.most_common(1)[0][0]}" if hosts else ""
    if len(tactics) > 1:
        pretty = [t.replace("-", " ") for t in tactics]
        return f"{len(tactics)}-stage intrusion ({pretty[0]} → {pretty[-1]}) involving {focus}{where}"
    top = max(dets, key=lambda d: SEVERITY_WEIGHT[d.severity])
    return f"{top.rule_name} involving {focus}{where}"


def refresh_investigation(db: Session, inv: Investigation) -> None:
    """Recompute aggregates and rebuild the event scope of one investigation."""
    settings = get_settings()
    dets = list(db.scalars(select(Detection).where(Detection.investigation_id == inv.id)))
    if not dets:
        return
    s = score_cluster(dets)
    inv.score, inv.severity, inv.tactics, inv.score_breakdown = s["score"], s["severity"], s["tactics"], s["breakdown"]
    inv.first_seen = min(d.first_seen for d in dets)
    inv.last_seen = max(d.last_seen for d in dets)
    entities: Counter[tuple[str, str]] = Counter()
    for d in dets:
        for e in d.entities:
            entities[(e["type"], e["value"])] += 1
    inv.entities = [{"type": t, "value": v, "detections": n} for (t, v), n in entities.most_common()]
    inv.title = _title(dets, s["tactics"])
    inv.updated_at = utcnow()

    evidence = set(db.scalars(
        select(DetectionEvent.event_id).where(DetectionEvent.detection_id.in_([d.id for d in dets]))
    ))  # fmt: skip
    users = [v for (t, v) in entities if t == "user"]
    hosts = [v for (t, v) in entities if t == "host"]
    ips = [v for (t, v) in entities if t == "ip"]
    pad = timedelta(minutes=settings.context_padding_minutes)
    conds = []
    if users:
        conds.append(Event.username.in_(users))
    if hosts:
        conds.append(Event.host.in_(hosts))
    if ips:
        conds += [Event.src_ip.in_(ips), Event.dst_ip.in_(ips)]
    context: list[str] = []
    if conds:
        context = list(db.scalars(
            select(Event.id).where(or_(*conds), Event.timestamp >= inv.first_seen - pad,
                                   Event.timestamp <= inv.last_seen + pad)
            .order_by(Event.timestamp).limit(settings.max_context_events + len(evidence))
        ))  # fmt: skip
    context = [c for c in context if c not in evidence][: settings.max_context_events]

    db.execute(delete(InvestigationEvent).where(InvestigationEvent.investigation_id == inv.id))
    rows = [{"investigation_id": inv.id, "event_id": e, "role": "evidence"} for e in evidence]
    rows += [{"investigation_id": inv.id, "event_id": e, "role": "context"} for e in context]
    insert_ignore(db, InvestigationEvent, rows, ["investigation_id", "event_id"])


def run_correlation(db: Session, window_minutes: int | None = None) -> dict[str, Any]:
    t0 = time.perf_counter()
    window = timedelta(minutes=window_minutes or get_settings().correlation_window_minutes)
    open_ids = select(Investigation.id).where(Investigation.status.in_(OPEN_STATUSES))
    dets = list(db.scalars(
        select(Detection).where(or_(Detection.investigation_id.is_(None), Detection.investigation_id.in_(open_ids)))
    ))  # fmt: skip
    clusters, suppressed = cluster_detections(dets, window)

    created, extended, touched = 0, 0, []
    invs = {i.id: i for i in db.scalars(select(Investigation).where(Investigation.status.in_(OPEN_STATUSES)))}
    for cluster in clusters:
        unassigned = [d for d in cluster if d.investigation_id is None]
        if not unassigned:
            continue
        existing = sorted({d.investigation_id for d in cluster if d.investigation_id},
                          key=lambda i: invs[i].created_at)  # fmt: skip
        if existing:
            inv = invs[existing[0]]
            extended += 1
        else:
            # A lone low-severity signal stays a detection; it does not deserve an investigation.
            if len(cluster) == 1 and cluster[0].severity == "low":
                continue
            first = min(d.first_seen for d in cluster)
            inv = Investigation(id=new_id("inv"), title="pending", status="new", severity="low", score=0,
                                first_seen=first, last_seen=first)  # fmt: skip
            db.add(inv)
            db.flush()
            invs[inv.id] = inv
            created += 1
        for d in unassigned:
            d.investigation_id = inv.id
        db.flush()
        refresh_investigation(db, inv)
        if not existing:  # initial priority follows severity; afterwards it belongs to the analysts
            inv.priority = SEVERITY_PRIORITY.get(inv.severity, "P3")
        touched.append(inv.id)

    return {
        "candidate_detections": len(dets),
        "clusters": len(clusters),
        "investigations_created": created,
        "investigations_extended": extended,
        "suppressed_entities": suppressed,
        "touched": touched,
        "ms": round((time.perf_counter() - t0) * 1000, 2),
    }
