"""
Evidence graph: entities as nodes, observed interactions as edges.

Every edge is aggregated from real events and carries the ids of the events
that produced it, so clicking an edge in the UI opens exactly the evidence
behind it. Nothing in the graph is inferred.

Edge semantics
  ip   -> user   authenticated as      (auth.login, with success/failure counts)
  user -> host   logged on to          (auth.login success)
  user -> host   executed on           (process.start)
  user -> user   added to group        (iam.change, actor -> member)
  host -> ip     sent data to          (network.flow, with total bytes)
  user -> host   cleared logs on       (log.cleared)
"""

from collections import defaultdict
from typing import Any

from app.detection.base import EventView, is_external
from app.integrity.scope import Scope

MAX_EVENT_IDS_PER_EDGE = 200


def build_graph(scope: Scope, flagged_event_ids: set[str]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    entity_dets: dict[str, set[str]] = defaultdict(set)
    for d in scope.detections:
        for eid in d.event_ids:
            e = scope.events.get(eid)
            if not e:
                continue
            for nid in _entity_ids(e):
                entity_dets[nid].add(d.id)

    def node(kind: str, value: str) -> str:
        nid = f"{kind}:{value}"
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": kind, "label": value, "events": 0,
                          "external": kind == "ip" and is_external(value)}  # fmt: skip
        nodes[nid]["events"] += 1
        return nid

    def edge(src: str, dst: str, relation: str, e: EventView) -> None:
        key = (src, dst, relation)
        ed = edges.setdefault(key, {"id": f"{src}|{relation}|{dst}", "source": src, "target": dst,
                                    "relation": relation, "count": 0, "failures": 0, "bytes": 0,
                                    "first_seen": e.timestamp, "last_seen": e.timestamp, "event_ids": [],
                                    "flagged": False})  # fmt: skip
        ed["count"] += 1
        ed["failures"] += e.outcome == "failure"
        ed["bytes"] += e.bytes_out or 0
        ed["first_seen"] = min(ed["first_seen"], e.timestamp)
        ed["last_seen"] = max(ed["last_seen"], e.timestamp)
        ed["flagged"] = ed["flagged"] or e.id in flagged_event_ids
        if len(ed["event_ids"]) < MAX_EVENT_IDS_PER_EDGE:
            ed["event_ids"].append(e.id)

    for e in scope.ordered():
        t = e.event_type
        if t == "auth.login" and e.username:
            u = node("user", e.username)
            if e.src_ip:
                edge(node("ip", e.src_ip), u, "authenticated as", e)
            if e.host and e.outcome == "success":
                edge(u, node("host", e.host), "logged on to", e)
        elif t == "process.start" and e.username and e.host:
            edge(node("user", e.username), node("host", e.host), "executed on", e)
        elif t == "iam.change" and e.username:
            member = (e.attributes or {}).get("member")
            if isinstance(member, str) and member:
                edge(node("user", e.username), node("user", member), "added to group", e)
        elif t == "network.flow" and e.host and e.dst_ip and is_external(e.dst_ip):
            edge(node("host", e.host), node("ip", e.dst_ip), "sent data to", e)
        elif t == "log.cleared" and e.host:
            edge(node("user", e.username or "unknown"), node("host", e.host), "cleared logs on", e)

    for nid, n in nodes.items():
        n["detections"] = sorted(entity_dets.get(nid, set()))
    for ed in edges.values():
        ed["first_seen"] = ed["first_seen"].isoformat()
        ed["last_seen"] = ed["last_seen"].isoformat()
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _entity_ids(e: EventView) -> list[str]:
    out = []
    if e.username:
        out.append(f"user:{e.username}")
    if e.host:
        out.append(f"host:{e.host}")
    for ip in (e.src_ip, e.dst_ip):
        if ip:
            out.append(f"ip:{ip}")
    return out
