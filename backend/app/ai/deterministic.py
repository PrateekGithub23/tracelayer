"""
Deterministic analyst: a template-based report writer that needs no model at all.

It is the fallback when Ollama is not installed, not running, too slow, or
returns garbage, and it is a useful baseline: because it builds every sentence
from the events it cites, it should score ~100% on the integrity validator.
If it ever does not, either a template or the validator has a bug, and the
test suite catches that (tests/test_integrity.py).

It writes four kinds of statement:
  observations   - one per detection, with exact counts and every evidence event cited
  correlations   - consecutive detections that share an entity ("A was followed by B")
  hypotheses     - explicitly hedged follow-up leads
  missing evidence - coverage gaps for hosts involved in the investigation
"""

from collections import Counter
from typing import Any

from app.ai.schema import AnalysisOutput, ClaimOut
from app.detection.base import EventView
from app.integrity.scope import DetectionRef, Scope, coverage_gaps
from app.models import Investigation


def _refs(scope: Scope, events: list[EventView]) -> list[str]:
    return [scope.id_to_ref[e.id] for e in events if e.id in scope.id_to_ref]


def _join(items: list[str]) -> str:
    items = list(dict.fromkeys(items))
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _evs(scope: Scope, d: DetectionRef) -> list[EventView]:
    return sorted((scope.events[e] for e in d.event_ids if e in scope.events), key=lambda e: e.timestamp)


def _top(values: list[str | None]) -> str | None:
    c = Counter(v for v in values if v)
    return c.most_common(1)[0][0] if c else None


def observation(scope: Scope, d: DetectionRef) -> ClaimOut | None:
    evs = _evs(scope, d)
    if not evs:
        return None
    rule = d.rule_id
    if rule == "TL-AUTH-001":
        fails = [e for e in evs if e.outcome == "failure"]
        ip = fails[0].src_ip
        users = sorted({e.username for e in fails if e.username})
        hosts = sorted({e.host for e in fails if e.host})
        tgt = f" targeting users {_join(users)}" if 0 < len(users) <= 6 else ""
        text = f"{len(fails)} failed logins from {ip} against host {_join(hosts)}{tgt}."
        return ClaimOut(text=text, kind="observation", citations=_refs(scope, fails))
    if rule == "TL-AUTH-002":
        success = evs[-1]
        fails = [e for e in evs if e.outcome == "failure" and e.src_ip == success.src_ip]
        text = (f"User {success.username} logged in successfully from {success.src_ip} on host {success.host} "
                f"after {len(fails)} failed login attempts from that address.")  # fmt: skip
        return ClaimOut(text=text, kind="observation", citations=_refs(scope, evs))
    if rule == "TL-AUTH-003":
        a, b = evs[0], evs[-1]
        mins = (b.timestamp - a.timestamp).total_seconds() / 60
        text = (f"User {b.username} logged in successfully from {a.src_ip} ({a.country}) and then from "
                f"{b.src_ip} ({b.country}) {mins:.0f} minutes later, an implied speed no commercial flight can reach.")  # fmt: skip
        return ClaimOut(text=text, kind="correlation", citations=_refs(scope, evs))
    if rule == "TL-EXEC-001":
        user, host = _top([e.username for e in evs]), evs[0].host
        tool = _top([e.process for e in evs]) or "a process"
        label = d.rule_name.split(": ", 1)[-1]
        text = (f"User {user} executed {len(evs)} command(s) on host {host} matching the '{label}' signature "
                f"({tool}).")  # fmt: skip
        return ClaimOut(text=text, kind="observation", citations=_refs(scope, evs))
    if rule == "TL-PRIV-001":
        change = evs[0]
        attrs = change.attributes or {}
        text = (f"User {attrs.get('member')} was added to the privileged group '{attrs.get('group')}' on host "
                f"{change.host} by account {change.username}.")  # fmt: skip
        return ClaimOut(text=text, kind="observation", citations=_refs(scope, evs))
    if rule == "TL-LAT-001":
        user = evs[0].username
        hosts = sorted({e.host for e in evs if e.host})
        mins = (evs[-1].timestamp - evs[0].timestamp).total_seconds() / 60
        text = f"User {user} logged on to {len(hosts)} distinct hosts within {mins:.0f} minutes: {_join(hosts)}."
        return ClaimOut(text=text, kind="observation", citations=_refs(scope, evs))
    if rule == "TL-EXFIL-001":
        total = sum(e.bytes_out or 0 for e in evs)
        text = (f"Host {evs[0].host} sent {total / 1024 / 1024:.1f} MB to external address {evs[0].dst_ip} "
                f"in {len(evs)} outbound flows.")  # fmt: skip
        return ClaimOut(text=text, kind="observation", citations=_refs(scope, evs))
    if rule == "TL-DEF-001":
        e = evs[-1]
        text = f"The Security log was cleared on host {e.host} by user {e.username}."
        return ClaimOut(text=text, kind="observation", citations=_refs(scope, evs))
    if rule == "TL-AI-001":
        text = (f"{len(evs)} event(s) on host {evs[0].host} contain text that attempts to instruct AI analysts; "
                "this content is treated as adversarial data, not as guidance.")  # fmt: skip
        return ClaimOut(text=text, kind="observation", citations=_refs(scope, evs))
    return None


def _phrase(scope: Scope, d: DetectionRef) -> tuple[str, list[EventView]] | None:
    """Short noun phrase for a detection, plus the events that substantiate the phrase."""
    evs = _evs(scope, d)
    if not evs:
        return None
    r = d.rule_id
    if r == "TL-AUTH-001":
        return f"the brute-force burst from {evs[0].src_ip}", evs[:3]
    if r in ("TL-AUTH-002", "TL-AUTH-003"):
        e = evs[-1]
        return f"a successful login by {e.username} from {e.src_ip}", [e]
    if r == "TL-EXEC-001":
        tool = _top([e.process for e in evs]) or "suspicious"
        return f"{tool} execution on {evs[0].host}", evs[:1]
    if r == "TL-PRIV-001":
        a = evs[0].attributes or {}
        return f"{a.get('member')} being added to {a.get('group')}", evs[:1]
    if r == "TL-LAT-001":
        return f"{evs[0].username} logging on to multiple hosts", evs
    if r == "TL-EXFIL-001":
        return f"an outbound transfer from {evs[0].host} to {evs[0].dst_ip}", evs[:2]
    if r == "TL-DEF-001":
        log_ev = [e for e in evs if e.event_type == "log.cleared"] or evs
        return f"Security log clearing on {evs[0].host}", log_ev[:1]
    return None


def correlations(scope: Scope) -> list[ClaimOut]:
    out = []
    # Order by when the *cited* events happened, not by detection first_seen: a detection's
    # evidence can start earlier than the moment its phrase describes (e.g. a success-after-
    # failures detection includes the failures). The validator caught exactly this bug.
    phrases: dict[str, list[EventView]] = {}
    for d in scope.detections:
        if d.rule_id == "TL-AI-001":
            continue
        p = _phrase(scope, d)
        if p and p[0] not in phrases:
            phrases[p[0]] = p[1]
    ordered = sorted(phrases.items(), key=lambda kv: min(e.timestamp for e in kv[1]))
    for (ta, ea), (tb, eb) in zip(ordered, ordered[1:], strict=False):
        pa, pb = (ta, ea), (tb, eb)

        def ents(evs: list[EventView]) -> set[tuple[str, str]]:
            s: set[tuple[str, str]] = set()
            for e in evs:
                s |= {("user", e.username or ""), ("host", e.host or "")}
            return {x for x in s if x[1]}

        shared = sorted(ents(ea) & ents(eb))
        if not shared:
            continue
        kind, value = shared[0]
        text = f"{pa[0][0].upper()}{pa[0][1:]} was followed by {pb[0]}; both involve {kind} {value}."
        out.append(ClaimOut(text=text, kind="correlation", citations=_refs(scope, ea + eb)))
    return out


def hypotheses(scope: Scope) -> list[ClaimOut]:
    out = []
    by_rule = {d.rule_id: d for d in scope.detections}
    for d in scope.detections:
        for e in _evs(scope, d):
            if "certutil" in (e.command_line or "").lower() and "http" in (e.command_line or "").lower():
                out.append(ClaimOut(
                    text=f"The certutil download on host {e.host} may have staged additional tooling; "
                         "the downloaded file itself was not captured.",
                    kind="hypothesis", citations=_refs(scope, [e])))  # fmt: skip
                break
    if "TL-AUTH-001" in by_rule:
        fails = [e for e in _evs(scope, by_rule["TL-AUTH-001"]) if e.outcome == "failure"]
        compromised = {e.username for d in scope.detections if d.rule_id == "TL-AUTH-002"
                       for e in _evs(scope, d) if e.outcome == "success"}  # fmt: skip
        others = sorted({e.username for e in fails if e.username} - compromised)
        if others and len(others) <= 6:
            cited = [next(e for e in fails if e.username == u) for u in others]
            out.append(ClaimOut(
                text=f"The other targeted accounts {_join(others)} may also be at risk and should have their "
                     "credentials reviewed.",
                kind="hypothesis", citations=_refs(scope, cited)))  # fmt: skip
    if "TL-EXFIL-001" in by_rule and "TL-LAT-001" in by_rule:
        flow = _evs(scope, by_rule["TL-EXFIL-001"])[0]
        logon = next((e for e in _evs(scope, by_rule["TL-LAT-001"]) if e.host == flow.host), None)
        if logon:
            out.append(ClaimOut(
                text=f"The data that left host {flow.host} likely came from file shares reachable by "
                     f"{logon.username}; file-level telemetry would be required to confirm what was taken.",
                kind="hypothesis", citations=_refs(scope, [flow, logon])))  # fmt: skip
    return out


def gaps(scope: Scope) -> list[ClaimOut]:
    out = []
    det_hosts = {e.host for d in scope.detections for e in _evs(scope, d) if e.host}
    for g in coverage_gaps(scope):
        if g["host"] not in det_hosts or "process.start" not in g["missing"]:
            continue
        logon = next((e for e in scope.ordered() if e.host == g["host"] and e.event_type == "auth.login"
                      and e.outcome == "success"), None)  # fmt: skip
        if not logon:
            continue
        out.append(ClaimOut(
            text=f"No process telemetry was ingested for host {g['host']}, so activity after {logon.username}'s "
                 "logon there cannot be verified.",
            kind="observation", citations=_refs(scope, [logon])))  # fmt: skip
    return out


def analyze(scope: Scope, inv: Investigation) -> tuple[AnalysisOutput, dict[str, Any]]:
    claims: list[ClaimOut] = []
    for d in scope.detections:
        c = observation(scope, d)
        if c:
            claims.append(c)
    claims += correlations(scope) + hypotheses(scope) + gaps(scope)

    tactics = ", ".join(t.replace("-", " ") for t in inv.tactics)
    users = [e["value"] for e in inv.entities if e["type"] == "user"][:3]
    hosts = [e["value"] for e in inv.entities if e["type"] == "host"][:4]
    summary = (
        f"{inv.title}. {len(scope.detections)} detection(s) spanning {tactics or 'one tactic'} between "
        f"{inv.first_seen:%Y-%m-%d %H:%M} and {inv.last_seen:%H:%M} UTC. Principal entities: "
        f"{', '.join(users + hosts) or 'n/a'}. Statements below are generated from the cited events; "
        "hypotheses and coverage gaps are labelled as such."
    )
    recs = []
    rules = {d.rule_id for d in scope.detections}
    if rules & {"TL-AUTH-002", "TL-AUTH-003"}:
        recs.append("Reset credentials and revoke active sessions for the compromised account(s).")
    if "TL-AUTH-001" in rules:
        recs.append("Block the brute-force source address at the perimeter and enforce MFA on exposed services.")
    if "TL-PRIV-001" in rules:
        recs.append("Remove unauthorised privileged group memberships and review recent admin actions.")
    if "TL-EXFIL-001" in rules:
        recs.append("Block the exfiltration destination and determine which data was transferred.")
    if "TL-DEF-001" in rules:
        recs.append("Recover cleared logs from a forwarder/SIEM copy; treat the host as fully compromised.")
    if gaps(scope):
        recs.append("Deploy endpoint/process telemetry to hosts listed as coverage gaps.")
    return AnalysisOutput(summary=summary, claims=claims, recommendations=recs), {"generator": "templates-v1"}
