"""
Claim validator: the heart of the Evidence Integrity Engine.

Every statement an analysis makes is classified into exactly one verdict:

  verified_observation   all checkable facts are directly present in cited, in-scope events
  heuristic_correlation  each fact is supported, but the *link* between them is inferred
  ai_hypothesis          explicitly speculative (or uncited but honestly hedged); not evidence
  missing_evidence       the claim depends on telemetry that does not exist in scope
  unsupported_claim      fabricated/out-of-scope citations, unknown entities, or facts the
                         citations do not show
  contradictory_finding  the evidence says otherwise (wrong count, outcome, order, attribution,
                         or a dismissal of high-severity activity)

Precedence when several problems apply (most dangerous first):
  fabricated/out-of-scope citations or unknown entities -> unsupported
  any contradiction                                    -> contradictory
  any unsupported fact                                 -> unsupported
  any missing telemetry                                -> missing_evidence
  otherwise framing decides: hypothesis > correlation > verified

The validator is deliberately conservative: an unsafe claim labelled "verified"
is far worse than a true claim labelled "unsupported", because the analyst can
always add citations, but cannot see a hallucination that was rubber-stamped.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from app.detection.base import EventView, is_external
from app.ingestion.parsers import INJECTION_PATTERNS
from app.integrity.extract import Assertions, Mention, extract, temporal_pairs
from app.integrity.scope import Scope

VERIFIED = "verified_observation"
CORRELATION = "heuristic_correlation"
HYPOTHESIS = "ai_hypothesis"
MISSING = "missing_evidence"
UNSUPPORTED = "unsupported_claim"
CONTRADICTORY = "contradictory_finding"
VERDICTS = [VERIFIED, CORRELATION, HYPOTHESIS, MISSING, UNSUPPORTED, CONTRADICTORY]
UNSAFE = {UNSUPPORTED, CONTRADICTORY}
# Contribution of each verdict to the analysis integrity score (0-100).
VERDICT_WEIGHT = {VERIFIED: 1.0, CORRELATION: 0.85, HYPOTHESIS: 0.6, MISSING: 0.6, UNSUPPORTED: 0.0,
                  CONTRADICTORY: 0.0}  # fmt: skip
MAX_CITATIONS = 500
# Citing many events of which few are relevant is a way to make anything look supported.
FLOOD_MIN_CITATIONS = 20
FLOOD_MIN_PRECISION = 0.25
# v2: claims must be atomic. Long or multi-sentence text hides unverified statements among verified ones.
MAX_CLAIM_CHARS = 600
MAX_CLAIM_SENTENCES = 3
_UPPER = {"at most", "no more than", "up to"}
_STRICT_UPPER = {"fewer than", "less than", "under"}
_LOWER = {"at least"}
_STRICT_LOWER = {"more than", "over", "upwards of", "in excess of"}
_APPROX = {"approximately", "about", "roughly", "around", "~"}


@dataclass
class ClaimInput:
    text: str
    kind: str = "observation"  # declared by the generator: observation | correlation | hypothesis
    citations: list[str] = field(default_factory=list)


@dataclass
class ClaimResult:
    text: str
    declared_kind: str
    raw_citations: list[str]
    citations: list[str]
    verdict: str
    reasons: list[str]
    checks: dict[str, Any]


# --------------------------------------------------------------------------- helpers


def _haystack(e: EventView) -> str:
    a = e.attributes or {}
    return " ".join(str(x) for x in (e.command_line, e.process, a.get("group"), a.get("query")) if x).lower()


def _matches(e: EventView, m: Mention) -> bool:
    """Does this event show the activity the mention describes?"""
    if e.event_type not in m.types:
        return False
    if m.outcome and e.outcome != m.outcome:
        return False
    if m.label == "AI-directed instructions":  # matches the ingest-time prompt-injection tag
        return "llm_injection_suspected" in (e.tags or [])
    hay = _haystack(e)
    if m.label == "log clearing":  # either the OS "log cleared" record or the clearing command itself
        return e.event_type == "log.cleared" or "wevtutil" in hay or "clear-eventlog" in hay
    if m.keyword and m.keyword not in hay:
        return False
    return not (m.external_only and not is_external(e.dst_ip))


def _involves(e: EventView, a: Assertions) -> bool:
    """Does the event touch any entity named in the claim? (True if the claim names none.)"""
    if not (a.ips or a.users or a.hosts):
        return True
    member = (e.attributes or {}).get("member")
    return bool(
        (e.src_ip in a.ips or e.dst_ip in a.ips)
        or (e.username and e.username.lower() in a.users)
        or (isinstance(member, str) and member.lower() in a.users)
        or (e.host and e.host.lower() in a.hosts)
    )


def _located(e: EventView, a: Assertions) -> bool:
    """If the claim names hosts, those hosts are *where* the activity happened."""
    if a.hosts:
        return (e.host or "").lower() in a.hosts
    return _involves(e, a)


def _entity_in(e: EventView, kind: str, value: str) -> bool:
    if kind == "ip":
        # An address inside a command line (e.g. a download URL) is evidence of that address too.
        return value in (e.src_ip, e.dst_ip) or value in (e.command_line or "")
    if kind == "host":
        return (e.host or "").lower() == value
    member = (e.attributes or {}).get("member")
    return (e.username or "").lower() == value or (isinstance(member, str) and member.lower() == value)


def _count_filter(events: list[EventView], a: Assertions) -> list[EventView]:
    """Narrow events to the most specific entity named: IP, else user, else host."""
    if a.ips:
        return [e for e in events if e.src_ip in a.ips or e.dst_ip in a.ips]
    if a.users:
        return [e for e in events if (e.username or "").lower() in a.users]
    if a.hosts:
        return [e for e in events if (e.host or "").lower() in a.hosts]
    return events


def _count_ok(claimed: float, qualifier: str, refs: list[float], tolerance: float) -> bool:
    for ref in refs:
        if qualifier in _LOWER and ref >= claimed * (1 - tolerance):
            return True
        if qualifier in _STRICT_LOWER and ref > claimed * (1 - tolerance):
            return True
        if qualifier in _UPPER and ref <= claimed * (1 + tolerance):
            return True
        if qualifier in _STRICT_UPPER and ref < claimed * (1 + tolerance) and ref != claimed:
            return True
        if qualifier in _APPROX and ref and abs(claimed - ref) / ref <= max(tolerance, 0.15):
            return True
        if not qualifier and (ref == claimed or (ref and abs(claimed - ref) / ref <= tolerance)):
            return True
    return False


def _time_ok(t: dict[str, Any], events: list[EventView]) -> bool:
    tol = 5.0 if t.get("has_seconds") else 90.0  # "11:09" means anywhere in that minute, plus clock skew
    for e in events:
        if t.get("utc") is not None:
            if abs((e.timestamp - t["utc"]).total_seconds()) <= tol:
                return True
        else:
            ev_min = e.timestamp.hour * 60 + e.timestamp.minute + e.timestamp.second / 60
            diff = abs(ev_min - t["minutes"]) % 1440
            if min(diff, 1440 - diff) * 60 <= tol:
                return True
    return False


# --------------------------------------------------------------------------- main entry


def validate_claim(claim: ClaimInput, scope: Scope) -> ClaimResult:
    reasons: list[str] = []
    checks: dict[str, Any] = {}
    kind = claim.kind if claim.kind in ("observation", "correlation", "hypothesis") else "observation"

    # 1. Resolve citations: short refs (E12) or full ids; classify each.
    raw = [str(c).strip() for c in claim.citations[:MAX_CITATIONS] if str(c).strip()]
    resolved, fabricated, out_of_scope = [], [], []
    for ref in dict.fromkeys(raw):  # de-duplicate, keep order
        eid = scope.ref_map.get(ref.strip("[]").upper(), ref.strip("[]"))
        if eid in scope.events:
            resolved.append(eid)
        elif eid.startswith("D") and eid[1:].isdigit():
            fabricated.append(ref)  # detections are not evidence; models must cite events
        elif scope.event_exists(eid):
            out_of_scope.append(ref)
        else:
            fabricated.append(ref)
    cited = [scope.events[e] for e in resolved]
    checks["citations"] = {"given": len(raw), "resolved": len(resolved), "fabricated": fabricated,
                           "out_of_scope": out_of_scope}  # fmt: skip

    a = extract(claim.text, scope)
    checks["extracted"] = {
        "ips": sorted(a.ips), "users": sorted(a.users), "hosts": sorted(a.hosts),
        "activities": [m.label + (" (negated)" if m.negated else "") for m in a.mentions],
        "counts": a.counts, "hedged": a.hedged, "correlational": a.correlational, "dismissive": a.dismissive,
    }  # fmt: skip

    checks["extracted"].update({"times": [t["text"] for t in a.times], "conclusions": a.conclusions,
                                "authority_appeal": a.authority, "deceptive": a.deceptive})  # fmt: skip
    warnings: list[str] = []
    trace: list[dict[str, str]] = [
        {"stage": "1. parse claim", "result": f"{len(a.mentions)} activity, {len(a.counts)} quantity, "
                                              f"{len(a.times)} time, {len(a.ips) + len(a.users) + len(a.hosts)} entity assertion(s)"},
        {"stage": "2. resolve citations", "result": f"{len(resolved)} in scope, {len(fabricated)} fabricated, "
                                                   f"{len(out_of_scope)} out of scope"},
    ]  # fmt: skip

    def result(verdict: str) -> ClaimResult:
        trace.append({"stage": "8. verdict", "result": verdict})
        checks["stages"] = trace
        checks["warnings"] = warnings
        # Anything short of verified/correlated, or verified with caveats, needs a human decision.
        checks["requires_review"] = verdict not in (VERIFIED, CORRELATION) or bool(warnings)
        return ClaimResult(claim.text, kind, raw, resolved, verdict, reasons, checks)

    # 2. Hard failures: anything invented, deceptive or manipulative makes the whole claim untrustworthy.
    sentences = [x for x in re.split(r"(?<=[.!?])\s+", claim.text.strip()) if len(x.strip()) > 3]
    if not claim.text.strip() or len(claim.text) > MAX_CLAIM_CHARS or len(sentences) > MAX_CLAIM_SENTENCES:
        reasons.append(f"Not an atomic claim ({len(claim.text)} characters, {len(sentences)} sentences): each "
                       "statement must be short enough to verify on its own")  # fmt: skip
        return result(UNSUPPORTED)
    if a.deceptive:
        reasons.append("Deceptive characters: " + "; ".join(a.deceptive[:3]))
        return result(UNSUPPORTED)
    if a.authority:
        reasons.append(
            "Appeals to approval or authority that is not in the telemetry (social engineering of the reviewer)"
        )
        return result(UNSUPPORTED)
    if any(p.search(claim.text) for p in INJECTION_PATTERNS):
        reasons.append("Claim text contains instructions aimed at the reviewer or validator (prompt injection)")
        return result(UNSUPPORTED)
    if fabricated:
        reasons.append(f"Cites {len(fabricated)} reference(s) that do not exist: {', '.join(fabricated[:5])}")
    if out_of_scope:
        reasons.append(f"Cites {len(out_of_scope)} real event(s) outside this investigation's scope")
    if a.unknown_entities:
        reasons.append(f"Names entities that appear in no ingested telemetry: {', '.join(a.unknown_entities[:5])}")
    if fabricated or out_of_scope or a.unknown_entities:
        return result(UNSUPPORTED)

    contradictions: list[str] = []
    unsupported: list[str] = []
    missing: list[str] = []
    scope_events = list(scope.events.values())
    high_dets = [d for d in scope.detections if d.severity in ("high", "critical")]

    # 3. Dismissals ("benign", "false positive") are conclusions, not observations.
    if a.dismissive:
        injected = [e.id for e in cited if "llm_injection_suspected" in (e.tags or [])]
        if injected:
            reasons.append("Conclusion relies on events containing adversarial instructions aimed at AI analysts")
            return result(UNSUPPORTED)
        if high_dets:
            contradictions.append(f"Dismisses activity flagged by {len(high_dets)} high/critical detection(s)")

    # 4. Absence and coverage-gap statements ("no exfiltration", "no process telemetry for db-01").
    negated = [m for m in a.mentions if m.negated]
    if a.gap_types or negated:
        hosts = a.hosts or {(e.host or "").lower() for e in scope_events}
        for t in a.gap_types:
            present = [e for e in scope_events if e.event_type == t and (e.host or "").lower() in hosts]
            if present:
                contradictions.append(f"States {t} telemetry is missing, but {len(present)} such event(s) exist")
            else:
                missing.append(f"No {t} telemetry in scope for {', '.join(sorted(hosts)) or 'these hosts'}")
        for m in negated:
            if a.gap_types and m.types & set(a.gap_types):
                continue
            hits = [e for e in scope_events if _matches(e, m) and _involves(e, a)]
            exfil_dets = [d for d in scope.detections if d.tactic == "exfiltration"] if m.external_only else []
            if hits or exfil_dets:
                n_hits = len(exfil_dets) if exfil_dets else len(hits)
                contradictions.append(f"Claims no {m.label}, but scope contains {n_hits} matching "
                                      f"{'detection(s)' if exfil_dets else 'event(s)'}")  # fmt: skip
            elif not any(e.event_type in m.types for e in scope_events):
                missing.append(f"Absence of {m.label} cannot be verified: no {'/'.join(sorted(m.types))} "
                               "telemetry in scope")  # fmt: skip
            else:
                checks.setdefault("absence_verified", []).append(m.label)

    # 4b. Attribution / intent / location conclusions cannot be established from telemetry.
    if a.conclusions and not (a.hedged or kind == "hypothesis"):
        unsupported.append(f"States an inference as fact ({', '.join(a.conclusions)}): telemetry cannot establish "
                           "who is responsible, their intent, or where they are")  # fmt: skip
    trace.append({"stage": "3. framing", "result": ", ".join(x for x, on in (
        ("hedged", a.hedged), ("correlational", a.correlational), ("dismissive", a.dismissive),
        ("conclusion", bool(a.conclusions)), ("negated", bool(negated))) if on) or "plain observation"})  # fmt: skip

    # 5. Uncited claims: only an honestly hedged hypothesis is acceptable.
    positive = [m for m in a.mentions if not m.negated]
    if not cited and not (a.gap_types or negated):
        if contradictions:
            reasons.extend(contradictions)
            return result(CONTRADICTORY)
        if unsupported and not (kind == "hypothesis" or a.hedged):
            reasons.extend(unsupported)
            return result(UNSUPPORTED)
        if kind == "hypothesis" or a.hedged:
            reasons.append("Speculative statement with no cited evidence; must not be treated as a finding")
            return result(HYPOTHESIS)
        reasons.append("States a fact but cites no evidence")
        return result(UNSUPPORTED)

    # 5b. Citation flooding: lots of citations, few of them relevant to what is claimed.
    if len(cited) >= FLOOD_MIN_CITATIONS:
        relevant = [e for e in cited if _involves(e, a) and (not positive or any(_matches(e, m) for m in positive))]
        precision = len(relevant) / len(cited)
        checks["citation_precision"] = round(precision, 3)
        if precision < FLOOD_MIN_PRECISION:
            reasons.append(f"Citation flooding: only {len(relevant)} of {len(cited)} cited events relate to the claim")
            return result(UNSUPPORTED)

    # 6. Each mentioned activity must be visible in the cited events.
    types_by_host = {h.lower(): t for h, t in scope.types_by_host().items()}
    for m in positive:
        if any(_matches(e, m) for e in cited):
            continue
        same_type_cited = [e for e in cited if e.event_type in m.types and _located(e, a)]
        in_scope = [e for e in scope_events if _matches(e, m) and _located(e, a)]
        if m.outcome and same_type_cited and not in_scope:
            other = {e.outcome for e in same_type_cited}
            contradictions.append(f"Claims {m.label}, but the cited events only show outcome {sorted(other)}")
        elif in_scope:
            unsupported.append(f"{m.label}: matching events exist in scope but none were cited")
        elif a.hosts and not any(types_by_host.get(h, set()) & m.types for h in a.hosts):
            # The named hosts never produced this kind of telemetry: a blind spot, not a disproof.
            missing.append(f"{m.label}: no {'/'.join(sorted(m.types))} telemetry exists for "
                           f"{', '.join(sorted(a.hosts))}")  # fmt: skip
        elif not any(e.event_type in m.types for e in scope_events):
            missing.append(f"{m.label}: no {'/'.join(sorted(m.types))} telemetry in scope")
        else:
            unsupported.append(f"{m.label}: no evidence of this activity for the named entities")

    # 7. Every named entity must appear in the cited evidence.
    for kind_, values in (("ip", a.ips), ("user", a.users), ("host", a.hosts)):
        for v in sorted(values):
            if any(_entity_in(e, kind_, v) for e in cited):
                continue
            seen_in_scope = any(_entity_in(e, kind_, v) for e in scope_events)
            unsupported.append(f"{kind_} {v} does not appear in the cited events"
                               + ("" if seen_in_scope else " (and is outside this investigation)"))  # fmt: skip

    # 8. Attribution: for a single observation, each named user must co-occur with a named IP/host.
    # The user must appear in an event that shows the claimed activity, so a decoy citation
    # (alice's real success + any event mentioning jsmith) cannot "prove" that jsmith logged in.
    # Only activities the citations actually show are checked here; an activity no cited event
    # shows at all was already classified in step 6 (unsupported or missing telemetry).
    shown = [m for m in positive if any(_matches(e, m) for e in cited)]
    if not (a.correlational or kind == "correlation") and a.users and (a.ips or shown):
        for u in sorted(a.users):
            linked = [e for e in cited if _entity_in(e, "user", u)
                      and (not a.ips or e.src_ip in a.ips or e.dst_ip in a.ips)
                      and (not shown or any(_matches(e, m) for m in shown))]  # fmt: skip
            if not linked and any(_entity_in(e, "user", u) for e in cited):
                what = ", ".join(m.label for m in shown) or "activity"
                target = f" from {', '.join(sorted(a.ips))}" if a.ips else ""
                contradictions.append(f"Misattribution: no cited event shows {what} by user {u}{target}")

    # 9. Quantities.
    for qty in a.counts:
        n, q = float(qty["n"]), str(qty["qualifier"])
        if qty["kind"] == "failed_auth":
            pred = [e for e in cited if e.event_type == "auth.login" and e.outcome == "failure"]
            spred = [e for e in scope_events if e.event_type == "auth.login" and e.outcome == "failure"]
            refs = [float(len(_count_filter(pred, a))), float(len(_count_filter(spred, a)))]
            tol, label = 0.0, "failed logins"
        elif qty["kind"] == "distinct_hosts":
            pred = [e for e in cited if e.event_type == "auth.login" and e.outcome == "success"]
            sel = [e for e in pred if not a.users or (e.username or "").lower() in a.users]
            refs = [
                float(len({e.host for e in sel if e.host})),
                float(len({e.host for e in sel if e.host and e.host.lower() in a.hosts})),
            ]
            tol, label = 0.0, "distinct hosts"
        elif qty["kind"] == "success_auth":
            pred = [e for e in cited if e.event_type == "auth.login" and e.outcome == "success"]
            spred = [e for e in scope_events if e.event_type == "auth.login" and e.outcome == "success"]
            refs = [float(len(_count_filter(pred, a))), float(len(_count_filter(spred, a)))]
            tol, label = 0.0, "successful logins"
        elif qty["kind"] == "times":
            # "N times": distinct events showing the claimed activity. Citing one event N times proves once.
            base = positive[:1]
            pred = [e for e in cited if (not base or _matches(e, base[0])) and _involves(e, a)]
            spred = [
                e for e in scope_events if (not base or _matches(e, base[0])) and _located(e, a) and _involves(e, a)
            ]
            refs = [float(len(pred)), float(len(spred))]
            tol, label = 0.0, f"occurrences of {base[0].label if base else 'the activity'}"
            checks["duplicate_citations"] = len(raw) - len(dict.fromkeys(raw))
        elif qty["kind"] == "flows":
            pred = _count_filter([e for e in cited if e.event_type == "network.flow"], a)
            refs, tol, label = [float(len(pred))], 0.0, "network flows"
        else:  # bytes
            pred = _count_filter([e for e in cited if e.event_type == "network.flow"], a)
            refs, tol, label = [float(sum(e.bytes_out or 0 for e in pred))], 0.05, "bytes transferred"
        checks.setdefault("count_checks", []).append({"kind": qty["kind"], "claimed": n, "evidence": refs})
        if not pred:
            unsupported.append(f"Quantity of {label} is not backed by any cited event")
        elif not _count_ok(n, q, refs, tol):
            found = [f"{r / 1024 / 1024:.1f} MB" if qty["kind"] == "bytes" else f"{r:.0f}" for r in refs]
            claimed = f"{n / 1024 / 1024:.1f} MB" if qty["kind"] == "bytes" else f"{n:.0f}"
            contradictions.append(f"Claims {q + ' ' if q else ''}{claimed} {label}; evidence shows {' / '.join(found)}")

    trace.append(
        {"stage": "4. compare attributes", "result": f"{len(checks.get('count_checks', []))} quantity check(s)"}
    )

    # 9b. Stated times must match the cited events showing the activity (timezone-converted to UTC).
    for t in a.times:
        if t.get("ambiguous"):
            unsupported.append(f"Time '{t['text']}' uses an ambiguous timezone abbreviation; state the UTC time")
            continue
        basis = [e for e in cited if any(_matches(e, m) for m in positive)] or [e for e in cited if _involves(e, a)]
        if not basis:
            unsupported.append(f"Time '{t['text']}' is not backed by any cited event")
        elif not _time_ok(t, basis):
            shown = sorted({f"{e.timestamp:%Y-%m-%d %H:%M:%S}" for e in basis})[:3]
            contradictions.append(f"Claims '{t['text']}' but the cited evidence is at {', '.join(shown)} UTC")
        elif t.get("assumed_utc"):
            warnings.append(f"Time '{t['text']}' has no timezone; it matched when read as UTC")
    trace.append(
        {
            "stage": "5. temporal checks",
            "result": f"{len(a.times)} stated time(s), {len(temporal_pairs(a))} ordering(s)",
        }
    )

    # 10. Temporal order ("X after Y", "X followed by Y").
    for earlier, later in temporal_pairs(a):
        e1 = [e.timestamp for e in cited if _matches(e, earlier)]
        e2 = [e.timestamp for e in cited if _matches(e, later)]
        if e1 and e2 and min(e1) > max(e2):
            contradictions.append(f"Order is reversed: evidence shows {later.label} before {earlier.label}")
    checks["temporal_pairs"] = [f"{x.label} -> {y.label}" for x, y in temporal_pairs(a)]

    trace.append({"stage": "6. contradictions", "result": "; ".join(contradictions) or "none"})
    trace.append(
        {
            "stage": "7. support",
            "result": f"{len(unsupported)} unsupported, {len(missing)} missing-telemetry finding(s)",
        }
    )

    # 11. Decide.
    if contradictions:
        reasons.extend(contradictions)
        return result(CONTRADICTORY)
    if unsupported:
        reasons.extend(unsupported)
        return result(UNSUPPORTED)
    if missing:
        reasons.extend(missing)
        return result(MISSING)
    if kind == "hypothesis" or a.hedged or a.dismissive:
        reasons.append("Facts referenced are consistent with evidence, but the conclusion is speculative")
        return result(HYPOTHESIS)
    # Two different *activities* (e.g. failed logins + a successful login) means facts are being linked.
    # Safety rule: if the engine recognised no activity and no quantity, it has not checked the claim's
    # substance - only that some named entity appears in a citation. That must never become "verified"
    # (found by the held-out evaluation: "alice never obtained administrative group membership").
    if not positive and not a.counts and not checks.get("absence_verified"):
        reasons.append(
            "No checkable activity or quantity was recognised; the engine cannot verify this "
            "statement, so it must not be treated as a finding"
        )
        return result(UNSUPPORTED)
    distinct_activities = {(m.types, m.outcome) for m in positive}  # "sent 5 MB" + "outbound flows" = one
    if kind == "correlation" or a.correlational or len(distinct_activities) > 1:
        reasons.append("Each fact is in the cited evidence; the relationship between them is inferred")
        return result(CORRELATION)
    reasons.append("All checkable facts are present in the cited in-scope events")
    return result(VERIFIED)


def summarize(results: list[ClaimResult]) -> dict[str, Any]:
    counts = {v: 0 for v in VERDICTS}
    for r in results:
        counts[r.verdict] += 1
    total = len(results)
    score = round(100 * sum(VERDICT_WEIGHT[r.verdict] for r in results) / total, 1) if total else 0.0
    cits = [r.checks.get("citations", {}) for r in results]
    return {
        "claims": total,
        "verdicts": counts,
        "integrity_score": score,
        "unsafe_claims": sum(counts[v] for v in UNSAFE),
        "citations_given": sum(c.get("given", 0) for c in cits),
        "citations_fabricated": sum(len(c.get("fabricated", [])) for c in cits),
        "citations_out_of_scope": sum(len(c.get("out_of_scope", [])) for c in cits),
    }


def validate_all(claims: list[ClaimInput], scope: Scope) -> tuple[list[ClaimResult], dict[str, Any]]:
    results = [validate_claim(c, scope) for c in claims]
    return results, summarize(results)
