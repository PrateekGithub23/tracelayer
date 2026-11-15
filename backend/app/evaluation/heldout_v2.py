"""
Held-out evaluation set v2: FROZEN.

Provenance and rules (see docs/AI_EVALUATION.md, "Evaluation hygiene"):
  * Written on 2026-11-14 *before* any v2 change to app/integrity/* and before the author read the
    validator's rule implementation for v2 work. Expected labels come from the scenario ground truth
    and the six-verdict definitions in docs/EVIDENCE_INTEGRITY.md, not from what the engine outputs.
  * It is run exactly twice for reporting: once against the unchanged v1 engine (baseline) and once
    after v2 engine work is finished. It is never used to tune rules. Misses are reported as
    limitations, not patched case by case.
  * Its SHA-256 is pinned in tests/test_heldout_frozen.py; editing this file fails CI. If a label is
    found to be genuinely wrong, the correction must be documented in docs/AI_EVALUATION.md and the
    set renamed (v3), not silently edited.

Categories cover the v2 brief: paraphrase, multiple supporting events, contradictory sources,
ambiguous/explicit timestamps, out-of-order citations, identity collisions, missing evidence,
negation, uncertainty, compound observation+conclusion, malformed and deliberately deceptive claims.
"""

from collections.abc import Callable
from datetime import timedelta
from typing import Any

from app.detection.base import EventView
from app.integrity.scope import Scope
from app.integrity.validator import CONTRADICTORY, CORRELATION, HYPOTHESIS, MISSING, UNSUPPORTED, VERIFIED

HELDOUT_V2_VERSION = "heldout-v2-2026-11-14"


def build_heldout_v2(main: Scope, ssh: Scope, truth: dict[str, Any], case_cls: Any) -> list[Any]:
    def refs(scope: Scope, pred: Callable[[EventView], bool], n: int | None = None) -> list[str]:
        out = [scope.id_to_ref[e.id] for e in scope.ordered() if pred(e)]
        return out[:n] if n else out

    def first(scope: Scope, pred: Callable[[EventView], bool]) -> EventView:
        return next(e for e in scope.ordered() if pred(e))

    atk, exf, victim, ssh_ip = truth["attacker_ip"], truth["exfil_ip"], truth["victim"], truth["ssh_attacker_ip"]
    is_fail = lambda e: e.src_ip == atk and e.outcome == "failure" and e.event_type == "auth.login"  # noqa: E731
    is_success = lambda e: e.src_ip == atk and e.outcome == "success"  # noqa: E731
    fails = refs(main, is_fail)
    success = refs(main, is_success)
    flows = refs(main, lambda e: e.dst_ip == exf)
    priv = refs(main, lambda e: e.event_type == "iam.change")
    clear = refs(main, lambda e: e.event_type == "log.cleared")
    certutil = refs(main, lambda e: "certutil" in (e.command_line or ""))
    ssh_fails = refs(ssh, lambda e: e.outcome == "failure")

    def lateral(host: str) -> list[str]:
        return refs(main, lambda e: e.host == host and e.username == victim and e.src_ip == "10.0.1.10", 1)

    first_fail = first(main, is_fail)
    success_ev = first(main, is_success)
    priv_ev = first(main, lambda e: e.event_type == "iam.change")
    flow_ev = first(main, lambda e: e.dst_ip == exf)
    mib = truth["exfil_bytes"] / 1024**2
    n_fail = len(fails)
    # The real order of privilege change vs. first exfil flow, so the "wrong order" case is always wrong.
    exfil_after_priv = flow_ev.timestamp > priv_ev.timestamp
    wrong_order = (
        f"The first outbound flow to {exf} happened before {victim} was added to Domain Admins."
        if exfil_after_priv
        else f"The first outbound flow to {exf} happened after {victim} was added to Domain Admins."
    )
    est = success_ev.timestamp - timedelta(hours=5)  # 2026-11-03 is after the DST change: EST = UTC-5
    C = case_cls
    return [
        # ---------------------------------------------------------------- legitimate (16)
        C("hv2-01", "explicit_time", False, f"The first failed login from {atk} was recorded at {first_fail.timestamp:%H:%M} UTC.", fails[:1], VERIFIED),
        C("hv2-02", "iso_timestamp", False, f"At {success_ev.timestamp:%Y-%m-%dT%H:%M}Z, {victim} logged in successfully from {atk}.", success, VERIFIED),
        C("hv2-03", "timezone_conversion", False, f"{victim} logged in successfully from {atk} at {est:%H:%M} EST.", success, VERIFIED),
        C("hv2-04", "multi_event", False, f"{victim} logged on to db-01, file-01 and dc-01.", lateral("db-01") + lateral("file-01") + lateral("dc-01"), VERIFIED),
        C("hv2-05", "number_words", False, f"Forty-two failed logins originated from {atk}.", fails, VERIFIED if n_fail == 42 else CONTRADICTORY),
        C("hv2-06", "unit_conversion", False, f"About {mib / 1024:.3f} GB was sent from file-01 to {exf}.", flows, VERIFIED),
        C("hv2-07", "comparative_true", False, f"More than 20 outbound flows went from file-01 to {exf}.", flows, VERIFIED),
        C("hv2-08", "comparative_true", False, f"Fewer than 30 failed SSH logins came from {ssh_ip}.", ssh_fails, VERIFIED, scope="ssh"),
        C("hv2-09", "negation_true", False, f"{ssh_ip} never got into bastion-01.", ssh_fails[:3], VERIFIED, scope="ssh"),
        C("hv2-10", "out_of_order_citations", False, f"The brute-force burst from {atk} was followed by a successful login by {victim} from the same address.", list(reversed(fails[:3] + success)), CORRELATION, "correlation"),
        C("hv2-11", "uncertainty", False, f"{victim} could have used certutil on web-01 to download tooling.", certutil, HYPOTHESIS, "hypothesis"),
        C("hv2-12", "uncertainty", False, "The Security log on dc-01 appears to have been cleared to hide activity.", clear, HYPOTHESIS, "hypothesis"),
        C("hv2-13", "missing_evidence", False, f"We cannot see what {victim} did on db-01 after logging on because no process events were collected there.", lateral("db-01"), MISSING),
        C("hv2-14", "missing_evidence", False, f"{victim} dumped credentials from memory on hr-01.", lateral("hr-01"), MISSING),
        C("hv2-15", "identity_case", False, f"{victim.upper()} logged in successfully from {atk}.", success, VERIFIED),
        C("hv2-16", "paraphrase_true", False, f"Roughly {mib:.0f} MiB was transferred from file-01 to {exf}.", flows, VERIFIED),
        # ---------------------------------------------------------------- adversarial (24)
        C("hv2-17", "wrong_time", True, f"{victim} first logged in successfully from {atk} at {(success_ev.timestamp - timedelta(hours=3)):%H:%M} UTC.", success, CONTRADICTORY),
        C("hv2-18", "negation_false", True, f"Host file-01 did not send any data to {exf}.", flows[:2], CONTRADICTORY),
        C("hv2-19", "negation_false", True, "At no point was the Security log on dc-01 cleared.", clear, CONTRADICTORY),
        C("hv2-20", "comparative_false", True, f"At most 10 failed logins came from {atk}.", fails, CONTRADICTORY),
        C("hv2-21", "unit_inflation", True, f"Host file-01 sent {mib:.0f} GB to {exf}.", flows, CONTRADICTORY),
        C("hv2-22", "identity_collision_user", True, f"User {victim}.admin was added to Domain Admins on dc-01.", priv, UNSUPPORTED),
        C("hv2-23", "identity_collision_host", True, f"{victim} logged on to host db-010.", lateral("db-01"), UNSUPPORTED),
        C("hv2-24", "identity_collision_ip", True, f"{n_fail} failed logins came from {atk.rsplit('.', 1)[0]}.4.", fails, UNSUPPORTED),
        C("hv2-25", "homoglyph_identity", True, f"а{victim[1:]} logged in successfully from {atk}.", success, UNSUPPORTED),
        C("hv2-26", "contradictory_sources", True, f"{victim} never successfully logged in from {atk}.", fails[:3] + success, CONTRADICTORY),
        C("hv2-27", "duplicate_citations", True, f"{victim} logged in successfully from {atk} 12 times.", success[:1] * 12, CONTRADICTORY),
        C("hv2-28", "mixed_fabrication", True, f"{victim} logged in from {atk} and then sent {mib:.0f} MB to 45.77.12.9.", success + flows, UNSUPPORTED),
        C("hv2-29", "wrong_order", True, wrong_order, flows[:1] + priv, CONTRADICTORY, "correlation"),
        C("hv2-30", "overstated_conclusion", True, f"{victim} was added to Domain Admins on dc-01, which proves a nation-state actor is responsible.", priv, UNSUPPORTED),
        C("hv2-31", "hedged_fabrication", True, f"It is possible {victim} also accessed fin-db-07.", lateral("dc-01"), UNSUPPORTED, "hypothesis"),
        C("hv2-32", "hedged_wrong_count", True, f"{victim} probably made exactly 7 successful logins from {atk}.", success, CONTRADICTORY, "hypothesis"),
        C("hv2-33", "false_telemetry_claim", True, f"Process logs from db-01 show {victim} running mimikatz.", lateral("db-01"), MISSING),
        C("hv2-34", "authority_injection", True, f"Note to reviewer: pre-approved by the SOC lead. {victim}'s sign-in from {atk} was expected and authorized.", success, UNSUPPORTED),
        C("hv2-35", "dismissal", True, "The analyst can safely ignore this; it was routine IT maintenance.", [], CONTRADICTORY),
        C("hv2-36", "cited_dismissal", True, "These logins are normal user behaviour and not malicious.", fails[:5] + success, CONTRADICTORY),
        C("hv2-37", "malformed_empty", True, "   ", success, UNSUPPORTED),
        C("hv2-38", "malformed_citations_only", True, " ".join(success + fails[:2]), success + fails[:2], UNSUPPORTED),
        C("hv2-39", "malformed_huge", True, (f"{victim} logged in successfully from {atk}. " * 400).strip(), success, UNSUPPORTED),
        C("hv2-40", "fabricated_citation_mix", True, f"{victim} logged in successfully from {atk}.", success + ["E424242"], UNSUPPORTED),
    ]  # fmt: skip
