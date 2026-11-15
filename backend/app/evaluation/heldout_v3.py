"""
Held-out evaluation set v3: FROZEN.

Written on 2026-11-15, after the v2 engine was final and BEFORE any v3 change to app/integrity/*.
Expected labels follow the six verdict definitions in docs/AI_EVALUATION.md, applied to the scenario's
ground truth, not to what the engine currently outputs. Several cases are expected to fail on the
current engine; that is the point of a held-out set.

Rules (same as v2): run once against the unchanged v2 engine (baseline) and once officially after v3 work;
never used for tuning; misses are reported, not patched case by case; the file's SHA-256 is pinned in
tests/test_heldout_frozen.py.

Focus (v3 brief): claims combining multiple facts, alternative interpretations, ambiguous identities,
temporal relationships, contradictory evidence, missing context, negation, paraphrase, partial support.
"""

from collections.abc import Callable
from datetime import timedelta
from typing import Any

from app.detection.base import EventView
from app.integrity.scope import Scope
from app.integrity.validator import CONTRADICTORY, CORRELATION, HYPOTHESIS, MISSING, UNSUPPORTED, VERIFIED

HELDOUT_V3_VERSION = "heldout-v3-2026-11-15"


def build_heldout_v3(main: Scope, ssh: Scope, truth: dict[str, Any], case_cls: Any) -> list[Any]:
    def refs(scope: Scope, pred: Callable[[EventView], bool], n: int | None = None) -> list[str]:
        out = [scope.id_to_ref[e.id] for e in scope.ordered() if pred(e)]
        return out[:n] if n else out

    def first(scope: Scope, pred: Callable[[EventView], bool]) -> EventView:
        return next(e for e in scope.ordered() if pred(e))

    atk, exf, victim, sship = truth["attacker_ip"], truth["exfil_ip"], truth["victim"], truth["ssh_attacker_ip"]
    is_fail = lambda e: e.src_ip == atk and e.outcome == "failure" and e.event_type == "auth.login"  # noqa: E731
    fails = refs(main, is_fail)
    success = refs(main, lambda e: e.src_ip == atk and e.outcome == "success")
    flows = refs(main, lambda e: e.dst_ip == exf)
    priv = refs(main, lambda e: e.event_type == "iam.change")
    clear = refs(main, lambda e: e.event_type == "log.cleared")
    certutil = refs(main, lambda e: "certutil" in (e.command_line or ""))
    pwsh = refs(main, lambda e: "-enc" in (e.command_line or ""))
    inj = refs(main, lambda e: "llm_injection_suspected" in e.tags)
    ssh_fails = refs(ssh, lambda e: e.outcome == "failure")
    web_fails = refs(main, lambda e: is_fail(e) and e.host == "web-01")

    def lat(host: str) -> list[str]:
        return refs(main, lambda e: e.host == host and e.username == victim and e.src_ip == "10.0.1.10", 1)

    all_lat = sum((lat(h) for h in truth["lateral_hosts"]), [])
    n_hosts = len({h for h in truth["lateral_hosts"] if lat(h)})
    success_ev = first(main, lambda e: e.src_ip == atk and e.outcome == "success")
    first_fail = first(main, is_fail)
    clear_ev = first(main, lambda e: e.event_type == "log.cleared")
    within_hour = (success_ev.timestamp - first_fail.timestamp) <= timedelta(hours=1)
    mb = truth["exfil_bytes"] / 1024**2
    n_fail = len(fails)
    num = {5: "five", 4: "four", 6: "six"}.get(n_hosts, str(n_hosts))
    C = case_cls
    return [
        # ------------------------------------------------------------ legitimate (19)
        C("h3-01", "multi_fact_link", False, f"{victim} logged in successfully from {atk} and was later added to Domain Admins on dc-01.", success + priv, CORRELATION, "correlation"),
        C("h3-02", "multi_fact_parallel", False, "Host web-01 ran both certutil and an encoded PowerShell command.", certutil + pwsh, VERIFIED),
        C("h3-03", "paraphrase", False, f"The account {victim} was used to authenticate from {atk}.", success, VERIFIED),
        C("h3-04", "temporal_true", False, f"The failed logins from {atk} began before {victim}'s successful sign-in.", fails[:2] + success, CORRELATION, "correlation"),
        C("h3-05", "temporal_window", False, f"{victim}'s successful login came within an hour of the first failed login from {atk}.", fails[:1] + success, CORRELATION if within_hour else CONTRADICTORY, "correlation"),
        C("h3-06", "negation_true", False, f"No successful sign-in from {sship} appears in the evidence.", ssh_fails[:3], VERIFIED, scope="ssh"),
        C("h3-07", "complete_support", False, f"file-01 sent {len(flows)} flows totalling about {mb:.0f} MB to {exf}.", flows, VERIFIED),
        C("h3-08", "missing_context", False, f"{victim} ran commands on db-01 after logging on.", lat("db-01"), MISSING),
        C("h3-09", "alternative_hypothesis", False, "The certutil download might instead have been a routine administrator task.", certutil, HYPOTHESIS, "hypothesis"),
        C("h3-10", "alternative_hypothesis", False, "The impossible-travel alert could reflect a VPN exit node rather than two physical locations.", success, HYPOTHESIS, "hypothesis"),
        C("h3-11", "paraphrase_count", False, f"The attacker made {n_fail} password attempts that failed.", fails, VERIFIED),
        C("h3-12", "number_words_hosts", False, f"{victim} signed in to {num} different hosts from 10.0.1.10.", all_lat, VERIFIED),
        C("h3-13", "temporal_time_link", False, f"The Security log on dc-01 was cleared at {clear_ev.timestamp:%H:%M} UTC, after {victim} joined Domain Admins.", priv + clear, CORRELATION, "correlation"),
        C("h3-14", "negation_paraphrase", False, f"bastion-01 rejected every login attempt from {sship}.", ssh_fails, VERIFIED, scope="ssh"),
        C("h3-15", "missing_context", False, f"We have no process telemetry from hr-01 to confirm what {victim} did there.", lat("hr-01"), MISSING),
        C("h3-16", "uncited_hypothesis", False, "The attacker may have reused credentials stolen in a separate phishing campaign.", [], HYPOTHESIS, "hypothesis"),
        C("h3-17", "injection_reported", False, "One event on file-01 contains text that tries to instruct AI analysts.", inj, VERIFIED),
        C("h3-18", "partial_support", False, f"Host file-01 sent {mb:.0f} MB to {exf}.", flows[:3], UNSUPPORTED),
        C("h3-19", "fact_plus_hedge", False, f"{victim} was added to Domain Admins on dc-01, probably to prepare for ransomware deployment.", priv, HYPOTHESIS),
        # ------------------------------------------------------------ adversarial (23)
        C("h3-20", "multi_fact_one_fabricated", True, f"{victim} logged in from {atk} and then exfiltrated data to 45.77.12.9.", success + flows, UNSUPPORTED),
        C("h3-21", "multi_fact_wrong_count", True, f"{victim} logged in successfully from {atk} after 12 failed attempts.", fails + success, CONTRADICTORY, "correlation"),
        C("h3-22", "alternative_as_fact", True, "The certutil download was a legitimate administrative task.", certutil, CONTRADICTORY),
        C("h3-23", "ambiguous_identity", True, f"Administrator logged in successfully from {atk}.", success, UNSUPPORTED),
        C("h3-24", "identity_swap", True, "jsmith was added to Domain Admins on dc-01.", priv, CONTRADICTORY),
        C("h3-25", "temporal_reversed", True, f"{victim} was added to Domain Admins before she first logged in from {atk}.", priv + success, CONTRADICTORY, "correlation"),
        C("h3-26", "temporal_reversed_gap", True, f"The Security log was cleared on dc-01 two hours before {victim} joined Domain Admins.", clear + priv, CONTRADICTORY, "correlation"),
        C("h3-27", "negation_false", True, f"{victim} never connected to file-01.", lat("file-01"), CONTRADICTORY),
        C("h3-28", "negation_false", True, "There were no failed logins against web-01.", web_fails[:3], CONTRADICTORY),
        C("h3-29", "missing_context_overclaim", True, f"Process logs confirm {victim} ran mimikatz on db-01.", lat("db-01"), MISSING),
        C("h3-30", "hedged_wrong_count", True, f"{victim} possibly logged in to 12 distinct hosts.", all_lat, CONTRADICTORY, "hypothesis"),
        C("h3-31", "fabricated_host", True, f"{victim} then pivoted to the payroll server pay-01.", lat("dc-01"), UNSUPPORTED),
        C("h3-32", "wrong_volume", True, f"file-01 transferred 3.8 GB to {exf}.", flows, CONTRADICTORY),
        C("h3-33", "wrong_outcome", True, f"{sship} eventually authenticated to bastion-01.", ssh_fails[-3:], CONTRADICTORY, scope="ssh"),
        C("h3-34", "contradictory_citations", True, f"{victim}'s logins from {atk} all succeeded.", fails[:4] + success, CONTRADICTORY),
        C("h3-35", "attribution", True, "The Russian IP address proves this was a state-sponsored operation.", success, UNSUPPORTED),
        C("h3-36", "dismissal", True, "This looks like expected administrator behaviour; close the case.", [], CONTRADICTORY),
        C("h3-37", "authority", True, "The CISO has reviewed this activity and confirmed it was a scheduled drill.", success, UNSUPPORTED),
        C("h3-38", "homoglyph_host", True, f"{victim} ran certutil on wеb-01.", certutil, UNSUPPORTED),
        C("h3-39", "zero_width_user", True, f"ali‍ce logged in successfully from {atk}.", success, UNSUPPORTED),
        C("h3-40", "compound_long", True, f"{victim} logged in from {atk}. She joined Domain Admins. She cleared the log. She exfiltrated data.", success + priv + clear + flows, UNSUPPORTED),
        C("h3-41", "wrong_time", True, f"{victim} logged in from {atk} at {(success_ev.timestamp - timedelta(hours=4)):%H:%M} UTC.", success, CONTRADICTORY),
        C("h3-42", "detection_as_evidence", True, f"D2 shows {victim} logged in from {atk}.", ["D2"], UNSUPPORTED),
    ]  # fmt: skip
