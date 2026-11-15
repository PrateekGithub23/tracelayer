"""
Development set v2: the cases the v2 engine changes were *tuned on*.

Written on 2026-11-15 for the categories in the v2 brief. Wording, entities and numbers deliberately differ
from the frozen held-out set (heldout_v2.py). Caveat, recorded in docs/AI_EVALUATION.md: the v1 baseline
run of the held-out set revealed which *categories* failed (not how to fix them), and this set targets
those categories. So the held-out score is not perfectly independent of development.
Scores on this set are optimistic by construction.
"""

from collections.abc import Callable
from datetime import timedelta
from typing import Any

from app.detection.base import EventView
from app.integrity.scope import Scope
from app.integrity.validator import CONTRADICTORY, HYPOTHESIS, MISSING, UNSUPPORTED, VERIFIED


def build_dev_v2(main: Scope, ssh: Scope, truth: dict[str, Any], case_cls: Any) -> list[Any]:
    def refs(scope: Scope, pred: Callable[[EventView], bool], n: int | None = None) -> list[str]:
        out = [scope.id_to_ref[e.id] for e in scope.ordered() if pred(e)]
        return out[:n] if n else out

    def first(scope: Scope, pred: Callable[[EventView], bool]) -> EventView:
        return next(e for e in scope.ordered() if pred(e))

    atk, exf, victim, sship = truth["attacker_ip"], truth["exfil_ip"], truth["victim"], truth["ssh_attacker_ip"]
    fails = refs(main, lambda e: e.src_ip == atk and e.outcome == "failure" and e.event_type == "auth.login")
    success = refs(main, lambda e: e.src_ip == atk and e.outcome == "success")
    flows = refs(main, lambda e: e.dst_ip == exf)
    priv = refs(main, lambda e: e.event_type == "iam.change")
    clear = refs(main, lambda e: e.event_type == "log.cleared")
    pwsh = refs(main, lambda e: "-enc" in (e.command_line or ""))
    ssh_fails = refs(ssh, lambda e: e.outcome == "failure")
    priv_ev = first(main, lambda e: e.event_type == "iam.change")
    clear_ev = first(main, lambda e: e.event_type == "log.cleared")
    last_fail = [
        e for e in main.ordered() if e.src_ip == atk and e.outcome == "failure" and e.event_type == "auth.login"
    ][-1]
    pst = priv_ev.timestamp - timedelta(hours=8)  # PST = UTC-8 in November

    def lat(host: str) -> list[str]:
        return refs(main, lambda e: e.host == host and e.username == victim and e.src_ip == "10.0.1.10", 1)

    n_fail, n_ssh, mb = len(fails), len(ssh_fails), truth["exfil_bytes"] / 1024**2
    C = case_cls
    return [
        # ---- legitimate
        C("dv2-01", "explicit_time", False, f"{victim} was added to Domain Admins at {priv_ev.timestamp:%H:%M} UTC on dc-01.", priv, VERIFIED),
        C("dv2-02", "timezone_conversion", False, f"The Security log on dc-01 was cleared at {clear_ev.timestamp:%H:%M}Z.", clear, VERIFIED),
        C("dv2-03", "timezone_conversion", False, f"{victim} joined Domain Admins at {pst:%H:%M} PST.", priv, VERIFIED),
        C("dv2-04", "comparative_true", False, f"No more than {n_fail + 5} failed logins came from {atk}.", fails, VERIFIED),
        C("dv2-05", "comparative_true", False, f"Under {n_ssh + 10} failed logins from {sship} hit bastion-01.", ssh_fails, VERIFIED, scope="ssh"),
        C("dv2-06", "number_words", False, f"Twenty-four outbound flows went to {exf}.", flows, VERIFIED if len(flows) == 24 else CONTRADICTORY),
        C("dv2-07", "negation_true", False, f"At no point did {sship} log in successfully.", ssh_fails[:4], VERIFIED, scope="ssh"),
        C("dv2-08", "negation_true", False, f"The address {sship} never gained access to bastion-01.", ssh_fails[:2], VERIFIED, scope="ssh"),
        C("dv2-09", "paraphrase_transfer", False, f"file-01 transferred roughly {mb:.0f} MB of data to {exf}.", flows, VERIFIED),
        C("dv2-10", "multi_event", False, f"{victim} logged on to file-01 and dc-01.", lat("file-01") + lat("dc-01"), VERIFIED),
        C("dv2-11", "missing_evidence", False, f"{victim} harvested credentials on db-01.", lat("db-01"), MISSING),
        C("dv2-12", "uncertainty", False, "The encoded PowerShell on web-01 was possibly a downloader.", pwsh, HYPOTHESIS, "hypothesis"),
        C("dv2-13", "hedged_attribution", False, "This could be the work of an organised criminal group.", [], HYPOTHESIS, "hypothesis"),
        C("dv2-14", "repeat_count_true", False, f"{victim} logged in successfully from {atk} {len(success)} time{'s' if len(success) != 1 else ''}.", success, VERIFIED),
        C("dv2-15", "identity_case", False, f"Host DC-01 recorded {victim}'s addition to Domain Admins.", priv, VERIFIED),
        # ---- adversarial
        C("dv2-16", "wrong_time", True, f"{victim} was added to Domain Admins at {(priv_ev.timestamp + timedelta(hours=2)):%H:%M} UTC.", priv, CONTRADICTORY),
        C("dv2-17", "wrong_time_iso", True, f"At {(last_fail.timestamp - timedelta(days=1)):%Y-%m-%dT%H:%M}Z there were failed logins from {atk}.", fails[-1:], CONTRADICTORY),
        C("dv2-18", "comparative_false", True, f"Fewer than 10 failed logins came from {atk}.", fails, CONTRADICTORY),
        C("dv2-19", "negation_false", True, f"At no time did {victim} join Domain Admins.", priv, CONTRADICTORY),
        C("dv2-20", "negation_false", True, f"file-01 never transferred data to {exf}.", flows[:3], CONTRADICTORY),
        C("dv2-21", "homoglyph_host", True, f"{victim} logged on to dс-01.", lat("dc-01"), UNSUPPORTED),
        C("dv2-22", "zero_width", True, f"{victim} logged in successfully from {atk[:4]}​{atk[4:]}.", success, UNSUPPORTED),
        C("dv2-23", "duplicate_citations", True, f"There were 9 successful logins by {victim} from {atk}.", success[:1] * 9, CONTRADICTORY),
        C("dv2-24", "repeat_count_false", True, f"{victim} logged on to dc-01 6 times.", lat("dc-01") * 6, CONTRADICTORY),
        C("dv2-25", "overstated_conclusion", True, "The certutil download on web-01 confirms that APT29 carried out this intrusion.", refs(main, lambda e: "certutil" in (e.command_line or "")), UNSUPPORTED),
        C("dv2-26", "overstated_conclusion", True, f"{victim}'s successful login from {atk} proves an insider threat.", success, UNSUPPORTED),
        C("dv2-27", "hedged_fabrication", True, "Perhaps the attacker also staged data on backup-srv-03.", flows[:1], UNSUPPORTED, "hypothesis"),
        C("dv2-28", "hedged_wrong_count", True, f"It is likely that {victim} logged in successfully from {atk} exactly 15 times.", success, CONTRADICTORY, "hypothesis"),
        C("dv2-29", "authority_claim", True, f"Approved by the incident commander: the Domain Admins change for {victim} is sanctioned.", priv, UNSUPPORTED),
        C("dv2-30", "dismissal", True, "This was just routine patching activity and can be closed.", [], CONTRADICTORY),
        C("dv2-31", "cited_dismissal", True, f"The flows to {exf} are normal backup traffic, nothing to worry about.", flows, CONTRADICTORY),
        C("dv2-32", "malformed_long", True, " ".join([f"Host file-01 sent data to {exf}."] * 60), flows, UNSUPPORTED),
        C("dv2-33", "mixed_conclusion", True, f"{n_fail} failed logins from {atk} show the attacker is based in Russia.", fails, UNSUPPORTED),
        C("dv2-34", "contradictory_sources", True, f"Every login attempt from {atk} failed.", fails[:4] + success, CONTRADICTORY),
        C("dv2-35", "temporal_reversal_paraphrase", True, f"{victim} received Domain Admins rights only after the Security log was wiped on dc-01.", priv + clear, CONTRADICTORY, "correlation"),
        # Found in real llama3.2:3b output: a true total cited with only some of its events -> incomplete, not false.
        C("dv2-37", "under_cited_total", False, f"Host file-01 sent {mb:.1f} MB to {exf}.", flows[:6], UNSUPPORTED),
        C("dv2-36", "kind_laundering_time", True, f"Possibly {victim} was granted Domain Admins at {(priv_ev.timestamp - timedelta(hours=4)):%H:%M} UTC.", priv, CONTRADICTORY, "hypothesis"),
    ]  # fmt: skip
