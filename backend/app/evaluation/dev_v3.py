"""
Development set v3: the cases the v3 engine changes were tuned on.

Written after the held-out v3 baseline run, which revealed failure *categories* (benign-washing with an
article, unknown subject identities, identity swaps, universal and negated paraphrases, hedged alternative
explanations). Wording, entities and structures here deliberately differ from heldout_v3.py, and the
held-out file is never read while tuning. Scores here are optimistic by construction.
"""

from collections.abc import Callable
from typing import Any

from app.detection.base import EventView
from app.integrity.scope import Scope
from app.integrity.validator import CONTRADICTORY, CORRELATION, HYPOTHESIS, MISSING, UNSUPPORTED, VERIFIED


def build_dev_v3(main: Scope, ssh: Scope, truth: dict[str, Any], case_cls: Any) -> list[Any]:
    def refs(scope: Scope, pred: Callable[[EventView], bool], n: int | None = None) -> list[str]:
        out = [scope.id_to_ref[e.id] for e in scope.ordered() if pred(e)]
        return out[:n] if n else out

    atk, exf, victim, sship = truth["attacker_ip"], truth["exfil_ip"], truth["victim"], truth["ssh_attacker_ip"]
    fails = refs(main, lambda e: e.src_ip == atk and e.outcome == "failure" and e.event_type == "auth.login")
    success = refs(main, lambda e: e.src_ip == atk and e.outcome == "success")
    flows = refs(main, lambda e: e.dst_ip == exf)
    priv = refs(main, lambda e: e.event_type == "iam.change")
    pwsh = refs(main, lambda e: "-enc" in (e.command_line or ""))
    certutil = refs(main, lambda e: "certutil" in (e.command_line or ""))
    ssh_fails = refs(ssh, lambda e: e.outcome == "failure")

    def lat(host: str) -> list[str]:
        return refs(main, lambda e: e.host == host and e.username == victim and e.src_ip == "10.0.1.10", 1)

    n_ssh = len(ssh_fails)
    C = case_cls
    return [
        # ---- benign-washing stated as fact vs offered as an alternative
        C("d3-01", "benign_wash_article", True, "The encoded PowerShell on web-01 was just a normal maintenance script.", pwsh, CONTRADICTORY),
        C("d3-02", "benign_wash_article", True, f"The transfer to {exf} was an authorized backup job.", flows, CONTRADICTORY),
        C("d3-03", "benign_wash_looks_like", True, "These sign-ins look like routine user activity, so the case can be closed.", success, CONTRADICTORY),
        C("d3-04", "hedged_alternative", False, f"One alternative is that the transfer to {exf} could have been an approved backup; this needs confirmation.", flows, HYPOTHESIS, "hypothesis"),
        C("d3-05", "hedged_alternative", False, "It is possible the PowerShell on web-01 was a legitimate admin script.", pwsh, HYPOTHESIS, "hypothesis"),
        # ---- identities in subject position and identity swaps
        C("d3-06", "unknown_subject", True, f"Svc_backup logged in successfully from {atk}.", success, UNSUPPORTED),
        C("d3-07", "unknown_subject", True, "Helpdesk ran certutil on web-01.", certutil, UNSUPPORTED),
        # Identity swaps are "not shown" (unsupported), consistent with v1's adv-19: alice's event does not
        # prove root did not also act. A decoy citation (v1 adv-20) is what makes it contradictory.
        C("d3-08", "identity_swap", True, "root was added to Domain Admins on dc-01.", priv, UNSUPPORTED),
        C("d3-09", "identity_swap", True, "admin logged on to file-01 from 10.0.1.10.", lat("file-01"), UNSUPPORTED),
        C("d3-10", "known_subject_ok", False, f"{victim.capitalize()} signed in to dc-01 from 10.0.1.10.", lat("dc-01"), VERIFIED),
        # ---- universal and negated paraphrases
        C("d3-11", "universal_fail_true", False, f"bastion-01 denied all sign-in attempts from {sship}.", ssh_fails, VERIFIED, scope="ssh"),
        C("d3-12", "universal_success_false", True, f"Every authentication from {atk} was successful.", fails[:3] + success, CONTRADICTORY),
        C("d3-13", "negation_connect_false", True, f"{victim} did not connect to dc-01.", lat("dc-01"), CONTRADICTORY),
        C("d3-15", "paraphrase_used_to", False, f"Credentials for {victim} were used to sign in from {atk}.", success, VERIFIED),
        C("d3-16", "paraphrase_attempts_failed", False, f"There were {n_ssh} login attempts that failed from {sship}.", ssh_fails, VERIFIED, scope="ssh"),
        # ---- regressions the v3 changes must not break
        C("d3-17", "true_observation", False, f"Host file-01 sent data to {exf} in {len(flows)} outbound flows.", flows, VERIFIED),
        C("d3-18", "dismissal_uncited", True, "Nothing to see here, just normal traffic.", [], CONTRADICTORY),
        C("d3-19", "missing", False, f"{victim} executed commands on db-01.", lat("db-01"), MISSING),
        C("d3-20", "correlation", False, f"After the failed logins, {victim} signed in from {atk}.", fails[:2] + success, CORRELATION, "correlation"),
    ]  # fmt: skip
