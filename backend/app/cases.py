"""
Case workflow rules: state machine, ownership, segregation of duties.

    new -> triaged -> investigating -> awaiting_review -> resolved -> closed
                 \\________________________________________/^         |
    resolved/closed --(reopen)--> investigating  <-------------------/

Rules (all enforced server-side, all tested in tests/test_cases.py):
  * Every status change states *why* (reason, 3-2000 chars). Resolving also needs a resolution code.
  * An analyst may change a case that is unassigned or assigned to them. Changing someone else's case,
    or reassigning it away from them, needs `investigations:manage_any` (administrators).
  * Moving to awaiting_review requires a reviewer who is not the assignee. Only that reviewer (or an
    administrator) may resolve it or send it back. The assignee cannot approve their own work.
  * Closing or resolving a case never touches evidence: events, detections, analyses and the case's
    event scope are left untouched, and correlation stops extending it (OPEN_STATUSES).
"""

from typing import Final

STATUSES: Final = ("new", "triaged", "investigating", "awaiting_review", "resolved", "closed")
OPEN_STATUSES: Final = ("new", "triaged", "investigating", "awaiting_review")
RESOLUTIONS: Final = ("true_positive", "benign_true_positive", "false_positive", "duplicate", "unspecified")
PRIORITIES: Final = ("P1", "P2", "P3", "P4")
SEVERITY_PRIORITY: Final = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}

TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "new": frozenset({"triaged", "investigating"}),
    "triaged": frozenset({"investigating", "resolved"}),  # quick resolution of an obvious false positive
    "investigating": frozenset({"awaiting_review", "resolved"}),
    "awaiting_review": frozenset({"investigating", "resolved"}),
    "resolved": frozenset({"closed", "investigating"}),
    "closed": frozenset({"investigating"}),
}
REOPEN_FROM: Final = frozenset({"resolved", "closed"})


class WorkflowError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def check_transition(current: str, target: str, *, resolution: str | None, reviewer_id: str | None,
                     assignee_id: str | None) -> None:  # fmt: skip
    if target == current:
        return
    if target not in TRANSITIONS.get(current, frozenset()):
        allowed = ", ".join(sorted(TRANSITIONS.get(current, ()))) or "none"
        raise WorkflowError(409, f"cannot move a case from {current} to {target} (allowed: {allowed})")
    if target == "resolved" and resolution not in RESOLUTIONS:
        raise WorkflowError(422, f"resolving needs a resolution: one of {', '.join(RESOLUTIONS)}")
    if target == "awaiting_review":
        if not reviewer_id:
            raise WorkflowError(422, "choose a reviewer before requesting review")
        if reviewer_id == assignee_id:
            raise WorkflowError(422, "the reviewer must be someone other than the assignee")


def may_modify(*, actor_id: str, can_manage_any: bool, assignee_id: str | None, reviewer_id: str | None,
               status: str) -> bool:  # fmt: skip
    if can_manage_any or assignee_id in (None, actor_id):
        return True
    # The designated reviewer acts on a case that is waiting for them.
    return status == "awaiting_review" and reviewer_id == actor_id
