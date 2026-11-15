"""
Role-based access control.

Permissions are the unit of enforcement; roles are named bundles of permissions. Routes depend on a
permission (never on a role name), so changing what a role may do is a one-line change here and the
authorization matrix test (tests/test_rbac_matrix.py) shows the effect on every endpoint.
"""

from typing import Final

ROLES: Final = ("admin", "analyst", "viewer")

VIEWER: Final = frozenset({
    "events:read", "detections:read", "investigations:read", "analyses:read", "metrics:read",
    "datasets:read", "filters:own", "account:own",
})  # fmt: skip

ANALYST: Final = VIEWER | frozenset({
    "investigations:write",   # status, priority, assignment (subject to ownership rules in cases.py)
    "comments:write",         # comments and investigation notes
    "evidence:pin",           # attach event references to a case
    "analyses:create",        # generate an AI / deterministic draft
    "claims:review",          # accept / reject individual claims
    "analyses:approve",       # approve or reject a reviewed analysis
    "export:create",          # download reports and evidence bundles
    "integrity:validate",     # validation playground
    "pipeline:run",           # re-run detection and correlation over existing events
})  # fmt: skip

ADMIN: Final = ANALYST | frozenset({
    "users:manage", "settings:manage", "audit:read", "ingest:write", "datasets:manage",
    "synthetic:generate", "evaluation:run", "benchmark:run", "integrity:verify", "investigations:manage_any",
})  # fmt: skip

PERMISSIONS: Final[dict[str, frozenset[str]]] = {"admin": ADMIN, "analyst": ANALYST, "viewer": VIEWER}


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, frozenset())
