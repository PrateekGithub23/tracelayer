"""
Hash-chained audit log for analyst and system decisions.

Every approval, rejection, status change and export is recorded with the hash
of the previous entry, so the review history of an investigation can be
verified in the same way as the evidence itself.
"""

import threading
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrity.provenance import GENESIS_HASH, audit_entry_hash
from app.models import AuditEntry, utcnow

_AUDIT_LOCK = threading.Lock()


def _payload(entry: AuditEntry) -> dict[str, Any]:
    return {
        "timestamp": entry.timestamp.isoformat(),
        "actor": entry.actor,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "details": entry.details,
    }


def record(
    db: Session, *, actor: str, action: str, target_type: str, target_id: str, details: dict[str, Any] | None = None
) -> AuditEntry:
    """Append an entry. The caller owns the transaction (commit happens with the change it describes)."""
    with _AUDIT_LOCK:
        prev = db.scalar(select(AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).limit(1)) or GENESIS_HASH
        entry = AuditEntry(
            timestamp=utcnow(), actor=actor[:100], action=action, target_type=target_type,
            target_id=target_id, details=details or {}, prev_hash=prev,
        )  # fmt: skip
        entry.entry_hash = audit_entry_hash(prev, _payload(entry))
        db.add(entry)
        db.flush()
        return entry


def verify_audit_chain(db: Session) -> dict[str, Any]:
    prev = GENESIS_HASH
    checked = 0
    broken: list[int] = []
    for entry in db.scalars(select(AuditEntry).order_by(AuditEntry.id)):
        checked += 1
        if entry.prev_hash != prev or audit_entry_hash(prev, _payload(entry)) != entry.entry_hash:
            broken.append(entry.id)
        prev = entry.entry_hash
    return {"ok": not broken, "entries_checked": checked, "broken_entries": broken[:100], "head": prev}
