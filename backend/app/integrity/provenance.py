"""
Provenance primitives: canonical hashing, Merkle roots and the ingest ledger chain.

Why these three pieces?
* record_hash  -> each raw record gets a stable fingerprint. It is the dedup key
                  AND the tamper-evidence check (recompute and compare).
* merkle_root  -> one digest commits to the exact set of events in a batch, so a
                  deleted or injected event changes the batch root.
* chain_hash   -> each batch commits to the previous one, so batches cannot be
                  silently removed, reordered or rewritten after the fact.

This is tamper-*evident*, not tamper-*proof*: someone with write access to the
database could recompute every hash. Exporting the chain head (included in
every evidence bundle) to an external location closes that gap.
"""

import hashlib
import json
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8 preserved."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def record_hash(source: str, raw: dict[str, Any]) -> str:
    """Fingerprint of a raw record. The source is included: the same bytes from two
    different collectors are two different observations."""
    return sha256_hex(f"{source}\n{canonical_json(raw)}")


def merkle_root(leaf_hashes: list[str]) -> str:
    """Binary Merkle root over *sorted* leaves (order-independent set commitment)."""
    if not leaf_hashes:
        return sha256_hex(b"")
    level = sorted(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate the last node on odd levels (Bitcoin-style)
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def batch_chain_hash(
    prev_chain_hash: str,
    seq: int,
    batch_id: str,
    source: str,
    parser: str,
    merkle: str,
    accepted_count: int,
    received_at_iso: str,
) -> str:
    facts = "|".join(
        [prev_chain_hash, str(seq), batch_id, source, parser, merkle, str(accepted_count), received_at_iso]
    )
    return sha256_hex(facts)


def audit_entry_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return sha256_hex(prev_hash + canonical_json(payload))
