"""The v2 held-out evaluation set must not change after it was frozen (see app/evaluation/heldout_v2.py)."""

import hashlib
from pathlib import Path

FROZEN_SHA256 = "b2598aa0d52137f1b825fcb6112e3ca87dd62cb2b353379a6324e3eec867048d"


def test_heldout_v2_is_frozen() -> None:
    path = Path(__file__).resolve().parents[1] / "app" / "evaluation" / "heldout_v2.py"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == FROZEN_SHA256, (
        "heldout_v2.py changed after it was frozen; create a new versioned set instead of editing it"
    )
