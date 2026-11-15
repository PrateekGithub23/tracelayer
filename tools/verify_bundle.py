#!/usr/bin/env python3
"""
Independently verify a TraceLayer evidence bundle (ZIP) using only the Python standard library.

This file deliberately imports nothing from TraceLayer: a recipient can audit these ~70 lines and run
them without trusting TraceLayer's code. It checks:

  1. every file listed in manifest.json has the stated SHA-256, and bundle_sha256 covers the file list;
  2. every event's content_hash == SHA-256(source + "\\n" + canonical JSON of its raw record);
  3. every event id == "evt_" + first 20 hex characters of its content hash;
  4. every audit entry's entry_hash == SHA-256(prev_hash + canonical JSON of its payload).

Limits (stated, not hidden): this proves the bundle is internally consistent and unmodified since export.
It cannot prove the original telemetry was truthful, or that someone with full database access did not
rewrite history *before* export. Compare manifest.ledger_head with a chain head you anchored externally.

Usage:  python3 verify_bundle.py tracelayer-inv_xxx.zip      (exit 0 = verified, 1 = problems)
"""

import hashlib
import json
import sys
import zipfile


def sha256(data: str | bytes) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify(path: str) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        manifest = json.loads(z.read("manifest.json"))
        for name, expected in manifest["files"].items():
            if name not in names:
                problems.append(f"missing file {name}")
            elif sha256(z.read(name).decode("utf-8")) != expected:
                problems.append(f"{name}: SHA-256 does not match the manifest")
        if sha256(canonical(manifest["files"])) != manifest.get("bundle_sha256"):
            problems.append("bundle_sha256 does not match the file list")
        events = [json.loads(line) for line in z.read("events.jsonl").decode("utf-8").splitlines() if line.strip()]
        for e in events:
            if sha256(f"{e['source']}\n{canonical(e['raw'])}") != e["content_hash"]:
                problems.append(f"event {e['id']}: raw record does not match content_hash")
            if e["id"] != "evt_" + e["content_hash"][:20]:
                problems.append(f"event {e['id']}: id does not match content_hash")
        meta = json.loads(z.read("investigation.json"))
        for a in meta.get("audit", []):
            payload = {k: a[k] for k in ("timestamp", "actor", "action", "target_type", "target_id", "details")}
            if sha256(a["prev_hash"] + canonical(payload)) != a["entry_hash"]:
                problems.append(f"audit entry {a['id']}: entry_hash does not match its contents")
    print(f"{path}: {len(events)} events, {len(meta.get('audit', []))} audit entries, "
          f"ledger head {manifest.get('ledger_head')}")
    return problems


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    found = verify(sys.argv[1])
    for p in found:
        print("FAIL:", p)
    print("VERIFIED" if not found else f"{len(found)} problem(s)")
    sys.exit(1 if found else 0)
