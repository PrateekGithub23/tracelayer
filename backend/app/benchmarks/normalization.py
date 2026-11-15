"""
Normalisation benchmark: parser throughput and coverage, v2 (otrf_windows) vs v3 (otrf_windows.v3), on the
catalogued OTRF archives in the dataset cache. Parse-only (no database), alternating versions per run so both
see the same machine conditions.

Run:  python -m app.benchmarks.normalization --runs 3 --json ../benchmarks/results/normalization-v2-vs-v3.json
"""

import argparse
import io
import json
import platform
import statistics
import time
from collections import Counter
from typing import Any

from app.datasets.archive import read_members
from app.datasets.catalog import DATASETS
from app.datasets.coverage import classify
from app.datasets.importer import cache_path
from app.ingestion.parsers import get_parser


def run(runs: int) -> dict[str, Any]:
    out: dict[str, Any] = {"datasets": {}, "environment": {"python": platform.python_version(),
                                                           "platform": platform.platform(), "runs": runs}}  # fmt: skip
    for ds in DATASETS.values():
        path = cache_path(ds)
        if not path.exists():
            continue
        members = read_members(io.BytesIO(path.read_bytes()))
        recs = [json.loads(line) for c in members.values() for line in c.decode().splitlines() if line.strip()]
        row: dict[str, Any] = {"records": len(recs)}
        for name in ("otrf_windows", "otrf_windows.v3"):
            row[name] = {"events_per_sec": [], "coverage": None}
        for _ in range(runs):
            for name in ("otrf_windows", "otrf_windows.v3"):
                p = get_parser(name)
                statuses: Counter[str] = Counter()
                rejected = 0
                t = time.perf_counter()
                for r in recs:
                    try:
                        ev = p.parse(p.to_raw(r, {}))
                    except Exception:  # noqa: BLE001 - counted as rejected, like the pipeline
                        rejected += 1
                        continue
                    statuses[classify(ev.event_type, ev.attributes)[0]] += 1
                row[name]["events_per_sec"].append(round(len(recs) / (time.perf_counter() - t)))
                n = len(recs)
                row[name]["coverage"] = {
                    **{k: round(100 * v / n, 2) for k, v in statuses.items()},
                    "rejected": rejected,
                }
        for name in ("otrf_windows", "otrf_windows.v3"):
            v = row[name]["events_per_sec"]
            row[name]["median_events_per_sec"] = int(statistics.median(v))
        out["datasets"][ds.id] = row
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--json")
    a = ap.parse_args()
    rep = run(a.runs)
    for ds_id, row in rep["datasets"].items():
        v2, v3 = row["otrf_windows"], row["otrf_windows.v3"]
        print(f"{ds_id:26} n={row['records']:6} v2 {v2['median_events_per_sec']:>7}/s {v2['coverage']}")
        print(f"{'':26} {'':8} v3 {v3['median_events_per_sec']:>7}/s {v3['coverage']}")
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rep, fh, indent=2)


if __name__ == "__main__":
    main()
