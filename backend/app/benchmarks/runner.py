"""
Benchmark runner.

Measures every stage of the real pipeline on an isolated database (a temporary
SQLite file by default, or any URL passed with --database-url, e.g. the Docker
PostgreSQL). Nothing is estimated: each number is a wall-clock measurement
from time.perf_counter() on the machine that ran it, and the environment is
recorded alongside the results.

Also scores detection quality against the generator's ground truth:
  rule_recall           fraction of expected attack rules that fired
  false_positive_dets   detections whose entities touch none of the attack entities

Run:
  python -m app.benchmarks.runner --events 100000 --json ../benchmarks/results/latest.json
"""

import argparse
import json
import os
import platform
import statistics
import tempfile
import time
from collections.abc import Callable
from functools import partial
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.ai import deterministic
from app.correlation.engine import run_correlation
from app.db import make_engine
from app.detection.engine import run_detection
from app.export import build_bundle
from app.ingestion.pipeline import ingest_records
from app.integrity.ledger import verify_ledger
from app.integrity.scope import build_scope
from app.integrity.validator import ClaimInput, validate_all
from app.migrate import upgrade
from app.models import Base, Detection, Event, Investigation
from app.synthetic.generator import generate


def _timed(fn: Callable[[], Any]) -> tuple[Any, float]:
    t = time.perf_counter()
    out = fn()
    return out, (time.perf_counter() - t) * 1000


def _query_latency(db: Session, stmt: Any, runs: int = 15) -> dict[str, float]:
    samples = []
    for _ in range(runs):
        t = time.perf_counter()
        db.execute(stmt).all()
        samples.append((time.perf_counter() - t) * 1000)
    samples.sort()
    return {"p50_ms": round(statistics.median(samples), 3), "p95_ms": round(samples[int(len(samples) * 0.95) - 1], 3)}


def run_benchmark(events: int = 20_000, database_url: str | None = None, seed: int = 7) -> dict[str, Any]:
    tmpdir = None
    if database_url is None:
        tmpdir = tempfile.mkdtemp(prefix="tracelayer-bench-")
        database_url = f"sqlite:///{os.path.join(tmpdir, 'bench.db')}"
        upgrade(database_url)
    engine = make_engine(database_url)
    if not database_url.startswith("sqlite"):
        Base.metadata.drop_all(engine)  # an explicit URL must point at a disposable database
        Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    results: dict[str, Any] = {}
    try:
        sc, gen_ms = _timed(lambda: generate(seed=seed, background_events=events))
        results["generate_ms"] = round(gen_ms, 1)

        ingest: dict[str, Any] = {}
        for recs, parser in ((sc.native, "native"), (sc.sshd, "sshd"), (sc.winsec, "winsec")):
            r, ms = _timed(partial(ingest_records, db, recs, source=f"bench-{parser}", parser_name=parser,
                                   options={"year": 2026}))  # fmt: skip
            ingest[parser] = {"records": len(recs), "accepted": r.accepted, "duplicates": r.duplicates,
                              "ms": round(ms, 1), "records_per_sec": round(len(recs) / (ms / 1000))}  # fmt: skip
        results["ingest"] = ingest

        # Re-sending the whole native batch measures the deduplication path (every record is a duplicate).
        r, ms = _timed(lambda: ingest_records(db, sc.native, source="bench-native", parser_name="native"))
        results["dedup_replay"] = {"records": len(sc.native), "accepted": r.accepted, "duplicates": r.duplicates,
                                   "ms": round(ms, 1), "records_per_sec": round(len(sc.native) / (ms / 1000))}  # fmt: skip

        det, ms = _timed(lambda: run_detection(db))
        db.commit()
        results["detection"] = {"ms": round(ms, 1), "events_scanned": det["events_scanned"],
                                "events_per_sec": round(det["events_scanned"] / (ms / 1000)),
                                "detections": det["created"], "timings_ms": det["timings_ms"]}  # fmt: skip
        det2, ms2 = _timed(lambda: run_detection(db))
        db.commit()
        results["detection_rerun"] = {"ms": round(ms2, 1), "created": det2["created"], "note": "idempotency check"}

        cor, ms = _timed(lambda: run_correlation(db))
        db.commit()
        results["correlation"] = {"ms": round(ms, 1), "investigations": cor["investigations_created"],
                                  "clusters": cor["clusters"]}  # fmt: skip

        analysis = []
        for inv in db.scalars(select(Investigation)):
            scope, scope_ms = _timed(partial(build_scope, db, inv.id))
            (out, _), gen_ms = _timed(partial(deterministic.analyze, scope, inv))
            claims = [ClaimInput(c.text, c.kind, c.citations) for c in out.claims]
            (_, summary), val_ms = _timed(partial(validate_all, claims, scope))
            analysis.append({"investigation": inv.title[:60], "events_in_scope": len(scope.events),
                             "claims": summary["claims"], "unsafe_claims": summary["unsafe_claims"],
                             "scope_ms": round(scope_ms, 1), "generate_ms": round(gen_ms, 2),
                             "validate_ms": round(val_ms, 2),
                             "validate_ms_per_claim": round(val_ms / max(1, summary["claims"]), 3)})  # fmt: skip
        results["analysis"] = analysis

        main = max(db.scalars(select(Investigation)), key=lambda i: i.score)
        (_, manifest), ms = _timed(lambda: build_bundle(db, main))
        results["export"] = {"ms": round(ms, 1), "events": manifest["event_count"]}

        ver, ms = _timed(lambda: verify_ledger(db))
        results["ledger_verification"] = {"ms": round(ms, 1), "ok": ver["ok"], "events_checked": ver["events_checked"],
                                          "events_per_sec": round(ver["events_checked"] / (ms / 1000))}  # fmt: skip

        results["queries"] = {
            "events_by_user": _query_latency(db, select(Event).where(Event.username == "alice")
                                             .order_by(Event.timestamp.desc()).limit(50)),
            "events_by_ip": _query_latency(db, select(Event).where(Event.src_ip == sc.truth["attacker_ip"]).limit(50)),
            "text_search": _query_latency(db, select(Event).where(Event.command_line.ilike("%powershell%")).limit(50)),
            "time_window": _query_latency(db, select(Event).order_by(Event.timestamp.desc()).limit(50)),
        }  # fmt: skip

        fired = set(db.scalars(select(Detection.rule_id).distinct()))
        expected = set(sc.truth["expected_rules"])
        attack_entities = {sc.truth["attacker_ip"], sc.truth["exfil_ip"], sc.truth["ssh_attacker_ip"],
                           sc.truth["victim"], "sam"}  # "sam" is the planted low-severity whoami  # fmt: skip
        fps = [d.summary for d in db.scalars(select(Detection))
               if not any(e["value"] in attack_entities for e in d.entities)]  # fmt: skip
        results["detection_quality"] = {"expected_rules": sorted(expected), "rules_fired": sorted(fired),
                                        "rule_recall": round(len(expected & fired) / len(expected), 3),
                                        "false_positive_detections": len(fps), "false_positive_examples": fps[:5]}  # fmt: skip
        total_events = db.query(Event).count()
    finally:
        db.close()
        engine.dispose()
        if tmpdir:
            for f in os.listdir(tmpdir):
                os.remove(os.path.join(tmpdir, f))
            os.rmdir(tmpdir)

    total_ingest_ms = sum(v["ms"] for v in results["ingest"].values())
    results["summary"] = {
        "background_events": events,
        "total_events": total_events,
        "ingest_records_per_sec": round(sum(v["records"] for v in results["ingest"].values()) / (total_ingest_ms / 1000)),
        "dedup_records_per_sec": results["dedup_replay"]["records_per_sec"],
        "detection_events_per_sec": results["detection"]["events_per_sec"],
        "detection_ms": results["detection"]["ms"],
        "correlation_ms": results["correlation"]["ms"],
        "validation_ms_per_claim": max((a["validate_ms_per_claim"] for a in results["analysis"]), default=0),
        "ledger_verify_events_per_sec": results["ledger_verification"]["events_per_sec"],
        "rule_recall": results["detection_quality"]["rule_recall"],
        "false_positive_detections": results["detection_quality"]["false_positive_detections"],
        "unsafe_claims_deterministic": sum(a["unsafe_claims"] for a in results["analysis"]),
    }  # fmt: skip
    results["environment"] = {
        "tracelayer": __version__, "python": platform.python_version(), "platform": platform.platform(),
        "machine": platform.machine(), "cpu_count": os.cpu_count(),
        "database": "sqlite (temp file)" if tmpdir else database_url.split("://")[0], "seed": seed,
    }  # fmt: skip
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="Benchmark the TraceLayer pipeline")
    ap.add_argument("--events", type=int, default=20_000, help="background events to generate")
    ap.add_argument("--database-url", help="disposable database to benchmark (default: temp SQLite file)")
    ap.add_argument("--json", help="write results to this path")
    args = ap.parse_args()
    res = run_benchmark(args.events, args.database_url)
    print(json.dumps(res["summary"], indent=2))
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w") as fh:
            json.dump(res, fh, indent=2, default=str)


if __name__ == "__main__":
    main()
