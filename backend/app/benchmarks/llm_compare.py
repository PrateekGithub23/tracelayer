"""
Benchmark: local LLM vs. the deterministic analyst on the same investigations.

Both engines receive the same evidence scope; every output goes through the same Evidence Integrity
Engine. Nothing is written to the application database (an isolated in-memory DB is used).

Metrics per run
  json_valid              the model's output parsed and passed schema validation
  latency_ms              wall-clock generation time
  claims                  number of claims produced
  verdicts                distribution of integrity verdicts
  unsafe_claims           unsupported + contradictory
  fabricated / out_of_scope citations
  citation_validity       resolved citations / citations given
  requires_review         claims the engine flags for a human decision
  detection_coverage      share of the investigation's detections backed by at least one trusted claim
                          (verified/correlation) citing that detection's evidence: a completeness measure
  summary_issues          problems found in the free-text summary

Run:  python -m app.benchmarks.llm_compare --runs 3 [--otrf-file path.zip] --json out.json
"""

import argparse
import json
import platform
import statistics
import time
from collections import Counter
from typing import Any

from sqlalchemy import select

from app.ai.service import AnalysisError, _generate, validate_output
from app.evaluation.suite import _find_investigation, build_environment
from app.integrity.scope import build_scope
from app.integrity.validator import CORRELATION, UNSAFE, VERIFIED
from app.models import Investigation

TRUSTED = {VERIFIED, CORRELATION}


def _score(scope: Any, gen: dict[str, Any]) -> dict[str, Any]:
    results, integrity = validate_output(gen["output"], scope)
    verdicts = Counter(r.verdict for r in results)
    given = sum(len(r.raw_citations) for r in results)
    resolved = sum(len(r.citations) for r in results)
    covered = 0
    for d in scope.detections:
        ev = set(d.event_ids)
        if any(r.verdict in TRUSTED and ev & set(r.citations) for r in results):
            covered += 1
    return {
        "claims": len(results), "verdicts": dict(verdicts), "unsafe_claims": sum(verdicts[v] for v in UNSAFE),
        "fabricated_citations": integrity["citations_fabricated"], "out_of_scope_citations": integrity["citations_out_of_scope"],
        "citation_validity": round(resolved / given, 3) if given else None,
        "requires_review": sum(1 for r in results if r.checks.get("requires_review")),
        "detection_coverage": round(covered / len(scope.detections), 3) if scope.detections else None,
        "summary_issues": len(integrity["summary_issues"]), "integrity_score": integrity["integrity_score"],
        "trusted_claims": sum(verdicts[v] for v in TRUSTED),
        "unsafe_rate": round(sum(verdicts[v] for v in UNSAFE) / len(results), 3) if results else None,
    }  # fmt: skip


def run(runs: int, otrf_file: str | None, modes: tuple[str, ...] = ("ollama", "grounded")) -> dict[str, Any]:
    db, truth = build_environment()
    targets = [("synthetic: 7-stage intrusion", _find_investigation(db, "TL-EXFIL-001").id)]
    ssh = next(
        i for i in db.scalars(select(Investigation)) if any(e["value"] == truth["ssh_attacker_ip"] for e in i.entities)
    )
    targets.append(("synthetic: SSH brute force", ssh.id))
    if otrf_file:
        from app.correlation.engine import run_correlation
        from app.datasets.catalog import DATASETS
        from app.datasets.importer import _records, obtain_archive
        from app.detection.engine import run_detection
        from app.ingestion.pipeline import ingest_records

        ds = DATASETS["otrf-sdwin-200914080546"]
        data, _ = obtain_archive(ds, otrf_file)
        recs, _bad = _records(data)
        ingest_records(db, recs, source=f"dataset:{ds.id}", parser_name=ds.parser, options={})
        run_detection(db)
        db.flush()
        run_correlation(db)
        inv = db.scalar(select(Investigation).where(Investigation.title.like("%pgustavo%")))
        if inv:
            targets.append(("OTRF lab: WMIC backdoor", inv.id))

    out: dict[str, Any] = {"investigations": []}
    for label, inv_id in targets:
        inv = db.get(Investigation, inv_id)
        assert inv
        scope = build_scope(db, inv_id)
        row: dict[str, Any] = {"investigation": label, "events_in_scope": len(scope.events),
                               "detections": len(scope.detections), "deterministic": None, "llm_runs": []}  # fmt: skip
        t = time.perf_counter()
        gen = _generate(scope, inv, "deterministic")
        row["deterministic"] = {
            "latency_ms": round((time.perf_counter() - t) * 1000, 1),
            "json_valid": True,
            **_score(scope, gen),
        }
        for mode in modes:
            key = "llm_runs" if mode == "ollama" else f"{mode}_runs"
            row.setdefault(key, [])
            for i in range(runs):
                t = time.perf_counter()
                try:
                    gen = _generate(scope, inv, mode)
                    rec = {"run": i + 1, "json_valid": True, "latency_ms": round((time.perf_counter() - t) * 1000, 1),
                           "model": gen["model"], "engine": gen["engine"], "model_digest": gen["provenance"].get("model_digest"),
                           "unknown_fact_ids": gen["provenance"].get("unknown_fact_ids"),
                           "output_tokens": gen["meta"].get("output_tokens"), **_score(scope, gen)}  # fmt: skip
                except AnalysisError as exc:
                    rec = {"run": i + 1, "latency_ms": round((time.perf_counter() - t) * 1000, 1), "error": str(exc)[:300],
                           "json_valid": False if "model output rejected" in str(exc) else None}  # fmt: skip
                row[key].append(rec)
                print(
                    f"  {label} [{mode}] run {i + 1}: {json.dumps({k: rec.get(k) for k in ('json_valid', 'latency_ms', 'claims', 'unsafe_claims', 'trusted_claims', 'fabricated_citations', 'detection_coverage', 'error')})}",
                    flush=True,
                )
        out["investigations"].append(row)

    def agg(rows: list[dict[str, Any]], key: str) -> float | None:
        vals = [r[key] for r in rows if r.get(key) is not None]
        return round(statistics.mean(vals), 3) if vals else None

    keys = ("latency_ms", "claims", "unsafe_claims", "unsafe_rate", "trusted_claims", "fabricated_citations",
            "citation_validity", "requires_review", "detection_coverage", "integrity_score")  # fmt: skip
    det = [inv["deterministic"] for inv in out["investigations"]]
    out["summary"] = {"deterministic": {k: agg(det, k) for k in keys}}
    for mode in modes:
        key = "llm_runs" if mode == "ollama" else f"{mode}_runs"
        runs_ = [r for inv in out["investigations"] for r in inv.get(key, [])]
        ok = [r for r in runs_ if r.get("json_valid")]
        lat = sorted(r["latency_ms"] for r in ok)
        out["summary"][mode] = {"runs": len(runs_), "invalid_json": sum(1 for r in runs_ if r.get("json_valid") is False),
                                "other_failures": sum(1 for r in runs_ if r.get("json_valid") is None),
                                **{k: agg(ok, k) for k in keys},
                                "latency_p95_ms": lat[max(0, int(len(lat) * 0.95) - 1)] if lat else None,
                                "latency_stdev_ms": round(statistics.stdev(lat), 1) if len(lat) > 1 else None}  # fmt: skip
    out["environment"] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "runs_per_investigation": runs,
    }
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--otrf-file")
    ap.add_argument("--json")
    args = ap.parse_args()
    rep = run(args.runs, args.otrf_file)
    print(json.dumps(rep["summary"], indent=1))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(rep, fh, indent=2, default=str)


if __name__ == "__main__":
    main()
