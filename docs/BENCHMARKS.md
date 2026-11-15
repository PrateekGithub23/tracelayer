# Benchmarks

All numbers below were **measured**: wall-clock `time.perf_counter()` on the stated machine, produced by `app/benchmarks/runner.py`. The raw JSON is in [`benchmarks/results/`](../benchmarks/results). Re-run them yourself; your hardware will differ.

**Machine:** Apple M4 MacBook Air, 16 GB RAM, macOS 26, Python 3.12. PostgreSQL 16 ran in Docker Desktop (Linux VM), with the benchmark running inside the API container.
**Workload:** seed 7, 100,000 background events + the attack scenario = **101,265 events** (plus ~1% re-sent duplicates).

## Results (100k events)

| Stage | SQLite (temp file) | PostgreSQL 16 (Docker) |
|---|---|---|
| Ingest (parse + hash + dedup + ledger + insert) | **22,208 records/s** | **17,822 records/s** |
| Dedup replay (re-send all 100k; every record a duplicate) | 90,623 records/s | 65,263 records/s |
| Detection (9 rules, load + evaluate + persist) | 859 ms (117,908 events/s) | 961 ms (105,344 events/s) |
| Re-run detection (idempotency) | 0 new detections | 0 new detections |
| Correlation | 26.5 ms | 55.4 ms |
| Claim validation (22-claim analysis, 1,929 events in scope) | 0.30 ms / claim | 0.32–0.36 ms / claim |
| Full ledger verification (re-hash + re-parse every event) | 40,043 events/s | 39,198 events/s |
| Query p50: events by user / by IP / `ILIKE` text / latest 50 | 0.41 / 0.35 / 0.55 / 0.41 ms | 0.54 / 0.51 / 0.79 / 0.54 ms |

### Detection quality against ground truth

| | 100k background |
|---|---|
| Expected attack rules fired (recall) | **9 / 9 (100%)** |
| False-positive detections (touching no attack entity) | **0** |
| Unsafe claims from the deterministic analyst | 0 |

## What benchmarking found (and fixed)

These are the most useful results, because each was a real defect that only showed up through measurement.

| Finding | Root cause | Fix | Effect |
|---|---|---|---|
| Ingest only **1,928 records/s** at 20k | SQLAlchemy's ORM bulk path emitted and compiled **one INSERT per row** (~14k statements) | Insert against the Core `Table` (single `executemany` / insertmanyvalues) | → 7,160 records/s |
| `dataclasses.asdict` was ~25% of ingest time | deep-copies every value | shallow field mapping | → 13,916 records/s at 20k |
| **160 false-positive detections** at 100k (0 at 20k) | brute-force / exfil used gap-chained "bursts" that could chain for hours under dense traffic; success-after-failures counted failures that were each followed by a success (typos) | true sliding windows (`sliding_segments`, O(n) two-pointer); reset the failure run on success | 0 false positives, recall unchanged; regression tests added (including a 60k-event FP test) |
| PostgreSQL dedup replay **167 records/s** | after a 100k bulk load the planner's statistics were stale, so dedup lookups did sequential scans | `ANALYZE events` after batches ≥ 5,000 rows | → 65,263 records/s (~390×) |

## Reproduce

```bash
# SQLite (temp file, auto-deleted)
cd backend && .venv/bin/python -m app.benchmarks.runner --events 100000 --json ../benchmarks/results/sqlite-100k.json

# PostgreSQL in the Compose stack (uses a separate, disposable database)
docker compose exec db psql -U tracelayer -c "CREATE DATABASE tracelayer_bench"
docker compose exec api python -m app.benchmarks.runner --events 100000 \
  --database-url postgresql+psycopg://tracelayer:tracelayer-local-only@db:5432/tracelayer_bench

# Adversarial evaluation
cd backend && .venv/bin/python -m app.evaluation.suite --json ../benchmarks/results/evaluation.json
```

The UI's **Performance** page can also start a benchmark (5k–100k events, isolated temp DB) and shows the latest stored report, live API latency percentiles, and per-run pipeline timings.

## Caveats

* The workload is synthetic. Event mix and density are realistic enough to exercise every code path, but real telemetry has more field variety.
* Single process, single machine; no concurrent client load was applied in these runs.
* LLM generation time is not included (Ollama wasn't installed on the benchmark machine). The deterministic analyst takes ~2 ms per investigation. With Ollama, expect seconds to tens of seconds for a 3B model on Apple Silicon, so measure it with the Performance page's "analysis latency by engine" table.
