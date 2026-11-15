# Performance

All numbers are measured, reproducible, and stored as JSON in `benchmarks/results/`. Hardware: MacBook
Air, Apple Silicon (10 cores, 16 GB), macOS, Python 3.12.16. PostgreSQL 16.16 ran in Docker Desktop
(8 GB VM) in a **throwaway container**; no benchmark ever touches a real database.

```bash
make bench                                    # SQLite, 100k background events
python -m app.benchmarks.runner --events 100000 --database-url postgresql+psycopg://…   # PostgreSQL
make eval                                     # integrity engine latency (part of the evaluation)
make llm-bench                                # local LLM vs deterministic (needs Ollama)
tracelayer dataset import <id> --file x.zip   # real-telemetry ingest timing
```

## Pipeline at 100k events (synthetic scenario + 100,000 background events = 101,265 records)

| Stage | v1 recorded (SQLite) | **v2 reproduced (SQLite)** | v1 recorded (PostgreSQL) | **v2 reproduced (PostgreSQL, warm)** |
|---|---|---|---|---|
| Ingest (parse, hash, dedup, Merkle, chain, persist) | 22,208/s | **23,904/s** | 17,822/s | **16,728–17,273/s** |
| Duplicate replay | 90,623/s | 93,506/s | 65,263/s | ~55,200/s |
| Detection (now 11 rules, was 9) | 117,908/s | **118,669/s** | 105,344/s | ~102,400/s |
| Correlation | 26.5 ms | 22.4 ms | 55.4 ms | **~93 ms** |
| Claim validation (per claim, inside the pipeline benchmark) | 0.30 ms | 0.36 ms | 0.36 ms | ~0.55 ms |
| Ledger verification (re-hash + re-parse) | 40,043/s | 45,589/s | 39,198/s | ~37,100/s |
| Rule recall on the planted attack | 1.0 | **1.0** | 1.0 | **1.0** |
| False-positive detections in 100k background | 0 | **0** | 0 | **0** |

### Reading these honestly

- **The baseline was reproduced before any new claim.** The v1 code itself was benchmarked again on
  the same machine and PostgreSQL image (git worktree at `0c6be04`): **16,673/s** ingest. So v1's
  recorded 17.8k reflects an earlier environment, and v2's 16.7–17.3k/s is the same performance, not a regression.
- **Cold vs warm.** The first PostgreSQL run after starting the container measured 12,482/s
  (`postgres-100k-v2-cold.json`); the next two measured 16,728 and 17,273/s. Report the warm range;
  expect slower first runs.
- **Regressions, stated:** PostgreSQL correlation went from 55 ms (v1, recorded) to ~93 ms, and per-claim
  validation from ~0.36 to ~0.55 ms. Likely causes are versioned investigation updates (optimistic
  locking) and the extra v2 validator stages. Both remain far below a second per pipeline run.
- **Two new rules cost nothing measurable** in detection throughput and added no false positives on
  100k background events.

## Integrity engine (evaluation suite, 124 validations)

p50 **0.14 ms**, p95 **0.26 ms**, max **0.68 ms**. The size gate before parsing reduced the worst case on
oversized input from 131 ms to under 1 ms.

## Real telemetry (OTRF, SQLite)

| Dataset | Records | Parse + hash + persist | Detect + correlate |
|---|---|---|---|
| Empire WMIC backdoor | 12,278 | 1.24 s (~9,900/s) | 113 ms |
| Empire Invoke-WMI | 6,383 | 0.61 s (~10,500/s) | 51 ms |

Real records average ~2.2 kB of raw JSON (many fields per event), roughly 5× the synthetic events,
hence about half the synthetic throughput.

## Local LLM

llama3.2:3b (Q4_K_M) on the same laptop via native Ollama: **18.6 s** mean, **27.9 s** p95 per analysis
(15 runs), compared with **~1 ms** for the deterministic analyst. A first request also loads the model
(~2 GB) into memory. Only one generation runs at a time (HTTP 429 otherwise). See AI_EVALUATION.md.

## Resource use

PostgreSQL ~50–150 MB, API ~150–250 MB, nginx under 10 MB; Ollama with llama3.2:3b loaded uses
~2.5–3.5 GB. The full stack plus the model fits comfortably in 16 GB.

## End-to-end and test runtimes

110 backend tests in ~24 s; 8 browser e2e tests (real API) in ~8 s; 5 static-demo e2e tests in ~4 s.
