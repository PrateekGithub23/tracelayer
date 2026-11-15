# Performance

> **v3 (2026-11-15):** see [v3 measurements](#v3-measurements) at the end. Headline: ingest and detection
> show no regression versus v2 in paired runs; claim validation is ~15% slower (more grammar); normalisation
> now types 97.7–99.8% of real events at 2.7k–18.3k events/s parse throughput, depending on how script-heavy
> the data is.

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


---

## v3 measurements

**Method.** MacBook Air (Apple Silicon, 10 cores, 16 GB), Python 3.12.16, PostgreSQL 16.16 in Docker.
Machine conditions varied during this session: a separately running Docker stack and background processes put the
load average at ~2–3, and absolute throughput was about half of the earlier v2 session. Comparisons below are
therefore **paired**: v2 code (commit `9734726`, via a git worktree) and v3 code ran alternately under the same
conditions. Absolute numbers from different sessions are not compared.

### Pipeline, 100k synthetic background events (paired)

| SQLite (3 pairs) | v2 code | v3 code |
|---|---|---|
| Ingest events/s (runs) | 10,297 · 11,884 · 11,490 (mean 11,224) | 10,536 · 11,440 · 11,207 (mean 11,061) |
| Detection events/s (mean) | 59,179 | 59,784 |
| Correlation | 47–52 ms | 50 ms, 50 ms, 131 ms (one outlier) |
| Claim validation (per claim) | 0.735 ms | 0.843 ms (+15%) |
| Rule recall / false positives | 1.0 / 0 | 1.0 / 0 (13 rules) |

| PostgreSQL (2 pairs, fresh container each) | v2 code | v3 code |
|---|---|---|
| Ingest events/s | 6,722 (cold) · 8,933 | 8,599 · 8,752 |
| Detection events/s | 52,432 · 57,065 | 56,449 · 55,710 |
| Correlation | 141 · 154 ms | 147 · 190 ms |
| Rule recall / false positives | 1.0 / 0 | 1.0 / 0 |

**Conclusion:** no measurable ingest or detection regression from v3 (differences are within run-to-run
noise); claim validation costs ~15% more. An apparent 50% "regression" seen earlier in the session was
environmental: the v2 code was equally slow at that moment.

### Normalisation (parse-only, median of 3 alternating runs)

| Dataset | Records | v2 events/s | v2 typed | v3 events/s | v3 full / partial / raw |
|---|---|---|---|---|---|
| WMIC backdoor | 12,278 | 15,161 | 3.5% | **18,316** | 99.59 / 0.03 / 0.37% |
| Invoke-WMI | 6,383 | 21,276 | 1.7% | 12,360 | 97.74 / 1.55 / 0.70% |
| Run keys | 657 | 18,408 | 37.9% | 7,711 | 99.24 / 0 / 0.76% |
| Mimikatz | 6,026 | 14,377 | 5.4% | 2,745 | 99.80 / 0.02 / 0.18% |
| net localgroup | 884 | 22,472 | 3.3% | 7,372 | 99.66 / 0 / 0.34% |

v3 does more work per event: it extracts process, identity and network fields, redacts credentials, and scans
every extracted script for prompt injection. Where a dataset is dominated by large PowerShell records (the
Mimikatz dataset includes ~20 kB script payloads), parse throughput falls to ~2.7k events/s. A 10× slowdown
found during development was traced to a per-character Python loop in a shared helper; it was replaced with
`str.translate`, proven byte-identical on 20,000 random inputs (so v2 events still verify), and v2's own
parser became faster as a result. Reproduce: `python -m app.benchmarks.normalization --runs 3`.

### Evidence verification

Warm latency over the dev sets: p50 0.27 ms, p95 0.40 ms, max 0.47 ms (v2: p50 0.14 ms). The first call after
start-up includes one-time regex compilation (~17 ms). Inside the pipeline benchmark (with database work and
mixed claims): 0.84 ms per claim.

### Local AI inference (llama3.2:3b, Q4_K_M, native Ollama, 15 runs per mode)

Free-form 32.1 s mean (p95 40.1 s, sd 5.2 s); grounded 22.7 s mean (p95 45.5 s, sd 16.5 s); deterministic
2 ms. See AI_EVALUATION.md for quality metrics. Latency depends on output length and model load state; the
first request after start-up also loads the ~2 GB model.

### Files

`sqlite-100k-v3-paired-run{1..3}.json`, `sqlite-100k-v2code-paired-run{1..3}.json`,
`postgres-100k-v3-paired-run{1,2}.json`, `postgres-100k-v2code-paired-run{1,2}.json`,
`normalization-v2-vs-v3.json`, `llm-v3-freeform-vs-grounded-idle.json`, `evaluation-v3.json`, and
`otrf-v3-*.json` (dataset imports).
