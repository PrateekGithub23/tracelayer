# Architecture

```
                ┌───────────────────────── browser ─────────────────────────┐
                │ React + TypeScript (Vite)   Cytoscape graph · SVG timeline │
                │ TanStack Query · evidence inspector · review workflow      │
                └──────────────────────────────┬─────────────────────────────┘
                                               │ /api (same origin)
                                   nginx :8080 │ static files + reverse proxy
                                               ▼
┌──────────────────────────────── FastAPI :8000 (one process) ────────────────────────────────┐
│  api/ingest ─► ingestion.parsers ─► ingestion.pipeline ─► ledger batch + events             │
│                                                                                             │
│  jobs (thread pool, status in pipeline_runs)                                               │
│     └─► detection.engine (9 rules) ─► correlation.engine (union-find) ─► investigations    │
│                                                                                             │
│  api/investigations ─► ai.service ─► Ollama (optional) │ deterministic analyst             │
│                                   └─► integrity.validator (every claim, always)             │
│                                                                                             │
│  integrity.ledger (re-hash / re-parse / Merkle / chain) · audit (hash chain) · export (ZIP) │
└────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                             │ SQLAlchemy 2.0 · Alembic
                                   PostgreSQL 16 (Docker)  │  SQLite (dev / tests / benchmarks)
```

## Data flow

1. **Ingest.** A batch arrives as JSON, an uploaded file, or the synthetic generator. Each record is turned into a `raw` dict (exactly what is stored), hashed (`SHA-256(source ∖n canonical_json(raw))`), parsed into the normalised schema, and deduplicated. The batch gets a Merkle root over its new event hashes and a chain hash linking it to the previous batch.
2. **Detect.** Rules run over time-ordered `EventView` tuples and emit candidates with a dedup key (rule + entity + window start). The detection id is derived from that key, so re-running is idempotent; extra evidence for an existing detection is merged into it.
3. **Correlate.** Detections that share an entity (user / host / IP) within a 2-hour window are unioned. Entities seen in more than 30% of a large candidate set are suppressed so one shared server can't merge everything. Each component becomes, or extends, an investigation with a scored, explainable risk breakdown, and its scope is evidence events plus same-entity context events.
4. **Analyse.** An evidence pack (short refs `E1…En`, quoted single-line fields, injection-flagged events marked) goes to Ollama, or the deterministic analyst writes from templates. Either way, the JSON output is parsed tolerantly but strictly bounded, and every claim is validated.
5. **Review.** Analysts accept or reject claims. Approval is blocked while any unsupported or contradictory claim is pending. Every decision goes to the hash-chained audit log.
6. **Export / verify.** The ZIP bundle includes a manifest of file hashes and the ledger head. Full verification re-derives every hash and re-runs every parser.

## Key decisions

| Decision | Alternative considered | Why |
|---|---|---|
| Modular monolith, one FastAPI process | Microservices | One developer, one machine; module boundaries (ingestion / detection / correlation / integrity / ai) give the separation without the network hops |
| Sync SQLAlchemy + FastAPI threadpool | async SQLAlchemy | Work is CPU- and DB-bound in short transactions; sync is simpler to reason about and test. Long work is moved off the request path by `jobs` |
| Thread-pool jobs with a status table | Celery + Redis | Only three job types. A table gives durable status, history and UI polling with zero extra services. Trade-off: queued jobs don't survive a restart (they're marked failed on startup) |
| Portable schema (String ids, JSON, UTC decorator) | Postgres-only types (JSONB, UUID, INET) | The same migrations run on SQLite, so tests and benchmarks need no server. Dialect-specific code is limited to `INSERT … ON CONFLICT`, an advisory lock, `ANALYZE` and hour bucketing |
| Content-derived event ids | Random UUIDs | One mechanism gives dedup, idempotent re-ingest and tamper evidence |
| Keyset pagination | OFFSET | Constant cost for deep pages; stable under concurrent inserts |
| Rule-based claim validation | LLM-as-judge | A judge model can hallucinate too. Deterministic checks are reproducible, explainable, and need no model |
| Short citation refs (E12) | Full ids in prompts | Small local models copy short tokens far more reliably and use fewer tokens; refs are deterministic, so they're never stored |

## Concurrency and consistency

* **Ledger appends** are serialised: a process-wide lock, plus `pg_advisory_xact_lock` on PostgreSQL for multi-worker deployments. The dedup lookup happens inside the lock, so two concurrent batches can never both claim the same event in their Merkle roots. A test with 8 concurrent writers checks this.
* **Detection + correlation** runs under a pipeline lock, so two runs can't race on investigation assignment.
* **Audit entries** are appended under a lock in the same transaction as the change they describe.

## Module map

| Path | Responsibility |
|---|---|
| `backend/app/ingestion/` | parsers (`native`, `sshd`, `winsec`) and the batch pipeline |
| `backend/app/detection/` | `EventView`, sliding-window helpers, 9 ATT&CK-mapped rules, engine |
| `backend/app/correlation/` | union-find clustering, scoring, investigation scope |
| `backend/app/integrity/` | provenance hashing, ledger verification, scope, claim extraction, validator |
| `backend/app/ai/` | output schema, prompt / evidence pack, Ollama client, deterministic analyst, orchestration |
| `backend/app/api/` | HTTP routers (ingest, events, investigations + review, system / metrics) |
| `backend/app/evaluation/` | adversarial suite with held-out cases |
| `backend/app/benchmarks/` | reproducible stage-by-stage benchmarks |
| `backend/app/migrations/` | Alembic migrations (a test checks they match the models exactly) |
| `frontend/src/` | pages, evidence inspector, graph, timeline, analysis review |
