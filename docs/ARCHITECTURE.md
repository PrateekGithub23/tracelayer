# Architecture

```
              ┌──────────────────────────────── browser ────────────────────────────────┐
              │ React 18 + TypeScript (Vite) · TanStack Query · Cytoscape · Recharts      │
              │ AuthProvider (session via /api/auth/me) · case workspace · evidence       │
              │ inspector · guided scenario                                               │
              │ api.ts ──► Transport ──┬─ HTTP (real app; cookie + X-CSRF-Token)          │
              │                        └─ demo transport (static build: recorded          │
              │                           responses + mirrored rules, no network)         │
              └──────────────────────────────────┬────────────────────────────────────────┘
                                                 │ /api (same origin)
                    nginx :8080 (unprivileged)   │ SPA + reverse proxy, auth rate limit, CSP
                                                 ▼
┌─────────────────────────────────────── FastAPI (one process) ─────────────────────────────────────┐
│ middleware: body-size limit · security headers · latency telemetry · sanitised errors              │
│ api/deps: session → CSRF → Origin → require(permission)   (every route; matrix-tested)            │
│                                                                                                    │
│ auth/ (Argon2id, sessions, rate limits, RBAC)   api/auth, api/admin (users, invites, settings)     │
│ api/ingest ─► ingestion.parsers (native, sshd, winsec, otrf_windows) ─► pipeline ─► ledger         │
│ datasets/ (pinned catalogue, safe zip reader, importer + evaluation) ─┘                            │
│ jobs (thread pool, single-flight expensive kinds) ─► detection (11 rules) ─► correlation           │
│ api/cases (workflow, ownership, SoD, optimistic locking, comments, pins, filters, activity)        │
│ ai.service ─► Ollama (optional, single-flight) │ deterministic analyst ─► integrity.validator      │
│ integrity (provenance, ledger verify, extract, validator) · audit (hash chain) · export (ZIP)      │
└──────────────────────────────────────────┬─────────────────────────────────────────────────────────┘
                                           │ SQLAlchemy 2 · Alembic (0001–0005)
            PostgreSQL 16: runtime role tracelayer_app (no UPDATE/DELETE on evidence) │ SQLite (dev/tests)
```

## Data flow

1. **Ingest.** JSON, files, catalogued public datasets or the synthetic generator. Each raw record is
   hashed (`SHA-256(source ∖n canonical_json(raw))`), parsed, deduplicated, committed with a batch
   Merkle root and chained to the previous batch.
2. **Detect** (11 ATT&CK-mapped rules, sliding windows) and **correlate** (union-find over shared
   entities, with suppression of ubiquitous entities) into cases with explainable risk scores.
3. **Work the case.** Assignment, priority and the state machine New → Triaged → Investigating → Awaiting
   review → Resolved → Closed (reopen to Investigating), with reasons, reviewer segregation of duties,
   comments, notes and pinned evidence. Every change goes to the audit chain.
4. **Analyse.** An evidence pack goes to the local LLM or the deterministic analyst; every claim is
   verified by the Evidence Integrity Engine; approval is blocked until unsafe claims are handled.
5. **Report.** Markdown or CSV report, or a ZIP bundle with a hash manifest that `tools/verify_bundle.py`
   can verify without TraceLayer.

## v2 design decisions

| Decision | Alternative | Why / trade-off |
|---|---|---|
| Keep React + Vite | Rewrite in Next.js (as the brief assumed) | The frontend is a SPA behind a JSON API with no SEO or SSR need. A rewrite would add a Node server and risk without user-visible benefit. Static builds also make the zero-cost demo trivial. |
| Server-side sessions, hashed tokens, HttpOnly cookie | JWT in `localStorage` | Instant revocation (role change, logout, "sign out everywhere"), no token theft via XSS, small cost: one indexed lookup per request (`last_seen` written at most once a minute) |
| Synchronizer CSRF token per session | Double-submit cookie only | Bound to the server session, so it cannot be planted by a sibling subdomain |
| Permissions, not role checks, on routes | `if role == "admin"` in handlers | One table defines access; the matrix test discovers every route and proves it |
| Audit log as the case activity source | A separate activity table | One verifiable history; the activity feed is covered by chain verification |
| `version_id_col` optimistic locking | Pessimistic row locks | No lock waits for a slow analyst; the UPDATE is atomic (`WHERE version = :seen`); the UI shows a clear conflict message |
| Removed shared API token | Keep it as an "automation" credential | A shared secret bypasses RBAC by design (audit C2/C3); automation uses the CLI |
| Pinned dataset catalogue + in-memory zip reading | Arbitrary URL import, extract to disk | No SSRF and no path traversal by construction; tampered upstream archives are refused |
| Demo = recorded real responses + browser transport | Hosted backend, or screenshots | $0, always on, nothing to attack, and the numbers are genuine engine output |
| DB-enforced evidence immutability | Application checks only | A compromised API process still cannot rewrite or erase evidence |
| Rule-based claim validation (kept) | LLM-as-judge or embeddings | A judge can hallucinate; similarity is not verification. Deterministic checks are reproducible and explainable |

Earlier v1 decisions (modular monolith, thread-pool jobs, portable schema, content-derived ids, keyset
pagination, short citation refs) still apply. See git history for the v1 architecture page.

## Module map

| Path | Responsibility |
|---|---|
| `backend/app/auth/` | passwords (Argon2id), sessions, RBAC permissions, rate limiter, account service |
| `backend/app/api/` | routers: auth, admin, cases, investigations, events, ingest, datasets, llm, system |
| `backend/app/cases.py` | case state machine, ownership and segregation-of-duties rules |
| `backend/app/ingestion/` | parsers, including the OTRF Windows adapter and credential redaction |
| `backend/app/datasets/` | catalogue (licences, pinned hashes), safe archive reader, importer and evaluation |
| `backend/app/detection/`, `correlation/` | rules and engines |
| `backend/app/integrity/` | provenance, ledger verification, claim extraction, validator |
| `backend/app/ai/` | prompt and evidence pack, Ollama client, deterministic analyst, orchestration with provenance |
| `backend/app/evaluation/` | integrity suite: dev v1, regression, dev v2, frozen held-out v2 |
| `backend/app/benchmarks/` | pipeline benchmark, LLM vs deterministic comparison |
| `backend/app/demo/` | demo snapshot builder (records real API responses, scrubs secrets) |
| `backend/app/migrations/` | 0001 v1 schema · 0002 identity · 0003 cases (data-preserving) · 0004 dataset imports · 0005 DB privileges |
| `frontend/src/lib/` | API client and transports, auth context, case metadata, types |
| `frontend/src/demo/` | browser-local demo transport |
| `frontend/e2e/`, `frontend/e2e-demo/` | Playwright suites (real backend; static demo) |
| `tools/verify_bundle.py` | stdlib-only evidence bundle verifier |
| `docker/postgres/` | least-privilege runtime role setup |
