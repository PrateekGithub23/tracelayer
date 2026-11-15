# Presenting TraceLayer

Every number below is reproducible from this repository (see PERFORMANCE.md and AI_EVALUATION.md).
Do not round numbers up, and keep the caveats when someone asks.

## Resume bullets

- **Built TraceLayer, a full-stack security investigation platform (FastAPI, PostgreSQL, React/TypeScript)**
  that ingests ~17k–24k events/s into a SHA-256 hash-chained, Merkle-committed evidence ledger. Its
  11 ATT&CK-mapped rules achieved 100% recall and 0 false positives on a 100k-event benchmark, and detected
  a held-out public attack dataset (OTRF) after real-data fixes.
- **Designed a deterministic "Evidence Integrity Engine" that verifies every AI-generated claim against
  cited events.** On a frozen 40-case adversarial held-out set it improved accuracy from 62.5% to 97.5% and
  cut dangerous false verifications from 5 to 0 at 0.14 ms p50. It caught 57% unsafe claims from a local
  llama3.2:3b model that produced valid JSON in 15/15 runs.
- **Hardened the platform for multi-user use:** Argon2id accounts, server-side HttpOnly sessions with CSRF
  protection, and role-based access verified by an automated test that checks all 79 API routes against
  every role. Added optimistic-locked case workflows with segregation of duties, PostgreSQL-enforced
  evidence immutability, and a $0 static public demo with 13 Playwright end-to-end tests.

(If space is tight, keep the second bullet: it is the most distinctive.)

## The 30-second explanation

"Security teams want AI to draft investigations, but small models hallucinate. TraceLayer lets a
model write the draft, then checks every sentence against the exact log events it cites: entities,
counts, times, outcomes and ordering. Anything unsupported is labelled with a reason and blocks
approval until a human decides. Underneath is a real pipeline: tamper-evident ingestion, detection,
correlation into cases, and a multi-user case workflow."

## Security engineering interviews

Be ready to go deep on:

- **Threat model and trust boundaries.** Attacker-controlled log text is untrusted input to the LLM
  (prompt injection tagged at ingest); model output is untrusted input to the analyst (the integrity
  engine); the browser is untrusted for authorization (server-side permission per route).
- **AuthN/AuthZ choices.** Why opaque sessions over JWT (revocation, no XSS theft); synchronizer CSRF;
  uniform login errors plus a dummy Argon2 verify to avoid user enumeration; no account lockout (it
  enables denial of service); rate limiting per IP *and* per account; session rotation on login and on
  password change.
- **Testing authorization.** The matrix test discovers routes from the app object, so a forgotten
  dependency on a new endpoint fails CI. That is the difference between "I added checks" and "I can prove coverage".
- **Tamper evidence vs tamper proofing.** What hash chains can and cannot prove, and why the database
  role was stripped of UPDATE/DELETE on evidence tables.
- **Real-data lessons.** The local-time trap in Windows telemetry, credentials in command lines, a
  mis-mapped ATT&CK technique, and the 96.5% of events the schema couldn't type. Show you treat data
  quality as a security property.
- **Honest evaluation.** Frozen held-out set with a hash check in CI, dev vs held-out separation, no
  invented FP rates without benign labels, and post-hoc results reported separately.

## Software engineering interviews

- **Concurrency.** Optimistic locking with `version_id_col`; the two-thread test where exactly one writer wins; ledger appends under a lock plus a PostgreSQL advisory lock.
- **Migrations that protect data.** Autogenerate would have dropped a column; the hand-written
  migration copies data first, maps old statuses, and is tested on a round-trip (upgrade → downgrade) with v1 rows.
  It was then run against a real v1 database after a `pg_dump` backup.
- **Testing strategy.** 110 backend tests, 10 unit tests and 13 browser tests. The e2e suite found a
  real bug (case header showing "unassigned") and several timing races in the tests themselves.
- **Pluggable transport.** One React app, two data sources (HTTP or recorded snapshot); a static demo
  with zero backend that still enforces the workflow rules.
- **Decisions you didn't make.** Kept React + Vite instead of migrating to Next.js: no SSR need, and a rewrite would add risk with no user-visible benefit.

## Backend interviews

- Request pipeline: body-size ASGI middleware → session lookup (hashed token, touched at most once a
  minute) → CSRF → permission → handler; errors sanitised.
- Data model: content-addressed event ids give dedup and tamper detection at once; keyset pagination; JSON columns kept portable between SQLite and PostgreSQL.
- Performance: ~24k events/s ingest on SQLite and ~17k/s on PostgreSQL (warm), measured; cold runs are slower, and the PostgreSQL correlation regression (55 → ~93 ms) is a known trade-off of versioned updates.
- Background work without Celery: thread pool, durable status rows, single-flight for expensive job kinds, and why that is fine for one node but not for scale-out.
- The LLM integration: schema-constrained decoding, timeouts, single-flight generation, provenance, and a fallback that is labelled, never silent.

## Questions you should expect, and honest answers

- *"Is this production-ready?"* It is hardened for a self-hosted single team. It lacks MFA and SSO, a
  shared rate-limit store, and real-network FP measurement (LIMITATIONS.md).
- *"Does the engine understand language?"* No. It is deterministic extraction with lexicons. It fails
  safe on phrasing it doesn't know and never uses similarity to verify.
- *"Why is your held-out score 97.5% and also 100%?"* 97.5% is the single pre-registered run.
  100% is a later run after real-data fixes, reported as post-hoc.
