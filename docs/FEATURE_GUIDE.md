# Feature guide: what was built, how and why

For each major feature, this guide covers: **what** was implemented · **files** · **how** it works · **why** this design · **testing** · **risks** (security and performance).

---

## 1. Ingestion and provenance

**What.** Three parsers (TraceLayer JSON, OpenSSH syslog, Windows Security JSON) normalise records into one schema. Each batch is deduplicated, hashed into a Merkle root, and appended to a hash-chained ledger.

**Files.** `backend/app/ingestion/parsers.py`, `ingestion/pipeline.py`, `integrity/provenance.py`, `integrity/ledger.py`, `db_utils.py`, `api/ingest.py`.

**How.**
- `to_raw()` captures exactly what is stored. For syslog that includes the year, which isn't in the line, so re-parsing stays deterministic.
- The hash is `SHA-256(source + "\n" + canonical_json(raw))`, and the event id is `evt_` + the first 20 hex characters of that hash.
- Duplicates are dropped within the batch, then against the database (inside the ledger lock), and `ON CONFLICT DO NOTHING` is the final net.
- The batch stores a Merkle root over its new hashes and `chain_hash = H(prev ‖ seq ‖ id ‖ source ‖ parser ‖ merkle ‖ count ‖ time)`.
- Verification re-hashes every raw record, **re-runs the parser** and compares 15 derived fields, then rebuilds every root and the full chain.

**Why.**
- One content hash gives dedup, idempotent re-ingest, and tamper evidence.
- Pure parsers are what make "were the normalised fields edited?" checkable.
- A Merkle root plus a chain is the minimal structure that detects edits, deletions, insertions and reordering.

**Testing.** `tests/test_provenance.py`: key-order-independent hashing; dedup within, across and between sources; chain linkage; detection of edited raw records, edited columns, deleted events and edited batches; 8 concurrent writers with an unbroken chain and no duplicates. `tests/test_parsers.py` covers each format plus invalid input.

**Risks.**
- Tamper-evident, not tamper-proof: a DB admin can recompute hashes, so anchor the chain head externally.
- Ledger appends are serialised, which caps parallel ingest throughput (measured ~18–22k records/s).
- Large batches are held in memory (50k cap).

---

## 2. Detection engine

**What.** Nine explainable rules mapped to MITRE ATT&CK: brute force, success after failures, impossible travel, suspicious command lines (9 signatures), privileged group changes, lateral movement, exfiltration, log clearing, and prompt injection in telemetry (ATLAS AML.T0051).

**Files.** `backend/app/detection/base.py`, `rules.py`, `engine.py`.

**How.**
- Events load once as slotted `EventView` tuples ordered by time.
- Each rule groups by a key and applies an O(n) sliding window (`sliding_segments`, two pointers) or a per-key state machine.
- Each candidate has a dedup key (rule + entity + window start); the detection id is a hash of it.
- Re-runs create nothing new, and later evidence is merged into the existing detection.

**Why.**
- Analysts must see *why* something fired, and simple rules with visible thresholds give that.
- Tuples instead of ORM objects avoid most of the ORM loading overhead.
- Bounded sliding windows replaced gap-chained bursts after the 100k benchmark showed bursts chaining for hours (160 false positives → 0).

**Testing.** `tests/test_detection.py`: threshold boundaries for every core rule, window expiry, internal vs external destinations, idempotent re-runs, full-scenario recall with zero false positives, and regression tests for the trickle and typo false positives, including a 60k-event FP check.

**Risks.**
- Signature regexes are evadable (obfuscation).
- Thresholds are global, not per-entity baselines.
- Detection reloads all relevant events on each run (~1 s at 100k). Incremental, watermark-based detection is the next step at larger scale.

---

## 3. Correlation

**What.** Groups detections into investigations using shared entities within a time window. Scores them with an explainable formula and builds each investigation's evidence and context scope.

**Files.** `backend/app/correlation/engine.py`.

**How.**
- Union-find over detections. For each entity, its detections are sorted by time and *consecutive* ones are unioned when within 2 h; that's enough for connectivity and keeps it O(n log n).
- Entities appearing in more than 30% of a large candidate set are suppressed.
- Score = (max severity weight + 8 per extra kill-chain stage + 2 per extra detection) × (0.7 + 0.3 × mean confidence), stored as a breakdown.
- Existing open investigations are extended, never rebuilt, so analyst work survives re-runs.

**Why.** Analysts triage incidents, not alerts. Shared entities plus time proximity is the standard, explainable correlation heuristic, and suppression prevents the classic "one DNS server merges everything" failure.

**Testing.** `tests/test_correlation.py`: transitive linking, window separation, ubiquitous-entity suppression, kill-chain scoring, the scenario producing exactly two investigations with the lone low-severity alert left alone, stable re-runs, and late evidence extending an existing case.

**Risks.**
- Entity linking can over-merge when an attacker reuses a common service account.
- Investigations are never split automatically.
- Context scope is capped at 1,500 events.

---

## 4. Evidence Integrity Engine (the differentiator)

**What.** Validates every statement in every analysis against the evidence it cites. Six verdicts: verified, correlation, hypothesis, missing evidence, unsupported, contradictory. Unsafe claims block approval.

**Files.** `backend/app/integrity/scope.py`, `extract.py`, `validator.py`; `ai/service.py` (summary checks); `docs/EVIDENCE_INTEGRITY.md`.

**How.**
- Citations resolve to in-scope, out-of-scope, or fabricated.
- Deterministic extraction pulls entities, activities, quantities (with qualifiers), negations, gap statements, hedging and dismissals out of the text.
- Checks run in order: hard failures → dismissals → absence/gap → activity presence → entity presence → attribution → quantities → temporal order → flooding.
- Precedence picks the most dangerous applicable verdict, and reasons are recorded for the UI.

**Why.** LLM output is untrusted input. An LLM judge shares the generator's failure modes, while rules are reproducible, sub-millisecond and explainable. The design principle is *fail safe*: unrecognised content can lower a verdict but never raise one.

**Testing.**
- `app/evaluation/suite.py`: 47 labelled cases (31 adversarial), 16 held-out paraphrases and 13 structural checks.
- `tests/test_integrity.py` asserts zero unsafe acceptances and zero false rejections on the development suite, plus a clean deterministic baseline.
- `tests/test_api.py` drives a mocked hallucinating LLM through the approval gate.

**Risks.**
- Lexicon recall: unusual phrasing isn't understood, but fails safe as "unsupported".
- Quantity filtering prefers IP > user > host, so mixed-entity counts can be ambiguous.
- Timestamps inside claim text aren't checked.

---

## 5. AI layer (local LLM with deterministic fallback)

**What.** Optional Ollama integration (default `llama3.2:3b`) using structured JSON-schema output, plus a template-based deterministic analyst that is always available.

**Files.** `backend/app/ai/schema.py`, `prompt.py`, `ollama.py`, `deterministic.py`, `service.py`.

**How.**
- The evidence pack selects a slice of every detection's events (up to 60), gives each a short ref (`E12`), quotes and truncates text fields, and flags injected events.
- Engine `auto` checks `/api/tags`, calls `/api/chat` with `format = schema` at temperature 0.1, and parses tolerantly but with hard size caps.
- On any failure it falls back to the deterministic analyst and stores the reason.
- The deterministic analyst writes observations, correlations, hypotheses and gap statements from the cited events.

**Why.**
- Zero cost and offline.
- Short refs make small models cite reliably.
- The fallback means the product works without any model, and it acts as a correctness baseline: it must score zero unsafe claims, which already caught a reversed-order bug in the templates.

**Testing.** `tests/test_api.py` mocks the Ollama HTTP layer for three cases: a hallucinating model, garbage output (auto falls back, `ollama` mode returns an error), and Ollama down (falls back with a reason).

**Risks.**
- A 3B model takes seconds to tens of seconds on CPU-only Docker; run Ollama natively for Metal acceleration.
- The prompt is truncated for an 8k context.
- Model quality varies, which is exactly why the validator exists.

---

## 6. Analyst workflow and audit trail

**What.** Accept or reject individual claims. An analysis can be approved only once every unsafe claim has been rejected or explicitly overridden with a written justification. Investigation status and assignee changes, exports and verifications are all recorded in a hash-chained audit log.

**Files.** `backend/app/api/investigations.py`, `audit.py`; `frontend/src/components/AnalysisPanel.tsx`.

**How.** The server enforces the gate (HTTP 409 with the blocking claim ids). Overriding an unsafe verdict without a note returns 422. Each audit entry hashes the previous entry's hash plus its own canonical payload.

**Why.** "Human in the loop" only means something if the system forces attention onto the risky parts, and the audit trail makes the review itself verifiable.

**Testing.** `test_ollama_analysis_review_gate_and_audit` covers the gate, override justification, approval, re-review prevention, audit order and chain verification.

**Risks.** The analyst name is a label, not authenticated identity (see SECURITY.md).

---

## 7. Investigation UI

**What.** React/TypeScript SPA with an overview dashboard, investigation queue, and investigation workspace (kill-chain strip, telemetry blind spots, AI review, timeline, entity graph, event table, detections, audit). Also an event explorer, detections and rule catalogue, integrity page (ledger, evaluation, playground), performance page, and ingest/system page. A global evidence inspector opens any event's raw record and provenance from anywhere.

**Files.** `frontend/src/**`; `components/EvidenceInspector.tsx`, `EvidenceGraph.tsx`, `Timeline.tsx`, `AnalysisPanel.tsx`.

**How.**
- TanStack Query for caching and polling; URL-synced filters and tabs.
- Keyset "load more" pagination.
- Cytoscape for the graph: edges carry event ids, so clicking one opens exactly that evidence.
- Hand-written SVG timeline with drag-to-zoom.
- Verdict and severity colours are semantic tokens used everywhere.

**Why.** Every visual element maps to stored data. Citations, graph edges, timeline points and table rows all lead to the same inspector, so an analyst can always get from a claim back to the raw evidence.

**Testing.** `vitest` component and unit tests; `tsc --strict`; manual verification via headless-Chrome screenshots against a seeded backend.

**Risks.**
- The timeline renders up to 5,000 SVG nodes; beyond that it needs canvas or aggregation.
- The investigation bundle is large (~150 KB gzipped) because of Cytoscape, so pages are code-split.

---

## 8. Export

**What.** ZIP bundle (investigation JSON, events JSONL with raw records and hashes, CSV, Markdown report, manifest with per-file SHA-256, bundle hash and ledger head), plus standalone `md`, `csv` and `json` downloads.

**Files.** `backend/app/export.py`.

**Why.** Evidence leaves the system: to legal, management or another team. A recipient can verify it without TraceLayer.

**Testing.** `test_export_bundle_is_self_verifying` recomputes every file hash and every event hash from the bundle alone.

**Risks.** Bundles contain raw logs, which may include sensitive data. CSV formula injection is neutralised.

---

## 9. Evaluation and benchmarks

**What.** A reproducible adversarial evaluation and a stage-by-stage benchmark that also scores detection quality against ground truth. Both can run from the CLI or the UI and are stored as reports.

**Files.** `backend/app/evaluation/suite.py`, `benchmarks/runner.py`, `docs/BENCHMARKS.md`.

---

## 10. Deployment

**What.** Docker Compose (PostgreSQL 16, API, nginx UI, optional Ollama profile), migrations on startup, a non-root container, health checks, a Makefile, and GitHub Actions CI (lint, types, tests, evaluation, Postgres benchmark smoke test, frontend build).

**Files.** `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`, `frontend/nginx.conf`, `Makefile`, `.github/workflows/ci.yml`.

**Risks.** One API worker, because background jobs are in-process. Scaling out would mean an external queue and running migrations as a separate step.

---

# v2 features

## 11. Accounts, sessions and roles

- **What:** per-user accounts (Argon2id), HttpOnly server-side sessions with idle and absolute expiry,
  per-session CSRF tokens, invitation registration, admin-issued recovery codes, active-sessions page,
  sign-in history, and three roles enforced through permissions.
- **Files:** `backend/app/auth/*`, `api/auth.py`, `api/admin.py`, `api/deps.py`; `frontend/src/lib/auth.tsx`,
  `pages/auth/*`, `pages/Account.tsx`, `pages/Admin.tsx`.
- **Why:** v1's shared token bypassed roles, and its client-supplied analyst name made the audit log
  record forged identities.
- **Tests:** `test_auth.py`, `test_rbac_matrix.py` (every route × every role), Playwright `e2e/`.
- **Risks:** no MFA; in-process rate limits. Details in [AUTHENTICATION.md](AUTHENTICATION.md).

## 12. Case management

- **What:** a six-state workflow with enforced transitions and mandatory reasons, ownership,
  reviewer segregation of duties, priority, comments and notes (author-only edits, hashed in the audit
  log), pinned evidence, private saved filters, queue views (mine, needs my review, unassigned,
  recently updated), an activity feed built from the hash-chained audit log, and optimistic locking.
- **Files:** `backend/app/cases.py`, `api/cases.py`, migration `0003`; `frontend/src/components/CasePanel.tsx`.
- **Why:** investigations became work that several people share, so changes must be attributable, ordered and conflict-safe.
- **Tests:** `test_cases.py`, including a real two-thread race where exactly one writer wins, closed cases
  never changing evidence, IDOR checks, and a migration round-trip of v1 data.

## 13. Public telemetry datasets

- **What:** a pinned, licence-checked catalogue (OTRF Security-Datasets, MIT); a complete Windows
  adapter (Security, Sysmon, PowerShell); safe archive import; dataset pages with provenance, field
  mapping, detection results and schema-loss analysis; MIT-compliant samples.
- **Files:** `backend/app/datasets/*`, `ingestion/parsers.py` (`OtrfWindowsParser`), `pages/Datasets.tsx`.
- **Findings it produced:** the local-time `EventTime` trap (−4 h), credentials in command lines, a
  T1098 → T1136.001 mislabel in a v1 rule, and two new rules validated on a held-out dataset.
  ([REAL_WORLD_DATA_EVALUATION.md](REAL_WORLD_DATA_EVALUATION.md))
- **Tests:** `test_datasets.py` (path traversal, symlinks, zip bombs, hash pinning, mapping, redaction, timezone refusal, API import).

## 14. Integrity engine v2 and the local LLM

- **What:** timestamp checks with timezone conversion, homoglyph and zero-width detection, clause-scoped
  negation, comparatives and number words, "N times" over distinct citations, attribution and authority
  detection, under-citation handling, a stage trace and `requires_review`; Ollama provenance, single-flight
  generation, an AI engine page, and the LLM-vs-deterministic benchmark.
- **Evidence:** held-out v2 rose from 62.5% (5 false verifications) to 97.5% (0) on the official run.
  llama3.2:3b: 15/15 valid JSON but 57% unsafe claims. ([AI_EVALUATION.md](AI_EVALUATION.md))

## 15. Public demo and guided scenario

- **What:** a static build of the same app whose transport serves real recorded API responses and applies
  the server's workflow rules in memory; a guided eight-step scenario, "The Suspicious Login That Wasn't Just
  a Login", built from live data in both modes.
- **Files:** `backend/app/demo/build_snapshot.py`, `frontend/src/demo/transport.ts`, `pages/Walkthrough.tsx`,
  `.github/workflows/deploy-demo.yml`.
- **Tests:** `e2e-demo/demo.spec.ts`: zero `/api` calls, segregation of duties, approval gate, reset on reload.

## 16. Hardening

PostgreSQL least privilege (runtime role cannot UPDATE/DELETE evidence), unprivileged read-only containers,
hash-pinned dependencies, SHA-pinned CI actions, a body-size limit, sanitised errors, Markdown-export
escaping, an open-redirect guard, gitleaks, pip-audit and npm audit, and a stdlib-only bundle verifier.
([SECURITY.md](SECURITY.md), [V2_SECURITY_AUDIT.md](V2_SECURITY_AUDIT.md))

# v3 features

## 17. Normalisation v3 and telemetry coverage

- **What:** a new parser version `otrf_windows.v3` (50 Windows Security, Sysmon, PowerShell and WMI event
  types) with per-event diagnostics (`attributes.norm`: schema `tl-event/3`, status full / partial / raw-only,
  missing fields, reason) and OCSF-inspired class hints; a coverage API and a **Telemetry coverage** tab;
  owner-only, audited re-normalisation of existing data (`tracelayer dataset renormalize <id> [--dry-run]`).
- **Files:** `backend/app/ingestion/windows_v3.py`, `datasets/coverage.py`, `datasets/renormalize.py`,
  `api/datasets.py` (`GET /api/datasets/coverage`); `frontend/src/components/CoveragePanel.tsx`.
- **Why:** v2 typed only 3.5% of real events; the rest landed in "other", invisible to detection.
- **Evidence:** 97.7–99.8% fully normalised across five OTRF datasets, 0 rejected
  ([REAL_WORLD_DATA_EVALUATION.md](REAL_WORLD_DATA_EVALUATION.md)).
- **Tests:** `test_datasets.py` (re-normalisation keeps raw, hash, id and batch; ledger still verifies;
  channel-case and key-spacing quirks).

## 18. Detection v3

- **What:** TL-CRED-001 LSASS memory access (T1003.001) and TL-PERS-002 registry Run keys (T1547.001), 13
  rules in total; late-arriving evidence merges into the existing detection instead of creating a duplicate.
- **Files:** `backend/app/detection/rules.py`, `detection/engine.py`; [DETECTION_RULES.md](DETECTION_RULES.md).
- **Evidence:** each new rule detected its technique on a fresh labelled dataset; the T1069 control dataset was
  missed (no discovery rule).
- **Tests:** `test_detection_v3.py` (access masks, benign callers, timezone, duplicates, late and missing fields).

## 19. Grounded AI generation and engine v3

- **What:** the default LLM mode. A fact table of deterministic claims the engine has verified → the model
  writes claims citing fact ids only → event citations are derived → every claim is re-verified → unsafe
  claims are auto-rejected with a recorded note. Engine v3 adds benign-wash and success/failure phrasing,
  subject-position actors, hedged-dismissal handling and identity-swap reasons.
- **Files:** `backend/app/ai/grounded.py`, `ai/service.py`, `integrity/extract.py`, `integrity/validator.py`,
  `evaluation/heldout_v3.py` (frozen, SHA-pinned in `tests/test_heldout_frozen.py`).
- **Evidence:** held-out v3 95.2% (v2 engine 76.2%), 0 false verifications; unsafe claims 55.4% → 2.9%,
  fabricated citations 7.9 → 0, at lower completeness ([AI_EVALUATION.md](AI_EVALUATION.md)).

## 20. Account usability and release hardening

- **What:** a session-expiry warning, a *My activity* tab, admin user detail with failed sign-ins (24 h),
  accessible confirmation dialogs (focus trap and restore), `make create-admin` (interactive, no defaults);
  internal model URLs visible only to administrators and scrubbed from the demo; a gated deploy workflow that
  builds for the Pages sub-path, runs the demo e2e suite against the artifact and scans it with gitleaks.
- **Files:** `components/SessionWarning.tsx`, `pages/Account.tsx`, `pages/Admin.tsx`, `components/ui.tsx`,
  `.github/workflows/deploy-demo.yml`; [RELEASE_SECURITY_REVIEW.md](RELEASE_SECURITY_REVIEW.md).
- **Tests:** `test_auth.py` (activity, hidden endpoints), `src/test/dialogs.test.tsx`, `e2e-demo/demo.spec.ts`
  (strict same-origin request policy, deep links under `/tracelayer/`).
