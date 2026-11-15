# TraceLayer v2: Security and Architecture Audit

**Audited revision:** `0c6be04` (v1 baseline) · **Date:** 2026-11-14 · **Method:** manual review of every
backend router, model, dependency, the job runner, Docker/nginx configuration, the frontend HTTP client, and
CI; reproduction of the v1 test suite (58 + 9 passing) and evaluation results; plus a new frozen held-out
evaluation of the integrity engine.

Passing tests are not evidence of security. Several findings below sit in code paths the tests exercised
successfully, because the tests checked the behaviour that was designed, not the behaviour an attacker
would try.

Severity scale: **Critical** means remote, unauthenticated, full data exposure or integrity loss. **High**
means an authenticated or local attacker can cause serious harm, or a core security claim is false.
**Medium** means defence-in-depth gaps or availability risk. **Low** means hygiene issues.

The "Status" column refers to the v2 work. Each fix is described in the linked document and covered by
tests (see `backend/tests/test_auth*.py`, `test_rbac_matrix.py`, `test_cases.py`, `test_hardening.py`).

---

## Summary

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| C1 | Critical | Every read endpoint is unauthenticated: raw events, investigations, audit log, exports | Fixed: session auth on all `/api/*` except health and login |
| C2 | Critical | Writes are unauthenticated by default (`TRACELAYER_API_TOKEN` unset) | Fixed: there is no unauthenticated write path |
| C3 | Critical | A single shared bearer token grants every write permission; there are no roles | Fixed: per-user accounts with three roles, enforced server-side |
| C4 | Critical | Audit attribution comes from a client-supplied `X-Analyst` header, so the hash chain faithfully preserves forged identities | Fixed: actor = authenticated user id/email; the header is ignored |
| H1 | High | Token stored in `localStorage` (readable by any XSS) | Fixed: HttpOnly session cookie; nothing secret in JS-readable storage |
| H2 | High | Synthetic/demo data generator writes into the same database as real telemetry | Fixed: admin-only, disabled when `TRACELAYER_ALLOW_SYNTHETIC=false`, batches labelled `synthetic` provenance |
| H3 | High | `GET /export` has a side effect (audit write) and no auth; CSRF-able via `<img src>` | Fixed: auth + `export` permission; GET remains side-effect-free except the audit record, which is now attributable |
| H4 | High | Job failures persist Python tracebacks and return them from `/api/pipeline/runs` | Fixed: clients get an error class + id; tracebacks go to the server log only |
| H5 | High | Integrity engine accepts 5 of 24 adversarial claims in a fresh held-out set (v1 reported 0) | Addressed in Phase 5; see AI_EVALUATION.md for post-fix numbers |
| H6 | High | No concurrency control on investigation updates (last write wins silently) | Fixed: optimistic locking (`version`), 409 on stale writes |
| M1 | Medium | No request-body size cap when the API is reached directly (only nginx caps at 30 MB); multipart spools unbounded to disk | Fixed: ASGI body-size limit middleware |
| M2 | Medium | Any writer can queue unbounded CPU-heavy benchmark/evaluation jobs | Fixed: admin-only, one concurrent run per kind |
| M3 | Medium | No rate limiting anywhere | Fixed: login/registration/password endpoints are rate-limited per IP and per account |
| M4 | Medium | `/docs` and `/openapi.json` publicly exposed | Fixed: disabled unless `TRACELAYER_EXPOSE_DOCS=true` |
| M5 | Medium | API responses lack CSP/HSTS/Permissions-Policy; nginx lacks HSTS | Fixed: strict API CSP, HSTS when `cookie_secure`, Permissions-Policy |
| M6 | Medium | App connects to PostgreSQL as the cluster superuser created by the image | Fixed: separate owner (migrations) vs. runtime role with DML-only grants (`docker/postgres/init.sql`) |
| M7 | Medium | Hash chain verification runs inside the same app against the same DB; the chain head is never anchored externally | Partly fixed: stdlib-only standalone verifier (`tools/verify_bundle.py`, `tools/verify_chain.py`); chain head can be exported for external anchoring. Remains tamper-*evident*, not tamper-*proof* |
| M8 | Medium | `/api/integrity/validate` accepts 500 kB of input with no auth (CPU DoS) | Fixed: auth + permission + 64 kB cap |
| M9 | Medium | Backend dependencies are lower-bounded only; no lockfile, no vulnerability scanning | Fixed: `uv.lock`, `pip-audit` and `npm audit` in CI |
| L1 | Low | `ollama/ollama:latest` and other images are not version-pinned | Fixed: images pinned to explicit versions |
| L2 | Low | Default Postgres password fallback in compose (`tracelayer-local-only`) | Kept for local use; compose now refuses to start the `prod` profile without an explicit password |
| L3 | Low | No secret scanning before commits | Fixed: gitleaks job in CI + `make secrets-scan` |
| L4 | Low | 422 validation errors echo the submitted input back | Fixed: custom handler returns field locations and messages only |

### Things that were already done well (verified, kept)

- **SQL injection:** every query uses SQLAlchemy expressions or bound parameters. The only `text()` calls are
  constants (`SELECT 1`, `ANALYZE events`, an advisory lock with a bound key). `LIKE` input is escaped.
- **CSV injection:** exports prefix `= + - @ \t \r` cells with `'`.
- **XSS from LLM output:** the UI renders model text only through React text nodes. There is no
  `dangerouslySetInnerHTML`, no `href` built from model text, and no Markdown rendering. The Markdown
  export is a downloaded file and is never rendered by TraceLayer.
- **Path traversal / decompression bombs:** v1 accepted no archives. v2 adds zip import for public datasets,
  which reads members in memory with member-count, per-member, total-size and compression-ratio limits
  and never writes member paths to disk (`app/datasets/archive.py`; tests in `test_datasets.py`).
- **Secrets in git:** `.env`, `*.db` and the WAL files are ignored. A manual scan of the baseline found no
  credentials.
- **Containers:** the API runs as uid 10001, multi-stage, no compilers. PostgreSQL is not published to the host.
  The API and UI bind to `127.0.0.1` only.

---

## Detailed findings

### C1, C2, C3: Authentication and authorization

`app/api/deps.py::require_writer` was attached only to mutating routes, and returned immediately when
`api_token` was unset (the default). Every `GET` (raw event records including command lines, the audit log,
`/export?format=zip`) had no dependency at all. With a token configured, possession of that one string
granted every write: approving analyses, generating synthetic data, running benchmarks. There was no
concept of a viewer or an administrator.

**Fix (Phase 2):** server-side sessions (`user_sessions` table storing only the SHA-256 of a 256-bit random
token), Argon2id password hashing (`argon2-cffi`), HttpOnly + SameSite=Lax cookies (Secure in HTTPS
deployments), double-submit CSRF token on unsafe methods, and a permission-based RBAC dependency on every
router. The `TRACELAYER_API_TOKEN` shared secret is **removed**. Keeping it as a parallel credential would
reintroduce exactly the bypass this finding describes. Automation now uses the CLI, which talks to the
database directly with the operator's OS-level access.

Verification: `tests/test_rbac_matrix.py` enumerates **every route registered on the app** and asserts that,
apart from an explicit public allow-list, each one returns 401 without a session. It also checks the
expected status for each role. A new route without a permission dependency fails the test.

### C4: Forgeable audit attribution

`analyst_name()` read `X-Analyst` and wrote it into the hash-chained audit log. The hash chain then
*proved the integrity of a forged record*. **Fix:** the actor is derived from the authenticated session
(`user:<id> <email>`). The header is no longer read.

### H2: Demo functionality writes to production data

`POST /api/synthetic/generate` ingested a generated intrusion into the shared database, interleaved with
real telemetry, for any token holder. **Fix:** admin-only, gated by `TRACELAYER_ALLOW_SYNTHETIC`
(default true locally, false in the `prod` compose profile), and every synthetic batch carries
`provenance.kind = "synthetic"`, which the UI shows. The public demo (Phase 7) is a static build with a
browser-local data layer and never talks to a backend.

### H4: Internal error leakage

`jobs._execute` stored `traceback.format_exc()` in `pipeline_runs.error`, which `GET /api/pipeline/runs`
returned verbatim, exposing file paths, library versions and exception messages that may contain data.
**Fix:** a stable error id and exception class are stored for clients. The traceback is logged server-side
with the same id.

### H5: Integrity engine generalisation

A new 40-case held-out set (`app/evaluation/heldout_v2.py`) was written and SHA-256-pinned *before* any v2
engine change. Against the unchanged v1 engine it scored **62.5% (25/40) with 5 dangerous acceptances**:

| Case | Claim pattern | v1 verdict |
|------|---------------|-----------|
| hv2-17 | Correct login, **wrong time** (3 h off) | verified |
| hv2-25 | **Cyrillic homoglyph** username (`аlice`) | verified |
| hv2-27 | One event cited 12×, claim says "12 times" | verified |
| hv2-30 | True fact + "which **proves a nation-state** actor" | verified |
| hv2-39 | Same claim repeated 400× (24 kB) | verified |

The v1 claim "0 unsafe acceptances" was true for the sets it was measured on but did not generalise. This
is the most important product-level finding, because evidence integrity is the product. See
`docs/AI_EVALUATION.md` for the v2 changes and the post-change held-out run.

### H6: Lost updates

`PATCH /investigations/{id}` read-modify-wrote without a version check. Two analysts changing status
simultaneously silently overwrote each other, and correlation re-runs could race with analyst edits.
**Fix:** `investigations.version` is a SQLAlchemy `version_id_col`, so the UPDATE includes
`WHERE version = :expected`. Clients must send `expected_version`, and a mismatch returns 409 with the
current state.

### M6: Database least privilege

The compose `POSTGRES_USER` is the cluster superuser, and the app used it for everything. **Fix:**
`docker/postgres/init.sql` creates `tracelayer_owner` (owns schema, runs migrations) and `tracelayer_app`
(SELECT/INSERT/UPDATE/DELETE only). The runtime role additionally has **no UPDATE or DELETE on
`events`, `ingest_batches` or `audit_log`**, so evidence immutability is enforced by the database, not
just by application code. Migrations run as the owner via `TRACELAYER_MIGRATION_DATABASE_URL`.

### M7: Tamper-evident, not tamper-proof

Anyone with write access to the database can rewrite an event *and* recompute every downstream hash. The
chain then verifies cleanly. Hash chains detect partial or naive tampering. They do not stop a
privileged insider. Mitigations in v2: the runtime DB role cannot UPDATE/DELETE evidence tables (M6), the
chain head can be exported and anchored externally (`tracelayer chain-head`), and stdlib-only verifiers
let a third party check an export bundle without trusting TraceLayer's code.

---

## Residual risks (accepted, documented)

1. **Single-node, in-process rate limiting.** Limits reset on restart and are per process. Adequate for the
   single-worker deployment; a multi-worker deployment would need a shared store.
2. **No MFA.** Password + session only. TOTP would be the next control to add.
3. **Admin-mediated recovery.** No email. An administrator issues a one-time reset code out of band. If
   the only admin loses their password, recovery is via CLI on the host (`tracelayer reset-password`).
4. **SQLite deployments** cannot enforce the DB-level immutability grants in M6.
5. **The integrity engine is rule-based.** It fails safe on phrasing it doesn't understand, but its
   held-out accuracy is well below 100%. The UI requires analyst review for every non-verified claim.
6. **Local LLM output is untrusted input.** It is schema-validated and every claim is re-verified, but a
   compromised or malicious local model could still waste analyst time. It cannot bypass the approval gate.
