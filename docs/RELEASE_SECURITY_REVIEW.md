# Release Security Review (v3)

**Purpose:** a pre-publication review of every area in the release checklist, with the evidence for each.
This review does **not** conclude that TraceLayer has no vulnerabilities. It records what was checked,
how, what was fixed, and what remains. Companion documents: [SECURITY.md](SECURITY.md) (design),
[V2_SECURITY_AUDIT.md](V2_SECURITY_AUDIT.md) (v2 findings), [LIMITATIONS.md](LIMITATIONS.md).

## Checklist

| Area | How it was checked | Result |
|---|---|---|
| Authentication | `test_auth.py` (15 tests), Playwright e2e (forced password change, reload persistence, revocation) | Argon2id, uniform failures, rate limits, rotation; no default accounts exist |
| Authorization | `test_rbac_matrix.py` discovers **every** route (82) × 3 roles + anonymous | 5 intended public routes; 401/403 everywhere else as expected; forged viewer requests refused |
| Session handling | idle + absolute expiry, fixation, revocation, role-change revocation tests | Pass. v3 adds an expiry warning computed client-side (no keep-alive polling) |
| CSRF / CORS | per-session token + Origin check tests; CORS limited to configured origins | Pass |
| Input validation | Pydantic bounds; 30 MB ASGI body cap; 64 kB validator input; 600-char claim gate before parsing | Pass |
| SQL injection | manual grep for string-built SQL | Only constant `text()` statements; every query uses bound parameters |
| XSS | manual grep for `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `new Function` | None. Model and log text is rendered as React text; Markdown exports are escaped |
| File upload / archives / path traversal | `test_datasets.py`: `../`, absolute, `C:`, symlink, zip bomb, ratio, member-count tests | Archives are read in memory only; catalogue SHA-256 pinning; constant URLs (no SSRF) |
| Secret leakage | gitleaks over the **full git history** and the working tree; manual pattern scan of the demo snapshot and build | No leaks. Allow-list covers fake test fixtures only |
| Dependency vulnerabilities | `pip-audit` (hash-pinned lock), `npm audit --omit=dev` | 0 known vulnerabilities at review time |
| Browser storage | grep for `localStorage`/`sessionStorage`/`indexedDB`/`document.cookie` | No use. Session cookie is HttpOnly; CSRF token is held in memory |
| Sensitive log fields | credential redaction in normalised command lines, parent command lines and registry values (tests) | Raw records keep original bytes (they are hashed evidence), visible to authenticated users only |
| Container security | compose review | Non-root, `cap_drop: ALL`, `no-new-privileges`, read-only root, only 127.0.0.1:8080 published; `.dockerignore` excludes data, dumps, env files |
| Database privileges | live check on an upgraded v1 database; CI job | Runtime role cannot UPDATE/DELETE/TRUNCATE events, batches or the audit log, and cannot CREATE |
| Audit log integrity | chain verification tests; stdlib bundle verifier with tamper test | Tamper-*evident* (see SECURITY.md); v3 re-normalisation is owner-only and audited |
| Public demo isolation | Playwright: every request must stay on the demo's own origin and path; publish guard in the workflow | Zero `/api`, other-host or other-port requests; snapshot scrubbed of tokens, credentials and internal URLs |

## Issues found and fixed in v3

| Issue | Severity | Fix |
|---|---|---|
| `/api/llm/status` and `/api/system/status` revealed the internal model-server URL to every signed-in user, including viewers | Low | Shown to administrators only (test added) |
| Demo snapshot contained the local Ollama URL | Low | Scrubber removes internal service URLs; the deploy workflow refuses `localhost:<service port>` in the artifact |
| `.dockerignore` did not exclude cached datasets, database dumps or env files | Low | Fixed (the Dockerfiles copy explicit paths, so no image contained them) |
| Late-arriving events created duplicate alerts for the same activity | Medium (analyst confusion) | Engine merges overlapping same-rule evidence into the existing detection (test added) |
| Lower-case `security` channel bypassed supported mappings | Medium (detection gap) | Case-insensitive channel matching in parser v3 (test added) |
| Under a URL sub-path, the root URL lacked its trailing slash, so a reload could break | Low (availability) | Router base keeps the slash; tested 4/4 under `/tracelayer/` |

## Manual review of new v3 code paths

- **Grounded LLM pipeline:** the model receives only verified fact text (no raw log text), so telemetry
  prompt injection cannot reach it on this path. Fact ids are mapped server-side; unknown ids are dropped and
  counted; the model cannot introduce citations.
- **Re-normalisation:** requires the owner database role (the runtime role cannot UPDATE events by
  design); changes only derived columns and the parser name; raw, hash, id and batch are unchanged (test);
  audited.
- **Coverage and activity endpoints:** read-only and RBAC-covered; activity is filtered by the stable
  user id embedded in audit actor strings; the admin variant requires `users:manage`.

## Repository contents for publication

Checked: no `.env` with real values (only `.env.example` with placeholders), no databases or dumps
(`*.db`, `backups/`, `backend/data/` are ignored), no personal identifiers (repository-wide search for the
author's username, name and email: none), no internal URLs in tracked files, no tokens. Large files: the
demo snapshot (~8 MB, 0.8 MB gzipped) and screenshots (each under 1 MB).

## Residual risks (accepted, documented)

1. No MFA or SSO; recovery is administrator-mediated.
2. In-process rate limiting and LLM concurrency guard (single worker).
3. Hash chains are tamper-evident, not tamper-proof; a database superuser can rewrite history consistently.
4. Raw evidence records may contain sensitive strings from source systems (by design, they are the
   evidence); they are restricted to authenticated users and redacted only in normalised fields and the public demo.
5. The integrity engine is rule-based: held-out accuracy is high but not perfect, and unfamiliar phrasing is rejected.
6. Third-party GitHub Actions are pinned to commit SHAs but are still third-party code running in CI.
7. CI has not yet run on GitHub (no remote exists); local replays and `actionlint` are not the same as hosted runs.
