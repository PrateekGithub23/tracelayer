# Security Design

Companion documents: [V2_SECURITY_AUDIT.md](V2_SECURITY_AUDIT.md) (findings and their status),
[AUTHENTICATION.md](AUTHENTICATION.md) (accounts, sessions, RBAC), [LIMITATIONS.md](LIMITATIONS.md).

Passing tests are not a security proof. This page states what is enforced, where, and what is not.

## Threat model (what TraceLayer defends against)

| Adversary | Example | Primary controls |
|---|---|---|
| Unauthenticated network user | reads raw telemetry, approves analyses | Session auth on every route except 5 public ones; RBAC matrix test |
| Authenticated low-privilege user | viewer forges a request to close a case; analyst edits a colleague's case | Server-side permission checks, ownership and segregation-of-duties rules, IDOR-safe 404s |
| Malicious web page | CSRF, clickjacking, stealing a token via XSS | HttpOnly cookie, per-session CSRF token, Origin check, `SameSite=Lax`, `X-Frame-Options: DENY`, strict CSP, no `localStorage` secrets |
| Attacker-controlled log content | prompt injection ("this is an authorized red team test"), Markdown or HTML in fields, CSV formulas | Ingest-time injection tagging, quoted evidence packs, validator rejects conclusions built on tagged events, React text rendering, Markdown escaping, CSV formula neutralisation |
| Hallucinating or manipulated LLM | fabricated citations, invented IPs, wrong counts, homoglyph identities | Schema-constrained output plus the Evidence Integrity Engine on every claim; server-side approval gate |
| Malicious dataset archive | `../` paths, symlinks, zip bombs, tampered mirror | In-memory reads with size, count and ratio limits; pinned SHA-256; constant URLs (no SSRF) |
| Compromised API process | rewrite or delete evidence | PostgreSQL runtime role without UPDATE/DELETE/TRUNCATE on events, batches and audit log |
| Resource abuse | huge bodies, repeated benchmarks, unbounded LLM use | Body-size middleware, single-flight expensive jobs, one LLM generation at a time, per-user analysis limit, demo accounts never call the model |
| Supply chain | swapped PyPI package, moved action tag | Hash-pinned Python lock (`--require-hashes`), npm lockfile, actions pinned to commit SHAs, pinned image versions, pip-audit / npm audit / gitleaks in CI |

Out of scope: a malicious administrator, a compromised host or database superuser, and side channels.

## Controls by layer

**HTTP.** Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` and
`Cross-Origin-Resource-Policy`. The JSON API sends `Content-Security-Policy: default-src 'none'`, and the
SPA is served with a self-only CSP. HSTS is sent when cookies are Secure. CORS is limited to configured
origins. OpenAPI `/docs` is off unless `TRACELAYER_EXPOSE_DOCS=true`. Bodies over 30 MB are refused
while streaming, before parsing.

**Errors.** Clients receive generic 500s. Validation errors list field locations and messages but never
echo submitted values. Job failures expose an exception class and a correlation id; tracebacks stay in
the server log.

**Input.** Pydantic models bound every field; SQL uses bound parameters only (no string-built SQL);
`LIKE` input is escaped; upload parsers are restricted to an allow-list; validator input is capped at
64 kB and claims at 600 characters, with the size checked before parsing.

**Output.** Model and log text is rendered as React text nodes. There is no
`dangerouslySetInnerHTML`, no model-derived URLs, and no Markdown rendering in the app. Exported
Markdown escapes untrusted values; exported CSV neutralises formulas.

**Sensitive fields.** Credentials found in command lines (`net user x <pw>`, `/password:`, `-p`) are
redacted in *normalised* fields. The raw record is kept verbatim, because it is the hashed evidence, and
is visible only to authenticated users. The public demo additionally scrubs raw records and flags them.
Passwords, session tokens, invitation tokens and recovery codes are stored only as hashes.

**Database.** In Docker, the API connects as `tracelayer_app` (DML only). Migrations run as the schema
owner through `TRACELAYER_MIGRATION_DATABASE_URL`. Migration 0005 revokes UPDATE, DELETE and TRUNCATE on
`events`, `ingest_batches` and `audit_log` from the runtime role. This was verified against the live
upgrade: `UPDATE events …` and `DELETE FROM audit_log` both fail with *permission denied*. PostgreSQL is
not published to the host.

**Containers.** Python and nginx images run as non-root (uid 10001 and the unprivileged nginx image),
with all Linux capabilities dropped, `no-new-privileges`, read-only root filesystems and tmpfs `/tmp`.
Only `127.0.0.1:8080` is published. Ollama is never published.

## Hash chains: tamper-evident, not tamper-proof

Each raw record's SHA-256 is its identity; each ingest batch commits to its events with a Merkle root
and chains to the previous batch; every analyst decision is chained in the audit log. Verification
re-hashes every record **and re-runs the parsers**, so edited normalised fields are detected too.

This makes tampering **evident**, not impossible. Someone with write access to the database can rewrite
an event *and* recompute every later hash, and the chain will verify. TraceLayer reduces that risk
(the runtime role cannot rewrite evidence; `tracelayer chain-head` prints heads to anchor externally,
for example in a signed commit, an email to yourself, or a public timestamping service; exported bundles
carry the ledger head and can be checked with the stdlib-only `tools/verify_bundle.py`), but it does not
claim tamper-proof storage.

## Secret rotation

| Secret | Rotate by | Effect |
|---|---|---|
| User password | Account → Password, or an admin recovery code | All sessions revoked |
| Sessions | Account → Active sessions; admin "sign out everywhere"; role change | Immediate |
| `TL_APP_PASSWORD` (runtime DB role) | `ALTER ROLE tracelayer_app PASSWORD …` as owner, update `.env`, `docker compose up -d api` | API reconnects with the new secret |
| `POSTGRES_PASSWORD` (owner) | `ALTER ROLE tracelayer PASSWORD …`, update `.env` | Used only for migrations |
| Bootstrap admin env vars | Remove after first start (production refuses to start while set) | n/a |
| Invitations, recovery codes | Single-use and expiring; revoke pending invitations in Admin | n/a |

There are no long-lived API keys or third-party credentials in TraceLayer, because it calls no paid services.

## Verification performed for v2

- 110 backend tests, including the route-by-role authorization matrix; 10 frontend unit tests;
  8 browser end-to-end tests against the real API; 5 against the static demo.
- `pip-audit`: no known vulnerabilities (hash-pinned lock). `npm audit --omit=dev`: 0 after upgrading react-router.
- `gitleaks` over the full git history and working tree: no leaks (fake test fixtures allow-listed by path).
- `actionlint` on workflows; live checks of PostgreSQL privileges after an in-place upgrade of a real v1 database.

## Reporting

See the repository's root `SECURITY.md`.
