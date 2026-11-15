# Security notes

TraceLayer is a self-hosted, single-team tool. This page lists what it protects against, what it doesn't, and how to harden it.

## Controls in place

| Area | Control | Where |
|---|---|---|
| Write authentication | Optional bearer token (`TRACELAYER_API_TOKEN`), constant-time comparison; required on every state-changing route | `app/api/deps.py` |
| Input limits | Max records per batch (50k), max upload size (25 MB, read one byte past the limit to detect oversize), request schema validation, source-name allow-list pattern | `app/api/ingest.py`, `app/schemas.py` |
| Injection (SQL) | ORM / Core parameter binding throughout; user search terms have `LIKE` wildcards escaped | `app/api/events.py` |
| Log forging | Control characters stripped from every string field at parse time | `app/ingestion/parsers.py` |
| Prompt injection via telemetry | Pattern tagging at ingest; events passed to the LLM as quoted, truncated, single-line data and explicitly flagged; system prompt states that event text is never an instruction; **all** model output re-validated, so injected conclusions are labelled unsupported | `parsers.py`, `ai/prompt.py`, `integrity/validator.py` |
| Untrusted model output | Size caps (500 KB output, 40 claims, 500 citations, 2,000 chars per claim); strict schema; failure → deterministic fallback | `app/ai/schema.py` |
| CSV injection | Cells starting with `= + - @ \t \r` are prefixed with `'` in exports | `app/export.py` |
| Evidence tampering | Hash per record, Merkle root per batch, chain across batches, re-parse verification | `app/integrity/ledger.py` |
| Decision tampering | Hash-chained audit log | `app/audit.py` |
| Approval safety | Unsafe claims block approval; overriding one needs a written justification | `app/api/investigations.py` |
| HTTP hardening | `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, CSP (nginx), restrictive CORS, no stack traces in error responses | `app/main.py`, `frontend/nginx.conf` |
| Container | Non-root user, no build tools in the runtime image, DB not published to the host, ports bound to 127.0.0.1 | `backend/Dockerfile`, `docker-compose.yml` |
| No egress | No external services; fonts bundled; the LLM is local | – |

## Known limitations

* **Single shared token, no per-user auth.** The analyst name (`X-Analyst`) is an attribution label, not an identity. For multi-user use, put the stack behind a reverse proxy with SSO (e.g. oauth2-proxy, both free) and derive the analyst from the authenticated identity.
* **Reads are unauthenticated** when a token is set. That's acceptable on localhost; for anything else, require auth on reads too (a one-line dependency change).
* **Tamper-evident, not tamper-proof.** See EVIDENCE_INTEGRITY.md. Anchor the chain head externally, or sign it.
* **Token stored in `localStorage`** in the UI, so it's readable by any script on the origin. The CSP blocks third-party scripts, but an HttpOnly session cookie would be stronger.
* **Prompt-injection detection is pattern-based** and will miss novel phrasings. The real safety net is that model output is never trusted without validation.
* **No rate limiting** on the API. Add it at the reverse proxy if exposed.
