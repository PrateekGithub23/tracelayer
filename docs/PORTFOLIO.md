# Presenting TraceLayer

Every number here is reproducible from this repository (PERFORMANCE.md, AI_EVALUATION.md,
REAL_WORLD_DATA_EVALUATION.md). Keep the caveats when someone asks. They are part of the story.

**On AI assistance:** TraceLayer was built with substantial help from an AI coding assistant (Claude),
directed and reviewed by me. Say so plainly if asked. What you should own and be able to defend is the
engineering judgement: the evaluation methodology, the security model, and the trade-offs recorded in these docs.

## Resume bullets

- **Built TraceLayer, an open-source security investigation platform (FastAPI, PostgreSQL, React/TypeScript)**
  that normalises real Windows attack telemetry (97.7–99.8% of OTRF lab events, up from 3.5%) into a
  hash-chained evidence ledger, with 13 ATT&CK-mapped detections; two new rules each detected their
  technique on first contact with fresh, independently labelled datasets.
- **Designed a deterministic "Evidence Integrity Engine" that checks every AI-written claim against the log
  events it cites,** scoring 95.2% on a frozen 42-case adversarial held-out set (v2 engine: 76.2%) with zero
  dangerous false verifications in under 0.5 ms per claim, and a grounded generation pipeline that cut a local
  3B model's unsafe claims from 63% to 3%.
- **Hardened it for multi-user use:** Argon2id accounts, HttpOnly server-side sessions with CSRF protection,
  role-based access tested across all 82 API routes, conflict-safe case workflows with reviewer segregation
  of duties, and evidence tables PostgreSQL itself makes immutable. Shipped a $0 static public demo verified by
  browser tests that it never contacts a backend.

## 60-second explanation

"Security teams want AI to draft investigations, but small models are confidently wrong. In my benchmark, a
local 3B model got the JSON format right every time while about 60% of its factual claims were unsupported
or contradicted. TraceLayer treats AI output as untrusted input. A deterministic engine re-checks every sentence
against the exact log events it cites (entities, counts, times, outcomes, ordering) and blocks approval until a
human handles anything unsupported. I then constrained the model so it can only write from facts the engine
already verified, which brought unsafe claims down to about 3%. Underneath is a real pipeline: real public
attack telemetry, hash-chained evidence, ATT&CK detections and a multi-user case workflow, all running on a laptop for free."

## Three-minute technical walkthrough

1. **Ingest (30 s).** Raw records are hashed (SHA-256 of source + canonical JSON), committed per batch with a
   Merkle root, and chained across batches. Parsers are *versioned*: verification re-runs the recorded parser,
   so changing a parser would make old events look tampered. v3 added a new parser version instead, plus an
   audited owner-only re-normalisation path.
2. **Real telemetry (30 s).** OTRF lab data exposed real problems: a local-time field four hours off UTC,
   credentials in command lines, a channel name in two cases, and 96.5% of events landing in "other". The v3
   adapter maps 50 Windows event types with per-event diagnostics (full, partial or raw-only, and *why*).
3. **Detect and correlate (30 s).** Thirteen O(n) rules; union-find correlation into cases. New rules were
   committed before their validation datasets were downloaded.
4. **AI plus verification (60 s).** Free-form drafts, then the integrity engine: parse claim → resolve citations
   → compare attributes → temporal and identity checks → contradictions → verdict with reasons → review flag.
   Grounded mode: verified fact table → model writes with fact ids only → citations are derived → re-verified →
   unsafe claims auto-rejected (recorded).
5. **Evaluation discipline (30 s).** Frozen, hash-pinned held-out sets, run once officially; post-hoc results
   are reported separately; no false-positive rates claimed without benign ground truth.

## Security engineering interview

- **Trust boundaries:** log text is untrusted input to the model; model output is untrusted input to the
  analyst; the browser is untrusted for authorization. Each boundary has a control and a test.
- **Authentication choices:** opaque server-side sessions over JWTs (instant revocation; nothing for XSS to
  steal), synchronizer CSRF tokens, uniform login errors with a dummy Argon2 verify, rate limits per IP *and*
  per account instead of lockout (lockout is itself a denial-of-service vector).
- **Provable authorization coverage:** the RBAC test enumerates routes from the application object, so a new
  endpoint without a permission check fails CI.
- **Evidence integrity:** hash chains are tamper-*evident*; immutability is enforced by revoking UPDATE/DELETE
  from the app's database role; a 70-line stdlib verifier lets a third party check an export.
- **Detection honesty:** rule validation on fresh labelled data, written down before the data was seen; no
  false-positive rate without benign ground truth; documented false-positive scenarios per rule.
- **Prompt injection:** tagged at ingest; grounded mode never shows raw log text to the model.

## Software engineering interview

- **Data safety:** a hand-written migration that copies data before dropping a column, with an
  upgrade/downgrade round-trip test, then a real upgrade of a v1 database after a backup.
- **Concurrency:** optimistic locking via `version_id_col` (a two-thread test: exactly one writer wins); the
  detection engine merges late-arriving evidence instead of duplicating alerts.
- **Performance work with proof:** a 10× ingest slowdown traced to a per-character Python loop; replaced with
  `str.translate`, proven byte-identical on 20,000 random inputs so old evidence still verifies.
- **Testing:** 119 backend tests, frontend unit tests, Playwright end-to-end suites against the real API and
  the static demo (including a strict "no request leaves the demo's own files" policy). E2E tests found real
  bugs: a missing owner name, and a sub-path reload race.
- **Decisions not taken:** no Next.js rewrite (no server-side rendering need); no light theme (it needs a
  colour-token refactor); no LLM-as-judge (a judge can hallucinate too).

## LinkedIn launch post (draft)

> I just published TraceLayer, an open-source security investigation platform built around one idea:
> AI can draft an investigation, but it has to prove what it says.
>
> In my benchmark, a local 3B model produced perfectly valid JSON every time, yet about 60% of its factual
> claims were unsupported by the evidence. So TraceLayer checks every sentence against the exact log events it
> cites and blocks approval until an analyst deals with anything unsupported. Constraining the model to write
> only from verified facts cut unsafe claims to about 3%.
>
> Under the hood: real public attack telemetry (OTRF), a hash-chained evidence ledger, 13 ATT&CK detections,
> multi-user case management, and evaluation on frozen held-out sets, all running on a laptop at zero cost.
>
> Interactive demo (no sign-up): <link> · Code: <link>
> Built with substantial help from an AI coding assistant. The methodology and trade-offs are documented in the repo.
>
> #cybersecurity #detectionengineering #AI #opensource

## 60–90 second demo video

1. (0–8 s) Demo landing → "Start the guided scenario".
2. (8–25 s) Steps 1–4: the suspicious sign-in, 42 failed logins from the same IP, endpoint tradecraft, Domain
   Admins. Click one event to show the raw record and its hash.
3. (25–35 s) Entity graph tab: the case at a glance.
4. (35–55 s) Step 5–6: the grounded draft vs the free-form draft's unsafe count; open a rejected claim and read
   the reason aloud.
5. (55–70 s) Case header: request review (reviewer must be someone else), then the activity feed.
6. (70–85 s) Download the incident report; finish on Datasets → Telemetry coverage.

## GitHub repository

- **Name:** `tracelayer`
- **Description:** Evidence-first security investigation platform: a local LLM drafts the analysis; a
  deterministic engine verifies every claim against the cited log events.
- **Topics:** `cybersecurity`, `security-tools`, `detection-engineering`, `incident-response`, `mitre-attack`,
  `llm`, `ai-safety`, `fastapi`, `react`, `typescript`, `postgresql`, `ollama`, `threat-hunting`, `siem`
