# Presenting TraceLayer

Every number here is reproducible from this repository (PERFORMANCE.md, AI_EVALUATION.md,
REAL_WORLD_DATA_EVALUATION.md). Keep the caveats when someone asks. They are part of the story.

**On AI assistance:** TraceLayer was built with substantial help from an AI coding assistant (Claude),
directed and reviewed by me. Say so plainly if asked. What you should own and be able to defend is the
engineering judgement: the evaluation methodology, the security model, and the trade-offs recorded in these docs.

## Resume bullets

- **Built TraceLayer, a security investigation platform (FastAPI, PostgreSQL, React/TypeScript),** with
  versioned Windows telemetry parsers that fully normalise 97.7–99.8% of events across 5 public OTRF attack
  datasets (26,228 events; prior parser: 4.4% typed), a SHA-256 hash-chained evidence ledger, and 13 MITRE
  ATT&CK-mapped detections correlated into investigation timelines and entity graphs.
- **Designed a deterministic Evidence Integrity Engine that verifies each LLM-generated claim against its cited
  log events** across six verdict classes, scoring 95.2% on a frozen 42-case adversarial held-out set (prior
  version: 76.2%) with zero dangerous false verifications; a grounded generation pipeline cut a local Llama 3.2
  3B model's unsafe claims from 55.4% to 2.9%.
- **Implemented Argon2id authentication, server-side sessions with CSRF protection, and RBAC verified by tests
  across all 82 API routes,** plus database-enforced evidence immutability; shipped through GitHub Actions CI
  (119 backend tests, Playwright E2E, secret and dependency scanning) with a $0 static demo on GitHub Pages.

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

## LinkedIn launch post (v3.0.0)

The hook is a real claim from the demo: the free-form llama3.2:3b draft says "Alice successfully brute forced
admin credentials after 42 failed attempts". Its six citations are failed logins for jsmith, root (3), admin and
alice, and only one is Alice's. The 42 is the total from 203.0.113.45 across several accounts. The engine marks
it contradictory ("Claims 42 failed logins; evidence shows 1 / 11", meaning 1 in the citations and 11 in the
whole case).

> A local LLM wrote me an incident report blaming a user for "42 failed attempts." Only one failed login it
> cited was theirs. The 42 came from an IP spraying several accounts.
>
> I built TraceLayer, an open-source security investigation platform, to catch exactly that.
>
> It normalises Windows Security, Sysmon and PowerShell telemetry, hashes every raw record into a
> tamper-evident ledger, runs 13 MITRE ATT&CK-mapped detections, and correlates related alerts into cases with
> timelines and entity graphs. FastAPI and PostgreSQL sit behind a React/TypeScript workspace with role-based
> access and an audit trail.
>
> A local Llama 3.2 3B model drafts each investigation. Then a deterministic Evidence Integrity Engine checks
> every claim against the events it cites: entities, counts, times, outcomes. Claims come out verified,
> correlated, hypothesis, missing evidence, unsupported or contradicted, and unsafe ones block approval until
> an analyst decides.
>
> On lab and synthetic data:
> • 95.2% on a frozen 42-case adversarial set, zero dangerous false verifications
> • Unsafe AI claims cut from 55.4% to 2.9% by letting the model cite only pre-verified facts
>
> The hardest part was measuring honestly. My first checker accepted 5 of 24 adversarial claims it had never
> seen, so I now tune only on development sets and score each frozen test set once.
>
> Built with AI-assisted development; methods and limits are in the repo.
>
> GitHub: https://github.com/PrateekGithub23/tracelayer
> Live demo: https://prateekgithub23.github.io/tracelayer/
>
> #CyberSecurity #SoftwareEngineering #DetectionEngineering #OpenSource #AI

Sources: held-out v3 `evaluation-v3.json` (`sets.heldout_v3`); unsafe rate `llm-v3-freeform-vs-grounded-idle.json`
(3 investigations × 5 runs per mode); "5 of 24" `heldout-v2-baseline-v1-engine.json` (`unsafe_acceptance`).

### Carousel (`portfolio/linkedin/`, 3200×2000 PNG)

1. `01-dashboard.png`: security overview (events, detections, investigations, AI claim verdicts).
2. `02-investigation.png`: the 7-stage case with ATT&CK stages, telemetry blind spots and entity graph.
3. `03-evidence-integrity.png`: the contradicted "42 failed attempts" claim with its reasons and review controls.
4. `04-evaluation.png`: v3 results, with every number read from `benchmarks/results/*.json` at render time.

Images 1–3 are unretouched screenshots of the public demo inside a titled frame. Regenerate them with
`cd frontend && LINKEDIN=1 DEMO_URL=https://prateekgithub23.github.io/tracelayer/ npx playwright test -c playwright.demo.config.ts linkedin`.
The graph layout is randomised, so pick a clear one with `GRAPH_LAYOUT=<n>` (see `portfolio/linkedin/raw/`).

## 60-second demo video (shot list)

Record the live demo at 1440×900 with the cursor visible and no narration overlay; move slowly and pause about
1 s after each click.

1. (0–6 s) Overview: hold on the stat tiles and priority investigations.
2. (6–14 s) Investigations → the 7-stage intrusion: pan across the ATT&CK stage strip and blind spots.
3. (14–22 s) Timeline tab: drag across the 11:00–12:00 window to zoom; click one failed-login dot.
4. (22–30 s) Entity graph: click the `203.0.113.45` → `alice` edge to open the exact events in the inspector.
5. (30–44 s) AI analysis → the `ollama` draft: scroll to the contradicted "42 failed attempts" claim and pause
   on "Claims 42 failed logins; evidence shows 1 / 11", then on the unsupported transfer claim.
6. (44–50 s) Analyst decision: show "2 unsafe claim(s) still need a decision", then reject the contradicted claim.
7. (50–56 s) Switch to the `ollama-grounded` draft: 1 unsafe claim, already auto-rejected.
8. (56–60 s) Report .md download; end on the repository URL.

## GitHub repository

- **Name:** `tracelayer`
- **Description:** Evidence-first security investigation platform: a local LLM drafts the analysis; a
  deterministic engine verifies every claim against the cited log events.
- **Topics:** `cybersecurity`, `security-tools`, `detection-engineering`, `incident-response`, `mitre-attack`,
  `llm`, `ai-safety`, `fastapi`, `react`, `typescript`, `postgresql`, `ollama`, `threat-hunting`, `siem`
