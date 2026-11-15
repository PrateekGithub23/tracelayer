# Known Limitations

What TraceLayer v2 does **not** do, or does only partially. Each item links to the evidence.

## Data and detection

- **No enterprise production data.** Evaluation uses a seeded synthetic scenario and two small OTRF
  *lab* datasets (one attack window each, little benign background). Detection quality on a real network
  is unmeasured. ([REAL_WORLD_DATA_EVALUATION.md](REAL_WORLD_DATA_EVALUATION.md))
- **No false-positive rate on real data.** The public datasets have technique-level labels only and no
  benign baseline, so precision, F1 and FP rates are deliberately not reported for them.
- **Small held-out samples.** Real-data generalisation rests on one held-out dataset (n = 1 technique);
  the integrity engine's held-out set has 40 claims.
- **Schema coverage.** About 97% of real Windows events map to `other` (process access, registry, image
  load and WFP events are kept raw but are not typed or detectable). One adapter (OTRF/NXLog Windows)
  exists; Zeek, firewall and cloud logs do not.
- **11 rules** covering a handful of ATT&CK techniques; no Sigma import, no ML.

## Evidence Integrity Engine

- Rule-based extraction: unusual phrasing is not understood and fails safe as *unsupported*, which
  costs analyst time. Compound or long claims (over 600 characters or 3 sentences) are rejected outright.
- Times without a timezone are read as UTC (flagged for review); ambiguous abbreviations (IST, AST) are rejected.
- The engine checks what the *cited* evidence shows. It cannot judge whether the evidence itself is
  truthful (an attacker who controls logs controls evidence).
- The held-out set is not perfectly independent: its baseline run revealed failure categories. The
  official result (39/40) and the post-hoc result (40/40) are reported separately. ([AI_EVALUATION.md](AI_EVALUATION.md))

## AI

- llama3.2:3b produces unsafe claims at a high rate (57% of claims in the benchmark) and takes ~19 s per
  analysis. It is a drafting aid that requires review, not an analyst.
- One generation at a time; no streaming, cancellation or queueing.
- The public demo cannot generate analyses or validate arbitrary text; it shows real pre-recorded results.

## Security

- **Tamper-evident, not tamper-proof.** A database superuser can rewrite history consistently; anchor
  chain heads externally. On SQLite, the database-level immutability grants do not exist.
- No MFA, SSO or WebAuthn. Password recovery depends on an administrator (no email by design).
- Rate limits and the LLM concurrency guard are in-process: a multi-worker deployment would need a shared store.
- There is no audit log of *reads* (who viewed which event), only of changes and exports.
- `ANALYZE` cannot run as the non-owner runtime role on PostgreSQL 16 (a warning, so statistics can go
  stale); run it periodically as the owner.

## Collaboration and operations

- No real-time collaboration (refresh-based; conflicts are detected with optimistic locking, not merged).
- No notifications (email or chat), SLAs or case templates.
- Background jobs run in-process and are marked failed if the process restarts mid-job.
- Single node. Backups are manual (`pg_dump`); there is no built-in retention policy for events.

## Deployment

- No free host offers persistent PostgreSQL plus an API at $0 without a card, so the full application is
  local-only and the public artifact is a read-only static demo. ([DEPLOYMENT.md](DEPLOYMENT.md))
- CI has been validated locally (every job's steps run on this machine, and the workflows pass
  `actionlint`) but has **not run on GitHub**, because no remote repository exists yet.

## UI

- Dark theme only; there is no light theme.
- Saved-filter naming and pin notes use browser prompts rather than custom dialogs.
- Accessibility work covered labels, focus, roles and a skip link, but no screen-reader audit was done.
