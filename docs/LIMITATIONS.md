# Known Limitations

What TraceLayer v2 does **not** do, or does only partially. Each item links to the evidence.

## Data and detection

- **No enterprise production data.** Evaluation uses a seeded synthetic scenario and five small OTRF
  *lab* datasets (one attack window each, little benign background). Detection quality on a real network
  is unmeasured. ([REAL_WORLD_DATA_EVALUATION.md](REAL_WORLD_DATA_EVALUATION.md))
- **No false-positive rate on real data.** The public datasets have technique-level labels only and no
  benign baseline, so precision, F1 and FP rates are deliberately not reported for them.
- **Small held-out samples.** Real-data generalisation rests on a handful of fresh datasets (one technique
  each); the integrity engine's held-out sets have 40 (v2) and 42 (v3) claims.
- **Schema coverage (improved in v3).** On the five OTRF datasets, 97.7–99.8% of events are fully
  normalised (v2: 3.5% typed). Coverage is per adapter: only Windows event logs exported by NXLog/OTRF
  have a v3 adapter. Zeek, firewall, cloud and Linux audit logs do not. Some Windows events remain raw-only
  (Kerberos 4769, scheduled tasks, Sysmon 2/23). Class names are OCSF-inspired; the output is **not**
  OCSF-compliant.
- **13 rules**, covering a small set of ATT&CK techniques; no discovery rule (the T1069 control dataset was
  missed), no Sigma import, no ML. Two v3 rules were validated on one fresh dataset each: evidence that
  they work, not a coverage or false-positive rate.

## Evidence Integrity Engine

- Rule-based extraction: unusual phrasing is not understood and fails safe as *unsupported*, which
  costs analyst time. Compound or long claims (over 600 characters or 3 sentences) are rejected outright.
- Times without a timezone are read as UTC (flagged for review); ambiguous abbreviations (IST, AST) are rejected.
- The engine checks what the *cited* evidence shows. It cannot judge whether the evidence itself is
  truthful (an attacker who controls logs controls evidence).
- The held-out sets are not perfectly independent: each baseline run revealed failure categories that
  the next dev set targeted. Official results (v2 39/40, v3 40/42) and post-hoc results are reported
  separately. ([AI_EVALUATION.md](AI_EVALUATION.md))
- Identity swaps ("jsmith did X" when the evidence shows alice) are *unsupported*, not *contradictory*:
  a deliberate semantic choice that one frozen held-out label disagrees with.
- Appeals to authority are recognised by a phrase list; new phrasings ("the CISO has reviewed …") can be
  classified as a dismissal instead. They are still rejected.

## AI

- llama3.2:3b writing freely produced unsafe claims at a high rate (57–63% of claims). Grounded mode (v3
  default) reduces this to ~3%, but is **less complete**: it only restates facts the deterministic stage
  extracted, and on thin cases the model wrote few useful claims (detection coverage 58% vs 65% free-form,
  93% deterministic). Either way, the model is a drafting aid that requires review.
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
- Hosted CI (GitHub Actions) runs lint, types, tests, the evaluation, a PostgreSQL privilege job, browser
  e2e and security scans. It does not run the real-LLM benchmark or the large real-dataset imports (no model
  or cached datasets on the runners); those results come from local runs recorded in `benchmarks/results/`.
- Script-heavy telemetry ingests more slowly (~2.8k events/s parse rate on the Mimikatz dataset), because
  every PowerShell script is scanned for prompt injection.

## UI

- Dark theme only. A light theme was considered and not added: accent colours are tuned for dark
  surfaces across ~40 components, and a clean light theme needs a token refactor, not a quick switch.
- Accessibility work covered labels, focus, roles and a skip link, but no screen-reader audit was done.
