# Evidence Integrity Engine

The engine answers two questions an analyst must be able to answer before acting:

1. **Is this evidence what was originally collected?** (provenance)
2. **Is this statement actually supported by that evidence?** (claim validation)

## 1. Provenance

| Layer | Mechanism | Detects |
|---|---|---|
| Event | `content_hash = SHA-256(source + "\n" + canonical_json(raw))`; `id = "evt_" + hash[:20]` | edited raw records |
| Normalisation | parsers are pure functions of `raw`; verification re-parses and compares 15 derived columns | edited normalised fields (e.g. a changed username) |
| Batch | Merkle root over the batch's event hashes, plus an accepted count | deleted or injected events |
| Ledger | `chain_hash = SHA-256(prev_chain ‖ seq ‖ batch facts ‖ merkle)` | removed, reordered or rewritten batches |
| Decisions | audit entries hash-chained the same way | edited approval history |
| Export | manifest of per-file SHA-256 + bundle hash + ledger head | modified bundle; recipients can re-derive event hashes without TraceLayer |

**Limitation (stated plainly):** this is tamper-*evident*, not tamper-*proof*. Someone with database write access could recompute every hash. Copying the chain head somewhere outside the database (it's in every export and on the dashboard) closes that gap; signing it with a key held elsewhere would be the next step.

## 2. Claim validation

Every analysis must be JSON: `{summary, claims: [{text, kind, citations}], recommendations}`. Each claim gets exactly one verdict:

| Verdict | Meaning | Trusted as evidence? |
|---|---|---|
| `verified_observation` | every checkable fact is in the cited, in-scope events | yes |
| `heuristic_correlation` | each fact is supported; the *link* between them is inferred | yes, labelled as inference |
| `ai_hypothesis` | speculative or hedged; a lead, not a finding | no |
| `missing_evidence` | depends on telemetry that does not exist in scope | no, and it surfaces a blind spot |
| `unsupported_claim` | invented citations or entities, or facts the citations don't show | **blocks approval** |
| `contradictory_finding` | the evidence says otherwise | **blocks approval** |

### Pipeline for one claim

1. **Prompt-injection check** on the claim text itself.
2. **Resolve citations:** `E12` / full id → in scope, real but *out of scope*, or *fabricated*. Detections (`D1`) aren't evidence.
3. **Extract facts** (deterministic regex + vocabulary, see `integrity/extract.py`): IPs, users, hosts (known names and keyword-introduced unknown names), activities (failed/successful auth, PowerShell, certutil, group changes, outbound transfers, log clearing…), quantities (failed-login counts, distinct hosts, flows, MB/GB with `at least` / `approximately` qualifiers), negations, coverage-gap statements, hedging, correlation language, dismissals.
4. **Hard failures** (fabricated / out-of-scope citations, unknown entities) → unsupported.
5. **Dismissals** ("benign", "false positive") relying on injection-tagged events → unsupported. Dismissals that contradict high or critical detections → contradictory.
6. **Absence and gap statements** are checked against scope: a false absence is contradictory; an unverifiable absence (no telemetry of that type) is missing evidence.
7. **Activities** must appear in cited events. If the named host has no such telemetry → missing evidence. If matching events exist but weren't cited → unsupported. If cited events show the opposite outcome → contradictory.
8. **Entities** must appear in the cited events.
9. **Attribution:** the user must appear in a cited event that shows the claimed activity, which defeats decoy citations.
10. **Quantities** are compared with qualifiers and tolerance (5% for volumes).
11. **Temporal order** ("A after B", "A followed by B") is checked against cited timestamps.
12. **Citation flooding** (≥20 citations with <25% relevant) → unsupported.
13. **Safety rule:** if no activity or quantity was recognised, the claim can never be *verified*.

Precedence is most-dangerous-first: hard failure → contradiction → unsupported → missing → hypothesis → correlation → verified.

### Why rules, not an LLM judge?

A judge model can be wrong in the same ways as the generator, costs inference time, and gives different answers from run to run. Rules are reproducible, run in under 1 ms per claim, and every verdict comes with human-readable reasons. The trade-off is **recall**: phrasing outside the lexicon isn't understood. The design makes that failure *safe*, because unrecognised content can't raise a verdict.

## 3. Evaluation

`python -m app.evaluation.suite` builds the seeded scenario in an in-memory database and runs:

* **47 labelled cases** (16 legitimate, 31 adversarial) across 25 categories: fabricated / out-of-scope / detection citations, invented IPs / users / hosts, inflated / deflated counts and volumes, outcome flips, reversed timelines, misattribution (including decoy citations), false absences, false telemetry gaps, injected dismissals, instructions inside claim text, uncited facts, irrelevant citations, citation flooding, kind laundering.
* **16 held-out paraphrases**, written after the validator was tuned and never used for tuning.
* **13 structural checks** on malformed model output (non-JSON, truncated, wrong type, fences, int / str citations, empty claims, 200-claim floods, oversized output, dismissive summaries, invented IPs in the summary, duplicate citations).
* The deterministic analyst as a baseline that must produce zero unsafe claims.

### Results (measured; see `benchmarks/results/evaluation.json`)

| Set | Cases | Accuracy | Unsafe accepted | False rejections |
|---|---|---|---|---|
| Development suite | 47 | 100% | 0 | 0 |
| Held-out paraphrases (before safety rule) | 16 | 87.5% | **1** | 0 |
| Held-out paraphrases (after safety rule) | 16 | 87.5% | **0** | 1 |
| Structural checks | 13 | 13/13 passed | – | – |

**Honest reading:** 100% on the development suite is expected, because the validator was tuned while looking at it, so treat it as a regression suite. The held-out set is the generalisation estimate.

On its first run, one adversarial paraphrase ("alice never obtained administrative group membership") was accepted as verified. Nothing in the lexicon matched the activity, and the validator fell through to "verified" because the entity appeared in the citation. The fix was a general rule, not a case patch: *no recognised activity or quantity means never verified.* Both remaining held-out misses now fail **safe** (labelled unsupported): one false rejection of a correctly stated telemetry gap phrased in unrecognised wording, and one mislabel (contradictory → unsupported).
