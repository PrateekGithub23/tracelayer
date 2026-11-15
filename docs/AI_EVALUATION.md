# AI Evaluation: Evidence Integrity Engine and Local LLM

> **v3 update (2026-11-15).** New frozen held-out set (42 cases): v2 engine **76.2%, 2 dangerous false
> verifications** → v3 engine **95.2%, 0**, official single run. A grounded two-stage LLM pipeline cut
> unsafe claims from **62.9% to 2.6%** with the same 3B model. See [v3](#v3-engine-and-grounded-generation)
> at the end. The v2 sections below are the historical record.

Two questions, answered with measurements:

1. **Does the integrity engine catch false, fabricated or deceptive claims, and does it generalise?**
2. **What does a real local LLM (llama3.2:3b) add, compared with the deterministic analyst?**

Raw results: `benchmarks/results/evaluation-v2.json` (official held-out run),
`evaluation-v2-final.json` (current engine), `heldout-v2-baseline-v1-engine.json`,
`llm-vs-deterministic.json`. Reproduce with `make eval` and `make llm-bench`.

---

## Part 1: Evidence Integrity Engine

### Verdicts (unchanged six-verdict model)

`verified_observation` · `heuristic_correlation` · `ai_hypothesis` · `missing_evidence` ·
`unsupported_claim` · `contradictory_finding`. The six verdicts already separate "true and shown",
"true but inferred", "speculative", "cannot be checked", "not shown" and "shown to be false", so
no new class was needed. v2 adds two things to each result instead: an explainable **stage
trace** and a **`requires_review`** flag.

### Pipeline (deterministic; no model involved)

0. **Size gate.** Claims over 600 characters are rejected before parsing (bounded CPU).
1. **Parse.** Entities (IPs, users, hosts, identifier-shaped names), activities, quantities (with
   qualifiers and number words), stated times with timezones, negation scope, hedging, correlational
   framing, dismissals, attribution/intent conclusions, appeals to authority, and deceptive characters
   (zero-width, mixed-script homoglyphs).
2. **Resolve citations.** Fabricated, out-of-scope and detection-id citations are rejected; duplicates collapse.
3. **Extract attributes** from the cited events.
4. **Compare.** Activities, entities, attribution, counts and volumes; partial citations of a true total
   are reported as incomplete evidence, not as a contradiction.
5. **Temporal and identity checks.** Stated times must match cited events (±90 s for `HH:MM`, after
   timezone conversion; a time without a zone is read as UTC and flagged for review). Ordering claims
   ("after", "followed by") are checked. Homoglyph or unknown identities are rejected.
6. **Contradictions.** False absences, wrong outcomes, reversed order, wrong quantities, dismissals of
   high-severity activity.
7. **Explainable verdict** with reasons and the stage trace.
8. **Review requirement.** Anything other than verified/correlated, or verified with caveats, sets
   `requires_review`. Approval of an analysis is blocked on the server while unsafe claims are unreviewed.

**No semantic similarity or model scoring is used anywhere.** A claim is only verified when explicit
checks pass. Phrasing the lexicon does not understand **fails safe** (unsupported), which costs the
analyst a review but never produces a false "verified".

### What counts as a dangerous false verification

An **adversarial** claim (factually false, fabricated, deceptive, manipulative, or overstating what the
evidence shows) that receives `verified_observation` or `heuristic_correlation`, i.e. one presented to
the analyst as supported by evidence. Labelling a false claim `ai_hypothesis` or `missing_evidence` is
counted as a mislabel, not a dangerous verification, because neither verdict is presented as evidence-backed.

### Evaluation hygiene

| Set | Cases | Role | Used for tuning? |
|---|---|---|---|
| `dev_v1` | 47 (31 adversarial) | v1 development set | yes (v1) |
| `regression_v1_heldout` | 16 | v1's held-out set. **Demoted**: v1 already fixed a flaw it exposed, so it is no longer unseen | yes (v2) |
| `dev_v2` | 37 | new v2 development set, written for the v2 categories with different wording and entities | **yes** |
| `heldout_v2` | 40 (24 adversarial) | **written and SHA-256-frozen before any v2 engine change**; a test fails if the file changes | no |

Two honest caveats about `heldout_v2`:
- Its v1-engine baseline run revealed which *categories* failed (not how to fix them), and `dev_v2`
  targets those categories, so it is not perfectly independent of development.
- It was run once for the official result, at commit `7d83345`. Two later engine changes driven by
  **real data** (prose nouns such as "Account creation" read as user names, found on OTRF telemetry,
  and `*.exe` mentions) also fixed its one miss. That later run is reported separately as **post-hoc**.

### Results

| Set | v1 engine | v2 official (`7d83345`) | v2 current (post-hoc) |
|---|---|---|---|
| dev_v1 (47) | 100% | 100% | 100% |
| regression (16) | 87.5% | 100% | 100% |
| dev_v2 | 33.3% · 11 false verifications | 100% (36) | 100% (37) |
| **heldout_v2 (40)** | **62.5% · 5 false verifications · 3 false rejections** | **97.5% · 0 false verifications · 0 false rejections** | 100% · 0 · 0 |

The five v1 false verifications on the held-out set were: a correct login at the wrong time, a
Cyrillic-homoglyph username, a count "proved" by citing one event 12 times, a true fact plus "which proves
a nation-state actor", and a 24 kB repeated claim.

The official miss, `hv2-36` "These logins are normal user behaviour and not malicious": "user behaviour"
was parsed as a user called *behaviour*, so the claim was rejected as *unsupported* instead of
*contradictory*. The outcome was safe but the class was wrong.

**Held-out v2, official run: confusion matrix** (rows = expected, columns = actual)

| expected \ actual | verified | correlation | hypothesis | missing | unsupported | contradictory |
|---|---|---|---|---|---|---|
| verified (11) | **11** | | | | | |
| correlation (1) | | **1** | | | | |
| hypothesis (2) | | | **2** | | | |
| missing (3) | | | | **3** | | |
| unsupported (12) | | | | | **12** | |
| contradictory (11) | | | | | 1 | **10** |

Per-class precision / recall: 1.0 / 1.0 for every class, except unsupported (precision 0.923) and
contradictory (recall 0.909). False-verification rate 0%; unsupported-claim rejection rate 100%
(every claim that should be rejected was rejected as unsupported or contradictory); false-rejection rate 0%.

**Latency** (124 validations, Apple Silicon): p50 **0.14 ms**, p95 **0.26 ms**, max **0.68 ms**.
The size gate removed a 131 ms worst case on oversized input.

### What the engine does not understand

It is a rule-based system with lexicons. It does not understand arbitrary paraphrase, implication,
or domain knowledge it was not given; compound claims must be split; and quantities it does not parse
are not checked (they cannot *raise* a verdict, only fail to lower it). A 40-case held-out set is small:
treat these figures as evidence the mechanisms work, not as a population accuracy.

---

## Part 2: Local LLM (llama3.2:3b) vs deterministic analyst

**Setup.** Ollama 0.40.16 installed with Homebrew, running natively on Apple Silicon (16 GB), bound to
127.0.0.1. Model `llama3.2:3b`: 3.2B parameters, Q4_K_M, digest `a80c4f17…`. Temperature 0.1, 8k context,
JSON-schema-constrained output. Three investigations: the synthetic 7-stage intrusion, the synthetic SSH
brute force, and the real OTRF lab WMIC backdoor. Five LLM runs each; the deterministic analyst is
deterministic, so it runs once. Both outputs go through the same integrity engine.

| Metric (mean per analysis) | llama3.2:3b | Deterministic |
|---|---|---|
| Valid JSON | **15 / 15** | n/a |
| Generation latency | **18.6 s** (p95 27.9 s) | **1 ms** |
| Claims | 11.3 | 9.0 |
| Unsafe claims (unsupported + contradictory) | **6.4 (57%)** | **0** |
| Fabricated citations | 6.9 | 0 |
| Citation validity (resolved / given) | 79.7% | 99.8% |
| Detection coverage (detections backed by a trusted claim) | 60.6% | 93.3% |
| Claims requiring analyst review | 7.1 | 2.0 |
| Integrity score (0–100) | 38.5 | 86.8 |

Per investigation (LLM means):

| Investigation | Events | Unsafe claims | Fabricated citations | Coverage |
|---|---|---|---|---|
| Synthetic 7-stage intrusion | 474 | 4.0 / 11 | 0 | 82% |
| Synthetic SSH brute force | 25 | **10.4 / 11.4** | **20.8** | 20% |
| OTRF lab WMIC backdoor | 1,507 | 4.8 / 11.4 | 0 | 80% |

**Findings**

- Schema-constrained decoding works: **0 invalid JSON** in 15 runs. Structure is not the problem; truth is.
- The 3B model is fluent and often wrong. More than half of its claims fail verification. On the thin
  SSH case it **invented references**, citing words like "TELEMETRY" and "COVERAGE" as event ids, about
  21 times per analysis.
- The deterministic analyst is less expressive but far more reliable, and 18,000× faster.
- The engine is what makes the LLM usable at all: every one of those claims is labelled, blocked from
  approval, and explained. The approval gate means an unverified LLM draft cannot become the record.
- Recommendation: keep `auto` mode for analyst convenience, treat LLM output as a *draft*, and prefer
  larger models if hardware allows. The engine's guarantees do not depend on model quality.

**Transparency.** Every analysis stores the requested engine, the engine actually used, the model name
and digest, the Ollama version, JSON validity and latency. In `auto` mode, a model that is down, busy or
returns invalid output produces an analysis labelled **deterministic** with the fallback reason. It is
never presented as LLM output.

**Caveat.** This benchmark ran before the final "under-cited total" change (claims citing part of a true
total are now *unsupported* rather than *contradictory*). That change moves claims between the two unsafe
classes; it does not change the unsafe counts.


---

## v3: engine and grounded generation

### Engine v3: what changed (tuned only on dev sets)

| Mechanism | Example it handles | Effect |
|---|---|---|
| Benign-washing grammar | "The certutil download **was a legitimate** administrative task" | contradicts high-severity activity (v2 verified this) |
| Hedged alternatives | "It is **possible** the PowerShell was a legitimate admin script" | hypothesis plus a review warning, not a contradiction |
| Subject-position actors | "**Administrator** logged in from …", "**root** was added to Domain Admins" | unknown actor is unsupported; known common names now count as named users (v2 verified both) |
| Identity swaps | "jsmith was added …" when the cited event shows alice | unsupported, with the reason naming the actual actor |
| Universal / negated paraphrases | "denied all sign-in attempts", "every authentication … was successful", "did not connect to dc-01" | checked against evidence instead of falling back to "unrecognised" |
| Paraphrase lexicon | "were used to sign in", "N login attempts that failed" | recognised activities and counts |

**A semantics decision, kept deliberately.** Is "jsmith logged in from X" *contradicted* by an event showing
alice logged in from X? It is not: that event does not prove jsmith did *not* also log in. v1 labelled such
claims *unsupported* and reserved *contradictory* for cited evidence that actually conflicts (its adv-20 decoy
case). An early v3 change made swaps contradictory; it broke two v1/regression cases for that reason and was
reverted to *unsupported* with a better explanation. The frozen held-out v3 file uses the stricter label for
h3-24; it was not edited, and the case is reported as a miss.

### Evaluation sets

| Set | Cases | Role | Tuned on? |
|---|---|---|---|
| dev_v1, regression, dev_v2 | 47 / 16 / 37 | earlier development and regression sets | yes (earlier versions) |
| dev_v3 | 19 | v3 development: new wording for the v3 categories | **yes** |
| heldout_v2 | 40 | v2 held-out, now regression (its post-hoc result is not "unseen") | no, but seen |
| **heldout_v3** | **42** (23 adversarial) | written and SHA-256-frozen **before** any v3 engine change | **no** |

Same caveat as v2: the v2-engine baseline run of heldout_v3 revealed failure *categories*, which dev_v3 then targeted.

### Results

| Set | v2 engine | **v3 engine (official, `df46a07`)** |
|---|---|---|
| dev_v1 / regression / dev_v2 | 100% / 100% / 100% | 100% / 100% / 100% |
| dev_v3 (19) | 47.4% · 5 false verifications | 100% · 0 |
| heldout_v2 (40) | 100% (post-hoc) | 100% (post-hoc) |
| **heldout_v3 (42)** | **76.2% · 2 false verifications · 4 false rejections** | **95.2% · 0 false verifications · 0 false rejections** |

**Held-out v3 confusion matrix (official run; rows expected, columns actual)**

| expected \ actual | verified | correlation | hypothesis | missing | unsupported | contradictory |
|---|---|---|---|---|---|---|
| verified (8) | **8** | | | | | |
| correlation (4) | | **4** | | | | |
| hypothesis (4) | | | **4** | | | |
| missing (3) | | | | **3** | | |
| unsupported (10) | | | | | **9** | 1 |
| contradictory (13) | | | | | 1 | **12** |

Per-class precision and recall: 1.0 for verified, correlation, hypothesis and missing; 0.90 / 0.90 for
unsupported; 0.923 / 0.923 for contradictory. False-verification rate 0%. Unsupported-claim rejection rate
100% (every claim that should be rejected was rejected, as unsupported or contradictory).

The two misses were both still rejected:
- **h3-24** identity swap: labelled contradictory, engine says unsupported (the semantics decision above).
- **h3-37** "The CISO has reviewed this activity and confirmed it was a scheduled drill": labelled
  unsupported (appeal to authority), but classified as a contradictory dismissal ("was a scheduled …"),
  because the authority grammar does not know "CISO has reviewed".

**Latency** (warm, 56 validations of the dev sets): p50 **0.27 ms**, p95 0.40 ms, max 0.47 ms, about 2×
v2's 0.14 ms because of the added grammar. The first validation after start-up includes one-time regex
compilation (~17 ms).

### Grounded two-stage generation (v3)

**Pipeline.** (1) The deterministic analyst extracts candidate facts; the engine keeps only verified or
correlated ones as a numbered fact table (F1…Fn) with their event citations. (2) The model sees *only* the
fact table, never raw log text, and must reference facts by id. (3) Citations are derived server-side from
the referenced facts; unknown ids are dropped and counted, so the model **cannot introduce a citation**.
(4) Every claim is verified as usual; claims that come out unsupported or contradictory are rejected by the
pipeline (a recorded system decision, with the reason); hypotheses and missing-evidence claims go to the analyst.

**Benchmark.** Same model (`llama3.2:3b`, Q4_K_M), same three investigations (synthetic intrusion,
synthetic SSH brute force, OTRF WMIC backdoor), five runs per mode, same scoring engine
(`benchmarks/results/llm-v3-freeform-vs-grounded-idle.json`; the earlier run, made while other tests
were executing, is kept as `llm-v3-freeform-vs-grounded.json`).

| Metric (mean per analysis) | Free-form | **Grounded** | Deterministic |
|---|---|---|---|
| Valid JSON | 15/15 | 15/15 | n/a |
| Unsafe-claim rate | 55.4% | **2.9%** | 0% |
| Unsafe claims | 6.47 | **0.40** | 0 |
| Fabricated citations | 7.93 | **0** | 0 |
| Citation validity | 66.3% | **100%** | 99.8% |
| Trusted claims (verified/correlated) | 4.27 | **6.13** | 7.0 |
| Claims needing analyst review | 7.27 | **1.47** | 2.0 |
| Detection coverage (completeness) | 57.6% | 57.0% | 93.3% |
| Integrity score | 40.3 | **75.7** | 86.8 |
| Latency mean / p95 / stdev | 32.1 s / 40.1 s / 5.2 s | 22.7 s / 45.5 s / 16.5 s | 2 ms |

**Reading it.**
- Grounding removes the failure mode that dominated free-form output: invented citations went from ~8 per
  analysis to 0 by construction, and the unsafe-claim rate fell about 19× (55% → 3%).
- **Completeness did not improve.** Both LLM modes cover about 57% of detections against 93% for the
  deterministic analyst; the busy-machine run showed grounded slightly *lower* (57.6% vs 64.5%). The
  model omits facts it was given, especially on the thin SSH case.
- Grounded is faster on average (shorter outputs) but more variable; latencies are *not* comparable to
  v2's 18.6 s figure, because the evidence packs differ (v3 events carry richer fields) and machine load
  differed. Only within-run comparisons are claimed.
- **Decision:** grounded is the default LLM mode in v3; the deterministic analyst remains fully operational
  and is still the most complete and reliable generator. The model's value is narrative, not facts.
