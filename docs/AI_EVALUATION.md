# AI Evaluation: Evidence Integrity Engine v2 and Local LLM

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
