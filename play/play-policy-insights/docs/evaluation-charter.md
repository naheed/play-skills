# Evaluation Charter — play-policy-insights (Jev hybrid)

Status: Living document
Last updated: 2026-09-26

This charter defines **what "good" means** for the play-policy-insights analysis
engine, and the dimensions every architecture change or model update is measured
on. It exists so that when we change the pipeline, swap a model, or add a policy,
we know exactly which numbers must hold or improve. If a change is not measured
on these dimensions, it is not done.

## North star

> Fast and efficient analysis that maintains or improves quality versus the
> existing skill — **high recall and high precision** — while remaining
> reproducible and cheap enough to run on every submission.

Two non-negotiables:

1. **Do not miss violations** (recall). A missed policy violation ships a
   non-compliant app; that is the worst outcome.
2. **Do not cry wolf** (precision). Excess false positives train developers to
   ignore the report and waste review time.

## The dimensions

Every change is evaluated on all of these. Bars live in
`scripts/typesafe_eval/constants.py` so they are reviewable in one place.

| # | Dimension | What it means | How we measure it | Current bar |
| --- | --- | --- | --- | --- |
| 1 | **Recall** | Fraction of true violations the tool flags (IMPORTANT/CRITICAL). | `run_eval` `is_risk` confusion matrix on the labeled set. | ≥ 0.90 (`EVAL_MIN_RECALL`) |
| 2 | **Precision** | Fraction of flagged violations that are real. | Same confusion matrix. | ≥ 0.75 (`EVAL_MIN_PRECISION`) |
| 3 | **Per-field agreement** | Atomic decisions (transmits, disclosure, core, status) matching labels. | `run_eval` per-field tally. | ≥ 0.85 (`EVAL_MIN_AGREEMENT`) |
| 4 | **Calibration** | Do confidence/probability track correctness? Low-confidence cases should be the ones that route to review. | Bucket answers by confidence; check accuracy rises with confidence. | Monotonic; no over-confident errors |
| 5 | **Latency** | Wall-clock per finding and per app scan. | `run_eval` p50 ms/case; end-to-end timing. | p50 ≤ 300 ms/case |
| 6 | **Cost** | Input tokens per finding and per app scan. | Sum `usage.input_tokens`; price per Models page. | Track; no >2× regression without cause |
| 7 | **Parity vs legacy** | Finding-level precision/recall of the Jev tool vs the current agent skill, against a shared gold corpus. | Parity harness (see coverage-evolution doc). | No regression per domain before switch |
| 8 | **Reproducibility** | Same input → same decision. | Pin model id; log raw `probabilities`; re-run diff. | Deterministic given a pinned model |
| 9 | **Coverage** | Share of legacy policy domains/data types with a Jev battery + eval set. | Coverage matrix in the coverage-evolution doc. | Grows toward 100% parity |

## Priority order

When dimensions trade off, resolve in this order:

**Recall > Precision > Calibration > Latency > Cost.**

Rationale: a false negative ships a violation (unrecoverable); a false positive
costs review time (recoverable, and mitigated by routing to a human);
mis-calibration only matters after the first two are healthy; latency and cost
are real but secondary to correctness for a pre-submission gate. Precision is
also protected structurally by the critic pass and confidence-gated
MANUAL_REVIEW.

## Severity is composed in code

We do **not** ask the model "how severe is this?" as a single question — live
testing showed that broad question cannot see that a disclosed, core-functionality
use is compliant. Instead Jev answers atomic booleans (transmitted? disclosed?
core? third-party?) and code composes severity (`evaluate.derive_*_severity`).
This keeps severity tunable, reviewable, and consistent, and is why the
per-field decisions (not a single Score) are the unit of evaluation.

## What to run before merging a change

1. `python -m typesafe_eval selftest` — offline invariants still hold.
2. `python -m typesafe_eval smoketest` — the live path still round-trips (needs key).
3. `python -m typesafe_eval.eval.run_eval --client http --sweep` — recall,
   precision, per-field agreement, latency, and (if a threshold moved) the sweep.
4. If the change touches a policy domain, re-run the **parity** comparison for
   that domain (coverage-evolution doc) and confirm no regression vs legacy.
5. Record the numbers in the PR. A change that lowers recall or precision must
   justify it explicitly or be rejected.

## Current baseline (jev-1.13.0, 2026-09-26)

Labeled set: 13 cases across location, contacts, audio, email, device id, photos,
name (data-safety + permission batteries).

- Recall **1.00**, Precision **1.00** (TP=7, TN=6, FP=0, FN=0).
- Per-field agreement **0.97** (29/30).
- Latency **~149 ms/case**; a full sample-app battery completes in ~1.6 s.
- `transmits_offdevice` threshold sweep: stable P=R=1.00 across T∈[0.40, 0.70]
  once snippets include the co-located data-flow lines.

These numbers are a small-set baseline, not a release gate. The coverage
evolution plan describes how the labeled set and gold corpus grow per domain.
