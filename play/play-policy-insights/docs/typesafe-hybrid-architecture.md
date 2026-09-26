# Play Policy Insights × TypeSafe (Jev): Hybrid Architecture Design

Status: Draft / prototype
Owner: play-policy-insights
Last updated: 2026-09-26

## 1. Purpose

`play-policy-insights` audits Android apps against a set of Google Play policy
domains and emits a deterministic compliance report. Today the audit is a
**pure skill**: the deterministic Python in `scripts/` gathers facts and renders
the report, but the actual policy *judgments* (Phase 2) are produced by whatever
LLM agent happens to invoke the skill, following Markdown prompt files
(`resources/goal_*.md`, `resources/critic.md`).

This document specifies a **hybrid architecture** that keeps everything that is
already deterministic, and replaces the *agent-produced judgment step* with
calls to [TypeSafe's Jev model](https://docs.typesafe.ai/introduction) — a
"System One" model that answers typed questions (`Choice`, `Score`, `Noul`) with
calibrated probabilities instead of free-form text.

The goal is to turn Phase 2 from "an agent emits JSON findings" into "a
deterministic program asks Jev a fixed battery of typed questions and composes
the answers in code," so the tool:

- runs without a host agent in the loop (usable directly in CI / as a
  pre-submission gate);
- produces calibrated, tunable confidence that maps onto real thresholds;
- is testable against a labeled evaluation set and pinnable to a model version;
- keeps a **pure-skill offline fallback** so nothing regresses when there is no
  network or API key.

This is explicitly a **hybrid**, not a wholesale replacement. Jev makes the
narrow decisions; Python owns the workflow, the arithmetic, the report prose,
and the routing.

## 2. Background: how the pipeline works today

Three stages, only the middle one uses AI:

| Stage | Entry point | Deterministic? | What it does |
| --- | --- | --- | --- |
| Phase 1 — triage | `orchestrator.py init <app_dir>` | Yes (Python) | Walks the app, runs the static signal scanner (`scanner.py`), parses the manifest/Gradle, ingests any local Play Store declaration, and writes per-goal inputs (`input_worker_<goal>.json`) plus prompts. |
| Phase 2 — judgment | the invoking agent (Mode A/B in `SKILL.md`) | **No (LLM)** | For each activated goal, an agent reads `prompt_worker_<goal>.md` and writes `worker_<goal>.json` findings; a critic agent reads `prompt_critic_<i>.md` and writes `critic_output_<i>.json` verdicts. |
| Finalization | `orchestrator.py aggregate` + `generate_report.py` | Yes (Python) | Chunks findings for the critic, reconciles worker findings + critic verdicts + Play Store declaration, routes by action/severity, and renders `compliance_report.md`/`.json`. |

### 2.1 What Phase 2 actually decides

The `worker_<goal>.json` schema (see `goal_data_safety.md`, `goal_user_account.md`,
`goal_permissions_and_apis.md`) is already a set of typed values, not prose:

- Booleans: `is_transferred`, `user_initiated`, `is_third_party`, `linked_to_user`.
- An enum: `prominent_disclosure_status` ∈ {DISCLOSED, MISSING, EXEMPT}.
- An ordered severity: `severity` ∈ {SUGGESTION, IMPORTANT, CRITICAL}.
- A policy id: `policy_id` (one of the ids in `policies.json`).
- Free text: `issue_summary`, `recommendation`, `evidence`.

The critic (`critic.md`) then emits a per-finding `action` ∈ {VERIFIED,
MANUAL_REVIEW, PRUNED} with a `confidence` ∈ {High, Medium, Low}, plus optional
text overrides. `generate_report.py` consumes these typed values directly.

In other words, **the pipeline is already shaped the way TypeSafe recommends**:
code owns the workflow and the model only makes narrow, structured judgments.
The only "generative" outputs are `issue_summary` and `recommendation`, and both
are formulaic — they can be produced deterministically from `policy_id` +
`data_type` + the decision (Section 5).

## 3. Why Jev fits (and where it does not)

### 3.1 Fits

- **Typed by construction.** Jev returns a value constrained to the options you
  gave it plus a probability distribution — no JSON-parsing-from-prose, which is
  the fragile part of the current Mode A/B flow.
- **Calibrated confidence.** `Choice`/`Score` answers carry a `confidence`
  derived from the probability distribution, trained to be calibrated. That
  replaces the LLM's made-up `confidence: "High"` string with a number your
  `route()` can threshold, exactly like the
  [guardrails cookbook](https://docs.typesafe.ai/cookbooks/llm_guardrails).
- **Parallel batteries.** Every question in a request is evaluated in parallel
  and in isolation; adding speculative questions is nearly free and avoids
  context-rot. One request per finding (or per file) covers the whole battery.
- **Maps 1:1 onto our schema.** See Section 4.

### 3.2 Does not fit — keep these in code (per the
[jaggedness notes](https://docs.typesafe.ai/model-jaggedness/jev-1.13.md))

- **Generation.** Jev cannot write `issue_summary`/`recommendation`. Template
  them (Section 5) or delegate that one part to a generative model.
- **Arithmetic / thresholds.** `targetSdk >= 33`, counts, date math stay in
  Python (they already are).
- **Multi-hop reasoning.** Some `goal_*.md` matrix rows fold several judgments
  into one ("trace the background worker, decide if deferrable"). These must be
  decomposed into atomic questions combined in code.
- **State quality.** Jev judges what is in `state`. The scanner today records
  `relpath (Pattern: X)` — a match location, not the surrounding code. We add
  deterministic **snippet extraction** so each question sees the real code
  (Section 6).

### 3.3 New non-functional considerations

- **Hosted dependency.** Jev is an external HTTP API needing `TYPESAFE_API_KEY`,
  network egress, and per-token spend, and it means **sending third-party app
  source snippets to an external service**. This repo is otherwise offline and
  stdlib-only, and `SKILL.md` emphasizes portability/containment. Therefore the
  Jev path is **opt-in** and there is always an offline fallback client.
- **Reproducibility.** Jev is self-consistent but not bit-identical. For an audit
  artifact we pin the model id (`jev-1.13.0`, not the `jev-latest` alias) and log
  the raw `probabilities` alongside each decision.
- **Adversarial input.** App code is an adversary (an app trying to pass review).
  Jev treats `state` as data but is not hardened; criteria must be precise and
  covered by the eval set.

## 4. Question mapping

One finding → one Jev request containing a small battery. Example for the
location prominent-disclosure domain:

| Decision we need | Primitive | Notes |
| --- | --- | --- |
| Is sensitive data transmitted off-device? | `Noul` `transmits_offdevice` | snippet + nearby network signals in `state` |
| Is there a gatekeeping disclosure before access? | `Noul` `has_prominent_disclosure` | `critic.md`'s "gatekeeper" rule |
| Is this access core to the app's purpose? | `Noul` `is_core_functionality` | app label + store category in `state` |
| Disclosure status | `Choice` {DISCLOSED, MISSING, EXEMPT} | drives Data-Safety reconciliation |
| Severity | `Score` [SUGGESTION, IMPORTANT, CRITICAL] | route on `score` + `confidence` |

Code then composes these into the existing `worker_<goal>.json` fields:

```
is_transferred            = transmits_offdevice.noul >= T_TRANSMIT
prominent_disclosure...   = disclosure_status.choice
severity                  = level_name(severity.score)
# route / suppress compliant findings exactly as generate_report.py already does
```

The **critic** becomes its own tiny battery per finding (this is the
[citation-check pattern](https://docs.typesafe.ai/cookbooks/citation_check)):

| Critic decision | Primitive |
| --- | --- |
| Does the cited snippet actually support the claim? | `Noul` `evidence_supports_claim` |
| Verdict | `Choice` {VERIFIED, MANUAL_REVIEW, PRUNED} + `confidence` |

Routing then uses the Choice `confidence`, matching `generate_report.py`'s
existing action routing. (Note the jaggedness caveat: do not carry a threshold
tuned on a `Noul` over to a `Choice`; they answer different questions.)

## 5. Deterministic `issue_summary` / `recommendation`

We formalize both as templates keyed by `policy_id` (+ `data_type` for
data-safety findings), sourced from the canonical policy names in `policies.json`
and the "Direct Actionable Recommendation" text already written in the
`goal_*.md` matrices. Jev supplies the *decision*; Python fills the sentence.

```
issue_summary   = SUMMARY_TEMPLATES[policy_id].format(data_type=..., app=...)
recommendation  = RECOMMENDATION_TEMPLATES[policy_id][severity]
```

This removes the last generative dependency from the default path and makes the
report reproducible. A generative model remains an optional enhancement for
bespoke, codebase-specific wording.

## 6. Snippet extraction

`scanner.py` finds signals but stores only `relpath (Pattern: X)`. The evaluator
adds a deterministic extractor that, for each signal, opens `<app_dir>/<relpath>`,
locates the line(s) containing the pattern, and returns the matched line plus a
few lines of context, together with any **co-located** network / disclosure
signals from the same file. That co-location is what lets a `Noul` answer "is
this location value transmitted off-device?" instead of merely "does this file
mention `FusedLocationProviderClient`?".

Extraction is pure, offline, and filtered (only the lines a question needs),
which also respects Jev's guidance to keep `state` small and relevant.

## 7. Component design

New, additive package `scripts/typesafe_eval/` (nothing in the existing scripts
changes; the evaluator emits the same `worker_<goal>.json` the pipeline already
consumes):

| Module | Responsibility |
| --- | --- |
| `constants.py` | All tunable thresholds + policy prose templates in one reviewable place (per TypeSafe's "keep questions and thresholds in one file" guidance). |
| `client.py` | `JevClient` protocol; `HttpJevClient` (stdlib `urllib`, real Jev HTTP API, retries/backoff); `HeuristicJevClient` (offline, deterministic stand-in — clearly labeled, not a substitute for real judgment). |
| `snippets.py` | Deterministic code-snippet extraction + co-located signal detection. |
| `questions.py` | The typed question batteries per domain, as plain dicts (SDK-free), so reviewers see all prompts in one file. |
| `templates.py` | Deterministic `issue_summary` / `recommendation` generation. |
| `evaluate.py` | Reads `input_worker_<goal>.json` + app dir, builds `state`, calls the client, composes typed answers into `worker_<goal>.json`. |
| `__main__.py` | CLI: `python -m typesafe_eval run <temp_dir> [--client heuristic|http] [--model jev-1.13.0]`. |
| `eval/` | Labeled fixtures + `run_eval.py` to measure agreement/calibration of a client against expected decisions. |
| `selftest.py` | Offline unit checks (snippets, templates, HTTP request-build/response-parse, answer composition). |

### 7.1 Where it plugs in

```
orchestrator.py init            ->  input_worker_<goal>.json          (unchanged)
python -m typesafe_eval run      ->  worker_<goal>.json   (NEW: replaces the agent)
orchestrator.py aggregate        ->  critic chunks                      (unchanged)
python -m typesafe_eval critic   ->  critic_output_<i>.json (NEW, optional)
generate_report.py               ->  compliance_report.md/.json         (unchanged)
```

The agent-driven Mode A/B remains the fallback when no client is configured.

## 8. Client selection & configuration

- `--client http` (or `TYPESAFE_API_KEY` present): real Jev over HTTPS. Pin
  `--model jev-1.13.0`. Raw probabilities are logged next to each decision.
- `--client heuristic` (default when no key): offline deterministic stand-in used
  for development, CI smoke tests, and wiring validation. It approximates Jev
  outputs from the static signals and is **explicitly not** a source of real
  policy judgments; every finding it produces is tagged `client: "heuristic"` so
  it can never be mistaken for a Jev verdict.

## 9. Validation plan

1. **Wiring (offline, no key):** run `init → typesafe_eval run (heuristic) →
   aggregate → generate_report` on the sample app and confirm a well-formed
   compliance report. This proves the integration end-to-end without network.
2. **Quality (live, needs key):** the `eval/` harness runs a labeled snippet set
   through `HttpJevClient` and reports agreement with expected decisions and
   confidence calibration, one policy domain at a time (start with location
   prominent-disclosure). Promote a domain to the Jev path only when agreement +
   calibration clear a bar you set in `constants.py`.

### 9.1 Live validation results (`jev-1.13.0`)

The HTTP path has been exercised against the real API on the synthetic sample
app (no real proprietary source involved):

- The client works end-to-end; a full app's worker battery completes in ~1.6s.
- Live Jev is calibrated and generally *stricter* than the offline heuristic; it
  rated the audio and broad-contacts cases as risks the heuristic under-rated.
- Real Jev surfaced a state-quality bug the heuristic masked: the snippet was
  anchored on the first occurrence of the matched pattern (a constructor type),
  missing the actual transmission code, so Jev reasonably rated it low. Fix:
  `snippets.py` now appends the co-located data-flow lines to the state. After
  the fix, the precise-location `transmits_offdevice` noul moved 0.58 → 0.93,
  severity confidence 0.28 → 0.90, and the report became correctly
  Non-Compliant.
- Offline-heuristic agreement with the provisional labels (0.94) is circular;
  live-Jev agreement (~0.72) is the real signal and reflects both debatable
  labels (a proper labeling pass is future work) and threshold tuning. This is
  exactly what the harness is for.

## 10. Rollout

- Phase A (this prototype): location, contacts, audio permission domains + the
  data-safety disclosure decision, behind the heuristic/HTTP client switch.
- Phase B: port the remaining `goal_*.md` matrices to atomic question batteries,
  build the labeled eval set per domain, tune thresholds on real traffic.
- Phase C: run the evaluator in CI as a pre-submission gate; keep the pure skill
  as the offline fallback.

## 11. Risks & open questions

- Sending app source to a third party — confirm data-handling posture (ZDR is
  enterprise-only) before enabling the HTTP client on real apps.
- Threshold tuning needs labeled data the project does not yet have; the eval
  harness is the vehicle to build it.
- `resources/` may be overwritten by the `update-skills` automation; keep the
  prototype self-contained under `scripts/typesafe_eval/` and treat `resources/`
  as read-only inputs.
