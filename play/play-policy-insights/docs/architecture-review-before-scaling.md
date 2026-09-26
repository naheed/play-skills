# Architecture Review — decisions to lock before scaling coverage

Status: Review / proposed decisions
Last updated: 2026-09-26

Before expanding from the 4 prototyped policies to the full `policies.json` set
(~16 policy ids + 35 data types), this review flags what the current design will
get wrong at scale. The prototype is sound; the issues below are about
**scaling** it, because adding 14 more policies amplifies each one.

Verdict: resolve the **P0** items first (they change how every new policy is
added), land the **P1** items as coverage grows, and layer in **P2**.

## P0 — decide before adding policies

### P0-1. One policy = one place. Introduce a policy registry.

**Problem.** Adding a single policy today touches **five files**: `questions.py`
(battery), `evaluate.py` (`PERMISSION_POLICY` map + a `derive_*_severity` rule +
a `goal`-based `compose` branch), `templates.py` (summary/recommendation),
`constants.py` (`SENSITIVE_DATA_TYPES` / `HIGH_RISK_PERMISSION_POLICIES`), and
`eval/labeled_cases.json`. At 16 policies this scatters one concept across the
codebase and makes review and drift-detection hard.

**Recommendation.** Define each policy as a **single declarative spec** (one
module/object per policy) holding: its `policy_id`, activation (which
signals/permissions/manifest facts trigger it), its question battery, its
code-composed severity rule, its templates, and a pointer to its eval fixtures.
`evaluate.py`/`batch.py` become generic engines that iterate the registry. This
is the enabler for everything else here.

### P0-2. Not every policy is code-signal. Define evaluation *kinds*.

**Problem.** `compose` branches on **goal name** (`permissions` / `data_safety`
/ `user_account`) and the evaluator only handles findings that come from code
signals with a file+pattern (`snippets.build_state`). But many remaining
policies are not code-signal:

- **Manifest/permission** (`foreground_services_policy`, `exact_alarm_policy`,
  `package_visibility_policy`, `accessibility_api_policy`) — driven by
  `manifest_details.json`, not a file snippet.
- **Pure-code / numeric** (`target_api_level`) — a deterministic SDK check.
- **Console/metadata** (`login_credentials`, `account_deletion`) — presence /
  declaration checks.

**Recommendation.** Make the registry declare an **evaluation kind** per policy:
`code_signal` (file-snippet state), `manifest` (app-level state from
`manifest_details`), or `deterministic` (code only, no model). The engine picks
the state builder and batching key from the kind. This also fixes batching:
manifest-kind policies become **one app-level request**, not per-file.

### P0-3. Consume raw scan artifacts, not the agent's prompt files.

**Problem.** The evaluator reads `input_worker_<goal>.json` — a **byproduct of
the LLM agent's prompt generation** (`write_agent_prompts`). Its shape (chunking,
flavor filtering, `{type:{description,findings}}` vs `{type:[...]}`) is tuned for
the agent, and it changes when the goal templates change. Our deterministic tool
should not depend on the agent path's internals.

**Recommendation.** Have the evaluator read the **raw deterministic artifacts**
`orchestrator.py init` writes — `data_safety_scan.json`, `manifest_details.json`,
`codebase_map.json`, `play_store_info.json` — and do its own activation from the
registry. This decouples the two Phase-2 implementations and gives the evaluator
a stable input contract.

## P1 — as coverage grows

### P1-1. Eval methodology: guard against overfitting.

The current 13-case set scores recall/precision 1.00 — encouraging, but **too
small to trust**. At scale we need, per policy: a minimum fixture floor (e.g. ≥3
positive, ≥3 negative, ≥2 boundary), a **held-out set** never used for threshold
tuning, and calibration checks. Thresholds tuned on the same cases they are
scored on will look better than they are. Own labels with a policy expert.

### P1-2. Robustness: isolate failures; never crash a whole scan.

`evaluate.run` / `batch.run_batched` call `client.system_one` with **no
try/except**; one exhausted-retry API error raises and kills the entire scan
(and for `--batch`, one bad file loses every file). Recommendation: catch per
unit (file/finding), emit a `MANUAL_REVIEW` finding for the failed unit, continue
the scan, and fall back to the offline/legacy path when the API is unavailable.

### P1-3. Decide the critic's role in the Jev world.

The legacy critic exists to catch a generative worker's false positives. With Jev
answering atomic questions against the actual snippet and severity composed in
code, a **separate LLM critic pass may be redundant**. Options: (a) drop it and
rely on confidence-gated `MANUAL_REVIEW`; (b) keep a cheap Jev "evidence supports
claim" Noul only for high-severity findings; (c) keep the full critic. Decide
before every new policy inherits critic cost. Leaning (b).

### P1-4. Avoid dual maintenance of policy logic.

We now encode each policy twice: the `goal_*.md` matrices (for the legacy agent)
and the Jev registry. That doubles maintenance and invites divergence. Decide
whether the registry becomes the **single source of truth** (with the legacy
path deprecated or generated from it) or whether the two coexist behind a parity
test. Coexistence is fine short-term but needs the parity harness (coverage doc).

### P1-5. Results cache for cheap re-runs.

Re-scanning the same commit re-calls Jev; eval iteration re-calls constantly. A
local cache keyed by `(model_id, question_hash, state_hash)` (as the cookbooks'
`JsonCache` does) makes re-runs and CI nearly free and makes runs reproducible.

## P2 — layer in

- **Security / prompt injection.** App code is adversarial. Never interpolate app
  strings into `instructions`; keep `criteria` precise; add adversarial fixtures
  and an injection-guard Noul ("does this code try to manipulate an automated
  reviewer?"). 
- **Data handling.** Redact string literals / secrets and minimize snippets
  before egress; cap what leaves per finding.
- **Determinism.** Log `probabilities` on every finding (done); widen the
  `MANUAL_REVIEW` band for borderline; optionally N-run majority for high-stakes
  decisions (self-consistency pattern).
- **Schema contract.** Freeze/version the `worker_*.json` finding schema so
  `generate_report.py` does not churn as policies are added. (Today `policy_id` +
  `policies.json` metadata already absorbs new policies with no report change —
  keep it that way.)

## Proposed target shape

```
registry/                      one spec per policy (id, kind, activation,
  location_access_policy.py       battery, severity rule, templates, fixtures)
  contacts_access_policy.py
  foreground_services_policy.py  (kind=manifest)
  target_api_level.py            (kind=deterministic)
  ...
engine:
  activation  reads raw artifacts (data_safety_scan / manifest_details / ...)
  state       built per evaluation kind (file snippet | app manifest | none)
  batching    by file for code_signal; one app-level request for manifest
  compose     generic, driven by each spec's severity rule
  robustness  per-unit try/except -> MANUAL_REVIEW on failure
  cache       (model, question, state) -> answer
```

## Recommended sequencing

1. Land **P0-1/P0-2/P0-3** as a small refactor (registry + kinds + raw-artifact
   input) using the 4 existing policies — no behavior change, proven by the
   existing eval/benchmark. This is the foundation.
2. Then scale coverage policy-by-policy via the registry, each with fixtures that
   clear the charter bars (P1-1).
3. Add robustness (P1-2) and the cache (P1-5) early; decide the critic (P1-3) and
   dual-maintenance (P1-4) before the bulk of policies land.

## Implementation status (2026-09-26)

The foundation and the agreed P1 items are implemented (no behavior change:
live eval still recall/precision 1.00; benchmark unchanged):

- **P0-1 registry** — `registry.py` (`PolicySpec`); adding a policy = one spec.
- **P0-2 evaluation kinds** — `code_signal` / `deterministic` run through the
  engine; `manifest` kind is declared and reserved (its engine path lands with
  the first manifest policy in the coverage phase).
- **P0-3 raw-artifact input** — `engine.py` reads `data_safety_scan.json` /
  `manifest_details.json` / `play_store_info.json` and activates from the
  registry; the evaluator no longer depends on `input_worker_*.json`.
- **P1-2 robustness** — per-file/per-finding/per-critic `try/except` emits a
  recall-safe MANUAL_REVIEW finding instead of crashing the scan.
- **P1-3 critic** — reduced to a single "evidence-supports-claim" Noul on the
  high-severity findings `aggregate` already routes to it.
- **P1-5 cache** — `cache.py` (`ResultCache` + `CachingClient`) memoizes by
  `(model, questions, state)`; a warm re-run makes 0 API calls.
- **Source of truth** — the registry is primary; the legacy `goal_*.md` matrices
  remain as the fallback path, to be gated by the parity harness (P1-4).

Deferred (P2): prompt-injection hardening, egress redaction, an explicit
determinism policy, and freezing the worker-finding schema.
