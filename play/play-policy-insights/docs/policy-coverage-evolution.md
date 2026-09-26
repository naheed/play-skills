# Policy Coverage Evolution & Model Selection

Status: Draft / plan
Last updated: 2026-09-26

How we grow the Jev hybrid evaluator from the current prototype to **parity with
the existing skill's coverage** — every policy domain the `goal_*.md` matrices
handle today, replaced by typed Jev questions composed in code — without
regressing the quality dimensions in the [evaluation charter](evaluation-charter.md).

Read the [architecture doc](typesafe-hybrid-architecture.md) first for how the
hybrid pipeline works; this doc is about scaling it across all policies and
choosing the right model.

## 1. What "parity" means

The legacy skill's judgment lives in three worker goals plus a critic. Parity =
every `policy_id` in `resources/policies.json` and every data type in the Data
Safety taxonomy that the legacy matrices evaluate has:

1. an atomic Jev question battery (`questions.py`),
2. code-composed severity/routing (`evaluate.derive_*`),
3. a labeled eval set (positive, negative, boundary cases), and
4. a live-eval run that clears the charter bars, plus a parity check vs legacy on
   a shared gold corpus.

## 2. Coverage matrix

Source of truth: `policies.json` + `goal_permissions_and_apis.md` /
`goal_data_safety.md` / `goal_user_account.md`.

| Domain | policy_id | Legacy goal | Jev status | Notes |
| --- | --- | --- | --- | --- |
| User Data | `data_safety_section` (35 taxonomy types) | data_safety | **Prototyped** | transmit/disclosure/third-party batteries; per data type |
| User Data | `prominent_disclosure_policy` | data_safety | **Prototyped** | gate-before-access Noul + disclosure Choice |
| User Data | `data_safety_section` (declaration coverage) | data_safety | **Prototyped (`play_declaration` kind)** | Jev checks detected off-device transfers vs the developer's declaration; semantic coverage, not string match. Needs a reliable declaration (prefer provided JSON). |
| Permissions | `location_access_policy` | permissions | **Prototyped** | core + disclosure + transmit |
| Permissions | `contacts_access_policy` | permissions | **Prototyped** | core + picker-alternative |
| Permissions | `audio_recording_policy` | permissions | **Prototyped** | core + mic-button alternative |
| User Data | `account_deletion` | user_account | **Prototyped (code)** | deterministic presence check; no model needed |
| Permissions | `photo_video_access_policy` | permissions | Planned | Photo Picker migration; SDK-version aware (code) |
| Permissions | `all_files_access_policy` | permissions | Planned | MANAGE_EXTERNAL_STORAGE justification |
| Permissions | `files_and_docs_policy` | permissions | Planned | Scoped storage / SAF |
| Permissions | `sms_call_log_policy` | permissions | Planned | default-handler check; OTP retriever alternative |
| Permissions | `package_visibility_policy` | permissions | Planned | QUERY_ALL_PACKAGES justification |
| Permissions | `accessibility_api_policy` | permissions | Planned | tool vs misuse; disclosure gate |
| Permissions | `exact_alarm_policy` | permissions | Planned | alarm/calendar core vs sync misuse |
| Privacy/Abuse | `foreground_services_policy` | permissions | Planned | FGS type present (mostly manifest → code) |
| Play Console | `login_credentials` | user_account | Planned | demo-credential presence for review |
| Privacy/Abuse | `target_api_level` | (Phase 1) | **Code-only** | numeric SDK check stays in code |

Numeric/threshold checks (target SDK, counts) stay in code per the charter — Jev
is not asked to do arithmetic.

## 3. Per-policy porting recipe

Each policy is now **one `PolicySpec` in `registry.py`** (the single source of
truth) plus fixtures — the engine handles the rest. For each planned policy:

1. **Read the legacy matrix.** Each "Common Evaluation Matrix" row in the
   `goal_*.md` file encodes a condition → severity → recommendation. That row is
   the spec.
2. **Add a `PolicySpec`.** Pick the evaluation `kind` (`code_signal`,
   `manifest`, or `deterministic`), its activation (data types or manifest
   facts), its battery, and its severity rule.
3. **Decompose into atomic questions.** Turn each independent factor into one
   `Noul`/`Choice`. Never ask a multi-hop question; split it. Reuse shared
   questions (`transmits_offdevice`, `has_prominent_disclosure`,
   `is_core_functionality`).
4. **Compose severity in code.** Extend `derive_permission_severity` /
   `derive_data_safety_severity` (or add a rule) for the policy. Recommendations
   and summaries come from `templates.py` (keyed by `policy_id`).
5. **Write labeled fixtures.** At least 3 positive, 3 negative, and 2 boundary
   cases per policy in `eval/labeled_cases.json`, plus a held-out slice never
   used for threshold tuning.
6. **Clear the charter bars live.** `run_eval --client http` must meet recall,
   precision, and agreement for the new cases.
7. **Parity-check vs legacy** on the gold corpus for that domain (Section 5).
8. **Enable** by leaving the spec in the registry; keep the legacy `goal_*.md`
   path as fallback until the parity harness gates the switch.

## 4. Model selection

### 4.1 Which Jev model

- **Pin a version** (`jev-1.13.0`), never the `jev-latest` alias, so reports are
  reproducible and threshold tuning stays valid.
- **Accepting a new Jev version** is a charter run: re-run `selftest`,
  `smoketest`, and the full `run_eval` suite against the new id; compare recall,
  precision, calibration, latency, and cost to the pinned baseline. Promote only
  on no-regression; re-tune thresholds if calibration shifts; update the pin.

### 4.2 When Jev is not the right model — the cascade

Jev is a fast first-pass judge, not a reasoning engine. Use a **confidence-gated
cascade** (intent-routing / SDE-cascade patterns):

1. **Jev first pass** over every finding (cheap, ~150 ms, parallel battery).
2. **Route the ambiguous minority up.** Findings the critic marks
   `MANUAL_REVIEW`, or whose Choice/Score confidence is below `CONF_REVIEW_FLOOR`,
   or that require multi-hop reasoning (data-flow across files, intent behind an
   abstraction) go to a **reasoning LLM** (the legacy agent, or a dedicated
   model) or a human.
3. **Everything else is decided by code** from Jev's calibrated booleans.

This keeps the common case fast and cheap while preserving quality on the hard
cases — most of the analysis at a fraction of the cost, with a reasoning model
only where it earns its latency.

### 4.3 Budgets

Track per the charter: latency p50 ≤ 300 ms/finding, and per-app input-token
cost. A domain that needs a reasoning-model escalation on more than a small
fraction of findings should be reconsidered (either better questions/state, or
the domain genuinely needs reasoning).

## 5. Parity methodology (replacing legacy without regressing)

1. **Build a gold corpus.** A set of real apps whose findings have been
   adjudicated (ideally by a policy expert) into a ground-truth list per policy
   domain. This is the highest-value asset and the main gap today.
2. **Run both engines** on the corpus: the legacy agent skill and the Jev tool.
3. **Score finding-level precision/recall** for each engine vs the gold set, per
   domain.
4. **Gate the switch.** Make Jev the default for a domain only when its
   precision and recall are ≥ the legacy skill's on that domain (no regression),
   and it clears the charter's absolute bars.
5. **Keep the fallback.** The offline heuristic and the legacy agent path remain
   available; a domain can be rolled back by flag.

## 6. Rollout phases

- **Phase A (done):** location, contacts, audio permissions; data-safety
  transmission/disclosure; account-deletion (code). Baseline: recall/precision
  1.00 on the 13-case set.
- **Phase B:** remaining permission policies (photo/video, all-files,
  files-and-docs, sms/call-log, package-visibility, accessibility, exact-alarm,
  foreground-services). Port via the Section 3 recipe.
- **Phase C:** user-account (login/demo credentials); confirm target-API stays
  code-only.
- **Phase D:** stand up the gold corpus + parity harness; switch defaults per
  domain on non-regression; run the Jev tool as a CI pre-submission gate with the
  legacy skill as fallback.

## 7. Open questions / risks

- **Gold corpus** does not exist yet; building and adjudicating it is the
  critical path for a defensible parity claim.
- **Data handling:** the live path sends app source snippets to TypeSafe;
  confirmed acceptable for this project, but keep snippets minimal and filtered.
- **Reasoning-model escalation** target is undecided (legacy agent vs a dedicated
  model); the cascade interface (`MANUAL_REVIEW` + low confidence) is in place.
- **`resources/` churn:** the `update-skills` automation may overwrite skill
  resources; the evaluator stays self-contained under `scripts/typesafe_eval/`.
