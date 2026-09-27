# v2 Improvement Execution Plan

Status: Execution plan (ready to start)
Last updated: 2026-09-27
Applies to: evaluator `2.0.0-capability` → `2.x`
Source of requirements:
[legacy-skill-lessons-and-coverage-plan.md](legacy-skill-lessons-and-coverage-plan.md)
(lessons L1–L7, anti-lessons A1–A5, per-policy specs §5.3, infrastructure §6)

This document turns the lessons into **work packages** (WPs) that can each be
built, tested and shipped independently, groups them into **milestones** with
hard gates, and fixes the cross-cutting rules (labels, versioning, logging,
documentation) every WP must follow. It is deliberately concrete: each WP
names the files it touches, the interfaces it adds, the tests that prove it,
and the metric that must not regress.

---

## 0. Ground rules

These hold for every work package.

1. **Charter order.** Recall > Precision > Calibration > Latency > Cost
   ([evaluation-charter.md](evaluation-charter.md)). No WP may reduce recall
   on the labelled dev set; a WP that trades precision for recall is
   acceptable, the reverse is not.
2. **Deterministic first, model second.** Anything readable from XML, Gradle,
   a path or an identifier boundary is decided in code. A model question is
   added only when the matrix requires a semantic claim, and it is always
   atomic (one Noul or one Choice).
3. **Findings are never suppressed by judgement** (anti-lesson A1). Purpose,
   justification and consent moderate severity between Suggestion, Important
   and Critical; they never remove a finding.
4. **Shared code is read-only.** `generate_report.py`, `orchestrator.py`,
   `scanner.py` and `resources/` are not edited. Facts the evaluator needs
   that the orchestrator does not provide are parsed by the evaluator itself.
5. **No vendor, library or application names** in evaluator logic; the
   `identifier_lint_no_vendor_names` selftest stays green. Repo docs refer to
   the dev apps as App A / App B.
6. **Everything leaves a trace.** New rules write to `decision_trace`, new
   drops write to `typesafe_triage.json` with a reason, new state additions
   are logged at `INFO`, and parse failures are logged at `WARNING`, never
   swallowed.
7. **Labels live out of tree** (`.scratch/labels/`), exported to
   `/opt/cursor/artifacts/` when reported. Thresholds change only through
   `calibrate.py`, and every change updates `constants.THRESHOLD_PROVENANCE`
   and bumps `EVALUATOR_VERSION`.
8. **One PR per work package**, stacked on the current branch, each with:
   selftest green, both dev apps run end to end, a triage diff against the
   previous WP reviewed, and the docs listed in §3.4 updated.

---

## 1. Work packages

Notation: **Depends on** lists WPs that must merge first. **Size** describes
invasiveness (which modules change and how deeply), not calendar time.

### WP0 — Baseline and diff tooling

- **Goal.** Freeze the current behaviour so every later WP is measured, not
  argued.
- **Changes.**
  - New subcommand `python -m typesafe_eval triage-diff <before.json> <after.json>`
    (new `triage_diff.py`): reports findings added/removed/changed by
    `(policy_id, file, data_type)`, decision changes (LOCAL/UNCERTAIN/TRANSMITS),
    severity changes, drop-reason deltas, model-call and token deltas.
  - Record `typesafe_triage.json`, `calibration_report.json`, per-app
    wall-clock and request counts for both dev apps as the **baseline** out
    of tree (`.scratch/baselines/<EVALUATOR_VERSION>/`) and in artifacts.
- **Tests.** Selftest for `triage_diff` on two small synthetic triage files.
- **Exit.** Baseline recorded; `triage-diff` of a run against itself is empty.
- **Size.** One new module, `__main__.py` wiring. No behaviour change.

### WP1 — Evaluator-owned Android manifest parsing (`AppProfile`)

Implements plan §6.1 and the structural half of L5; unblocks WP5.

- **Depends on.** WP0.
- **Changes.**
  - New `android_manifest.py`: discovers every `AndroidManifest.xml` under
    the app (respecting `structure.IGNORED_DIR_NAMES` and the test source-set
    exclusions in `constants.EXCLUDED_PATH_SUBSTRINGS`), parses with
    `xml.etree` after BOM strip, merges into one `AppProfile` dataclass with
    per-element `source` attribution:
    `permissions[{name, max_sdk, flags, source}]`, `application{...legacy
    storage flags}`, `activities/services/receivers/providers` with
    `exported`, `intent_filters`, `fgs_types`, `properties`, `meta_data`,
    `accessibility_services[{name, config_resource}]`, `queries`.
  - `AppProfile.render_compact()` → the block placed in `app_facts["profile"]`
    by `evaluate._app_facts()`, size-capped.
  - `engine.load_artifacts()` builds the profile once per run and stores it
    on `RunContext`; `manifest_details.json` remains as fallback when no
    manifest is found (logged at `WARNING`).
- **Tests.** Selftests with synthetic manifests: single manifest; base +
  flavor merge with duplicate permission (one entry, two sources); typeless
  service present; `maxSdkVersion` parsed; `<property>` on a service;
  `<queries>`; BOM-prefixed file; malformed XML (warning, partial profile).
- **Exit.** Both dev apps produce a profile; App A shows the typeless-service
  case does not exist but the two-type service does; App B shows the
  commented-out `maxSdkVersion` as absent. `triage-diff` vs baseline: no
  finding changes (this WP only adds facts).
- **Size.** One new module (~400 lines), small edits to `engine.py`,
  `evaluate.py`, `context.py`.
- **Outcome (done).** `android_manifest.py` + `resources.py` (the
  default-locale string/xml index was split out because WP4/WP8 reuse it).
  Deliberate deviations from the text above:
  - The profile is **not** placed in `app_facts` yet. Doing so changes every
    model-facing state (capability-cache misses, answer drift) and would
    violate this WP's "no finding changes" exit; only a short `purpose` line
    is added to `app_facts` in WP4. The profile lives on `RunContext.profile`
    and its `summary()` is written to `typesafe_triage.json["app_profile"]`.
  - Modern projects keep `namespace` / `applicationId` / `targetSdk` in
    Gradle, so the module's `build.gradle(.kts)` is scanned for *literals*
    (comments stripped) before falling back to `manifest_details.json`.
    Every value carries `sdk_provenance`. On App B this exposed that the
    orchestrator's `package_name` is a library's namespace; the profile logs
    the disagreement and keeps the Gradle value. `engine._first_party_packages`
    still reads the orchestrator value in this WP (switching it changes
    first-party classification and therefore findings; tracked for WP2's
    triage-diff).
  - Added `AppProfile.ships_in_play_build(entry)` mirroring the engine's
    flavor rule (`main` + `play` when a `play` flavor exists), because App A's
    accessibility service is declared only in the non-Play `full`/`tv`
    flavors — exactly the attribution WP12 needs to avoid a false Critical.
  - Exit re-checked against the dev apps: App A has three services *without*
    a `foregroundServiceType`, but all are bound services (tile, locale
    holder, accessibility), not foreground services. A "typeless FGS" cannot
    be decided from the manifest alone; WP5 pairs the manifest fact with the
    `startForeground` code signal in the same class before raising Critical.
    App B's commented-out `maxSdkVersion` is correctly absent; its
    `MANAGE_EXTERNAL_STORAGE minSdkVersion=30` is captured.
  - `triage-diff` vs baseline on both dev apps: identical (60 → 60, 45 → 45).

### WP2 — Identifier-boundary lexical pre-gate (L1)

- **Depends on.** WP0.
- **Changes.**
  - `structure.py`: `identifier_boundary_hits(lines, token)` returning hit
    line indices where `token` matches at a camelCase / snake_case / kebab /
    dot boundary; `is_type_position(line, col)` for class/interface/generic/
    import positions.
  - `engine._filter_candidates()`: new cascade step 0 that drops anchors
    with no boundary hit (`reason="no identifier-boundary match"`) or only
    type-position hits (`reason="type position only"`); extends path
    exclusion to `values-*/`, `*.po`, `*.arb`, `*.strings`. Every drop goes
    through `_drop()` so it lands in triage.
  - `constants.py`: `LEXICAL_PREGATE_ENABLED = True` flag for rollback.
- **Tests.** Selftests for each boundary class from the legacy examples
  (foreign stem, camelCase container type, snake_case prefix, kebab, file
  path bound to a name-like key); negative test that a genuine
  `user.fullName` anchor survives.
- **Exit.** On the dev set, every labelled positive still produces a
  candidate (recall 1.0 by construction check in `calibrate.py`: fail if any
  labelled case has no probability). Model-call count on both apps drops
  (report the number); no VERIFIED TRANSMITS lost in `triage-diff`.
- **Size.** Medium in `structure.py`, small in `engine.py`.
- **Outcome (done).** Pre-gate as specified plus a run of recall fixes that
  the new `calibrate --rejoin` check surfaced. Everything is flagged for
  rollback and traced in `typesafe_triage.json["counters"]["lexical_pregate"]`
  and on each finding's `decision_trace.anchor.lexical`.
  - `structure.py`: `boundary_matches` / `boundary_columns` /
    `is_type_position` / `lexical_hits` → `LexicalHits` with a per-file
    verdict (`value`, `type_only`, `substring_only`, `demoted_only`, `none`,
    `non_identifier`). Boundaries are camel/snake/kebab/dot **plus** a small
    set of English affixes (`re`-prefix, `s/es/ed/er/ing/ion/able/y`
    suffixes, capitalised opener) so `Relogin`, `records`, `tracking` still
    count; foreign stems (`dob`, `grace`→`race`, `multimap`→`imap`,
    `fluid`→`uid`, `uuid`→`uid`) do not. Only identifier-shaped patterns are
    gated; MIME literals and paths (`video/*`) are `non_identifier` and pass.
  - `engine._lexical_pregate()` runs after `_analyze_files` and before the
    capability classifier, so files whose only hits are coincidences are
    pruned from the import inventory too (`files_pruned`: 9 on App A, 11 on
    App B — fewer capability requests). Drops carry the offending line as
    `example` plus `lines`. Type-position-only drops are **off**
    (`LEXICAL_TYPE_ONLY_DROP = False`): a `: AudioRecord` field driven via
    the field name is a real use; the verdict is recorded so the effect can
    be measured on a labelled set first. Path exclusion extended with
    `EXCLUDED_PATH_SUFFIXES` (`.po .pot .arb .strings .xliff .xlf`).
  - `calibrate --rejoin --worker-dir …` re-joins the frozen labels to a new
    run and **exits 2** when any labelled transfer has no finding
    (`missing_positives`). This is the WP's recall-1.0 check and it caught
    five silent losses in a row, each fixed at its root:
    1. `all_occurrences` capped hits at 5 *before* ranking — the sink-adjacent
       occurrence of a clipboard transfer was the sixth in file order.
       `MAX_OCCURRENCES_RANKED = 60`; the model-facing list is capped
       separately (`MAX_HIT_LINES_IN_STATE = 5`, chosen line always included);
       exact-case hits rank before case-folded ones.
    2. `symbol_references` stopped after **12** lines per symbol, so the
       `startActivity(Intent.createChooser(…))` that was the 14th `Intent`
       use in a 2 000-line activity was invisible to scope/proximity ranking
       (a labelled MIME-sharing transfer ranked tier 3). Bound raised to
       `MAX_SYMBOL_REFERENCE_LINES = 400`; `Sink.to_state()` lists at most
       `MAX_SINK_REF_LINES_IN_STATE = 20` lines nearest the anchors and
       reports `omitted_lines`; `related_lines` are now the sink lines
       **nearest an anchor**, not the first in file order.
    3. `enclosing_scope` treated any `… ) {` header as a declaration, so a
       hit inside `switch (which) { … }` had the *switch block* as its scope
       and the sink two lines after the block was "out of scope".
       `is_declaration_header()` now rejects control-flow headers
       (`if/else/for/while/do/switch/when/case/try/catch/finally/…` and the
       expression forms `= when (…) {`, `return if (…) {`).
    4. The per-type cap (`MAX_FINDINGS_PER_TYPE`, raised 8 → 12) dropped
       tier-2 candidates *with a sink in scope* while keeping tier-3 ones of
       other types. `CAP_EXEMPTS_SINK_IN_SCOPE = True`: the cap is a cost
       control and only trims tier-3 candidates; exemptions are counted
       (`cap_exempt_sink_in_scope`: 2 on App A, 1 on App B).
    5. The relevance question listed "a MIME type" among *unrelated* uses, so
       `video/*` inside an `ACTION_VIEW` chooser was answered p=0.09–0.12
       while its sibling `audio/*`, `image/*`, `text/*` in the same `switch`
       passed. Reworded: a MIME/picker filter that selects, opens or shares
       files of that kind *is* handling the data type (sharing via intent is
       a transfer by policy). Question text is part of the cache key, so only
       relevance answers were re-asked. **This is a question change and
       therefore part of the M2 version bump.**
  - Soft relevance gate (`RELEVANCE_SOFT_GATE_ENABLED`): a `signal_relevant`
    answer below `T_RELEVANCE` may suppress a finding only when the anchor's
    scope has no egress/IPC sink (tier 2–3). With a sink in scope the finding
    is kept, capped at IMPORTANT, `needs_manual_review`, summary suffixed
    `[data-type match uncertain: p=…; verify]`, trace `relevance: "low"`.
    Below `T_RELEVANCE_FLOOR = 0.10` the model is confidently negative and
    the finding is dropped even with a sink (every keep under 0.10 on the dev
    apps was `track`→MUSIC, `record`→AUDIO, `PowerManager`→DIAGNOSTICS).
    Soft keeps after the floor: 2 on App A, 6 on App B, all plausible review
    items.
  - `evaluate.reconcile_disclosure_status()`: the `disclosure_status` Choice
    is cross-checked against the battery's own `has_prominent_disclosure`
    Noul. `DISCLOSED` with p < `T_DISCLOSURE` → `MISSING` + review (a wider
    scope had flipped four Panels-file media transfers to DISCLOSED at
    p=0.15–0.18); `EXEMPT` on a non-user-initiated transfer → `MISSING`.
    Trace: `decision_trace.disclosure_reconciled`.
  - **Exit measured.** Selftest 233 checks green. `calibrate --rejoin` on
    both dev apps: exit 0, 48/48 labelled cases rejoined, 0 missing
    positives (rejoined band `T_LOW 0.30 / T_HIGH 0.60`, ECE 0.28 — used at
    M2, not applied here). Model calls, measured offline at a **fixed** cap
    of 8 (heuristic client, same batching): App A 86 → 78 (−9 %), App B
    43 → 36 (−16 %) — that is the pre-gate's own effect. With the recall
    fixes (cap 12 + sink-in-scope exemption) the totals are App A 111 /
    App B 46 offline, 100 / 39 live; the WP therefore **spends** the
    pre-gate saving on recall, which is the charter's ordering. Pre-gate
    drops: 41 (App A), 37 (App B), all inspected as genuine coincidences.
    `triage-diff` vs baseline: App A 60 → 75 findings, TRANSMITS 16 → 17,
    no TRANSMITS lost (one moved from `prominent_disclosure_policy` to
    `data_safety_section` because the model now answers `EXEMPT` for the
    user-initiated share; it stays TRANSMITS and critic-VERIFIED). App B
    45 → 60, TRANSMITS 4 → 7; two threshold-adjacent flips TRANSMITS →
    UNCERTAIN (`p` 0.77 → 0.68 and 0.70 → 0.61 against `T_HIGH = 0.70`) —
    both remain routed to review and one is critic-VERIFIED; the rejoined
    band (`T_HIGH ≈ 0.60`) would keep both as TRANSMITS and is applied at
    M2 with the version bump.
  - Not done here (tracked): `engine._first_party_packages` still reads the
    orchestrator's `package_name` (WP6 switches to the profile's value with
    the first-party index).

### WP3 — Structured evidence (L6)

- **Depends on.** WP0.
- **Changes.** `evaluate._evidence_line()` renders
  `source@<file>:<lstart>-<lend> -> sink@<file>:<line> [<capability>]`
  from the mini-state (anchor scope, nearest sink, capability tag); falls
  back to the current single-line form when no sink exists. Destination
  class is appended once WP7 lands.
- **Tests.** Golden-string selftest for sink / no-sink cases.
- **Exit.** Evidence in both apps' reports shows scope ranges; no metric
  change.
- **Size.** Small, one function.
- **Outcome (done).** `evaluate._evidence_line()` renders
  `source@<file>:L<start>-L<end> (L<line>: <matched>) -> sink@L<n> <Symbol>
  [<CAPS>]`, suffixed `(out of scope)` when the nearest transfer sink lies
  outside the anchor's function; the old `<file>:L<n> — <matched>` form is
  kept when the file has no transfer-capable sink or the state is the legacy
  one (deterministic account-deletion findings). `evaluate.nearest_sink()`
  prefers an in-scope sink, then the smallest line distance, and ignores
  `LOCAL_PERSISTENCE` / `USER_DISCLOSURE_UI` symbols. The same data is
  attached structurally as `finding["evidence_flow"]` (`source{file, line,
  scope, matched}`, `sink{symbol, line, capabilities, in_scope, distance}`)
  so WP7 can append `destination_class` without re-parsing strings. The
  matched text is truncated at 96 chars and `|`/newlines are neutralised
  because `generate_report.py` (read-only) renders evidence inside a Markdown
  table cell. Seven golden-string selftests. Exit measured: 24 (App A) and 7
  (App B) structured evidence lines in the reports; `triage-diff` against
  the WP2 output: 75 → 75 and 60 → 60 with zero changed findings.

### WP4 — Once-per-app `declared_core_purpose` (L5, semantic half)

- **Depends on.** WP1.
- **Changes.**
  - `questions.py`: `app_purpose_battery()` — one Choice with the closed
    option set from plan §5.3 (`file_manager`, `backup_or_antivirus`,
    `alarm_or_timer`, `calendar`, `messaging_default_handler`,
    `accessibility_tool`, `media_gallery_or_editor`, `launcher`,
    `per_app_network_control`, `other`), plus `unknown`.
  - `capabilities.CapabilityCache`: new `per_app` section keyed by
    `sha256(AppProfile.render_compact())` + model; `get_app_answer()` /
    `put_app_answer()`.
  - `engine.run()`: asks once after `load_artifacts`, stores the answer and
    its confidence in `RunContext.app_purpose` and in `app_facts`; logs the
    answer; writes it to `typesafe_triage.json`.
  - Helper `evaluate.purpose_in(ctx, allowed: frozenset) -> bool` returning
    `False` when confidence < `constants.CONF_APP_PURPOSE` (so low
    confidence means "not justified" → higher severity, never suppression).
- **Tests.** Selftest with heuristic client for cache hit/miss and the
  low-confidence path.
- **Exit.** App B → `file_manager`, App A → `per_app_network_control`, both
  recorded in triage; one extra model request per cold run.
- **Size.** Small additions to three modules.
- **Outcome (done).**
  - `questions.APP_PURPOSE_OPTIONS` / `app_purpose_battery()`: one Choice,
    eleven closed options (`unknown` always present). The state is compact
    and reviewable: app name, package, `targetSdk`, store category, the first
    600 chars of the store description, and `AppProfile.render_compact()`.
  - `capabilities.CapabilityCache.get_app_answer / put_app_answer` under
    `app|<taxonomy>|<model>|<qid>|<digest>` keys; the digest is the SHA-256 of
    the *whole* state plus the battery (not only the profile as planned), so a
    changed store listing or reworded option re-asks instead of reusing a
    stale answer. Human entries are model-independent and never overwritten.
  - `engine._ask_app_purpose()` runs once after `_load_profile`, records
    `{purpose, confidence, source ∈ model|cache|human|unavailable,
    probabilities, digest}` on `RunContext.app_purpose` and in
    `typesafe_triage.json["app_purpose"]`, copies the label alone into
    `app_facts["purpose"]` (confidence is a routing input, not evidence), and
    never raises: an out-of-set choice, transport failure or malformed reply
    degrades to `unknown` / `unavailable` with `counters.app_purpose_error`.
    Symbol-classification states keep only the package so the cross-app
    capability cache stays purpose-free.
  - `evaluate.purpose_in(app_purpose, allowed)` with
    `constants.CONF_APP_PURPOSE = 0.75`: `False` for `unknown`, missing or a
    model answer below the confidence unless human-pinned. `HeuristicJevClient`
    answers `unknown` (labelled stand-in).
  - **Exit measured.** App B → `file_manager` (p = 1.00), App A →
    `per_app_network_control` (p = 1.00), both in triage;
    `app_purpose_requests = 1` per cold run (App B 39 + 1, App A 100 + 1).
    Selftest 261 checks (16 new: `purpose_in_*`, cache miss/hit/human-pin,
    failure degradation, state compactness, `app_facts` propagation,
    classification-state exclusion, and the soft-gate cases below).
  - **Recall fix surfaced by the gate.** Adding `purpose` to `app_facts`
    changes every model-facing state, so the live re-run was a full cache
    miss and answers drifted. `calibrate --rejoin` exited 2: App B's labelled
    `SMBAdapter.java/USER_ACCOUNT` was lost because `signal_relevant` moved to
    0.29 against `T_RELEVANCE = 0.30` at a tier-3 anchor (the `login` token
    sits in a menu handler; the network client is elsewhere in the same
    file). Fix: a second soft-gate condition
    (`constants.RELEVANCE_SOFT_GATE_FILE_EGRESS`, rollback flag) keeps an
    uncertain relevance answer (floor ≤ p < `T_RELEVANCE`) when the *file*
    references a strong egress sink (`NETWORK_EGRESS` /
    `THIRD_PARTY_TELEMETRY` / `ADVERTISING_SDK`), traced as
    `relevance = "low_file_egress"`, capped at IMPORTANT and routed to review
    with the WP3 evidence line showing the sink `(out of scope)`. IPC-only or
    `UNKNOWN` file sinks do not qualify. Measured cost: exactly one extra
    review item per app (App B recovers the labelled transfer, now TRANSMITS
    p = 0.77 with `[data-type match uncertain: p=0.29; verify]`; App A adds
    one LOCAL diagnostics SUGGESTION at p = 0.12). `calibrate --rejoin`: exit
    0, 48/48 rejoined.
  - `triage-diff` vs WP3 output: App A 75 → 75 (+5 −5 ~3), App B 60 → 60
    (+3 −3 ~3). All differences are answer drift from the state change: two
    App A TRANSMITS → UNCERTAIN flips against `T_HIGH = 0.70` (p 0.73 → 0.69,
    0.70 → 0.68; both remain review items and both would be TRANSMITS under
    the rejoined band applied at M2), the play-declaration representative for
    CRASH_LOGS moving between two files in the same flavour, and the usual
    per-file swaps between `data_safety_section` and
    `prominent_disclosure_policy` for UNCERTAIN findings. No labelled positive
    lost.

### WP5 — Wave 1 policies (deterministic manifest policies)

- **Depends on.** WP1, WP4.
- **Changes** (all in `registry.py` as `MANIFEST` specs whose
  `compose_manifest` now receives the `AppProfile`; text in `templates.py`):
  - `foreground_services_policy` — replace `_foreground_service_findings`
    input with the profile: typeless service started as foreground
    (`startForeground` reference in a first-party file resolving to the
    class, via `structure.symbol_references`) on `targetSdk ≥ 34` →
    **Critical**; `specialUse` without `PROPERTY_SPECIAL_USE_FGS_SUBTYPE`
    property → **Critical**; `FOREGROUND_SERVICE_SPECIAL_USE` permission with
    no `specialUse` service → Suggestion; type/purpose misalignment table
    (per type, allowed purposes) → Important; existing type-permission check
    and Suggestion inventory retained.
  - `package_visibility_policy` — `QUERY_ALL_PACKAGES` → Suggestion if
    `purpose_in(...)` else Important; `<queries>` also present → Important.
  - `all_files_access_policy` — `MANAGE_EXTERNAL_STORAGE` → Suggestion if
    `purpose_in({file_manager, backup_or_antivirus})` else **Critical**;
    plus media permissions → Important (redundant scope).
  - `exact_alarm_policy` — `USE_EXACT_ALARM` outside
    `{alarm_or_timer, calendar}` → Important; `SCHEDULE_EXACT_ALARM` →
    Suggestion.
  - `target_api_level` — `DETERMINISTIC`: `targetSdk` below
    `constants.PLAY_REQUIRED_TARGET_SDK` (with provenance date) → Critical;
    one behind → Important.
- **Tests.** Selftests per rule (positive, negative, `targetSdk` boundary);
  `registry` selftest asserting every `policies.json` id in wave 1 has a spec.
- **Exit.** App A: FGS misalignment Important + special-use Suggestion +
  package-visibility Suggestion. App B: package-visibility Suggestion,
  all-files Suggestion (the two findings the legacy skill dropped, A1),
  FGS Suggestion. `triage-diff` shows only additions.
- **Size.** Medium in `registry.py`, small in `templates.py`, `constants.py`.

### WP6 — One-hop first-party callee resolution (L3)

- **Depends on.** WP2 (so hops are computed only for surviving anchors).
- **Changes.**
  - `structure.py`: per-app `FirstPartyIndex` (`simple_name → relpath`,
    collisions resolved by the caller's imports), built once in
    `engine._analyze_files()`.
  - `context.build_file_state()`: for each anchor whose enclosing scope
    references a first-party symbol, append that file's `file_sinks()` and
    capability tags as `state["callees"][...]` with `hop=1`, capped at 3
    callees and by the existing snippet size cap (sink lines only when the
    cap would be exceeded). Log what was appended.
  - `constants.py`: `MAX_CALLEE_HOPS = 1`, `MAX_CALLEES_PER_ANCHOR = 3`.
- **Tests.** Two-file fixtures: anchor → helper → network sink (expect
  TRANSMITS-capable state); anchor → helper → local DB (expect LOCAL).
- **Exit.** Dev-set recall 1.0; abstention rate (UNCERTAIN share) falls
  below 0.50 from 0.625; precision-at-high ≥ 0.90. Re-run `calibrate`,
  update `THRESHOLD_PROVENANCE` only if the derived band moves.
- **Size.** Medium in `structure.py` and `context.py`.

### WP7 — `destination_class` and label schema v2 (L2)

- **Depends on.** WP6 (state now includes callee sinks, so the destination
  is answerable more often).
- **Changes.**
  - `questions.py`: replace `is_third_party` Noul with `destination_class`
    Choice (`developer_backend`, `third_party_sdk`,
    `user_chosen_destination`, `platform_component`, `other_app_ipc`,
    `unknown`), asked only when `p_transmit ≥ T_TRANSMIT_LOW` (batched as
    today; the answer is ignored below the band).
  - `capabilities.py`: deterministic hint `USER_CHOSEN_DESTINATION` when the
    sink's host/URL flows from a preference read or UI field in the same
    scope; passed in state as a prior, not a decision.
  - `evaluate._compose_data_safety_finding()`: composition table from plan
    §2 L2; `user_chosen_destination` and `platform_component` yield no
    finding but are recorded in `decision_trace`; `unknown` →
    `MANUAL_REVIEW`; `other_app_ipc` keeps IPC = sharing.
  - `calibrate.py`: label schema v2 adds `destination_class`; report
    per-class precision and the reliability table split by class.
  - Relabel the 48 dev cases with `destination_class` (out of tree).
- **Tests.** Selftests for each class → severity/sharing outcome; heuristic
  client mapping.
- **Exit.** ECE in the UNCERTAIN band improves vs WP6; recall 1.0; no
  labelled sharing case loses its sharing flag. `EVALUATOR_VERSION` bump
  (question wording changed).
- **Size.** Medium across `questions.py`, `evaluate.py`, `calibrate.py`.

### WP8 — Consent defaults, string resources, flavor attribution (L4)

- **Depends on.** WP1 (flavor sources), WP6 (declaration lookup reuses the
  first-party index).
- **Changes.**
  - New `resources.py`: default-locale `values/strings.xml` index,
    `resolve_string(name)`; also used by WP1 for `@string/` attributes.
  - `structure.py`: `guard_flags(scope)` returns boolean identifiers guarding
    the scope; `declaration_of(identifier)` via the first-party index
    returns the declaration line + initialiser.
  - `context.build_file_state()`: adds `state["guards"]` (flag, declaration,
    initialiser) and resolves `R.string.<name>` / `getString(...)` references
    in the anchor scope and in disclosure symbols to text.
  - `questions.py`: Noul `consent_default_on` on in-band anchors;
    `evaluate` composes: default-on + no prior disclosure → Critical row of
    `prominent_disclosure_policy`; opt-in → Suggestion.
  - Findings carry `manifest_sources` when the relevant permission or
    component exists only in some flavours.
- **Tests.** Default-on / default-off / opt-in fixtures; string resolution
  with and without the resource present; a flavor-only permission.
- **Exit.** App A's default-on crash-report transfer shows the default in
  evidence and `consent_default_on=true`; the background-location disclosure
  Choice is asked against real text. Recall unchanged.
- **Size.** One new module, medium edits to `structure.py`, `context.py`.

### WP9 — Wave 2 policies (`photo_video_access_policy`, `files_and_docs_policy`)

- **Depends on.** WP1, WP4.
- **Changes.** `MANIFEST` rules from plan §5.3 (`maxSdkVersion` caps,
  `targetSdk ≥ 33` Photo Picker rule, `requestLegacyExternalStorage` on
  30+, redundant scopes) plus two small `CODE_SIGNAL` batteries:
  `accesses_full_media_library` and `creates_root_level_external_folder`
  (activated by file-write sinks whose path composes from the external
  storage root, detected in `structure`).
- **Tests.** Selftests per rule; boundary at `targetSdk` 32/33 and 29/30.
- **Exit.** App B: uncapped legacy storage permissions → Important
  (`photo_video`), root-level folder → Suggestion (`files_and_docs`),
  matching or exceeding the legacy findings.
- **Size.** Small–medium in `registry.py`, `questions.py`, `templates.py`.

### WP10 — `data_type_confirmed` (L7)

- **Depends on.** WP7.
- **Changes.** Choice `data_type_confirmed` on in-band anchors with sibling
  types from the taxonomy; `evaluate` composes on the confirmed type;
  `calibrate.py` prints a labelled-vs-confirmed confusion table; label
  schema gains `confirmed_type`.
- **Tests.** Selftest for `as_labelled`, `different_type`, `not_personal`.
- **Exit.** The recurring legacy relabels (`uid` → not personal,
  `country_code` from a remote peer → not user location) reproduce on the
  dev apps; recall unchanged.
- **Size.** Small.

### WP11 — Wave 3 policies (`account_deletion` heuristics, `login_credentials`)

- **Depends on.** WP6, WP7.
- **Changes.**
  - `account_deletion`: deterministic pass over first-party network sinks
    for *server-assigned identity written back to persistent storage* with
    no deletion/unregistration endpoint (closed verb list at identifier
    boundaries); Noul `is_remote_delete` to confirm candidates; Noul
    `clears_local_state_only` for the partial-deletion trap → Important.
  - `login_credentials`: `CODE_SIGNAL` spec with Choice `login_gate_type`
    (`app_account`, `user_remote_server_credentials`,
    `third_party_sign_in_bridge`, `none`) → Important for account/bridge,
    evidence-only for user-remote-server, drop for none.
- **Tests.** Fixtures for each `login_gate_type`; provisioning-without-delete
  fixture; deletion-with-remote-call negative.
- **Exit.** App A → `account_deletion` Important; App B → no
  `account_deletion` finding and `login_gate_type=user_remote_server_credentials`
  recorded. Both match the legacy adjudication.
- **Size.** Medium in `registry.py`, `questions.py`, `evaluate.py`.

### WP12 — Wave 4 policies in review-only mode (`sms_call_log_policy`, `accessibility_api_policy`)

- **Depends on.** WP1, WP4, WP8.
- **Changes.** `MANIFEST` rules from plan §5.3 (default-handler intent
  filters, incoming-SMS receiver, `isAccessibilityTool` in the config
  resource via `resources.py`), `CODE_SIGNAL` Nouls `reads_one_time_code`
  and `siphons_screen_content_offdevice`. `PolicySpec.review_only=True`
  routes every finding to `MANUAL_REVIEW` until labels exist.
  Acquire two to three open-source fixture apps per policy (out of tree)
  and label them.
- **Tests.** Synthetic manifests for every rule; fixture-app runs once
  available.
- **Exit.** Rules fire on synthetic fixtures; `review_only` cleared for a
  policy only when its labelled recall is 1.0 and precision ≥ 0.90.
- **Size.** Medium; blocked on fixture acquisition for the final gate.

### WP13 — Wave 5 refinements to existing permission specs

- **Depends on.** WP8.
- **Changes.** `location_access_policy`: background-location rows
  (`ACCESS_BACKGROUND_LOCATION` for a secondary feature → Important;
  disclosure text must contain the required phrase, checked on resolved
  string text → Suggestion on mismatch; fine location on `targetSdk ≥ 37`
  → Location Button Suggestion). `audio_recording_policy`: Noul
  `captures_audio_continuously_in_background` → Critical.
  `contacts_access_policy`: Contact Picker Suggestion on 37+.
- **Tests.** Fixtures per row.
- **Exit.** App A reproduces the legacy background-location Important and
  wording Suggestion.
- **Size.** Small–medium in `registry.py`, `questions.py`, `evaluate.py`.

---

## 2. Milestones and gates

| Milestone | Work packages | Theme | Gate (all must hold) |
| --- | --- | --- | --- |
| **M1 — Deterministic breadth** | WP0, WP1, WP2, WP3, WP4, WP5 | New facts, fewer wasted model calls, five more policies with zero tuned thresholds | selftest green; both apps run; `triage-diff` vs baseline shows only additions plus pre-gate drops; dev-set recall 1.0; model calls per app ↓; the two App B findings the legacy skill dropped are present |
| **M2 — Calibration** | WP6, WP7 | Answerable questions, less abstention | recall 1.0; abstention < 0.50; precision-at-high ≥ 0.90; ECE improved in the UNCERTAIN band; `THRESHOLD_PROVENANCE` and `EVALUATOR_VERSION` updated |
| **M3 — Context and depth** | WP8, WP9, WP10, WP11 | Consent, resources, flavors; waves 2–3 | App A default-on transfer carries the default; wave 2/3 findings match or exceed legacy adjudication on both apps; recall unchanged |
| **M4 — Long tail** | WP12, WP13 | Waves 4–5 | wave 4 fires on synthetic fixtures in review-only mode; wave 5 reproduces App A location findings; per-policy coverage table complete |

Parallelism inside a milestone: WP1/WP2/WP3 are independent; WP4 follows
WP1; WP5 follows WP4. In M3, WP9 can proceed alongside WP8; WP10 and WP11
follow WP7.

A milestone gate that fails is resolved inside the milestone (fix or revert
the offending WP by its flag); the next milestone does not start on a red
gate.

---

## 3. Cross-cutting rules

### 3.1 Label schema v2

```
{
  "schema": 2,
  "cases": [{
    "id": "...", "file": "...", "data_type": "...",
    "transfer": true|false,
    "destination_class": "developer_backend|third_party_sdk|user_chosen_destination|platform_component|other_app_ipc",
    "confirmed_type": "<taxonomy type or NOT_PERSONAL>",
    "consent_default_on": true|false|null,
    "expected": [{"policy_id": "...", "severity": "CRITICAL|IMPORTANT|SUGGESTION"}]
  }]
}
```

`calibrate.py` accepts schema 1 (transfer only) and 2; per-policy
recall/precision is reported wherever `expected` is present. Labels stay in
`.scratch/labels/`; the exported copy in artifacts is refreshed whenever the
numbers in `THRESHOLD_PROVENANCE` change.

### 3.2 Versioning

- Bump `EVALUATOR_VERSION` (minor) when question wording, the capability
  taxonomy, thresholds, or the pinned model change — WP7, WP8, WP10 at
  least. Patch bump for deterministic rule additions (WP5, WP9, WP11–13).
- Every bump re-runs `calibrate` and refreshes `THRESHOLD_PROVENANCE`
  (`calibrated_at`, `metrics_at_shipped`, and the label count).
- Deterministic rules with dated externals (`PLAY_REQUIRED_TARGET_SDK`, the
  API levels in matrix rows) carry a `_PROVENANCE` note beside the constant.

### 3.3 Logging and observability

- `INFO`: profile summary (manifests merged, components counted), pre-gate
  drop counts by reason, callee additions per anchor, per-app purpose
  answer with confidence, each manifest rule's inputs and outcome.
- `WARNING`: manifest parse failures, missing string resources referenced by
  disclosure symbols, low-confidence purpose answer.
- `typesafe_triage.json` gains `app_profile_summary`, `app_purpose`,
  `pregate_drops`, `callee_hops`, `manifest_rules[]`.

### 3.4 Documentation per WP

Each PR updates, additively: `scripts/typesafe_eval/README.md` (commands,
module table), `docs/capability-based-evaluation.md` (§3 cascade steps, §5
results, §7 change control as relevant), `docs/policy-coverage-evolution.md`
§2 status column, and this document's checklist (§5). Module docstrings
describe the rule and cite the matrix row.

### 3.5 Rollback

Each behavioural WP ships behind a constant flag (`LEXICAL_PREGATE_ENABLED`,
`CALLEE_HOPS_ENABLED`, `DESTINATION_CLASS_ENABLED`, `CONSENT_CONTEXT_ENABLED`)
and each policy spec can be disabled by removing it from `REGISTRY`, so a
regression found after merge is reverted by a one-line change without
touching the rest of the cascade.

---

## 4. Risks and mitigations

| Risk | Where | Mitigation |
| --- | --- | --- |
| Pre-gate too strict removes a real anchor | WP2 | `calibrate.py` fails if any labelled case has no probability; flag for rollback |
| Callee state blows the snippet cap and dilutes the anchor | WP6 | sink-lines-only fallback; cap of 3 callees; measure tokens per request in triage |
| Closed option lists miss a real case | WP4, WP7, WP11 | `unknown` always present and always routes to `MANUAL_REVIEW`; add options only with a fixture |
| Purpose inference gamed or wrong | WP4/WP5 | purpose only moderates severity (never suppresses); low confidence counts as "not justified" |
| Flavor merge double-counts | WP1 | findings keyed by permission/component name with a `manifest_sources` list |
| Relabel effort stalls M2 | WP7 | schema 2 is additive; `calibrate` runs on partial labels and reports coverage |
| Wave 4 has no real positives | WP12 | ship review-only; gate on fixture apps, not on synthetic manifests alone |
| Shared-code changes upstream (`orchestrator.py`) alter `manifest_details.json` | WP1 | evaluator parses manifests itself; `manifest_details.json` is fallback only |

---

## 5. Tracking checklist

- [x] WP0 baseline + `triage-diff`
- [x] WP1 `android_manifest.py` / `AppProfile`
- [x] WP2 identifier-boundary pre-gate
- [x] WP3 structured evidence
- [x] WP4 `declared_core_purpose` (per-app cache)
- [ ] WP5 wave 1 policies (FGS fixes, package visibility, all files, exact alarm, target API)
- [ ] **M1 gate**
- [ ] WP6 one-hop callee resolution
- [ ] WP7 `destination_class` + label schema v2 + relabel
- [ ] **M2 gate**
- [ ] WP8 consent defaults, string resources, flavor attribution
- [ ] WP9 wave 2 policies
- [ ] WP10 `data_type_confirmed`
- [ ] WP11 wave 3 policies
- [ ] **M3 gate**
- [ ] WP12 wave 4 (review-only) + fixture apps
- [ ] WP13 wave 5 refinements
- [ ] **M4 gate**
