# Capability-Based Evaluation (hybrid evaluator v2)

Status: Implemented (`EVALUATOR_VERSION = "2.0.0-capability"`)
Owner: play-policy-insights
Last updated: 2026-09-27
Supersedes: the single-cliff `T_TRANSMIT` decision and pattern-anchored snippets described
in [`typesafe-hybrid-architecture.md`](typesafe-hybrid-architecture.md) §4 and §6 (kept there
for history; §9.2 of that document points here).

## 1. Problem statement

The first hybrid prototype (v1) reproduced the legacy skill's *shape* (typed questions,
code-composed severity) but on real applications it missed the findings that matter:

- Every real off-device send that the legacy agent flagged as Critical on one development
  app was downgraded to "local only" by v1. The `transmits_offdevice` probability landed at
  0.52-0.54, just under a single 0.55 cliff, and the finding silently became Compliant.
- On the second app, a credential sent over a raw socket was ranked ninth among nine
  candidates for its data type and dropped by the per-type cap before any question was asked.
- The critic scored a genuine device-id upload at `evidence_supports_claim = 0.10` and pruned
  it, because the "evidence" it was shown was the first line matching the scanner pattern (a
  type declaration), not the code that performs the send.
- The snippet extractor knew nothing about the code: no imports, no scopes, no notion of
  which identifiers in a file are capable of moving data anywhere.

Two tempting fixes were rejected explicitly: (a) adding rules that name specific libraries
(an HTTP client, a crash reporter) and (b) tuning constants until the two development apps
produce the expected reports. Both overfit. The design below gives the model the ability to
say what an identifier *can do* and lets code compose that into a policy decision.

## 2. Design principles

1. **Recall before precision, precision before cost.** The
   [evaluation charter](evaluation-charter.md) orders the dimensions Recall > Precision >
   Calibration > Latency > Cost. A missed real transfer is the worst outcome; an extra item
   in "needs review" is the cheapest.
2. **Uncertainty is a first-class output.** A probability in the middle of the range is
   reported as UNCERTAIN, routed to a human, and never pruned. The model is not forced to
   pick a side it cannot support.
3. **Capabilities, not vendors.** Evaluator logic never contains a library, SDK, or vendor
   name. It contains a small taxonomy of *behaviours* (network egress, third-party telemetry,
   IPC hand-off, ...). The model labels identifiers with those behaviours; a selftest lint
   fails the build if a vendor token appears in evaluator code.
4. **IPC is sharing.** Handing data to another application via an `Intent`, a
   `ContentProvider`, the clipboard, a bound service, or a file-provider URI is a transfer
   under the Data Safety policy. It is judged as such; it is only *ranked* below explicit
   egress because IPC-capable platform types appear in nearly every Android source file.
5. **Deterministic where possible, model where necessary.** Structure (imports, scopes,
   symbol references, dependency manifests) is parsed in code. The model is asked three
   kinds of narrow questions: what can this identifier do, does this snippet handle this
   data type, and does this snippet transfer it.
6. **Every decision carries its provenance.** Findings record the probabilities, the
   thresholds in force, the anchor that was shown, the sinks in scope, the model id, the
   taxonomy version and the evaluator version.
7. **Thresholds are calibrated artifacts.** `constants.THRESHOLD_PROVENANCE` records the
   label set, method, derived band and measured metrics; `calibrate.py` regenerates it.

## 3. Architecture: three layers and a cascade

```
                 scanner hits (data_safety_scan.json), manifest, Play declaration
                                            |
  +-------------------- structure layer (deterministic) --------------------+
  |  structure.py: language, imports, declared package, dependency inventory |
  |  symbol references, scope detection, comment/import demotion            |
  +-------------------------------------------------------------------------+
                                            |
  +-------------------- semantic layer (model + cache) ---------------------+
  |  capabilities.py: classify third-party identifiers into the capability  |
  |  taxonomy; package level first, class level only where it matters;      |
  |  persistent human-reviewable cache                                      |
  +-------------------------------------------------------------------------+
                                            |
  +-------------------- policy layer (model + code) ------------------------+
  |  context.py: anchor each hit on the occurrence nearest a transfer sink  |
  |  engine.py: filter -> triage (tiered rank) -> batched batteries         |
  |  evaluate.py: relevance gate, three-way transfer decision, severity,    |
  |               critic on the atomic transfer claim, decision trace       |
  +-------------------------------------------------------------------------+
                                            |
              worker_<goal>.json  +  typesafe_triage.json  (consumed unchanged
              by orchestrator.py aggregate and generate_report.py)
```

### 3.1 Structure layer (`structure.py`)

Pure Python, no network. Per file it produces a `FileStructure` with the language, the
import inventory, the declared `package`/`namespace`, and helpers over the line array:

- `symbol_references(lines, symbol)` returns the lines that *use* a symbol, skipping import
  lines and comment lines (a mention in a comment is not a data flow). Every call site is
  returned (bounded only by `MAX_SYMBOL_REFERENCE_LINES = 400`); an earlier cap of 12 hid the
  14th `Intent` use in a large activity from ranking (WP2).
- `all_occurrences(lines, pattern)` returns scanner-pattern hits with comment and import
  lines demoted to the end, so an anchor prefers executable code. With the lexical pre-gate
  on, identifier-boundary hits come first and exact-case hits before case-folded ones.
- `enclosing_scope(lines, index)` finds the *function* containing a line using an
  indentation/brace depth profile, so the snippet shown to the model is the whole function
  that performs the operation rather than a fixed window. Control-flow headers
  (`switch (x) {`, `if (…) {`, `= when (…) {`, …) are not declarations
  (`is_declaration_header`), so a hit inside a `switch` still sees a sink called two lines
  after the block.
- `dependency_inventory(app_dir)` reads Gradle, `pubspec.yaml`, `package.json` and similar
  manifests so build-declared dependencies can be classified even when no import is seen.
- `package_of(module)` and `declared_package(content)` support first-party detection: an
  import whose package equals the manifest package or any package declared by an analysed
  source file is the app's own code and is not sent for classification.

Wildcard imports (`import foo.bar.*`) are preserved so the package can still be classified.

#### 3.1.1 App profile (`android_manifest.py`, `resources.py`) — added in WP1

The orchestrator's `manifest_details.json` records only a handful of facts (package,
target SDK, permission names, services that *have* a `foregroundServiceType`), and the
orchestrator is read-only for this work. The evaluator therefore parses the manifests itself,
once per run, into an `AppProfile` stored on `RunContext.profile`:

- **Module discovery.** Every `AndroidManifest.xml` (skipping `IGNORED_DIR_NAMES` and test
  source sets) is grouped by module root (the prefix before `/src/`). The primary module is
  the one whose manifest declares a LAUNCHER activity, then the one with most components;
  other modules (benchmarks, libraries) are logged in `other_modules` and never merged, so a
  library manifest cannot inject permissions or components.
- **Source-set merge with attribution.** `src/main` first, then flavors and build types in
  sorted order. Every permission and component carries `sources` (the source sets that
  declared it) and `removed_in` (`tools:node="remove"`). Attribute conflicts follow the
  Gradle manifest merger: `main` wins unless the flavor's `<application>` lists the
  attribute in `tools:replace`. `AppProfile.ships_in_play_build(entry)` applies the same
  flavor rule as candidate filtering (`main` + `play` when a `play` flavor exists), so a
  component declared only in a non-Play flavor is visible as such rather than silently
  merged in.
- **Facts that `manifest_details.json` lacks.** Services *without* a
  `foregroundServiceType`, `<property>` sub-tags (special-use FGS subtype), `<queries>`,
  `maxSdkVersion` / `minSdkVersion` / `usesPermissionFlags` on permissions,
  `requestLegacyExternalStorage` and similar `<application>` flags, exported state,
  intent filters, app- and component-level `<meta-data>`, `<uses-feature>`, and the
  `isAccessibilityTool` flag read from the accessibility service's `res/xml` config.
- **Provenance.** Modern projects keep `namespace`/`applicationId`/`targetSdk` in Gradle,
  so the module's `build.gradle(.kts)` is scanned for numeric/quoted literals (comments
  stripped); the manifest's `package` and `<uses-sdk>` come next; `manifest_details.json`
  is the last fallback. `sdk_provenance` records the source of each value and any
  disagreement with the orchestrator is logged at WARNING and kept in `warnings`.
- **Derived platform facts (no policy judgement).** `launcher_activities()`,
  `default_handler_roles()` (SMS / dialer / assistant / home / telecom roles from
  framework intent constants), `sms_receivers()`, `file_handling_activities()`,
  `services_without_fgs_type()`, `exported_components()`.
- **Observability.** `AppProfile.summary()` is written to
  `typesafe_triage.json["app_profile"]`; counters `manifests_merged`, `manifest_warnings`,
  `manifest_other_modules` are recorded. A parse failure in one flavor manifest degrades to
  a warning and a partial profile; a total failure falls back to `manifest_details.json`
  and never aborts a run.

`resources.py` indexes the default-locale `res/values/*.xml` strings and `res/xml/` paths so
`@string/` labels (and, from WP8, disclosure wording referenced as `R.string.x`) resolve to
text.

#### 3.1.2 Identifier-boundary lexical pre-gate — added in WP2

The scanner's patterns are substrings, so `race` matches `printStackTrace`, `uid` matches
`fluid`, `imap` matches `Multimap` and `dob` matches `adobe`. The v1 evaluator paid a model
call to reject each of these. The pre-gate is a deterministic cascade step that runs after
file analysis and before the capability classifier, so files whose only hits are
coincidences also leave the import inventory (fewer classification requests):

- **What counts as a match.** For identifier-shaped patterns only
  (`^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*$`), an occurrence must start and end at an identifier
  boundary: a non-alphanumeric character, a camelCase transition (`userUid`, `UidCache`), a
  digit, or a short English affix (`Relogin`, `records`, `tracking`, `tracker`, `trackable`).
  A capitalised variant of a lowercase pattern counts as a (non-exact) match. MIME literals,
  paths and other non-identifier patterns are `non_identifier` and always pass.
- **Type vs value position.** `is_type_position` recognises class/interface headers,
  `: Type`, `<Type>`, `@Type`, and `Type name =` declarations. A file whose only boundary
  hits are type positions gets verdict `type_only`; dropping those is **off**
  (`LEXICAL_TYPE_ONLY_DROP = False`) because a `: AudioRecord` field driven through the field
  name is a real use. The verdict is recorded so the effect can be measured on labels first.
- **Verdicts** per (file, pattern): `value`, `type_only`, `substring_only` (dropped, with the
  offending line as `example`), `demoted_only` (hits only in comments/imports; kept), `none`.
  They land in `typesafe_triage.json["counters"]["lexical_pregate"]`, in each drop record,
  and on every finding as `decision_trace.anchor.lexical`.
- **Rollback.** `LEXICAL_PREGATE_ENABLED = False` restores the previous behaviour exactly.

Measured on the two development apps: 41 and 37 candidates dropped, 9 and 11 files pruned,
all inspected as genuine coincidences; battery requests at a fixed cap fell 9 % and 16 %.

#### 3.1.3 Recall checks that shaped the cascade — WP2

`calibrate --rejoin` (see §4) re-joins the frozen label set to every new run and fails when a
labelled transfer has no finding. Running it after each change surfaced five silent recall
losses that had nothing to do with the model, each fixed at its root rather than by tuning:
occurrence capping before ranking (`MAX_OCCURRENCES_RANKED`), symbol-reference truncation
(`MAX_SYMBOL_REFERENCE_LINES`), control-flow headers clipping the anchor scope
(`is_declaration_header`), the per-type cost cap dropping candidates that had a sink in
scope (`CAP_EXEMPTS_SINK_IN_SCOPE`), and a relevance question that told the model MIME
types were coincidences (`questions._relevance`). The rule that emerged: **caps bound cost,
never evidence** — a candidate whose own function calls an egress/IPC sink is never dropped
for cost, and every list shown to the model is bounded separately from the list used for
ranking.

### 3.2 Semantic layer (`capabilities.py`)

The taxonomy (`TAXONOMY_VERSION = "1"`) is behavioural and vendor-free:

| Capability | Meaning | Transfer? | Sharing? |
| --- | --- | --- | --- |
| `NETWORK_EGRESS` | Can send bytes off-device (sockets, HTTP, RPC, DNS, websockets). | yes | no |
| `THIRD_PARTY_TELEMETRY` | Reports events, crashes or analytics to a party other than the developer. | yes | yes |
| `ADVERTISING_SDK` | Serves or measures advertising. | yes | yes |
| `IPC_SHARING` | Hands data to another application on the device (intents, providers, clipboard, bound services). | yes | yes |
| `LOCAL_PERSISTENCE` | Writes to local storage or databases. | no | no |
| `LOGGING` | Emits diagnostic output that stays on-device by default. | no | no |
| `USER_DISCLOSURE_UI` | Presents consent or disclosure UI. | no | no |
| `UNKNOWN` | Could not be classified with confidence. | treated as transfer-capable | no |

The model is asked, per identifier, a battery of `Noul` questions "does this identifier
provide capability X" (`classification_battery`), batched `CAPABILITY_BATCH_SIZE` identifiers
per request. A label is applied at `T_CAPABILITY = 0.60`; a transfer capability scoring in
`[T_CAPABILITY_UNKNOWN_LOW, T_CAPABILITY)` yields `UNKNOWN` rather than a confident "no",
which keeps the identifier in scope as a possible sink (recall first).

**Cascade.** Third-party imports are grouped by package and the package is classified first.
Only packages labelled with a transfer capability or `UNKNOWN` have their individual classes
refined; classes from packages that are clearly local-only inherit the package profile with
`source = "package:<...>"`. On the development set this cut identifiers sent for
classification by roughly 60 %. Build-declared dependencies are classified too and summarised
into `app_facts["declared_capabilities"]`, which is included in every policy question's state
so the model knows, for example, that the app links a crash reporter even when the current
file does not import it.

**Cache.** `CapabilityCache` persists profiles keyed by
`"{TAXONOMY_VERSION}|{model}|{identifier}"` (default path `~/.cache/play_policy_insights/
capabilities.json`, overridable by `PPI_CAPABILITY_CACHE` or `--capability-cache`). The file
is plain JSON so a reviewer can inspect or correct a label; human-authored entries always win
over model entries. A taxonomy or model change changes the key and therefore invalidates
nothing silently. Cache hit/miss counts are recorded in the triage file.

The same file also holds **per-app answers** (WP4) under keys
`"app|{TAXONOMY_VERSION}|{model}|{question_id}|{digest}"`, where `digest` is the SHA-256 of
the exact state and battery the model saw. Today the only such question is
`declared_core_purpose` (below). `get_app_answer()` returns a human-authored entry regardless
of model; `put_app_answer()` never overwrites one. A reviewer therefore pins an app's purpose
by editing one JSON entry with `"source": "human"`, and the pin survives model changes.

**Offline stand-in.** `HeuristicJevClient` answers classification questions from generic
substring hints (`"http"`, `"socket"`, `"intent"`, `"prefs"`, ...). It exists so selftest and
the wiring can run without a key. It is a labelled mock, never a source of judgment, and
every finding it produces carries `client = "heuristic"`.

### 3.3 Policy layer (`context.py`, `engine.py`, `evaluate.py`, `questions.py`)

**Sinks and anchors.** For each analysed file `context.file_sinks` lists every imported
identifier whose profile is transfer-capable, with the lines that reference it. For a scanner
hit, `anchor_signal` chooses among all occurrences of the pattern the one that is best by
`(tier, proximity)`, where proximity is the distance to the nearest sink reference (0 means
the sink is used inside the hit's own scope) and tier is:

| Tier | Meaning |
| --- | --- |
| 0 | A `NETWORK_EGRESS`, `THIRD_PARTY_TELEMETRY` or `ADVERTISING_SDK` sink is referenced in the anchor's scope. |
| 1 | An `IPC_SHARING` sink is referenced in scope. |
| 2 | Only `UNKNOWN`-capability sinks are in scope. |
| 3 | No transfer-capable sink in scope. |

The `Anchor` records `scope_capabilities` so the trace shows *why* a tier was assigned.

**Triage.** `engine._filter_candidates` drops non-prioritised build flavours, excluded paths
(`res/values*` string catalogs and `src/test*` source sets, which are not shipped), and
anything past `MAX_CANDIDATES_PER_TYPE`. `engine._triage` ranks the remaining candidates of a
data type by `(tier, proximity, scanner order)` and keeps `MAX_FINDINGS_PER_TYPE = 8` with at
most `MAX_PER_FILE_PER_TYPE = 2` per file. Every dropped candidate is written to the triage
file with its rank, tier, proximity and reason, so a reviewer can see exactly what was not
asked and why.

**Declared core purpose** (`engine._ask_app_purpose`, `questions.app_purpose_battery`, WP4).
Several policies (foreground-service types, `MANAGE_EXTERNAL_STORAGE`, exact alarms, package
visibility, accessibility, SMS/call log) are only satisfiable when the app's *core purpose* is
one of a short list Play names in the policy. The evaluator asks that once per app, before any
per-finding work, as a single `Choice` over a closed option set —
`file_manager`, `backup_or_antivirus`, `alarm_or_timer`, `calendar`,
`messaging_default_handler`, `accessibility_tool`, `media_gallery_or_editor`, `launcher`,
`per_app_network_control`, `other`, `unknown` — with a compact state: app name, package,
`targetSdk`, store category, the first 600 characters of the store description and the
`AppProfile` digest (permissions, components, intent filters). The answer, its confidence and
the full distribution are recorded in `typesafe_triage.json["app_purpose"]` with `source`
`model` / `cache` / `human` / `unavailable`, and the label alone is copied into
`app_facts["purpose"]` so every later finding-level state carries it (symbol-classification
states do not: identifier capability is app-independent and the cross-app cache must stay
purpose-free). Rules that make the answer safe to consume:

- `evaluate.purpose_in(app_purpose, allowed)` is the only reader. It returns `False` for
  `unknown`, for a missing answer, and for any model answer below
  `CONF_APP_PURPOSE = 0.75`; only a human pin bypasses the confidence check. Low confidence
  therefore reads as "purpose not established" → the policy treats the permission as
  *unjustified* (higher severity, review), never as a reason to suppress or soften.
- An answer outside the closed set, a transport failure or a malformed reply degrade to
  `unknown` / `unavailable`, are counted (`app_purpose_error`) and the run continues.
- The offline `HeuristicJevClient` always answers `unknown` (peaked distribution) — it is a
  labelled stand-in, not a purpose classifier.
- Cost is one request per cold run (`app_purpose_requests`); the cache key covers the whole
  state, so a changed store listing, manifest or option wording re-asks instead of reusing a
  stale answer. On the development set the model answers `file_manager` (App B, p = 1.00) and
  `per_app_network_control` (App A), matching the apps' listings.

**Batteries.** Kept candidates are grouped per file and sent in chunks of
`MAX_ASKS_PER_REQUEST = 6` data types per request (question ids are namespaced
`a<i>__<qid>`). The file state contains the anchored scope, the capability-labelled sink
lines (`MAX_SINK_LINES_IN_STATE`), the app facts and declared capabilities. Each ask contains:

| Question | Type | Used for |
| --- | --- | --- |
| `signal_relevant` — does this snippet read, hold, process, select, open or share *this* data type (the literal matched token is embedded; a MIME/picker filter that picks, opens or hands off files of that kind counts) | `Noul` | relevance gate at `T_RELEVANCE = 0.30`; drops semantic false positives such as a database `record` matching AUDIO |
| `transmits_offdevice` — is the value sent off-device *or handed to another app* | `Noul` | three-way transfer decision |
| `is_third_party`, `has_prominent_disclosure`, `is_core_functionality`, `user_initiated` | `Noul` | severity composition in code |
| `disclosure_status` — DISCLOSED / MISSING / EXEMPT | `Choice` | policy routing, after reconciliation with `has_prominent_disclosure` (below) |

**Soft relevance gate** (`evaluate.relevance_verdict`, WP2). A `signal_relevant` answer below
`T_RELEVANCE` may *suppress* a finding only when the anchor's own scope has no
capability-labelled egress or IPC sink (rank tier 2–3). With a sink in scope the code
demonstrably hands data to a transfer channel, so the finding is kept, capped at IMPORTANT,
marked `needs_manual_review`, suffixed `[data-type match uncertain: p=…; verify]` and traced
as `relevance: "low"`. Below `T_RELEVANCE_FLOOR = 0.10` the model is confidently negative and
the finding is dropped regardless (on the dev apps every keep under 0.10 was `track`→MUSIC,
`record`→AUDIO or `PowerManager`→DIAGNOSTICS). Rollback: `RELEVANCE_SOFT_GATE_ENABLED`.

A second condition (WP4, `RELEVANCE_SOFT_GATE_FILE_EGRESS`) keeps an uncertain answer when the
*file* references a strong egress sink (`NETWORK_EGRESS`, `THIRD_PARTY_TELEMETRY`,
`ADVERTISING_SDK`) outside the anchor's function. The evidence is weaker, so the verdict is
distinct: traced as `relevance: "low_file_egress"`, and the evidence line shows the sink
`(out of scope)`. IPC-only or `UNKNOWN` file sinks do not qualify (every Activity references
`Intent`). It was added when a labelled credential transfer was lost to answer drift
(`signal_relevant` 0.29 against 0.30 at a tier-3 anchor in a file whose network client sits in
another method); on the development set it costs one extra review item per app.

**Disclosure reconciliation** (`evaluate.reconcile_disclosure_status`, WP2). The battery asks
about disclosure twice (a Noul and a Choice); when they disagree the Choice is the less stable
one. `DISCLOSED` with `has_prominent_disclosure < T_DISCLOSURE` becomes `MISSING` + review;
`EXEMPT` on an off-device transfer that is not user-initiated becomes `MISSING`. The change is
traced as `decision_trace.disclosure_reconciled`. LOCAL decisions are EXEMPT in code and never
reconciled.

**Three-way transfer decision** (`evaluate.transfer_decision`):

```
p < T_TRANSMIT_LOW  (0.35)            -> LOCAL      is_transferred=False, SUGGESTION, prunable
T_LOW <= p < T_TRANSMIT_HIGH (0.70)   -> UNCERTAIN  is_transferred=True,  >= IMPORTANT,
                                                    needs_manual_review=True, never pruned,
                                                    title suffixed "[transfer uncertain: p=..; verify]"
p >= T_TRANSMIT_HIGH                  -> TRANSMITS  is_transferred=True, severity from booleans
```

`is_transferred=True` for UNCERTAIN is deliberate: `generate_report.py` only surfaces a
MANUAL_REVIEW item in "needs review" when the finding is transferred, and an undeclared
transferred type becomes a Data Safety discrepancy. Sharing (`is_third_party`) is set when a
sink with a sharing capability is in scope, which is how IPC hand-offs reach the report as
sharing.

**Play declaration check** (`_run_play_declaration`) runs only for TRANSMITS findings and only
when a Play declaration is present; UNCERTAIN findings are not turned into Non-Compliant
verdicts on their own.

**Manifest checks** (`_run_manifest`) are deterministic and bypass the critic. Each
`MANIFEST`-kind spec receives `registry.ManifestInputs` — the merged `AppProfile` (WP1), the
legacy `manifest_details` dict as fallback, the cached `declared_core_purpose` answer (WP4)
and the app root — and returns zero or more findings with `client = "deterministic"`,
`kind = "manifest"` and a `decision_trace` holding the facts it read. Only components and
permissions that ship in the Play build are examined. Wave 1 (WP5):

| Policy | Rule (severity) |
| --- | --- |
| `foreground_services_policy` | typeless service whose own class calls `startForeground` on `targetSdk >= 34` → **Critical** (the branch the legacy input made unreachable: `manifest_details.foreground_services` listed only typed services); `specialUse` without `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` → **Critical**; type without its `FOREGROUND_SERVICE_<TYPE>` permission → Important; type whose definition the *established* purpose clearly falls outside (`constants.FGS_TYPE_MISALIGNED_PURPOSES`) → Important; every typed service → Suggestion inventory; `FOREGROUND_SERVICE_SPECIAL_USE` with no `specialUse` service → Suggestion |
| `all_files_access_policy` | `MANAGE_EXTERNAL_STORAGE`: purpose in `ALL_FILES_ACCESS_PURPOSES` → Suggestion, otherwise **Critical** (review-marked when the purpose is not established); plus scoped media / uncapped legacy storage permissions → Important (redundant scope) |
| `package_visibility_policy` | `QUERY_ALL_PACKAGES`: `<queries>` also declared → Important; purpose in `PACKAGE_VISIBILITY_PURPOSES` → Suggestion; otherwise Important (review-marked when not established) |
| `exact_alarm_policy` | `USE_EXACT_ALARM`: purpose in `EXACT_ALARM_PURPOSES` → Suggestion, otherwise Important; `SCHEDULE_EXACT_ALARM` → Suggestion |
| `target_api_level` | lowest `targetSdk` among the shipped flavours: `< PLAY_EXISTING_APP_MIN_TARGET_SDK` → **Critical**, `< PLAY_REQUIRED_TARGET_SDK` → Important, unknown → Suggestion + review. The requirement is a dated constant (`PLAY_TARGET_SDK_PROVENANCE`), never a model question |

Purpose conditioning goes through `evaluate.purpose_in` only, so an `unknown`, `other` or
low-confidence purpose can raise a severity (and marks the finding for review) but never
lowers one. The one code fact a manifest policy reads — `startForeground` in the service's own
class file — is an exact-identifier match (`structure.value_reference_lines`) that ignores
comments, imports and `startForegroundService`; a base-class call is not resolved, so a miss
means "not confirmed", never "not a foreground service".

**Critic** (`evaluate.evaluate_critic_chunk`) verifies one atomic claim per finding, the
transfer claim ("this snippet sends or shares <data type>"), against the anchored evidence
plus sink lines, instead of the compound "does the evidence support the whole finding". The
routing (`evaluate._critic_decision`) is recall-weighted:

| Finding decision | `evidence_shows_transfer` | Verdict |
| --- | --- | --- |
| TRANSMITS | >= `CONF_ACT` (0.75) | VERIFIED, High |
| TRANSMITS | >= `T_EVIDENCE_SUPPORTS` (0.50) | VERIFIED, Medium |
| TRANSMITS | < 1 - `CONF_ACT` (0.25) | PRUNED, High (strong evidence of a false positive) |
| TRANSMITS | otherwise | MANUAL_REVIEW, Low |
| UNCERTAIN | >= `CONF_ACT` | VERIFIED, Medium (the critic saw the flow the battery was unsure about) |
| UNCERTAIN | otherwise | MANUAL_REVIEW, Low; never PRUNED |

Findings already marked `needs_manual_review` are routed without a model call.

**Structured evidence (WP3).** `finding["evidence"]` reads
`source@<file>:L<start>-L<end> (L<line>: <matched>) -> sink@L<n> <Symbol> [<CAPS>]`: the
anchor's whole function, the matched line, and the nearest capability-labelled *transfer*
sink (`(out of scope)` when it lies outside that function). Files without a transfer sink keep
the single-line `<file>:L<n> — <matched>` form. `finding["evidence_flow"]` carries the same
facts as a dict (`source`, `sink`) for downstream tooling; WP7 appends `destination_class`.

**Decision trace.** Each finding's `decision_trace` records `scores` (every probability),
`thresholds` (the values in force), `anchor` (file, line, scope, `scope_capabilities`,
`rank_tier`, proximity, `lexical` verdict), `sinks`, `relevance` (`ok`/`low`),
`disclosure_reconciled`, `model`, `taxonomy_version` and `evaluator_version`.

### 3.4 Triage file (`typesafe_triage.json`)

Written next to the worker files on every run. Keys: `evaluator_version`, `model`,
`counters` (raw signals, candidates, kept, files analysed, imports first-party skipped,
third-party, packages, refined, dependencies, capability-cache hits/misses,
`lexical_pregate{checked, kept_*, dropped_*, files_pruned}`, `cap_exempt_sink_in_scope`,
`app_purpose_requests` / `app_purpose_error`),
`app_profile` (WP1), `app_purpose` (WP4: `purpose`, `confidence`, `source`, `probabilities`,
`digest`), `usage`
(requests, tokens), `findings_by_severity`, `transfer_decisions`, `capabilities` (label
histogram and unknown count), `dependency_capabilities`, `sinks_by_file`, `thresholds`, and
`dropped` (every candidate not asked, with reason and rank data). This is the observability
surface for the run; the legacy pipeline had none.

## 4. Calibration (`calibrate.py`)

Input is a JSON label set kept **out of the repository** (it names real files of real apps):

```json
{"description": "...",
 "worker_dirs": ["/path/to/run_a", "/path/to/run_b"],
 "cases": [{"file": "Foo.kt", "data_type": "DEVICE_ID", "transfers": true, "p_transmit": 0.87}]}
```

`p_transmit` may be omitted and is then joined from the worker files by file suffix and data
type (max probability). The method:

- `T_TRANSMIT_LOW` = highest threshold on the 0.01 grid with recall 1.0 (no true transfer
  falls into LOCAL).
- `T_TRANSMIT_HIGH` = lowest threshold with precision >= `--min-precision` (0.90) among
  findings at or above it.
- Reliability: Brier score, expected calibration error and per-bin table.
- Metrics at the derived band and at the constants currently in `constants.py`, plus a
  `provenance` block ready to paste into `THRESHOLD_PROVENANCE`.

A warning is emitted below `MIN_RECOMMENDED_CASES = 30`.

**Re-join as a recall gate (WP2).** `calibrate <labels> --rejoin --worker-dir A --worker-dir B`
ignores the frozen `p_transmit` values and re-joins every case to the worker files of a new
run. A labelled *transfer* with no finding is a recall loss by construction: it is listed in
`missing_positives`, logged at ERROR, printed as `FAIL`, and the command exits 2. Every work
package runs this against both development apps before it is committed; the band and
reliability numbers it reports are recorded but only *applied* to `constants.py` at a
milestone with the version bump.

### 4.1 Result on the development set

48 hand-adjudicated claims (23 true transfers) drawn from the evaluator's own evidence traces
on two open-source apps; test source sets and ambiguous anchors excluded; IPC hand-offs
counted as sharing.

| | derived | shipped |
| --- | --- | --- |
| `T_TRANSMIT_LOW` | 0.38 | 0.35 |
| `T_TRANSMIT_HIGH` | 0.60 | 0.70 |
| false negatives in LOCAL | 0 | 0 |
| precision of TRANSMITS | 0.909 | 0.944 |
| recall of TRANSMITS alone | 0.87 | 0.739 |
| abstention (UNCERTAIN) rate | 0.479 | 0.625 |
| Brier / ECE | 0.1785 / 0.2552 | same |

The shipped band is deliberately wider than the derived one. 0.35 keeps a 0.03 margin under
the lowest-scoring true transfer (a file handed to another app's document provider at 0.38).
The derived upper bound rests on a probability bin with four cases, too thin to move the
threshold that drives Non-Compliant verdicts. The 0.5-0.6 bin is over-confident (14 cases,
none a real transfer), which is exactly the region the band abstains on. Revisit
`T_TRANSMIT_HIGH` once the label set exceeds about 100 cases.

## 5. Results on the development set (regression check, not a hold-out)

| | App A (published, VPN/DNS) | App B (unpublished, file manager) |
| --- | --- | --- |
| Legacy skill | Non-Compliant (3 Critical: purchase token, device id, crash upload) | Compliant + note to declare User IDs |
| Hybrid v1 | Compliant (all 3 missed) | Compliant (credential send dropped) |
| Hybrid v2 | Non-Compliant (13 Important; all 3 legacy items recovered as TRANSMITS + Data Safety discrepancies, plus Emails and Files via IPC) | Needs Review (credential send over a socket p=0.90 VERIFIED; SMB credentials 0.62-0.77; media hand-offs UNCERTAIN) |
| Raw -> candidates -> evaluated | 691 -> 318 -> 117 | 198 -> 141 -> 87 |
| Imports: third-party -> packages -> refined | 544 -> 157 -> 143 (2306 first-party skipped) | 303 -> 78 -> 124 |
| Requests / input tokens (cold) | 129 / 568k | 35 / 123k |
| Wall time cold / warm | ~30 s + 4 s critic / 7.7 s with 0 requests | ~9 s / ~3 s with 0 requests |
| Decisions LOCAL / UNCERTAIN / TRANSMITS | 28 / 9 / 16 | 15 / 23 / 4 |
| Critic VERIFIED / MANUAL_REVIEW | 15 / 10 | 7 / 19 |

Known residual false positive: a Suggestion-level "broad audio-recording access" item anchored
on a MIME-type table passed the relevance gate at 0.60 on App B. It is left as-is rather than
adding an app-specific rule.

### 5.1 Time to outcome and cost versus the original agent skill

The original skill's Phase 2 was run on the same two trees exactly as `SKILL.md` prescribes for
Mode A (one general-purpose sub-agent per `prompt_worker_<goal>.md`, at most 3 concurrently,
then one per critic chunk) with Claude Fable 5.1 at thinking effort `high`, timed between
batches, and its 25 sub-agent transcripts were metered afterwards. Phase 1 (`init`, ~2 s) and
report generation (<1 s) are shared and excluded.

| | App A (220 files) | App B (60 files) |
| --- | --- | --- |
| Original skill wall clock, 3-way concurrency as prescribed | 18 min 37 s (13 workers + 2 critics; 330 LLM calls) | 8 min 23 s (10 workers; 175 LLM calls) |
| Original skill theoretical floor, unlimited parallelism | ~7 min | ~2.5 min |
| Hybrid v2 cold | 34 s (129 requests) | 10 s (35 requests) |
| Hybrid v2 warm | 7.7 s (0 requests) | ~3 s (0 requests) |
| Speed-up, v2 cold vs prescribed skill | 33x | 50x |

Public list prices used (checked 2026-09-27): Claude Fable 5.1 $10 / MTok input, $12.50 5-min
cache write, $0.25 cache read, $50 output; Jev 1.13 $0.042 / MTok input, output free.

| | App A | App B |
| --- | --- | --- |
| Original skill, best case (perfect prompt caching, hidden reasoning excluded) | $30.11 | $13.24 |
| Original skill, worst case (no caching, hidden reasoning excluded) | $254.50 | $91.46 |
| Hybrid v2 cold (568k / 123k metered Jev input tokens, no output charge) | $0.024 | $0.005 |
| Hybrid v2 warm | $0 | $0 |
| Ratio, original / v2 cold | 1,260x to 10,700x | 2,560x to 17,700x |

The original-skill figures are estimates, not invoices: sub-agent transcripts carry no billing
fields, so tokens were reconstructed from the files each agent read (5.1 MB across 138 files on
App A), an assumed 1,500 tokens per un-recorded shell/grep result, visible output, one LLM call
per assistant step with linearly growing context, 3.5 characters per token, and a 6k-token
system prompt. Hidden reasoning tokens at effort `high` are billed as output and are not in the
transcript, so both bounds are low. v2's tokens are the `usage` counts Jev returns.

Two runs of the original skill on the same App A tree also disagreed with each other on
severity for the same three sends (Critical in one run; Important or discrepancy-table-only in
the other). v2's decisions are reproducible from cache.

The v1 hybrid prototype used ~78k Jev tokens on App A; v2 uses ~7x more because it classifies
identifiers and shows the model real code. That is the trade that recovered the three missed
Criticals, and it is still three orders of magnitude below the agent path.

## 6. Operating the evaluator

```
python -m typesafe_eval run <temp_dir> --client http \
    [--capability-cache PATH | --no-capability-cache] [--cache PATH] [--per-finding] [-v]
python -m typesafe_eval critic <temp_dir> --client http [--cache PATH] [-v]
python -m typesafe_eval calibrate <labels.json> [--out report.json] [--min-precision 0.90]
python -m typesafe_eval selftest
```

- The API key is read only from `TYPESAFE_API_KEY`; nothing is hard-coded.
- Logging goes to stderr via the `typesafe_eval.*` loggers; `-v` enables DEBUG including
  per-request question ids, cache decisions and relevance-gate drops.
- Mock data: the heuristic client and the fixtures in `selftest.py` are the only synthetic
  inputs. Fixtures may name a library (to test that the *model* labels it), evaluator code
  may not (`identifier_lint_no_vendor_names`).

## 7. Change control

Bump `EVALUATOR_VERSION` and re-run `calibrate` when any of these change: question wording
(`questions.py`), the taxonomy (`capabilities.TAXONOMY_VERSION`), the thresholds
(`constants.py`), or the pinned model. Update `THRESHOLD_PROVENANCE` in the same change.

## 8. Deferred work

- Dynamic evidence from Android CLI Journeys was evaluated and deliberately deferred; the
  routing is static-only for now.
- Growing the label set beyond two apps (target > 100 cases) before touching
  `T_TRANSMIT_HIGH`.
- Human corrections to the capability cache are supported by the file format but there is no
  review UI; edit the JSON directly.
- Generalisations mined from the full legacy-skill runs (identifier-boundary pre-gate,
  `destination_class`, one-hop first-party call resolution, consent-default and string-resource
  context, a manifest-derived `AppProfile`) and the per-policy plan for the nine policies v2 does
  not evaluate yet are specified in
  [legacy-skill-lessons-and-coverage-plan.md](legacy-skill-lessons-and-coverage-plan.md).
  Known defect recorded there: the "missing `foregroundServiceType`" branch in
  `registry._foreground_service_findings` is unreachable because `manifest_details.json` only
  lists services that already declare a type; the fix is the evaluator-owned manifest parser
  in that plan (§6.1).
