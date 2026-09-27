# Lessons from the Legacy Skill Runs and the Coverage-Expansion Plan

Status: Design / plan
Last updated: 2026-09-27
Evaluator version this applies to: `2.0.0-capability` (see
[capability-based-evaluation.md](capability-based-evaluation.md))

This document does two things:

1. **Mines the full legacy-skill runs** (the original agent-driven
   `play-policy-insights` skill, executed with Claude Fable 5.1 (high)
   sub-agents on the two development apps) for behaviours that the v2 hybrid
   evaluator should **generalise**, and for behaviours it must **not** copy.
2. **Plans the expansion of v2 coverage** to every `policy_id` in
   `resources/policies.json` that v2 does not evaluate yet, using those lessons.

It complements, and does not replace,
[policy-coverage-evolution.md](policy-coverage-evolution.md) (the porting
recipe and parity methodology) and the
[evaluation charter](evaluation-charter.md) (Recall > Precision > Calibration >
Latency > Cost). The sequenced work packages, milestone gates and
cross-cutting rules that implement this document are in
[v2-improvement-execution-plan.md](v2-improvement-execution-plan.md). Where the two documents overlap, this one is the more specific
and more recent plan.

Naming: the two development apps are referred to as **App A** (a
network-filtering / VPN utility, `targetSdk` 37, 17 permissions, one
foreground service with two types, has a paid tier backed by a developer
server) and **App B** (a file manager, `targetSdk` 34, 17 permissions, one
`dataSync` foreground service, connects to user-supplied remote servers). No
application, vendor or library names appear in the evaluator logic proposed
here; where the legacy agents named a vendor, this document describes the
*capability* instead.

---

## 1. What was investigated

| Input | App A | App B |
| --- | --- | --- |
| Legacy sub-agents (workers + critics) | 15 (11 data-safety shards, permissions, user-account, 2 critics) | 10 (8 data-safety shards, permissions, user-account) |
| LLM calls (assistant turns) | 330 | 175 |
| Wall-clock to outcome | 18 min 37 s | 8 min 23 s |
| Reasoning summaries recovered | 112 in total across both apps | |
| Outputs inspected | `worker_*.json`, `critic_output_*.json`, `aggregated_findings.json`, `compliance_report.md`, per-agent tool-call sequences | |
| Legacy findings (by severity) | 2 Critical, 4 Important, 31 Suggestion | 0 Critical, 0 Important, 23 Suggestion |

The transcripts contain every tool call the agents made (file reads, greps,
shell commands) and a short summary of each reasoning step, but **not** tool
results or the full chain of thought. Conclusions below are therefore drawn
from three sources triangulated together: the reasoning summaries, the files
each agent chose to open, and the evidence strings in the final findings. The
timing and cost method is in
[capability-based-evaluation.md §5.1](capability-based-evaluation.md).

---

## 2. Behaviours worth generalising into v2

Each lesson states the observation (with the legacy evidence), why it matters
under the charter, the **generalisation** (what v2 should do, in which module
and layer), and how the change is validated. None of these introduce a
vendor, library or application name into the evaluator; all of them are
expressed as *capabilities*, *structure* or *language-level* rules.

### L1. Lexical false positives are the largest single source of wasted work

**Observation.** A large share of legacy data-safety shard time went into
dismissing scanner hits where the keyword matched *inside* a longer or
foreign-language token. Recovered examples: `dob` inside a Croatian verb
stem, `fico` inside `gráfico`, `iban` inside a Hungarian word, `race` inside
`grace`, `imap` inside `HashMultimap`, `record` inside `LogRecord`, `track`
inside `ConnectionTracker`, `full_name` bound to a file path, and a
`*_step_counter` used for an onboarding tour rather than fitness data. Each
took the agent a file read (frequently the whole file) and one or two
reasoning turns.

**Why it matters.** These are pure precision losses that also cost latency
and tokens. In v2 they already fall out at the cascade's relevance gate, but
they still consume a model call each.

**Generalisation.** Add a **deterministic lexical pre-gate** in the structure
layer, before any model call:

- Match the anchor token at an identifier boundary (camelCase, snake_case,
  kebab and dot boundaries), not as a raw substring. `record` must not match
  `LogRecord`; `dob` must not match `dobiti`.
- Treat a hit whose enclosing identifier is a well-known *type* rather than a
  *value* (class/interface declaration, generic parameter, import line) as
  structural, not data-bearing, and drop it with a recorded reason.
- Detect string-catalog and localisation resources by path and by content
  shape (already partly done via `EXCLUDED_PATH_SUBSTRINGS`) and extend to
  `values-*/` locale folders and `*.po`/`*.arb`/`*.strings` catalogs.
- Record every drop in `decision_trace.dropped[]` with the reason so recall
  auditing is possible (`--per-finding`).

**Module / layer.** `structure.py` (new `identifier_boundary_hits()`),
`engine.py` cascade step 0. No policy knowledge involved.

**Validation.** Selftest fixtures for each boundary class (camelCase,
snake_case, foreign stem, type-vs-value). Regression check: on the two dev
apps, no labelled true transfer in `transfer_labels.json` may be dropped by
the pre-gate (recall must stay 1.0); measure model-call count before/after.

### L2. Destination class is the pivot of almost every legacy judgement

**Observation.** In nearly every legacy reasoning summary the deciding
question was *where does the data go*, expressed as one of five destination
classes, not as a binary "third party or not":

1. the developer's own backend (App A: purchase token, account id, device id
   posted to the developer's billing server → **Important**);
2. a third-party SDK's backend (App A: crash logs to a crash-reporting SDK →
   **Critical** because default-on and undisclosed);
3. a **user-chosen** destination (App B: credentials and files sent to the
   user's own FTP/SFTP/SMB server; a share-sheet intent) → not collection;
4. a platform component (App B: writes via the media store provider) → local;
5. another app via IPC (both apps: intents/`ContentProvider`) → sharing.

v2's `is_third_party` Choice collapses classes 1–2 and 3–5, which is why the
worst-calibrated bin in the dev-set reliability table sits in the
UNCERTAIN band: the model is being asked a question that does not have a
crisp answer for user-chosen destinations.

**Generalisation.** Replace `is_third_party` with a single **`destination_class`
Choice** with exactly these five options plus `unknown`, asked only when the
transfer claim is already ≥ `T_TRANSMIT_LOW`. Compose severity in code from
`(destination_class, consent_gate, disclosure)`:

| destination_class | Transfer is | Data-safety consequence |
| --- | --- | --- |
| `developer_backend` | collection | declare; disclosure required if sensitive |
| `third_party_sdk` | collection + sharing | declare both; disclosure required |
| `user_chosen_destination` | not collection (user-initiated) | no finding; record as evidence |
| `platform_component` | local | no finding |
| `other_app_ipc` | sharing | declare sharing; flag (IPC = sharing, per charter) |
| `unknown` | uncertain | `MANUAL_REVIEW`, never pruned |

Deterministic hints feed the question: a sink whose host/URL is read from a
user-editable preference or a UI field is `user_chosen_destination` with high
prior; a sink whose host is a compile-time constant is `developer_backend` or
`third_party_sdk` depending on whether the sink's declaring package is
first-party (already known from the package index).

**Module / layer.** `questions.py` (new Choice), `evaluate.py` composition,
`capabilities.py` (a `USER_CHOSEN_DESTINATION` hint derived from
preference/UI reads feeding the sink). Semantic layer; policy layer composes.

**Validation.** Extend the label schema with `destination_class`; re-label
the 48 dev cases (expected ~20 minutes: the class is usually obvious from the
evidence); rerun `calibrate.py` and require ECE to improve in the UNCERTAIN
band with recall unchanged.

### L3. One-hop, first-party call resolution decides most tier-3 anchors

**Observation.** The legacy agents routinely followed exactly one call edge
to reach the sink: a logging helper → an event logger → a local database
(local); a credentials object → a command dispatcher → a network adapter
(user-chosen destination); a device-id getter → a backend client → an HTTP
client interface (developer backend). They almost never needed two hops, and
when they tried (App A billing client → identity store → keystore) they gave
up and reasoned from names.

**Why it matters.** v2 evaluates a file's anchors against *that file's* sink
profile. A tier-3 anchor whose sink lives one hop away in another first-party
file is exactly the UNCERTAIN case, and it is the case v2 currently abstains
on (abstention rate 0.625 at the shipped band).

**Generalisation.** In `context.py`, when an anchor's enclosing scope calls a
symbol that `structure.symbol_references()` resolves to a **first-party**
module (already indexed for triage), append that callee file's sink profile
and its capability tags to the state, marked `hop=1`. Cap at one hop and at
three callees per anchor; never follow into third-party packages (their
capability comes from the dependency inventory). Include the callee's
snippet only if the combined snippet stays under the current size cap;
otherwise include only its sink lines.

**Module / layer.** `context.py` `build_file_state()`; `structure.py` already
has `symbol_references()` and `package_of()`. Structure + semantic layers.

**Validation.** Selftest fixture with a two-file first-party hop (local sink
and network sink variants). Calibration target: abstention rate drops below
0.50 on the dev set with recall 1.0 and precision-at-high ≥ 0.90.

### L4. Consent gates and configuration defaults are read from three places v2 does not look

**Observation.** The two legacy **Critical** findings on App A hinged on a
preference default: a crash-reporting flag whose default was
`= isStoreFlavour()` (on for the store build), with only a post-hoc snackbar
rather than a prior disclosure. The Important finding on background location
hinged on the wording of a disclosure string resource (`R.string.*`) not
matching the required phrase "when the app is closed or not in use". The
permissions agent also had to go looking for **flavor-specific manifests**
because the base manifest did not declare the activity it needed to reason
about.

**Generalisation.**

- **Guard-flag declarations.** When the enclosing scope of a sink is guarded
  by a boolean (`if (flag)`, `?.takeIf`, `enabled &&`), locate the flag's
  declaration in first-party code (one hop, L3) and include the declaration
  line and its initialiser in the state. Ask a new Noul `consent_default_on`
  ("the transfer happens unless the user opts out") rather than only
  `has_prominent_disclosure`.
- **String-resource resolution.** When the anchor or disclosure symbol
  references `R.string.<name>` or `getString(...)`, resolve `<name>` in the
  *default* `values/strings.xml` and include the text. This is a deterministic
  lookup; the policy layer then asks the existing disclosure Choice against
  real text instead of a symbol name. (Localised catalogs stay excluded from
  candidate *anchors*, per L1; they are used here only for resolution.)
- **Flavor manifests.** Parse every `AndroidManifest.xml` under
  `src/<flavor>/` and `src/<buildType>/` in addition to `src/main/`, and
  merge permissions, components and `<meta-data>` with a `source` attribute
  so findings can say "declared only in the store flavour".

**Module / layer.** `structure.py` (flag declaration, string resolution),
new `android_manifest.py` (see §6), `questions.py`, `evaluate.py`.

**Validation.** Selftests for default-on/default-off/opt-in variants and for
string resolution. Regression: App A's default-on crash-reporting case must
become a VERIFIED TRANSMITS with `consent_default_on = true`; today it is a
correct TRANSMITS but the evidence line does not mention the default.

### L5. The legacy agents infer app purpose first and judge permissions against it

**Observation.** Every permissions and user-account agent opened by
establishing "this is a file manager" / "this is a per-app firewall" from the
package name, launcher activity and permission set, and then judged each
permission against that purpose (fine location is required to read the Wi-Fi
SSID on API 29+; all-files access is core to a file manager). v2's
`app_facts` today is a thin set (target SDK, permission list, first-party
packages).

**Generalisation.** Build a deterministic **`AppProfile`** from the merged
manifest and the dependency inventory:

- launcher activity and its intent filters; declared `<intent-filter>`
  actions and MIME types (file handling, `ACTION_VIEW` of documents, share
  targets, default-handler roles such as SMS/dialer/assistant/home);
- component inventory: services with types and `<property>` elements,
  receivers and the broadcasts they filter (e.g. incoming-SMS receivers),
  providers and their export state, accessibility services and their
  `<meta-data>` config resource;
- permission attributes: `maxSdkVersion`, `usesPermissionFlags`,
  `requestLegacyExternalStorage`/`preserveLegacyExternalStorage` on
  `<application>`;
- `<queries>` element presence and contents.

Feed a compact rendering of the profile into every policy battery's
`app_facts`, and add a single reusable Choice `declared_core_purpose` with a
closed option set drawn from the policy matrices (file manager / backup /
antivirus, alarm or timer, calendar, messaging default handler,
accessibility tool, media gallery, location-centric, other). The model is
asked it **once per app** and the answer is cached; policy compositions then
read the cached answer rather than asking a per-file "is this core
functionality" question with no context.

**Module / layer.** New `android_manifest.py` (structure layer),
`context.py` `app_facts`, `questions.py`. This is also the enabler for most of
§5.

**Validation.** Unit tests on synthetic manifests; App B must be classified
as `file_manager` and App A as `per_app_network_control` (or `other` if that
option is folded away), recorded in `decision_trace`.

### L6. Evidence should carry scope ranges and sink lines, deterministically

**Observation.** The legacy findings' most useful property for a human
reviewer was evidence of the form *source symbol (file:lines) → sink call
(file:lines) → destination*. v2 already knows all three pieces (anchor scope,
sink lines, capability tag) but its `evidence` string reports only the anchor
line and the capability.

**Generalisation.** Render evidence as `source@file:lstart-lend -> sink@file:line
[capability] -> destination_class`, entirely from `FileStructure` data.
This costs no model call and makes `MANUAL_REVIEW` items materially faster to
adjudicate.

**Module / layer.** `evaluate._evidence_line()`. Output layer only.

**Validation.** Golden-string selftest; no metric impact expected.

### L7. Data-type disambiguation deserves a small, explicit question set

**Observation.** The legacy agents corrected the scanner's data type in a
handful of recurring ways: a `uid` is an *app* UID (not a user id); a
`country_code` derived from a remote peer's IP is not the *user's* location; a
server-assigned device id is a `DEVICE_ID` even though no hardware id is read.
These are the cases where the scanner's taxonomy label is wrong but the
transfer is real.

**Generalisation.** Add one Choice `data_type_confirmed` with options
`{as_labelled, different_type: <closed list of sibling types>, not_personal}`
asked only for anchors already ≥ `T_TRANSMIT_LOW`. Compose the data-safety
finding on the *confirmed* type. Do not ask it below the band: it is a
precision/labelling refinement, not a recall lever.

**Module / layer.** `questions.py`, `evaluate.py` composition. Policy layer.

**Validation.** Add `confirmed_type` to the label schema; report a per-type
confusion table from `calibrate.py`.

---

## 3. Behaviours v2 must not copy

These are places where the legacy skill is weaker than v2 today, observed
directly in the runs. They are recorded so that "parity with legacy" is never
read as "reproduce legacy".

### A1. Silently dropping "justified" permission findings (recall loss)

App B declares `MANAGE_EXTERNAL_STORAGE` and `QUERY_ALL_PACKAGES`. The
permissions prompt activated the all-files, package-visibility and
photo/video sections. The agent's recorded reasoning was: *"confirming the
MANAGE_EXTERNAL_STORAGE and QUERY_ALL_PACKAGES permissions are justified by
its core function"* — and it emitted **no** finding for either policy. The
legacy matrices for both policies require, even for a justified use, a
finding that reminds the developer of the Play Console declaration
(`SUGGESTION`). On App A the same agent *did* emit the package-visibility
reminder. This is exactly the non-determinism the charter puts recall above
everything to prevent.

**v2 rule.** A restricted permission that is declared always produces a
finding; justification only *moderates severity* (Critical → Important →
Suggestion) and never *suppresses*. This is already how `_compose_permission_finding`
behaves for location/contacts/audio and is carried into every new spec in §5.

### A2. Run-to-run disagreement on the highest-severity findings

Two legacy runs on App A (an earlier one and the metered one) disagreed on
the top findings: three Critical items in one, three Important plus a
table-only item in the other, with the same code. A gate that flips between
Critical and Important on identical input cannot be used as a CI gate.

**v2 rule.** Keep severity composition in code from calibrated booleans; keep
the model's job to atomic claims. Never let a model choose a severity.

### A3. Critic moderation is unreproducible

The legacy critic downgraded or merged findings based on narrative judgement
("this is a nitpick rather than a real violation"). The same judgement is not
reproducible and leaves no trace of the rule applied.

**v2 rule.** The critic decides one atomic claim (`supports`, `uncertain`)
and routes by the fixed `_critic_decision` table; UNCERTAIN is never pruned.

### A4. Whole-file reads and tooling overhead

Agents read entire files of 200 KB+ into context, re-read the prompt file,
and spent up to 28 shell calls per agent validating the JSON they had just
written. None of this is analysis. v2's scoped snippets and typed outputs
avoid it structurally; this is the main reason for the 30× to 50× time
difference. Do not reintroduce free-form tool use into the hot path; if a
reasoning-model escalation is added (see
[policy-coverage-evolution.md §4.2](policy-coverage-evolution.md)), give it a
bounded state, not a shell.

### A5. Reasoning is not auditable

The final chain of thought is hidden; only summaries survive, and tool results
are not stored. Findings therefore cannot be re-derived after the fact. v2's
`decision_trace` (every question, answer, confidence, threshold, drop reason)
is the property to protect as coverage grows: every new spec in §5 must write
its deterministic checks and model answers into the trace.

---

## 4. Generalisation work items, mapped to modules

| Id | Change | Module(s) | Layer | Model calls | Risk | Validation |
| --- | --- | --- | --- | --- | --- | --- |
| L1 | Identifier-boundary lexical pre-gate; localisation catalog exclusion; recorded drops | `structure.py`, `engine.py` | structure | fewer | recall if boundary rule is too strict → mitigated by label regression | selftest + dev-set recall 1.0 + call count |
| L2 | `destination_class` Choice replaces `is_third_party`; code composition table | `questions.py`, `evaluate.py`, `capabilities.py` | semantic → policy | same | label relabel effort | relabel 48 cases; ECE improves in UNCERTAIN band |
| L3 | One-hop first-party callee sink profile in state | `context.py`, `structure.py` | structure/semantic | same (larger state) | snippet size; cap and truncate | selftest hop fixtures; abstention < 0.50 |
| L4 | Guard-flag declaration + `consent_default_on`; `R.string` resolution; flavor manifests | `structure.py`, `android_manifest.py`, `questions.py`, `evaluate.py` | structure → policy | +1 Noul on in-band anchors only | flag resolution heuristics | selftests; App A default-on case carries the default in evidence |
| L5 | `AppProfile` + once-per-app cached `declared_core_purpose` | `android_manifest.py`, `context.py`, `questions.py` | structure/semantic | +1 per app | closed option list must cover matrices | synthetic manifests; dev apps classified |
| L6 | Structured evidence string | `evaluate.py` | output | none | none | golden selftest |
| L7 | `data_type_confirmed` Choice on in-band anchors | `questions.py`, `evaluate.py` | policy | +1 on in-band anchors only | none | confusion table in `calibrate.py` |

Order of implementation: **L5 → L1 → L6 → L3 → L2 → L4 → L7.** L5 is the
enabler for §5; L1 and L6 are risk-free and immediately measurable; L3 and L2
are the two changes expected to move calibration; L4 and L7 refine precision.

Each item ships with: docstring-level documentation of the rule, `INFO`
logging of what was added to state or dropped (and why), a selftest, and an
entry in `THRESHOLD_PROVENANCE` if it changes any threshold.

---

## 5. Coverage-expansion plan

### 5.1 Current coverage

| policy_id | v2 today | Gap |
| --- | --- | --- |
| `data_safety_section` | code_signal + play_declaration | L2/L4/L7 refinements |
| `prominent_disclosure_policy` | composed inside data-safety | `consent_default_on` (L4) |
| `location_access_policy` | code_signal (fine/approx) | background-location rows; disclosure wording; API-37 location-button suggestion |
| `contacts_access_policy` | code_signal | picker alternative on 37+ |
| `audio_recording_policy` | code_signal | continuous-capture Critical row |
| `account_deletion` | deterministic presence + gate | "server-side identity without delete endpoint" heuristic; partial-deletion trap |
| `foreground_services_policy` | manifest (Suggestion inventory; permission check) | **missing-type check cannot fire** (see §6); `specialUse` property; type/purpose alignment; notification integrity |
| `photo_video_access_policy` | — | whole policy |
| `all_files_access_policy` | — | whole policy |
| `files_and_docs_policy` | — | whole policy |
| `sms_call_log_policy` | — | whole policy |
| `package_visibility_policy` | — | whole policy |
| `accessibility_api_policy` | — | whole policy |
| `exact_alarm_policy` | — | whole policy |
| `target_api_level` | — (legacy Phase 1 handles it) | deterministic port |
| `login_credentials` | — | whole policy |

### 5.2 Design principles for every new spec

1. **Deterministic first.** Every manifest fact (permission present, attribute
   value, component present, SDK threshold) is decided in code from the
   `AppProfile`. No model call is made to read XML.
2. **One justification question, asked once.** Where the matrix conditions
   severity on "core purpose", read the cached `declared_core_purpose` (L5).
   Only where the matrix needs a code-level claim (e.g. "captures audio
   continuously in the background") is a per-file battery used.
3. **A declared restricted permission always yields a finding** (A1). Purpose
   moderates severity; it never suppresses.
4. **Alternatives are Suggestions, misuse is Important/Critical**, following
   the matrices verbatim; severity text and recommendations live in
   `templates.py` keyed by `policy_id`.
5. **No vendor, library or app names.** Signals are permission strings,
   platform API names, manifest elements and capability tags.
6. **Every check writes to `decision_trace`** and logs at `INFO` what it saw
   and decided (A5).
7. **Labels before enabling.** At least 3 positive / 3 negative / 2 boundary
   cases per policy, kept out of tree like `transfer_labels.json`; the two
   dev apps contribute real cases where they have the permission.

### 5.3 Per-policy specifications

Severities follow the corresponding row in `goal_permissions_and_apis.md` /
`goal_user_account.md`. "Profile" = `AppProfile` field (L5); "Purpose" = the
cached `declared_core_purpose` answer.

#### photo_video_access_policy — kind `manifest` + optional `code_signal`

- **Activation.** `READ_MEDIA_IMAGES` / `READ_MEDIA_VIDEO` / legacy
  `READ_EXTERNAL_STORAGE` present, or scanner `MEDIA`/`PHOTOS`/`VIDEOS`.
- **Deterministic.** `targetSdk ≥ 33` and legacy storage permission without
  `maxSdkVersion ≤ 32` → Important. Media permissions present and Purpose ∉
  {gallery, media editor, backup, file manager, social with broad media}
  → Important "one-off access should use the Photo Picker"; Purpose in the
  set → Suggestion (declaration reminder).
- **Model (code_signal, only if the permission is present).** Noul
  `accesses_full_media_library` on files that reference media-store
  collections, to separate "picks one file" from "enumerates the library".
- **Dev-app evidence.** App B: legacy storage permissions with the
  `maxSdkVersion` cap commented out → Important on this rule; legacy emitted
  only a Suggestion under `files_and_docs_policy`.

#### all_files_access_policy — kind `manifest`

- **Activation.** `MANAGE_EXTERNAL_STORAGE` present.
- **Deterministic.** Purpose ∈ {file manager, backup, antivirus, document
  management} → Suggestion (Play Console declaration reminder, exact matrix
  wording); otherwise → **Critical**. Also Important if the app declares both
  `MANAGE_EXTERNAL_STORAGE` and media permissions (redundant scope).
- **Model.** None beyond the cached Purpose.
- **Dev-app evidence.** App B declares it and is a file manager → Suggestion.
  Legacy emitted nothing (A1).

#### files_and_docs_policy — kind `manifest` + `code_signal`

- **Activation.** `READ/WRITE_EXTERNAL_STORAGE` present, scanner
  `FILES_AND_DOCS`, or file-system sinks writing under external storage.
- **Deterministic.** `WRITE_EXTERNAL_STORAGE` without `maxSdkVersion ≤ 29`
  and `targetSdk ≥ 30` → Important (permission is inert; misleads users);
  `requestLegacyExternalStorage` with `targetSdk ≥ 30` → Suggestion (ignored
  by platform).
- **Model (code_signal).** Noul `creates_root_level_external_folder` on files
  whose sink is a file write with a path composed from the external-storage
  root → Suggestion (use app-specific or SAF-scoped directories).
- **Dev-app evidence.** App B: legacy found both (root-level `temp` folder
  fallback; uncapped legacy permissions) → parity target.

#### sms_call_log_policy — kind `manifest` + `code_signal`

- **Activation.** Any of `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`,
  `READ_CALL_LOG`, `WRITE_CALL_LOG`, `PROCESS_OUTGOING_CALLS`; or a receiver
  filtering the incoming-SMS broadcast.
- **Deterministic.** Profile lacks a default-handler intent filter
  (SMS/dialer/assistant) → **Critical** unless Purpose is an allowed
  exception; receiver for incoming SMS with no default-handler role →
  Critical.
- **Model.** Noul `reads_one_time_code` on files touching SMS content →
  recommendation to use the platform OTP retriever (Suggestion text
  attached to the Critical/Important finding, not a separate finding).
- **Dev-app evidence.** Neither app; needs external fixtures (synthetic
  manifests + 2–3 open-source messaging/OTP apps for labels).

#### package_visibility_policy — kind `manifest`

- **Activation.** `QUERY_ALL_PACKAGES` present.
- **Deterministic.** Purpose ∈ {launcher, file manager, device search,
  antivirus/security, accessibility tool, app management, per-app network
  control} → Suggestion (declaration reminder); otherwise → **Important**
  "use `<queries>`"; if a `<queries>` element already exists alongside the
  permission → Important (redundant broad grant).
- **Model.** None.
- **Dev-app evidence.** Both apps declare it. App A → legacy Suggestion; App B
  → legacy emitted nothing (A1). v2 must emit for both.

#### accessibility_api_policy — kind `manifest` + `code_signal`

- **Activation.** `BIND_ACCESSIBILITY_SERVICE` service present; scanner
  `accessibility` signals.
- **Deterministic.** Accessibility service without the `isAccessibilityTool`
  flag in its config resource → Important (must be disclosed as non-tool
  use); no in-app disclosure symbol near the enable flow → composes with the
  existing `has_prominent_disclosure` question.
- **Model (code_signal).** Noul `siphons_screen_content_offdevice` on files
  that both handle accessibility events and reach a `NETWORK_EGRESS`
  capability → **Critical**.
- **Dev-app evidence.** Neither app; external fixtures needed.

#### exact_alarm_policy — kind `manifest`

- **Activation.** `USE_EXACT_ALARM` or `SCHEDULE_EXACT_ALARM` present
  (scanner already has an `exact_alarm` category).
- **Deterministic.** `USE_EXACT_ALARM` and Purpose ∉ {alarm/timer, calendar}
  → **Important** (use `SCHEDULE_EXACT_ALARM` and request at runtime);
  `SCHEDULE_EXACT_ALARM` → Suggestion (confirm runtime check and fallback
  to inexact).
- **Model.** None beyond Purpose.
- **Dev-app evidence.** Neither app; synthetic manifests.

#### foreground_services_policy — extend the existing `manifest` spec

- **Prerequisite.** v2 must parse services itself (§6): today
  `manifest_details.foreground_services` contains only services that
  *already* have a type, so the "no type when targeting 34+" branch in
  `_foreground_service_findings` is unreachable.
- **Deterministic additions.** `targetSdk ≥ 34`, service is started as
  foreground (a `startForeground` reference in a first-party file resolves
  to the class) and declares no type → **Critical**. `specialUse` declared
  without `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE">`
  → **Critical**. `FOREGROUND_SERVICE_SPECIAL_USE` permission with no
  `specialUse` service → Suggestion (App A). Type ∈ set but Purpose clearly
  outside the type's definition (e.g. `connectedDevice` on a VPN utility,
  App A) → Important "type misalignment".
- **Model (code_signal, bounded).** Noul `notification_is_dismissible_or_hidden`
  on the service file (notification integrity) → Important.
- **Dev-app evidence.** App A: two-type service including `connectedDevice`
  → Important alignment finding + Suggestion for the stray special-use
  permission; App B: `dataSync` on a file-transfer worker → Suggestion only.

#### account_deletion — extend the existing `deterministic` spec

- **New heuristic (from App A).** If any first-party file has a
  `NETWORK_EGRESS` sink whose request includes a *server-assigned identity*
  (an identifier written back from a response into persistent storage) and
  no first-party file has a network sink whose path or method name denotes
  deletion/unregistration, emit **Important** "server-side identity
  provisioned without a deletion path". Both halves are deterministic over
  capability tags plus a small closed set of deletion verbs matched at
  identifier boundaries (L1); one Noul `is_remote_delete` confirms a
  candidate deletion endpoint when found.
- **Partial-deletion trap.** When a deletion candidate exists, ask Noul
  `clears_local_state_only`; true → Important.
- **Dev-app evidence.** App A → Important (legacy agreed); App B → no
  finding (user-supplied server credentials stored locally; destination
  class `user_chosen_destination` from L2 makes this deterministic).

#### login_credentials — kind `code_signal`, Suggestion/Important only

- **Activation.** Scanner `USER_ACCOUNT` signals or `semantic_files.USER_ACCOUNT`.
- **Model.** Choice `login_gate_type` ∈ {app account login wall, user's own
  remote-server credentials, third-party sign-in bridge, none}. App account
  or bridge → **Important** (reviewer demo credentials + deletion link
  reminders); user's own remote server → no finding but record as evidence
  (App B); none → drop.
- **Deterministic pre-gate.** Presence of a layout or composable named like
  a login/sign-in screen in the semantic file inventory raises the prior;
  absence does not suppress (hidden-gatekeeper heuristic).
- **Dev-app evidence.** App B → no finding (legacy: Suggestion noting the
  distinction); App A → Suggestion/Important depending on whether the paid
  tier is judged a login gate — a good boundary label.

#### target_api_level — kind `deterministic`

- Port the legacy Phase 1 numeric rule unchanged: `targetSdk` below the
  current Play requirement → Critical; one behind → Important. The required
  level is a constant in `constants.py` with a provenance date, not a model
  question.

### 5.4 Rollout waves (risk × feasibility)

| Wave | Policies | Why this order |
| --- | --- | --- |
| 1 | `AppProfile` + manifest parser (§6); `foreground_services_policy` fixes; `package_visibility_policy`; `all_files_access_policy`; `exact_alarm_policy`; `target_api_level` | Pure deterministic + one cached Purpose question; both dev apps exercise FGS, package visibility and all-files; fixes an unreachable branch |
| 2 | `photo_video_access_policy`; `files_and_docs_policy` | Manifest attributes (`maxSdkVersion`, legacy-storage flags) + one small battery; App B provides real positives |
| 3 | `account_deletion` heuristics; `login_credentials` | Depend on L2 (`destination_class`) and L3 (one hop); App A/App B give one positive and one negative each |
| 4 | `sms_call_log_policy`; `accessibility_api_policy` | Highest severity, no dev-app coverage; need external fixture apps and labels first |
| 5 | `location_access_policy` background rows and wording; `audio_recording_policy` continuous-capture row; `contacts_access_policy` picker on 37+ | Refinements to existing specs once L4 (string resolution) lands |

Every wave ends with: selftest green, `run` on both dev apps with `--per-finding`
diffed against the previous wave, labels added, `calibrate.py` re-run if any
transfer threshold is touched, and the coverage table in
[policy-coverage-evolution.md §2](policy-coverage-evolution.md) updated.

### 5.5 Labels and calibration

- New label schema fields: `destination_class`, `confirmed_type`,
  `consent_default_on`, and per-policy `expected_severity`. Labels remain
  out of tree (`.scratch/labels/`), with a copy exported to
  `/opt/cursor/artifacts/` when reported.
- Wave 4 policies require **external fixture apps** (open-source messaging
  and accessibility tools); until they exist those specs ship behind a
  registry flag defaulting to enabled-with-`MANUAL_REVIEW` (findings are
  emitted and routed to review, never auto-verified).
- `calibrate.py` gains a per-policy report: findings emitted per policy per
  app, severity distribution, and — where labels exist — recall/precision by
  severity band. The transfer band remains the only *tuned* threshold; all
  manifest rules are exact.

### 5.6 Definition of done for a policy

1. `PolicySpec` in `registry.py` with docstring citing the matrix row(s).
2. Deterministic rules covered by selftest fixtures (positive, negative,
   boundary on `targetSdk`/`maxSdkVersion` where relevant).
3. Any model question is atomic, documented in `questions.py`, and its
   threshold is recorded in `THRESHOLD_PROVENANCE`.
4. Both dev apps run end to end; findings appear in
   `typesafe_triage.json` with a complete `decision_trace`.
5. Labels exist and recall on them is 1.0; precision at the emitted severity
   ≥ 0.90 or the finding routes to `MANUAL_REVIEW`.
6. `templates.py` has the summary and recommendation text; the coverage table
   is updated; a paragraph is added to `capability-based-evaluation.md §5`.

---

## 6. Shared infrastructure the plan depends on

### 6.1 `android_manifest.py` (new, structure layer)

The evaluator must own its manifest facts rather than depend on
`orchestrator.extract_manifest_details()`, which (a) records only services that
already declare a `foregroundServiceType`, (b) drops per-permission attributes
such as `maxSdkVersion`, (c) reads a single manifest rather than the
flavor/build-type set, and (d) is shared code that this project treats as
read-only alongside `generate_report.py`.

The module parses every `AndroidManifest.xml` under the app (excluding
`IGNORED_DIR_NAMES` and test source sets), merges them with source
attribution, and exposes an `AppProfile` dataclass:

```
AppProfile
  package_name, target_sdk, min_sdk
  permissions: [{name, max_sdk, flags, source_manifest}]
  application: {request_legacy_external_storage, preserve_legacy_external_storage}
  activities: [{name, exported, intent_filters: [{actions, categories, mime_types}], source}]
  services:   [{name, exported, fgs_types, properties: {name: value}, permission, source}]
  receivers:  [{name, exported, intent_filters, source}]
  providers:  [{name, exported, authorities, source}]
  accessibility_services: [{name, config_resource, is_accessibility_tool}]
  queries: {packages: [...], intents: [...]}
  meta_data: {name: value, source}
```

Attribute values that are resource references (`@string/...`,
`@integer/...`) are resolved against default `values/` resources where
possible, reusing the string-resolution helper from L4. The module logs at
`INFO` how many manifests were merged and at `WARNING` any parse failure
(never silently degrading, unlike the BOM failure mode documented in the
orchestrator).

### 6.2 String resource resolution (L4)

A small index over `res/values/strings.xml` (default locale only) keyed by
name, built once per app and cached alongside the capability cache. Used for
disclosure text, app label, and resource-referenced manifest attributes.

### 6.3 First-party callee resolution (L3)

Reuses the package index already built for triage. Adds a per-app map
`simple_name → relpath` for first-party classes, with collisions resolved by
import statements in the calling file.

### 6.4 Cached per-app answers (L5)

A `per_app` section in the capability cache for questions asked once per
app (`declared_core_purpose`), keyed by a hash of the rendered `AppProfile`
so the cache invalidates when the manifest changes.

---

## 7. Risks and open questions

- **Closed option lists** (`destination_class`, `declared_core_purpose`,
  `login_gate_type`) must cover every case the matrices distinguish; a
  missing option pushes the model to `unknown` and the finding to
  `MANUAL_REVIEW`, which is the safe direction but raises abstention.
- **Flavor manifest merging** can double-count permissions declared in
  several flavours; findings should be keyed by permission name and carry the
  set of sources rather than one finding per source.
- **External fixture apps** for wave 4 do not exist yet; those policies
  cannot be claimed as validated until they do (they *can* be shipped in
  review-only mode).
- **Purpose inference bias.** Reading purpose from the manifest can be gamed
  by a developer who declares a launcher-style intent filter. The Purpose
  answer only moderates severity between Suggestion and Important/Critical;
  it never suppresses a finding (A1), so the failure mode is a lower severity,
  not a missed finding.
- **Label debt.** L2 and L7 require relabelling the 48-case dev set. The
  work is small but must happen before the calibration numbers in
  `THRESHOLD_PROVENANCE` are updated.
