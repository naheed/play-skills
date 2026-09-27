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
  lines and comment lines (a mention in a comment is not a data flow).
- `all_occurrences(lines, pattern)` returns scanner-pattern hits with comment and import
  lines demoted to the end, so an anchor prefers executable code.
- `enclosing_scope(lines, index)` finds the method or block containing a line using an
  indentation/brace depth profile, so the snippet shown to the model is the whole function
  that performs the operation rather than a fixed window.
- `dependency_inventory(app_dir)` reads Gradle, `pubspec.yaml`, `package.json` and similar
  manifests so build-declared dependencies can be classified even when no import is seen.
- `package_of(module)` and `declared_package(content)` support first-party detection: an
  import whose package equals the manifest package or any package declared by an analysed
  source file is the app's own code and is not sent for classification.

Wildcard imports (`import foo.bar.*`) are preserved so the package can still be classified.

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

**Batteries.** Kept candidates are grouped per file and sent in chunks of
`MAX_ASKS_PER_REQUEST = 6` data types per request (question ids are namespaced
`a<i>__<qid>`). The file state contains the anchored scope, the capability-labelled sink
lines (`MAX_SINK_LINES_IN_STATE`), the app facts and declared capabilities. Each ask contains:

| Question | Type | Used for |
| --- | --- | --- |
| `signal_relevant` — does this snippet handle *this* data type (the literal matched token is embedded in the question) | `Noul` | relevance gate at `T_RELEVANCE = 0.30`; drops scanner false positives such as a MIME table matching "record" |
| `transmits_offdevice` — is the value sent off-device *or handed to another app* | `Noul` | three-way transfer decision |
| `is_third_party`, `has_prominent_disclosure`, `is_core_functionality`, `user_initiated` | `Noul` | severity composition in code |

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

**Manifest checks** (`_run_manifest`) are deterministic: foreground-service types declared in
the manifest yield a Suggestion to confirm the Play Console declaration, bypassing the critic.

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

**Decision trace.** Each finding's `decision_trace` records `scores` (every probability),
`thresholds` (the values in force), `anchor` (file, line, scope, `scope_capabilities`,
`rank_tier`, proximity), `sinks`, `model`, `taxonomy_version` and `evaluator_version`.

### 3.4 Triage file (`typesafe_triage.json`)

Written next to the worker files on every run. Keys: `evaluator_version`, `model`,
`counters` (raw signals, candidates, kept, files analysed, imports first-party skipped,
third-party, packages, refined, dependencies, capability-cache hits/misses), `usage`
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
