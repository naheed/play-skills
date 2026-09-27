# typesafe_eval — hybrid TypeSafe (Jev) evaluator (prototype)

Prototype of the hybrid architecture in
[`../../docs/typesafe-hybrid-architecture.md`](../../docs/typesafe-hybrid-architecture.md).
It replaces the agent-driven **Phase 2** of `play-policy-insights` (an LLM emits
`worker_*.json` findings and a critic verdict) with deterministic Python that
asks TypeSafe's Jev model a fixed battery of typed questions and composes the
answers in code. Phase 1 (`orchestrator.py init`) and finalization
(`generate_report.py`) are unchanged.

Standard library only. The real Jev client uses `urllib`; an offline heuristic
client lets the whole pipeline run without a key or network.

## Where it plugs in

```
orchestrator.py init <app_dir>          # unchanged: writes input_worker_<goal>.json
python -m typesafe_eval run  <temp_dir> # NEW: writes worker_<goal>.json (replaces the agent)
orchestrator.py aggregate <temp_dir>    # unchanged: writes input_critic_<i>.json
python -m typesafe_eval critic <temp_dir># NEW (optional): writes critic_output_<i>.json
generate_report.py <temp_dir>           # unchanged: writes compliance_report.md/.json
```

Run the commands from the `scripts/` directory (or put it on `PYTHONPATH`).

## Clients

- `--client heuristic` (default): offline, deterministic **development stand-in**.
  It approximates Jev from the static scanner signals and is **not** a source of
  real policy judgment. Findings it produces are tagged `client="heuristic"`.
- `--client http`: the real Jev HTTP API. Requires `TYPESAFE_API_KEY` and network
  egress, and sends app source snippets to the API. Pin `--model jev-1.13.0`.

## Commands

```bash
python -m typesafe_eval run <temp_dir> [--client heuristic|http] [--model ID] [--goals ...] \
    [--cache PATH] [--capability-cache PATH | --no-capability-cache] [--per-finding] [-v]
python -m typesafe_eval critic <temp_dir> [--client heuristic|http] [--cache PATH] [-v]
python -m typesafe_eval calibrate <labels.json> [--out report.json] [--min-precision 0.90]
python -m typesafe_eval benchmark <temp_dir> [--client http]   # per-finding vs batched: requests/tokens/latency/agreement
python -m typesafe_eval selftest                 # offline unit checks
python -m typesafe_eval smoketest                # live smoke test (SKIPs without a key)
python -m typesafe_eval.eval.run_eval [--client heuristic|http] [--sweep]  # recall/precision + threshold sweep
```

Batching by source file is the default: one request per file chunk of up to
`MAX_ASKS_PER_REQUEST` data types (fanning out every policy question about that
file) instead of one per finding — Jev has no cross-request cache, so batching
questions that share a file's code is the way to avoid re-sending it.
`--per-finding` restores one request per (policy, finding); `--batch` is
accepted for backwards compatibility and is a no-op. See
[`../../docs/request-batching-optimization.md`](../../docs/request-batching-optimization.md).

`--cache` memoizes Jev answers by (model, questions, state). `--capability-cache`
is the persistent, human-reviewable JSON of identifier -> capability labels
(default `$PPI_CAPABILITY_CACHE` or `~/.cache/play_policy_insights/capabilities.json`);
human-authored entries always win over model entries. `-v` enables DEBUG logging
on the `typesafe_eval.*` loggers (per-request question ids, cache decisions,
relevance-gate drops).

`calibrate` reads a label set kept **outside the repository** (it names real
files of real apps) and derives `T_TRANSMIT_LOW`/`T_TRANSMIT_HIGH`, Brier/ECE and
a provenance block for `constants.THRESHOLD_PROVENANCE`; see
[`../../docs/capability-based-evaluation.md`](../../docs/capability-based-evaluation.md) §4
for the label format and method.

See [`../../docs/evaluation-charter.md`](../../docs/evaluation-charter.md) for the
quality dimensions and bars, and
[`../../docs/policy-coverage-evolution.md`](../../docs/policy-coverage-evolution.md)
for the plan to reach parity across all policies and select models.

## Files

| File | Purpose |
| --- | --- |
| `registry.py` | **Single source of truth**: one `PolicySpec` per policy (id, kind, activation, battery, compose, `compose_manifest`). Add a policy here. |
| `engine.py` | Cascade evaluator: reads raw scan artifacts, filters candidates, analyses file structure, classifies identifiers, triages by capability tier, batches by file, isolates failures, writes `worker_*.json` + `typesafe_triage.json`. |
| `structure.py` | Deterministic structure layer: language, imports, declared package, scopes, symbol references (comments/imports demoted), dependency inventory, first-party detection helpers. |
| `capabilities.py` | Behavioural capability taxonomy (`NETWORK_EGRESS`, `THIRD_PARTY_TELEMETRY`, `ADVERTISING_SDK`, `IPC_SHARING`, `LOCAL_PERSISTENCE`, `LOGGING`, `USER_DISCLOSURE_UI`, `UNKNOWN`), model-driven classification, `CapabilityCache`. No vendor names. |
| `context.py` | Sinks (transfer-capable identifiers referenced in a file) and anchors (the occurrence of a hit nearest a sink, with tier and scope capabilities); builds the per-file state. |
| `constants.py` | All tunable thresholds + sensitivity/risk tables + model id + `THRESHOLD_PROVENANCE` + `EVALUATOR_VERSION`. |
| `questions.py` | The typed question batteries (Choice/Score/Noul); the relevance question embeds the literal matched token. |
| `client.py` | `HttpJevClient` (real API) + `HeuristicJevClient` (offline, labelled stand-in). |
| `cache.py` | `ResultCache` + `CachingClient`: memoize by (model, questions, state). |
| `snippets.py` | Legacy deterministic code-snippet + co-located data-flow extraction (v1 path). |
| `templates.py` | Deterministic `issue_summary` / `recommendation`. |
| `evaluate.py` | Compose functions: relevance gate, three-way transfer decision, code-derived severity, decision trace, critic on the atomic transfer claim. |
| `calibrate.py` | Derives the transfer band and reliability metrics from an out-of-tree label set. |
| `batch.py` | File-state builder + namespacing used by the engine's batched path. |
| `benchmark.py` | Per-finding vs batched: requests / tokens / latency / agreement. |
| `eval/` | Labeled cases + `run_eval.py` precision/recall harness. |
| `livetest.py` / `selftest.py` | Live smoke test / offline unit checks (including the vendor-name lint). |

The evaluator reads the **raw** artifacts `orchestrator.py init` writes
(`data_safety_scan.json`, `manifest_details.json`, `play_store_info.json`) and
activates policies from the registry — it no longer depends on the agent's
`input_worker_*.json` prompt files. Add `--cache <path>` to `run`/`critic` to
memoize calls (a warm re-run makes zero API calls).

Evaluation kinds: `code_signal` (per-file battery), `deterministic` (code, with
an optional model "evidence gate" that filters generic-pattern false positives),
`play_declaration` (detected off-device collection vs the developer's Play Data
Safety declaration — semantic coverage; runs only for TRANSMITS findings), and
`manifest` (deterministic checks on `AndroidManifest.xml`, currently
foreground-service types). Activation prioritizes the Play build flavor, skips
`res/values*` string catalogs and `src/test*` source sets, caps candidates and
findings per data type, and ranks candidates by capability tier (explicit egress
in scope > IPC in scope > unknown sink > none) then sink proximity.

### Transfer decision and observability (v2)

`transmits_offdevice` is composed into a three-way decision rather than a single
cliff: `LOCAL` (p < `T_TRANSMIT_LOW`), `UNCERTAIN` (in the band; reported as
transferred, severity at least IMPORTANT, `needs_manual_review`, never pruned,
title suffixed `[transfer uncertain: p=..; verify]`), `TRANSMITS`
(p >= `T_TRANSMIT_HIGH`). IPC hand-offs to other apps count as sharing. Every
finding carries a `decision_trace` (scores, thresholds, anchor with
`scope_capabilities` and `rank_tier`, sinks, model, taxonomy and evaluator
version), and every run writes `typesafe_triage.json` with counters, decision and
severity histograms, capability summaries, cache statistics, token usage and the
full list of dropped candidates with reasons. Details in
[`../../docs/capability-based-evaluation.md`](../../docs/capability-based-evaluation.md).

## Status

Phase A prototype: data-safety disclosure, location, contacts, and audio
domains. The heuristic client cannot judge permission-*justification* severity
(e.g. broad contacts/mic access for a non-core feature) because it keys off data
transmission; those cases are where the real Jev path adds value.

### Validated against live Jev (`jev-1.13.0`)

The `http` client has been run end-to-end against the real API on synthetic
sample code. On the 13-case labeled set the current build reaches **recall 1.00,
precision 1.00**, per-field agreement 0.97, ~149 ms/case. Getting there drove
three design changes (architecture doc §9.1): including co-located data-flow
lines in the state, composing severity in code from Jev's atomic booleans
(rather than asking a broad Score), and tuning `T_TRANSMIT` from a live
threshold sweep. The earlier offline-heuristic "0.94" was circular (the
heuristic is derived from the same signals); the live numbers are the real
signal. Growth to full policy parity is planned in the coverage-evolution doc.

### Validated on real applications (v2, `2.0.0-capability`)

The v2 cascade was run end-to-end with live `jev-1.13.0` on two open-source
Android applications and compared against the legacy agent skill on the same
trees. v2 recovers every Critical the legacy skill found and v1 had missed
(purchase token, device id and crash-log uploads, now TRANSMITS findings plus
Data Safety discrepancies) and surfaces a credential sent over a raw socket
(p=0.90) that v1 had dropped in triage. Against 48 hand-adjudicated transfer
labels (23 true transfers) the shipped band has **zero false negatives**;
TRANSMITS alone has precision 0.944. The label set lives outside the repository;
the method and numbers are in the capability-based-evaluation doc §4-5 and in
`constants.THRESHOLD_PROVENANCE`.
