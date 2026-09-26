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
python -m typesafe_eval run <temp_dir> [--client heuristic|http] [--model ID] [--goals ...]
python -m typesafe_eval critic <temp_dir> [--client heuristic|http]
python -m typesafe_eval selftest                 # offline unit checks
python -m typesafe_eval smoketest                # live smoke test (SKIPs without a key)
python -m typesafe_eval.eval.run_eval [--client heuristic|http] [--sweep]  # recall/precision + threshold sweep
```

See [`../../docs/evaluation-charter.md`](../../docs/evaluation-charter.md) for the
quality dimensions and bars, and
[`../../docs/policy-coverage-evolution.md`](../../docs/policy-coverage-evolution.md)
for the plan to reach parity across all policies and select models.

## Files

| File | Purpose |
| --- | --- |
| `constants.py` | All tunable thresholds + model id in one place. |
| `questions.py` | The typed question batteries (Choice/Score/Noul). |
| `client.py` | `HttpJevClient` (real API) and `HeuristicJevClient` (offline). |
| `snippets.py` | Deterministic code-snippet + co-located-signal extraction. |
| `templates.py` | Deterministic `issue_summary` / `recommendation`. |
| `evaluate.py` | Reads goal inputs, calls a client, writes `worker_*.json`. |
| `eval/` | Labeled cases + `run_eval.py` agreement harness. |
| `selftest.py` | Offline unit checks. |

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
