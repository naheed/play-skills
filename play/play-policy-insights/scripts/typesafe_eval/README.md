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
python -m typesafe_eval.eval.run_eval [--client heuristic|http]   # labeled agreement
```

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
transmission; those cases are where the real Jev path is expected to add value.
See the design doc for the rollout plan.
