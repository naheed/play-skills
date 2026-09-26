# Copyright 2026 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Benchmark per-finding vs file-batched evaluation.

Runs both strategies over the same scratch directory and reports requests, input
tokens, latency, and — crucially — whether the two strategies produce the same
findings, so the cost/speed win of batching can be weighed against any accuracy
change from sending a whole file's state instead of a tight per-finding snippet.

    python -m typesafe_eval benchmark <temp_dir> [--client heuristic|http] [--model ID]
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import time
from typing import Dict

from typesafe_eval import batch
from typesafe_eval import constants
from typesafe_eval import evaluate
from typesafe_eval.client import HeuristicJevClient
from typesafe_eval.client import HttpJevClient


def _load_findings(temp_dir: str) -> Dict[str, str]:
  """Maps a finding key -> severity across all worker files."""
  out: Dict[str, str] = {}
  for path in sorted(glob.glob(os.path.join(temp_dir, "worker_*.json"))):
    goal = os.path.basename(path)[len("worker_"):-len(".json")]
    data = json.load(open(path, encoding="utf-8"))
    for finding in data.get("findings", []):
      key = "|".join([
          goal,
          str(finding.get("policy_id")),
          str(finding.get("psl_constant", "")),
          str((finding.get("files_involved") or [""])[0]),
      ])
      out[key] = finding.get("severity", "")
  return out


def _make_client(name: str, model: str):
  if name == "http":
    return HttpJevClient(model=model)
  return HeuristicJevClient()


def _run(strategy, temp_dir, client, model):
  client.reset_usage()
  start = time.time()
  if strategy == "batched":
    batch.run_batched(temp_dir, client, model=model)
  else:
    evaluate.run(temp_dir, client, model=model)
  elapsed = time.time() - start
  findings = _load_findings(temp_dir)
  return {
      "requests": client.request_count,
      "input_tokens": client.total_input_tokens,
      "latency_s": elapsed,
      "findings": findings,
  }


def main(argv=None) -> int:
  parser = argparse.ArgumentParser(prog="benchmark")
  parser.add_argument("temp_dir")
  parser.add_argument("--client", default="http", choices=["heuristic", "http"])
  parser.add_argument("--model", default=constants.DEFAULT_MODEL)
  args = parser.parse_args(argv)

  pf = _run("per_finding", args.temp_dir, _make_client(args.client, args.model), args.model)
  bt = _run("batched", args.temp_dir, _make_client(args.client, args.model), args.model)

  price = 0.042 / 1e6  # $ per input token (jev-1.13 Models page)
  print(f"client={args.client} model={args.model}\n")
  header = f"{'strategy':<14}{'requests':>10}{'in_tokens':>12}{'latency_s':>12}{'cost_usd':>12}"
  print(header)
  for name, r in (("per_finding", pf), ("batched", bt)):
    print(f"{name:<14}{r['requests']:>10}{r['input_tokens']:>12}"
          f"{r['latency_s']:>12.2f}{r['input_tokens'] * price:>12.6f}")

  def ratio(a, b):
    return (a / b) if b else float("inf")

  print(f"\nbatching wins: {ratio(pf['requests'], bt['requests']):.1f}x fewer requests, "
        f"{ratio(pf['input_tokens'], bt['input_tokens']):.1f}x fewer input tokens, "
        f"{ratio(pf['latency_s'], bt['latency_s']):.1f}x faster")

  # Accuracy: do the two strategies agree on findings?
  keys = set(pf["findings"]) | set(bt["findings"])
  same = sum(1 for k in keys if pf["findings"].get(k) == bt["findings"].get(k))
  print(f"\nfinding agreement (per_finding vs batched): {same}/{len(keys)} "
        f"= {same / len(keys) if keys else 1.0:.2f}")
  for k in sorted(keys):
    if pf["findings"].get(k) != bt["findings"].get(k):
      print(f"  DIFF {k}: per_finding={pf['findings'].get(k)} batched={bt['findings'].get(k)}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
