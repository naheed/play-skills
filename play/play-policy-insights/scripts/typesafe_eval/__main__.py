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

"""Command-line entry point for the hybrid TypeSafe evaluator.

Usage:
  python -m typesafe_eval run <temp_dir> [--client heuristic|http] [--model ID]
  python -m typesafe_eval critic <temp_dir> [--client heuristic|http]
  python -m typesafe_eval selftest

``<temp_dir>`` is the scratch directory produced by ``orchestrator.py init``.
The default client is ``heuristic`` (offline, deterministic, development-only);
pass ``--client http`` to call the real Jev API (needs TYPESAFE_API_KEY and
network egress, and sends app source snippets to the API).
"""

from __future__ import annotations

import argparse
import sys

from typesafe_eval import constants
from typesafe_eval import evaluate
from typesafe_eval.client import HeuristicJevClient
from typesafe_eval.client import HttpJevClient
from typesafe_eval.client import JevClient


def _make_client(name: str, model: str) -> JevClient:
  if name == "http":
    return HttpJevClient(model=model)
  if name == "heuristic":
    print(
        "WARNING: using the offline HEURISTIC client. Its findings approximate "
        "Jev from static signals and are NOT real policy judgments.",
        file=sys.stderr,
    )
    return HeuristicJevClient()
  raise SystemExit(f"Unknown client: {name!r} (use 'heuristic' or 'http')")


def main(argv=None) -> int:
  parser = argparse.ArgumentParser(prog="typesafe_eval")
  sub = parser.add_subparsers(dest="command", required=True)

  run_p = sub.add_parser("run", help="Evaluate goals into worker_<goal>.json.")
  run_p.add_argument("temp_dir")
  run_p.add_argument("--client", default="heuristic", choices=["heuristic", "http"])
  run_p.add_argument("--model", default=constants.DEFAULT_MODEL)
  run_p.add_argument("--goals", nargs="*", default=None)

  crit_p = sub.add_parser("critic", help="Verify findings into critic_output_<i>.json.")
  crit_p.add_argument("temp_dir")
  crit_p.add_argument("--client", default="heuristic", choices=["heuristic", "http"])
  crit_p.add_argument("--model", default=constants.DEFAULT_MODEL)

  sub.add_parser("selftest", help="Run offline unit checks.")

  args = parser.parse_args(argv)

  if args.command == "selftest":
    from typesafe_eval import selftest
    return selftest.main()

  client = _make_client(args.client, args.model)

  if args.command == "run":
    written = evaluate.run(
        args.temp_dir, client, model=args.model, goals=args.goals
    )
    print(f"Wrote worker files for goals: {', '.join(written) or '(none)'}")
    return 0

  if args.command == "critic":
    written = evaluate.run_critic(args.temp_dir, client, model=args.model)
    print(f"Wrote critic outputs for chunks: {', '.join(written) or '(none)'}")
    return 0

  return 1


if __name__ == "__main__":
  raise SystemExit(main())
