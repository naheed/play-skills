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
                                        [--per-finding] [--cache PATH]
                                        [--capability-cache PATH | --no-capability-cache]
                                        [--verbose]
  python -m typesafe_eval critic <temp_dir> [--client heuristic|http]
  python -m typesafe_eval calibrate <labels.json> [--out PATH]
  python -m typesafe_eval selftest

``<temp_dir>`` is the scratch directory produced by ``orchestrator.py init``.
The default client is ``heuristic`` (offline, deterministic, development-only);
pass ``--client http`` to call the real Jev API (needs TYPESAFE_API_KEY and
network egress, and sends app source snippets to the API).

``run`` is batched by file by default (one request per source file chunk);
``--per-finding`` sends one request per (policy, finding) instead. Capability
classifications are memoized in a persistent cache (``--capability-cache``,
default ``$PPI_CAPABILITY_CACHE`` or ``~/.cache/play_policy_insights/
capabilities.json``); ``--no-capability-cache`` classifies from scratch.
"""

from __future__ import annotations

import argparse
import logging
import sys

from typesafe_eval import constants
from typesafe_eval import evaluate
from typesafe_eval.client import HeuristicJevClient
from typesafe_eval.client import HttpJevClient
from typesafe_eval.client import JevClient


def _configure_logging(verbose: bool) -> None:
  """INFO to stderr by default (stage counters); DEBUG with ``--verbose``."""
  logging.basicConfig(
      level=logging.DEBUG if verbose else logging.INFO,
      stream=sys.stderr,
      format="%(asctime)s %(levelname)s %(name)s: %(message)s",
  )


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
  run_p.add_argument("--goals", nargs="*", default=None,
                     help="Deprecated: the engine activates goals from the registry.")
  run_p.add_argument(
      "--batch", action="store_true",
      help="Deprecated (now the default): one request per source-file chunk.",
  )
  run_p.add_argument(
      "--per-finding", action="store_true",
      help="One request per (policy, finding) instead of batching by file.",
  )
  run_p.add_argument("--cache", default=None, help="Path to a JSON result cache.")
  run_p.add_argument(
      "--capability-cache", default=None,
      help="Path to the persistent capability-profile cache (JSON). Default: "
           f"${constants.CAPABILITY_CACHE_ENV} or ~/.cache/play_policy_insights/capabilities.json.",
  )
  run_p.add_argument(
      "--no-capability-cache", action="store_true",
      help="Do not read or write the capability cache (classify everything).",
  )
  run_p.add_argument("--verbose", "-v", action="store_true", help="DEBUG logging.")

  bench_p = sub.add_parser("benchmark", help="Compare per-finding vs batched.")
  bench_p.add_argument("temp_dir")
  bench_p.add_argument("--client", default="http", choices=["heuristic", "http"])
  bench_p.add_argument("--model", default=constants.DEFAULT_MODEL)

  crit_p = sub.add_parser("critic", help="Verify findings into critic_output_<i>.json.")
  crit_p.add_argument("temp_dir")
  crit_p.add_argument("--client", default="heuristic", choices=["heuristic", "http"])
  crit_p.add_argument("--model", default=constants.DEFAULT_MODEL)
  crit_p.add_argument("--cache", default=None, help="Path to a JSON result cache.")
  crit_p.add_argument("--verbose", "-v", action="store_true", help="DEBUG logging.")

  cal_p = sub.add_parser(
      "calibrate", help="Derive transfer thresholds + reliability from a labelled set."
  )
  cal_p.add_argument("labels", help="JSON file of labelled findings (see calibrate.py).")
  cal_p.add_argument("--out", default=None, help="Write the calibration report JSON here.")
  cal_p.add_argument("--min-precision", type=float, default=0.90)

  sub.add_parser("selftest", help="Run offline unit checks.")

  smoke_p = sub.add_parser(
      "smoketest", help="Live smoke test against the real API (skips without a key)."
  )
  smoke_p.add_argument("--model", default=constants.DEFAULT_MODEL)

  args = parser.parse_args(argv)
  _configure_logging(bool(getattr(args, "verbose", False)))

  if args.command == "selftest":
    from typesafe_eval import selftest
    return selftest.main()

  if args.command == "smoketest":
    from typesafe_eval import livetest
    return livetest.main(model=args.model)

  if args.command == "benchmark":
    from typesafe_eval import benchmark
    return benchmark.main([args.temp_dir, "--client", args.client, "--model", args.model])

  if args.command == "calibrate":
    from typesafe_eval import calibrate
    return calibrate.main(args.labels, out_path=args.out, min_precision=args.min_precision)

  client = _make_client(args.client, args.model)

  if getattr(args, "cache", None):
    from typesafe_eval.cache import CachingClient
    from typesafe_eval.cache import ResultCache
    client = CachingClient(client, ResultCache(args.cache))

  if args.command == "run":
    from typesafe_eval import capabilities
    from typesafe_eval import engine
    cap_cache = None
    if not args.no_capability_cache:
      cap_cache = capabilities.CapabilityCache(
          args.capability_cache or capabilities.default_cache_path()
      )
    written = engine.run(
        args.temp_dir, client, model=args.model,
        batched=not args.per_finding, capability_cache=cap_cache,
    )
    print(f"Wrote worker files for goals: {', '.join(written) or '(none)'}")
    print(f"Triage record: {engine.TRIAGE_FILENAME} in {args.temp_dir}")
    return 0

  if args.command == "critic":
    written = evaluate.run_critic(args.temp_dir, client, model=args.model)
    print(f"Wrote critic outputs for chunks: {', '.join(written) or '(none)'}")
    return 0

  return 1


if __name__ == "__main__":
  raise SystemExit(main())
