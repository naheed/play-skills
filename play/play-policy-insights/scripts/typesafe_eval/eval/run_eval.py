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

"""Measure a JevClient's agreement with hand-labeled policy decisions.

    python -m typesafe_eval.eval.run_eval [--client heuristic|http] [--model ID]

For each labeled case, this builds the appropriate question battery, sends the
case's state to the chosen client, converts the answers into decisions using the
same thresholds ``evaluate.py`` uses, and compares them to the expected labels.
It reports per-field agreement and an overall score against
``constants.EVAL_MIN_AGREEMENT``.

Run it against ``--client http`` (real Jev, needs TYPESAFE_API_KEY) to judge
model quality and calibration. Against the default heuristic client it mostly
validates the harness itself, since the heuristic is derived from the same
signals as the labels.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from typesafe_eval import constants
from typesafe_eval import questions as q
from typesafe_eval.client import HeuristicJevClient
from typesafe_eval.client import HttpJevClient


def _cases_path() -> str:
  return os.path.join(os.path.dirname(os.path.abspath(__file__)), "labeled_cases.json")


def _decision_for(field: str, answers) -> object:
  """Turns a raw answer into the same decision ``evaluate.py`` would make."""
  answer = answers.get(field)
  if answer is None:
    return None
  if answer.type == "noul":
    threshold = {
        "transmits_offdevice": constants.T_TRANSMIT,
        "has_prominent_disclosure": constants.T_DISCLOSURE,
        "is_core_functionality": constants.T_CORE_FUNCTION,
        "user_initiated": constants.T_USER_INITIATED,
        "is_third_party": constants.T_THIRD_PARTY,
    }.get(field, 0.5)
    return (answer.noul or 0.0) >= threshold
  if answer.type == "choice":
    return answer.choice
  if answer.type == "score":
    return constants.severity_name(answer.score or 0.0)
  return None


def _battery_for(case):
  if case["battery"] == "permission":
    return q.permission_battery(case.get("policy_id", ""), case["data_type"])
  return q.data_safety_battery(case["data_type"], case.get("description", ""))


def _make_client(name: str, model: str):
  if name == "http":
    return HttpJevClient(model=model)
  return HeuristicJevClient()


def main(argv=None) -> int:
  parser = argparse.ArgumentParser(prog="run_eval")
  parser.add_argument("--client", default="heuristic", choices=["heuristic", "http"])
  parser.add_argument("--model", default=constants.DEFAULT_MODEL)
  args = parser.parse_args(argv)

  client = _make_client(args.client, args.model)
  with open(_cases_path(), "r", encoding="utf-8") as f:
    cases = json.load(f)["cases"]

  total = 0
  correct = 0
  print(f"client={client.name} model={args.model}\n")
  for case in cases:
    answers = client.system_one(case["state"], _battery_for(case), model=args.model)
    line = [f"{case['name']:<32}"]
    for field, expected in case["expected"].items():
      got = _decision_for(field, answers)
      ok = got == expected
      total += 1
      correct += int(ok)
      mark = "ok" if ok else "XX"
      line.append(f"{field}={got}[{mark}]")
    print("  " + "  ".join(line))

  agreement = correct / total if total else 0.0
  print(f"\nagreement: {correct}/{total} = {agreement:.2f} "
        f"(bar {constants.EVAL_MIN_AGREEMENT:.2f})")
  if agreement < constants.EVAL_MIN_AGREEMENT:
    print("BELOW BAR", file=sys.stderr)
    return 1
  print("meets bar")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
