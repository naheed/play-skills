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

"""Measure a JevClient against hand-labeled policy decisions.

    python -m typesafe_eval.eval.run_eval [--client heuristic|http] [--model ID] [--sweep]

Reports three things, tied to the goals in the evaluation charter
(``docs/evaluation-charter.md``): high recall, high precision, calibrated speed.

1. Per-field agreement with expected atomic decisions.
2. Precision / recall / F1 for the headline ``is_risk`` decision (does the tool
   surface a finding at IMPORTANT or CRITICAL?), against the recall/precision
   bars in ``constants.py``.
3. With ``--sweep``, a threshold sweep for ``transmits_offdevice`` so
   ``T_TRANSMIT`` can be chosen empirically from live data.

Run against ``--client http`` (real Jev, needs TYPESAFE_API_KEY) to judge model
quality. The heuristic client mostly validates the harness itself.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from typesafe_eval import constants
from typesafe_eval import evaluate
from typesafe_eval import questions as q
from typesafe_eval.client import HeuristicJevClient
from typesafe_eval.client import HttpJevClient

_RISK_LEVELS = {"IMPORTANT", "CRITICAL"}


def _cases_path() -> str:
  return os.path.join(os.path.dirname(os.path.abspath(__file__)), "labeled_cases.json")


def _battery_for(case):
  if case["battery"] == "permission":
    return q.permission_battery(case.get("policy_id", ""), case["data_type"])
  return q.data_safety_battery(case["data_type"], case.get("description", ""))


def _noul(answers, field, threshold):
  a = answers.get(field)
  return (a.noul or 0.0) >= threshold if a else False


def _predict(case, answers):
  """Predicted atomic decisions + composed is_risk, mirroring evaluate.py."""
  transmits = _noul(answers, "transmits_offdevice", constants.T_TRANSMIT)
  has_disc = _noul(answers, "has_prominent_disclosure", constants.T_DISCLOSURE)
  pred = {
      "transmits_offdevice": transmits,
      "has_prominent_disclosure": has_disc,
      "is_third_party": _noul(answers, "is_third_party", constants.T_THIRD_PARTY),
  }
  if case["battery"] == "permission":
    is_core = _noul(answers, "is_core_functionality", constants.T_CORE_FUNCTION)
    pred["is_core_functionality"] = is_core
    sev = evaluate.derive_permission_severity(
        case.get("policy_id", ""), is_core, has_disc, transmits
    )
  else:
    status = answers["disclosure_status"].choice if "disclosure_status" in answers else "MISSING"
    if not transmits:
      status = "EXEMPT"  # local-only data is exempt from disclosure (composed in code)
    pred["disclosure_status"] = status
    sev = evaluate.derive_data_safety_severity(case["data_type"], transmits, status)
  pred["is_risk"] = sev in _RISK_LEVELS
  return pred


def _make_client(name: str, model: str):
  if name == "http":
    return HttpJevClient(model=model)
  return HeuristicJevClient()


def _prf(tp, fp, fn):
  precision = tp / (tp + fp) if (tp + fp) else 1.0
  recall = tp / (tp + fn) if (tp + fn) else 1.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
  return precision, recall, f1


def main(argv=None) -> int:
  parser = argparse.ArgumentParser(prog="run_eval")
  parser.add_argument("--client", default="heuristic", choices=["heuristic", "http"])
  parser.add_argument("--model", default=constants.DEFAULT_MODEL)
  parser.add_argument("--sweep", action="store_true", help="Sweep T_TRANSMIT.")
  args = parser.parse_args(argv)

  client = _make_client(args.client, args.model)
  with open(_cases_path(), "r", encoding="utf-8") as f:
    cases = json.load(f)["cases"]

  print(f"client={client.name} model={args.model}  cases={len(cases)}\n")

  # Cache raw answers once per case so the sweep does not re-call the API.
  raw = {}
  field_total = field_ok = 0
  tp = fp = fn = tn = 0
  latencies = []

  for case in cases:
    start = time.time()
    answers = client.system_one(case["state"], _battery_for(case), model=args.model)
    latencies.append(time.time() - start)
    raw[case["name"]] = answers
    pred = _predict(case, answers)
    exp = case["expected"]

    marks = []
    for field, expected in exp.items():
      if field == "is_risk":
        continue
      got = pred.get(field)
      ok = got == expected
      field_total += 1
      field_ok += int(ok)
      marks.append(f"{field}={got}{'' if ok else '!=' + str(expected)}")

    want_risk = bool(exp.get("is_risk"))
    got_risk = bool(pred["is_risk"])
    if got_risk and want_risk:
      tp += 1
    elif got_risk and not want_risk:
      fp += 1
    elif (not got_risk) and want_risk:
      fn += 1
    else:
      tn += 1
    flag = "RISK" if got_risk else "ok  "
    verdict = "" if got_risk == want_risk else "  <-- is_risk MISMATCH"
    print(f"  [{flag}] {case['name']:<44} {'  '.join(marks)}{verdict}")

  precision, recall, f1 = _prf(tp, fp, fn)
  agree = field_ok / field_total if field_total else 0.0
  p50 = sorted(latencies)[len(latencies) // 2] if latencies else 0.0

  print(f"\nper-field agreement : {field_ok}/{field_total} = {agree:.2f} "
        f"(bar {constants.EVAL_MIN_AGREEMENT:.2f})")
  print(f"is_risk confusion   : TP={tp} FP={fp} FN={fn} TN={tn}")
  print(f"precision           : {precision:.2f} (bar {constants.EVAL_MIN_PRECISION:.2f})")
  print(f"recall              : {recall:.2f} (bar {constants.EVAL_MIN_RECALL:.2f})")
  print(f"F1                  : {f1:.2f}")
  print(f"latency p50         : {p50 * 1000:.0f} ms/case")

  if args.sweep:
    print("\nthreshold sweep for transmits_offdevice (vs expected):")
    sweep_cases = [c for c in cases if "transmits_offdevice" in c["expected"]]
    for thr in [0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]:
      s_tp = s_fp = s_fn = 0
      for c in sweep_cases:
        got = (raw[c["name"]]["transmits_offdevice"].noul or 0.0) >= thr
        want = bool(c["expected"]["transmits_offdevice"])
        if got and want:
          s_tp += 1
        elif got and not want:
          s_fp += 1
        elif (not got) and want:
          s_fn += 1
      p, r, fone = _prf(s_tp, s_fp, s_fn)
      print(f"  T={thr:.2f}  P={p:.2f} R={r:.2f} F1={fone:.2f}  (TP={s_tp} FP={s_fp} FN={s_fn})")

  ok = (
      recall >= constants.EVAL_MIN_RECALL
      and precision >= constants.EVAL_MIN_PRECISION
  )
  print("\nmeets bar" if ok else "\nBELOW BAR", file=sys.stderr if not ok else sys.stdout)
  return 0 if ok else 1


if __name__ == "__main__":
  raise SystemExit(main())
