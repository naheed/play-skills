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

"""Threshold calibration and reliability reporting for the transfer decision.

Thresholds are *calibrated artifacts*, not constants. This tool derives the
three-way transfer band from a labelled set and emits the provenance block
that ``constants.THRESHOLD_PROVENANCE`` must carry, so a reviewer can always
answer "where did 0.35 / 0.70 come from?".

Method (matches the evaluation charter: recall > precision > calibration):

- ``T_TRANSMIT_LOW``  = the highest threshold on the 0.01 grid at which every
  labelled *true* transfer is still at/above it (recall 1.0). Below this the
  evaluator may say LOCAL.
- ``T_TRANSMIT_HIGH`` = the lowest threshold at which precision among findings
  at/above it reaches ``--min-precision`` (default 0.90). At/above this the
  evaluator says TRANSMITS.
- The band in between is UNCERTAIN (emitted for manual review). If the two
  cross (precision target unreachable without losing recall) the band collapses
  to ``T_LOW`` and the report says so; the reviewer then decides whether to
  lower the precision target or collect more labels.

Reliability: Brier score and a 10-bin expected calibration error (ECE) on the
raw ``p_transmit`` probabilities, plus recall/precision/abstention at the derived
band, so a model upgrade can be checked for calibration drift before the
thresholds are trusted.

Input format (JSON)::

    {
      "description": "free text: where the labels came from",
      "worker_dirs": ["/path/to/scratch_a", "/path/to/scratch_b"],   # optional
      "cases": [
        {"file": "app/src/.../Foo.kt", "data_type": "PRECISE_LOCATION",
         "transfers": true, "p_transmit": 0.82},
        ...
      ]
    }

``p_transmit`` may be omitted when ``worker_dirs`` is given: the case is then
joined to the ``worker_*.json`` finding with the same (file suffix, data_type)
and the probability is read from its decision trace. Labels live *outside* the
repository (they name app files); only this tool and the derived numbers are
checked in.
"""

from __future__ import annotations

import glob
import json
import logging
import os
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from typesafe_eval import constants

log = logging.getLogger("typesafe_eval.calibrate")

_GRID = [round(i / 100.0, 2) for i in range(0, 101)]
MIN_RECOMMENDED_CASES = 30


def _load_json(path: str) -> Dict[str, Any]:
  with open(path, "r", encoding="utf-8") as f:
    return json.load(f)


def _finding_probability(finding: Dict[str, Any]) -> Optional[float]:
  trace = finding.get("decision_trace") or {}
  p = (trace.get("scores") or {}).get("transmits_offdevice")
  if p is None:
    p = ((finding.get("typesafe_answers") or {}).get("transmits_offdevice") or {}).get("noul")
  return float(p) if p is not None else None


def _index_findings(worker_dirs: List[str]) -> List[Tuple[str, str, float]]:
  """``(file, data_type, p_transmit)`` for every finding with a probability."""
  out: List[Tuple[str, str, float]] = []
  for d in worker_dirs:
    for path in sorted(glob.glob(os.path.join(d, "worker_*.json"))):
      try:
        data = _load_json(path)
      except (OSError, ValueError) as exc:
        log.warning("skipping unreadable %s: %s", path, exc)
        continue
      for f in data.get("findings", []):
        p = _finding_probability(f)
        dt = f.get("psl_constant")
        files = f.get("files_involved") or []
        if p is None or not dt or not files:
          continue
        out.append((files[0], dt, p))
  log.info("indexed %d findings with transfer probabilities from %d dirs", len(out), len(worker_dirs))
  return out


def join_probabilities(cases: List[Dict[str, Any]], worker_dirs: List[str]) -> List[Dict[str, Any]]:
  """Fills ``p_transmit`` for cases that lack it from the worker files."""
  index = _index_findings(worker_dirs) if worker_dirs else []
  joined: List[Dict[str, Any]] = []
  for c in cases:
    if c.get("p_transmit") is not None:
      joined.append(c)
      continue
    match = [p for (f, dt, p) in index
             if dt == c.get("data_type") and f.endswith(c.get("file", "\x00"))]
    if not match:
      log.warning("no probability found for %s / %s; case skipped", c.get("file"), c.get("data_type"))
      continue
    joined.append({**c, "p_transmit": max(match)})
  return joined


def _recall_precision(cases: List[Dict[str, Any]], t: float) -> Tuple[float, Optional[float], int]:
  positives = [c for c in cases if c["transfers"]]
  predicted = [c for c in cases if c["p_transmit"] >= t]
  tp = sum(1 for c in predicted if c["transfers"])
  recall = (tp / len(positives)) if positives else 1.0
  precision = (tp / len(predicted)) if predicted else None
  return recall, precision, len(predicted)


def derive_band(cases: List[Dict[str, Any]], min_precision: float = 0.90) -> Dict[str, Any]:
  """Derives ``(T_LOW, T_HIGH)`` on the 0.01 grid per the documented method."""
  t_low = 0.0
  for t in _GRID:
    recall, _, _ = _recall_precision(cases, t)
    if recall >= 1.0:
      t_low = t
    else:
      break
  t_high: Optional[float] = None
  for t in _GRID:
    _, precision, n = _recall_precision(cases, t)
    if n > 0 and precision is not None and precision >= min_precision:
      t_high = t
      break
  collapsed = False
  if t_high is None:
    t_high = 1.0
    collapsed = True
  if t_high < t_low:
    t_high = t_low
    collapsed = True
  return {"T_TRANSMIT_LOW": t_low, "T_TRANSMIT_HIGH": t_high, "band_collapsed": collapsed}


def reliability(cases: List[Dict[str, Any]], bins: int = 10) -> Dict[str, Any]:
  """Brier score and expected calibration error of ``p_transmit`` vs labels."""
  if not cases:
    return {"brier": None, "ece": None, "bins": []}
  brier = sum((c["p_transmit"] - (1.0 if c["transfers"] else 0.0)) ** 2 for c in cases) / len(cases)
  edges = [i / bins for i in range(bins + 1)]
  rows = []
  ece = 0.0
  for lo, hi in zip(edges[:-1], edges[1:]):
    members = [c for c in cases if lo <= c["p_transmit"] < hi or (hi == 1.0 and c["p_transmit"] == 1.0)]
    if not members:
      continue
    conf = sum(c["p_transmit"] for c in members) / len(members)
    acc = sum(1 for c in members if c["transfers"]) / len(members)
    ece += abs(acc - conf) * len(members) / len(cases)
    rows.append({"bin": [lo, hi], "n": len(members), "mean_p": round(conf, 3), "frac_true": round(acc, 3)})
  return {"brier": round(brier, 4), "ece": round(ece, 4), "bins": rows}


def band_metrics(cases: List[Dict[str, Any]], t_low: float, t_high: float) -> Dict[str, Any]:
  positives = [c for c in cases if c["transfers"]]
  transmits = [c for c in cases if c["p_transmit"] >= t_high]
  local = [c for c in cases if c["p_transmit"] < t_low]
  uncertain = [c for c in cases if t_low <= c["p_transmit"] < t_high]
  tp = sum(1 for c in transmits if c["transfers"])
  fn_local = sum(1 for c in local if c["transfers"])
  return {
      "n": len(cases),
      "positives": len(positives),
      "recall_at_high": round(tp / len(positives), 3) if positives else None,
      "precision_at_high": round(tp / len(transmits), 3) if transmits else None,
      "abstention_rate": round(len(uncertain) / len(cases), 3),
      "uncertain_true_transfers": sum(1 for c in uncertain if c["transfers"]),
      "false_negatives_local": fn_local,
  }


def provenance_block(report: Dict[str, Any], description: str, model: str) -> Dict[str, Any]:
  """The dict to paste into ``constants.THRESHOLD_PROVENANCE``."""
  import datetime
  return {
      "model": model,
      "calibrated_on": description or f"{report['metrics']['n']} labelled findings",
      "calibrated_at": datetime.date.today().isoformat(),
      "method": (
          "T_TRANSMIT_LOW = highest threshold with recall 1.0 on labelled "
          "transfers; T_TRANSMIT_HIGH = lowest threshold with precision >= "
          f"{report['min_precision']:.2f} on labelled transfers; band in between "
          "abstains. See calibrate.py."
      ),
      "note": (
          "Fewer than %d cases: regression check, not a hold-out." % MIN_RECOMMENDED_CASES
          if report["metrics"]["n"] < MIN_RECOMMENDED_CASES
          else "Derived from a labelled set; re-run on model or taxonomy change."
      ),
  }


def calibrate(labels: Dict[str, Any], min_precision: float = 0.90,
              model: str = constants.DEFAULT_MODEL) -> Dict[str, Any]:
  cases = [c for c in labels.get("cases", []) if "transfers" in c]
  cases = join_probabilities(cases, labels.get("worker_dirs") or [])
  cases = [{**c, "p_transmit": float(c["p_transmit"]), "transfers": bool(c["transfers"])}
           for c in cases]
  band = derive_band(cases, min_precision)
  report: Dict[str, Any] = {
      "evaluator_version": constants.EVALUATOR_VERSION,
      "min_precision": min_precision,
      "band": band,
      "current_constants": {"T_TRANSMIT_LOW": constants.T_TRANSMIT_LOW,
                            "T_TRANSMIT_HIGH": constants.T_TRANSMIT_HIGH},
      "metrics": band_metrics(cases, band["T_TRANSMIT_LOW"], band["T_TRANSMIT_HIGH"]),
      "metrics_at_current_constants": band_metrics(
          cases, constants.T_TRANSMIT_LOW, constants.T_TRANSMIT_HIGH),
      "reliability": reliability(cases),
      "warnings": [],
  }
  if len(cases) < MIN_RECOMMENDED_CASES:
    report["warnings"].append(
        f"only {len(cases)} labelled cases (< {MIN_RECOMMENDED_CASES}); treat as a "
        "regression check, not a calibration")
  if band["band_collapsed"]:
    report["warnings"].append(
        "precision target unreachable without losing recall; band collapsed to T_LOW "
        "(no abstention). Lower --min-precision or add labels.")
  report["provenance"] = provenance_block(report, labels.get("description", ""), model)
  return report


def main(labels_path: str, out_path: Optional[str] = None, min_precision: float = 0.90) -> int:
  labels = _load_json(labels_path)
  report = calibrate(labels, min_precision=min_precision)
  text = json.dumps(report, indent=2, sort_keys=True)
  if out_path:
    with open(out_path, "w", encoding="utf-8") as f:
      f.write(text)
    print(f"Calibration report written to {out_path}")
  print(text)
  for w in report["warnings"]:
    print(f"WARNING: {w}")
  return 0
