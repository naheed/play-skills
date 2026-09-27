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

Label schema v2 (WP7) adds an optional ``destination_class`` per case, one of
``questions.DESTINATION_CLASS_OPTIONS`` (``developer_backend``,
``third_party_sdk``, ``user_chosen_destination``, ``platform_component``,
``other_app_ipc``) for labelled transfers; non-transfers leave it out (or
``null``). When present the report adds:

- ``destination``: the model's predicted class (read from the joined finding)
  against the label -- per-class precision / recall / support, the confusion
  table, and the share of labelled transfers whose *sharing* flag
  (``is_third_party``) the run got right (``sharing_agreement``). A labelled
  sharing case whose finding lost its sharing flag is listed in
  ``sharing_regressions`` -- the WP7 exit criterion forbids any.
- ``reliability_by_class``: Brier / ECE of ``p_transmit`` split by the labelled
  class (non-transfers grouped as ``none``), so a badly calibrated class is
  visible instead of averaged away.
- ``reliability_in_band``: Brier / ECE restricted to the cases whose
  ``p_transmit`` falls inside the *current* UNCERTAIN band -- the number the
  WP7 exit criterion compares against WP6.
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


#: Fields copied from the joined finding onto the case (prefixed ``run_``) so
#: the destination report can compare the run against the label.
_RUN_FIELDS = ("destination_class", "is_third_party", "transfer_decision", "severity")


def _index_findings(worker_dirs: List[str]) -> List[Tuple[str, str, float, Dict[str, Any]]]:
  """``(file, data_type, p_transmit, run_fields)`` for every finding with a probability.

  ``run_fields`` carries the finding's ``destination_class`` (WP7; falls back
  to the decision trace's ``destination.class``), ``is_third_party``,
  ``transfer_decision`` and ``severity``.
  """
  out: List[Tuple[str, str, float, Dict[str, Any]]] = []
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
        trace = f.get("decision_trace") or {}
        run = {k: f.get(k) for k in _RUN_FIELDS}
        if run.get("destination_class") is None:
          run["destination_class"] = (trace.get("destination") or {}).get("class")
        run["destination_confirmed"] = (trace.get("destination") or {}).get("confirmed")
        run["destination_applied"] = (trace.get("destination") or {}).get("applied")
        out.append((files[0], dt, p, run))
  log.info("indexed %d findings with transfer probabilities from %d dirs", len(out), len(worker_dirs))
  return out


def join_probabilities(
    cases: List[Dict[str, Any]], worker_dirs: List[str], rejoin: bool = False,
    unmatched: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
  """Fills ``p_transmit`` for cases from the worker files.

  Args:
    cases: Label cases; those with a stored ``p_transmit`` are used as-is
      unless ``rejoin`` is set.
    worker_dirs: Scratch directories holding ``worker_*.json``.
    rejoin: Ignore stored probabilities and look every case up in
      ``worker_dirs`` (WP2 recall check against a *new* run).
    unmatched: When given, cases with no matching finding are appended here
      (with ``"reason"``) instead of only being logged. A labelled *transfer*
      with no finding means the pipeline lost a true positive before the
      model saw it (pre-gate, caps or relevance gate) -- the one regression
      the charter forbids.
  """
  index = _index_findings(worker_dirs) if worker_dirs else []
  joined: List[Dict[str, Any]] = []
  for c in cases:
    if c.get("p_transmit") is not None and not rejoin:
      joined.append(c)
      continue
    match = [(p, run) for (f, dt, p, run) in index
             if dt == c.get("data_type") and f.endswith(c.get("file", "\x00"))]
    if not match:
      level = logging.ERROR if c.get("transfers") else logging.WARNING
      log.log(level, "no probability found for %s / %s (transfers=%s); case skipped",
              c.get("file"), c.get("data_type"), c.get("transfers"))
      if unmatched is not None:
        unmatched.append({**c, "reason": "no finding with a transfer probability in worker_dirs"})
      continue
    # The highest-probability finding is the one the report acts on; its
    # run-side fields (destination class, sharing flag) travel with the case.
    p_best, run_best = max(match, key=lambda m: m[0])
    joined.append({**c, "p_transmit": p_best, **{f"run_{k}": v for k, v in run_best.items()}})
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


def reliability_by_class(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
  """Brier / ECE of ``p_transmit`` per *labelled* destination class (WP7).

  Non-transfers are grouped as ``none``; labelled transfers without a class
  as ``unlabelled``. Bins are omitted per class (too thin to read); the
  headline numbers and the support are enough to spot a class that is
  mis-calibrated on its own.
  """
  groups: Dict[str, List[Dict[str, Any]]] = {}
  for c in cases:
    if not c["transfers"]:
      key = "none"
    else:
      key = c.get("destination_class") or "unlabelled"
    groups.setdefault(key, []).append(c)
  out: Dict[str, Any] = {}
  for key in sorted(groups):
    r = reliability(groups[key])
    out[key] = {"n": len(groups[key]), "brier": r["brier"], "ece": r["ece"],
                "mean_p": round(sum(c["p_transmit"] for c in groups[key]) / len(groups[key]), 3)}
  return out


def reliability_in_band(cases: List[Dict[str, Any]], t_low: float, t_high: float) -> Dict[str, Any]:
  """Brier / ECE restricted to the UNCERTAIN band ``[t_low, t_high)`` (WP7 exit metric)."""
  members = [c for c in cases if t_low <= c["p_transmit"] < t_high]
  r = reliability(members)
  return {"band": [t_low, t_high], "n": len(members),
          "positives": sum(1 for c in members if c["transfers"]),
          "brier": r["brier"], "ece": r["ece"]}


def destination_report(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
  """Predicted ``destination_class`` (from the joined findings) vs the labels (WP7).

  Only labelled transfers with a ``destination_class`` label *and* a joined
  ``run_destination_class`` take part. Reports per-class precision / recall /
  support, the confusion table (``label -> predicted -> n``), the agreement of
  the run's sharing flag with the label's sharing classes, and every labelled
  sharing case whose finding lost its sharing flag (``sharing_regressions``,
  which the WP7 exit criterion requires to be empty).
  """
  labelled = [c for c in cases if c["transfers"] and c.get("destination_class")]
  scored = [c for c in labelled if c.get("run_destination_class")]
  if not labelled:
    return {"n_labelled": 0, "note": "no destination_class labels (schema v1)"}
  sharing_classes = set(constants.SHARING_DESTINATION_CLASSES)
  confusion: Dict[str, Dict[str, int]] = {}
  for c in scored:
    row = confusion.setdefault(str(c["destination_class"]), {})
    pred = str(c.get("run_destination_class"))
    row[pred] = row.get(pred, 0) + 1
  classes = sorted({str(c["destination_class"]) for c in scored}
                   | {str(c.get("run_destination_class")) for c in scored})
  per_class: Dict[str, Any] = {}
  for k in classes:
    tp = sum(1 for c in scored if str(c["destination_class"]) == k and str(c.get("run_destination_class")) == k)
    support = sum(1 for c in scored if str(c["destination_class"]) == k)
    predicted = sum(1 for c in scored if str(c.get("run_destination_class")) == k)
    per_class[k] = {
        "support": support,
        "predicted": predicted,
        "precision": round(tp / predicted, 3) if predicted else None,
        "recall": round(tp / support, 3) if support else None,
    }
  accuracy = (sum(1 for c in scored if str(c["destination_class"]) == str(c.get("run_destination_class")))
              / len(scored)) if scored else None
  sharing_cases = [c for c in scored if c["destination_class"] in sharing_classes]
  sharing_regressions = [
      {"file": c.get("file"), "data_type": c.get("data_type"),
       "destination_class": c.get("destination_class"),
       "run_destination_class": c.get("run_destination_class"),
       "run_is_third_party": c.get("run_is_third_party")}
      for c in sharing_cases if not c.get("run_is_third_party")
  ]
  sharing_agreement = (
      sum(1 for c in scored if bool(c.get("run_is_third_party")) == (c["destination_class"] in sharing_classes))
      / len(scored)) if scored else None
  # Confirmed non-collection classes lower a severity, so a *wrong* one is the
  # precision risk WP7 introduces; list every applied downgrade against its label.
  applied = [
      {"file": c.get("file"), "data_type": c.get("data_type"),
       "destination_class": c.get("destination_class"),
       "run_destination_class": c.get("run_destination_class"),
       "agrees": c.get("destination_class") == c.get("run_destination_class")}
      for c in scored if c.get("run_destination_applied")
  ]
  return {
      "n_labelled": len(labelled),
      "n_scored": len(scored),
      "accuracy": round(accuracy, 3) if accuracy is not None else None,
      "per_class": per_class,
      "confusion": confusion,
      "sharing_agreement": round(sharing_agreement, 3) if sharing_agreement is not None else None,
      "sharing_regressions": sharing_regressions,
      "applied_downgrades": applied,
      "applied_downgrades_wrong": sum(1 for a in applied if not a["agrees"]),
  }


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
              model: str = constants.DEFAULT_MODEL, rejoin: bool = False,
              worker_dirs: Optional[List[str]] = None) -> Dict[str, Any]:
  """Builds the calibration report.

  Args:
    labels: The label set (``description``, ``worker_dirs``, ``cases``).
    min_precision: Precision target for ``T_TRANSMIT_HIGH``.
    model: Recorded in the provenance block.
    rejoin: Re-join every case against the worker files instead of using the
      probabilities stored in the labels (checks a *new* run against the
      frozen labels).
    worker_dirs: Overrides ``labels["worker_dirs"]``.
  """
  cases = [c for c in labels.get("cases", []) if "transfers" in c]
  dirs = list(worker_dirs) if worker_dirs else list(labels.get("worker_dirs") or [])
  unmatched: List[Dict[str, Any]] = []
  cases = join_probabilities(cases, dirs, rejoin=rejoin, unmatched=unmatched)
  cases = [{**c, "p_transmit": float(c["p_transmit"]), "transfers": bool(c["transfers"])}
           for c in cases]
  band = derive_band(cases, min_precision)
  missing_positives = [u for u in unmatched if u.get("transfers")]
  report: Dict[str, Any] = {
      "evaluator_version": constants.EVALUATOR_VERSION,
      "min_precision": min_precision,
      "rejoined": rejoin,
      "worker_dirs": dirs,
      "unmatched_cases": unmatched,
      "missing_positives": missing_positives,
      "band": band,
      "current_constants": {"T_TRANSMIT_LOW": constants.T_TRANSMIT_LOW,
                            "T_TRANSMIT_HIGH": constants.T_TRANSMIT_HIGH},
      "metrics": band_metrics(cases, band["T_TRANSMIT_LOW"], band["T_TRANSMIT_HIGH"]),
      "metrics_at_current_constants": band_metrics(
          cases, constants.T_TRANSMIT_LOW, constants.T_TRANSMIT_HIGH),
      "reliability": reliability(cases),
      # WP7 (label schema v2): per-class views and the in-band metric.
      "reliability_by_class": reliability_by_class(cases),
      "reliability_in_band": reliability_in_band(
          cases, constants.T_TRANSMIT_LOW, constants.T_TRANSMIT_HIGH),
      "reliability_in_derived_band": reliability_in_band(
          cases, band["T_TRANSMIT_LOW"], band["T_TRANSMIT_HIGH"]),
      "destination": destination_report(cases),
      # The joined rows themselves (label fields + ``p_transmit`` + ``run_*``),
      # so two reports can be diffed case by case. The report is written
      # next to the label file, out of tree, so real file names are fine here.
      "cases": [dict(sorted(c.items())) for c in cases],
      "warnings": [],
  }
  regressions = report["destination"].get("sharing_regressions") or []
  if regressions:
    report["warnings"].append(
        f"{len(regressions)} labelled sharing case(s) lost the sharing flag: "
        + ", ".join(f"{r.get('file')}/{r.get('data_type')}" for r in regressions))
  wrong = report["destination"].get("applied_downgrades_wrong") or 0
  if wrong:
    report["warnings"].append(
        f"{wrong} confirmed non-collection destination(s) disagree with the label "
        "(a severity was lowered on a wrong class); see destination.applied_downgrades")
  if len(cases) < MIN_RECOMMENDED_CASES:
    report["warnings"].append(
        f"only {len(cases)} labelled cases (< {MIN_RECOMMENDED_CASES}); treat as a "
        "regression check, not a calibration")
  if band["band_collapsed"]:
    report["warnings"].append(
        "precision target unreachable without losing recall; band collapsed to T_LOW "
        "(no abstention). Lower --min-precision or add labels.")
  if missing_positives:
    report["warnings"].append(
        f"{len(missing_positives)} labelled transfer(s) have no finding in the run: "
        + ", ".join(f"{u.get('file')}/{u.get('data_type')}" for u in missing_positives)
        + ". Recall is below 1.0 by construction; find the drop reason in typesafe_triage.json.")
  report["provenance"] = provenance_block(report, labels.get("description", ""), model)
  return report


def main(labels_path: str, out_path: Optional[str] = None, min_precision: float = 0.90,
         rejoin: bool = False, worker_dirs: Optional[List[str]] = None) -> int:
  """CLI entry.

  Returns 2 when a labelled transfer is missing from the run and 3 when a
  labelled sharing case lost its sharing flag (WP7 exit criterion); both are
  recall regressions the charter forbids.
  """
  labels = _load_json(labels_path)
  report = calibrate(labels, min_precision=min_precision, rejoin=rejoin, worker_dirs=worker_dirs)
  text = json.dumps(report, indent=2, sort_keys=True)
  if out_path:
    with open(out_path, "w", encoding="utf-8") as f:
      f.write(text)
    print(f"Calibration report written to {out_path}")
  print(text)
  for w in report["warnings"]:
    print(f"WARNING: {w}")
  if report["missing_positives"]:
    print(f"FAIL: {len(report['missing_positives'])} labelled transfer(s) not found in the run")
    return 2
  regressions = report["destination"].get("sharing_regressions") or []
  if regressions:
    print(f"FAIL: {len(regressions)} labelled sharing case(s) lost the sharing flag")
    return 3
  return 0
