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

"""Diff two evaluator runs: findings, decisions, drops, and cost.

Every behavioural change to the evaluator is measured against a recorded
baseline rather than argued from the code. This tool compares two scratch
directories (each produced by ``python -m typesafe_eval run``) and reports,
deterministically and in a stable order:

- findings **added**, **removed**, and **changed** (severity or transfer
  decision), keyed by ``(policy_id, file, data_type)``;
- per-reason deltas in the **dropped** candidate list from
  ``typesafe_triage.json``;
- deltas in the stage **counters** (candidates, kept, battery requests) and in
  **usage** (requests, input/output tokens).

Usage::

    python -m typesafe_eval triage-diff <before_dir> <after_dir> [--json PATH]

The exit code is 0 whether or not differences exist; the tool reports, the
milestone gate (a human, or a script checking ``--json``) decides. A diff of a
directory against itself is empty by construction, which is the selftest.
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

log = logging.getLogger("typesafe_eval.triage_diff")

TRIAGE_FILENAME = "typesafe_triage.json"

# Fields whose change is reported for a finding present on both sides.
_COMPARED_FIELDS = ("severity", "transfer_decision", "is_third_party", "needs_manual_review")

FindingKey = Tuple[str, str, str]


def _load_json(path: str) -> Dict[str, Any]:
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except (OSError, ValueError) as exc:
    log.warning("could not read %s: %s", path, exc)
    return {}


def _finding_key(finding: Dict[str, Any]) -> FindingKey:
  files = finding.get("files_involved") or [""]
  # Manifest findings share ``AndroidManifest.xml``; disambiguate by the
  # component the trace names so two services do not collapse into one key.
  trace = finding.get("decision_trace") or {}
  discriminator = finding.get("psl_constant") or trace.get("service") or ""
  return (str(finding.get("policy_id", "")), str(files[0]), str(discriminator))


def load_findings(scratch_dir: str) -> Dict[FindingKey, Dict[str, Any]]:
  """All findings in ``worker_*.json`` under ``scratch_dir``, keyed for diffing.

  When two findings share a key (e.g. two anchors of one data type in one
  file), the higher severity wins so the diff reports the worst case.
  """
  rank = {"SUGGESTION": 0, "IMPORTANT": 1, "CRITICAL": 2}
  out: Dict[FindingKey, Dict[str, Any]] = {}
  for path in sorted(glob.glob(os.path.join(scratch_dir, "worker_*.json"))):
    for f in _load_json(path).get("findings", []) or []:
      k = _finding_key(f)
      prev = out.get(k)
      if prev is None or rank.get(f.get("severity"), -1) > rank.get(prev.get("severity"), -1):
        out[k] = f
  log.info("%s: %d findings across worker files", scratch_dir, len(out))
  return out


def _drop_reason_counts(triage: Dict[str, Any]) -> Dict[str, int]:
  counts: Dict[str, int] = {}
  for d in triage.get("dropped", []) or []:
    reason = str(d.get("reason", "?"))
    # Collapse the per-policy suffix so "x: compliant or relevance gate" from
    # several policies aggregates under one reason family.
    counts[reason] = counts.get(reason, 0) + 1
  return counts


def _scalar_counters(triage: Dict[str, Any]) -> Dict[str, Any]:
  counters = triage.get("counters", {}) or {}
  keep = ("raw_signals", "candidates", "kept", "tasks", "battery_requests",
          "files_analyzed", "imports_third_party", "imports_refined", "dependencies")
  out = {k: counters.get(k) for k in keep if k in counters}
  usage = triage.get("usage", {}) or {}
  out.update({f"usage.{k}": usage.get(k) for k in ("requests", "input_tokens", "output_tokens")})
  out["findings_by_severity"] = triage.get("findings_by_severity", {})
  out["transfer_decisions"] = triage.get("transfer_decisions", {})
  out["evaluator_version"] = triage.get("evaluator_version")
  return out


def diff(before_dir: str, after_dir: str) -> Dict[str, Any]:
  """Structured diff of two runs (see module docstring for the sections)."""
  before = load_findings(before_dir)
  after = load_findings(after_dir)
  added = sorted(set(after) - set(before))
  removed = sorted(set(before) - set(after))
  changed: List[Dict[str, Any]] = []
  for k in sorted(set(before) & set(after)):
    b, a = before[k], after[k]
    delta = {fld: (b.get(fld), a.get(fld)) for fld in _COMPARED_FIELDS if b.get(fld) != a.get(fld)}
    if delta:
      changed.append({"key": list(k), "changes": {f: list(v) for f, v in delta.items()}})

  t_before = _load_json(os.path.join(before_dir, TRIAGE_FILENAME))
  t_after = _load_json(os.path.join(after_dir, TRIAGE_FILENAME))
  d_before, d_after = _drop_reason_counts(t_before), _drop_reason_counts(t_after)
  drop_delta = {
      r: {"before": d_before.get(r, 0), "after": d_after.get(r, 0)}
      for r in sorted(set(d_before) | set(d_after))
      if d_before.get(r, 0) != d_after.get(r, 0)
  }
  c_before, c_after = _scalar_counters(t_before), _scalar_counters(t_after)
  counter_delta = {
      k: {"before": c_before.get(k), "after": c_after.get(k)}
      for k in sorted(set(c_before) | set(c_after))
      if c_before.get(k) != c_after.get(k)
  }

  def _describe(k: FindingKey, src: Dict[FindingKey, Dict[str, Any]]) -> Dict[str, Any]:
    f = src[k]
    return {"key": list(k), "severity": f.get("severity"),
            "transfer_decision": f.get("transfer_decision"),
            "issue_summary": (f.get("issue_summary") or "")[:120]}

  report = {
      "before": before_dir,
      "after": after_dir,
      "summary": {
          "findings_before": len(before), "findings_after": len(after),
          "added": len(added), "removed": len(removed), "changed": len(changed),
          "drop_reasons_changed": len(drop_delta), "counters_changed": len(counter_delta),
      },
      "added": [_describe(k, after) for k in added],
      "removed": [_describe(k, before) for k in removed],
      "changed": changed,
      "dropped_by_reason": drop_delta,
      "counters": counter_delta,
  }
  report["identical"] = not (added or removed or changed or drop_delta or counter_delta)
  return report


def render(report: Dict[str, Any]) -> str:
  """Compact human-readable rendering for the terminal."""
  s = report["summary"]
  lines = [
      f"triage-diff: {report['before']}  ->  {report['after']}",
      f"  findings {s['findings_before']} -> {s['findings_after']}: "
      f"+{s['added']} -{s['removed']} ~{s['changed']}",
  ]
  for item in report["added"]:
    lines.append(f"  + {item['key']} {item['severity']} {item['transfer_decision'] or ''}  {item['issue_summary']}")
  for item in report["removed"]:
    lines.append(f"  - {item['key']} {item['severity']} {item['transfer_decision'] or ''}  {item['issue_summary']}")
  for item in report["changed"]:
    lines.append(f"  ~ {item['key']} " + ", ".join(f"{f}: {v[0]} -> {v[1]}" for f, v in item["changes"].items()))
  if report["dropped_by_reason"]:
    lines.append("  dropped by reason:")
    for r, v in report["dropped_by_reason"].items():
      lines.append(f"    {r}: {v['before']} -> {v['after']}")
  if report["counters"]:
    lines.append("  counters:")
    for k, v in report["counters"].items():
      lines.append(f"    {k}: {v['before']} -> {v['after']}")
  if report["identical"]:
    lines.append("  (identical)")
  return "\n".join(lines)


def main(before_dir: str, after_dir: str, json_out: Optional[str] = None) -> int:
  report = diff(before_dir, after_dir)
  print(render(report))
  if json_out:
    with open(json_out, "w", encoding="utf-8") as f:
      json.dump(report, f, indent=2, sort_keys=True)
    print(f"JSON written to {json_out}")
  return 0
