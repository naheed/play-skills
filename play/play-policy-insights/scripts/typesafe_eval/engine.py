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

"""Generic evaluation engine driven by the policy registry.

The engine owns the workflow; policies are data (``registry.py``). It:

1. reads the *raw* deterministic artifacts ``orchestrator.py init`` produced
   (``data_safety_scan.json``, ``manifest_details.json``, ``play_store_info.json``)
   rather than the agent-oriented ``input_worker_*.json`` prompt files;
2. activates policies from the registry per evaluation kind;
3. evaluates them (batched by file for ``code_signal``), isolating failures so
   one bad unit becomes a MANUAL_REVIEW finding instead of crashing the scan; and
4. writes the same ``worker_<goal>.json`` schema the rest of the pipeline
   consumes (``aggregate`` globs every ``worker_*.json``).
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from typesafe_eval import batch
from typesafe_eval import constants
from typesafe_eval import evaluate
from typesafe_eval import registry
from typesafe_eval import snippets
from typesafe_eval.client import JevClient

_FLAVOR_RE = re.compile(r"/src/([^/]+)/")

_GOAL_DOMAIN = {
    "permissions_and_apis": "Permissions and APIs",
    "user_account": "User Account and Identity",
    "data_safety": "Data Safety and Privacy",
}


@dataclasses.dataclass
class Task:
  spec: registry.PolicySpec
  data_type: str
  finding_str: str
  relpath: str


def _load_json(path: str) -> dict:
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception:  # pylint: disable=broad-exception-caught
    return {}


def load_artifacts(temp_dir: str):
  """Reads the raw scan artifacts and derives app-level facts."""
  scan = _load_json(os.path.join(temp_dir, "data_safety_scan.json"))
  data_sources = scan.get("data_safety_scan", {}).get("data_sources", {})
  manifest = _load_json(os.path.join(temp_dir, "manifest_details.json"))
  store = _load_json(os.path.join(temp_dir, "play_store_info.json"))
  app_dir = manifest.get("app_dir", "") or ""
  app_facts = {
      "name": manifest.get("app_label")
      or os.path.basename(os.path.normpath(app_dir)),
      "package": manifest.get("package_name"),
      "target_sdk": manifest.get("target_sdk"),
      "store_category": store.get("category"),
  }
  return data_sources, manifest, app_facts, app_dir


def _reduce_noise(data_sources: Dict[str, List[str]]) -> Dict[str, List[str]]:
  """Prioritizes the Play flavor and caps findings per data type.

  Mirrors the orchestrator's smart filtering so the evaluator processes the same
  bounded set the agent path would, instead of every raw signal.
  """
  # Detect build flavors present; only filter when a Play flavor exists.
  flavors = set()
  for findings in data_sources.values():
    if isinstance(findings, list):
      for f in findings:
        m = _FLAVOR_RE.search("/" + f)
        if m:
          flavors.add(m.group(1))
  prioritized = set(constants.PRIORITIZED_FLAVORS)
  excluded = (flavors - prioritized) if ("play" in flavors) else set()

  reduced: Dict[str, List[str]] = {}
  for data_type, findings in data_sources.items():
    if not isinstance(findings, list):
      continue
    per_file: Dict[str, int] = {}
    kept: List[str] = []
    for f in findings:
      path = "/" + f
      if any(f"/src/{flavor}/" in path for flavor in excluded):
        continue
      # Skip string-catalog / UI-text resources (translations cause FPs).
      if any(frag in path for frag in constants.EXCLUDED_PATH_SUBSTRINGS):
        continue
      relpath, _ = snippets.parse_finding(f)
      relpath = relpath or f
      if per_file.get(relpath, 0) >= constants.MAX_PER_FILE_PER_TYPE:
        continue
      kept.append(f)
      per_file[relpath] = per_file.get(relpath, 0) + 1
      if len(kept) >= constants.MAX_FINDINGS_PER_TYPE:
        break
    if kept:
      reduced[data_type] = kept
  return reduced


def plan(data_sources: Dict[str, List[str]]) -> List[Task]:
  """Turns raw signals into per-(policy, finding) tasks via the registry."""
  tasks: List[Task] = []
  specs = registry.code_signal_specs() + registry.deterministic_specs()
  for data_type, findings in _reduce_noise(data_sources).items():
    for finding_str in findings:
      relpath, _ = snippets.parse_finding(finding_str)
      relpath = relpath or finding_str
      for spec in specs:
        if spec.applies_data_type(data_type):
          tasks.append(Task(spec, data_type, finding_str, relpath))
  return tasks


def _description(data_type: str) -> str:
  return evaluate._taxonomy().get(data_type, {}).get("description", "")  # pylint: disable=protected-access


def _error_finding(task: Task, mini_state: Dict[str, Any], exc: Exception) -> Dict[str, Any]:
  """A recall-safe placeholder when evaluation fails: surface, do not drop."""
  file = mini_state.get("signal", {}).get("file", task.relpath)
  return {
      "policy_id": task.spec.policy_id,
      "psl_constant": task.data_type,
      "issue_summary": "Automated evaluation failed; manual review required",
      "severity": "IMPORTANT",
      "files_involved": [file],
      "evidence": f"{task.data_type} in {file}",
      "recommendation": "Re-run the audit or review this finding manually.",
      "client": "error",
      "error": str(exc)[:200],
      "needs_manual_review": True,
  }


def _compose_task(task: Task, mini_state: Dict[str, Any], answers, client_name: str):
  try:
    return task.spec.compose(
        task.data_type, task.finding_str, mini_state, answers, client_name
    )
  except Exception as exc:  # pylint: disable=broad-exception-caught
    return _error_finding(task, mini_state, exc)


def run(
    temp_dir: str,
    client: JevClient,
    model: Optional[str] = None,
    batched: bool = True,
) -> List[str]:
  """Evaluates all registry policies for an app and writes worker files."""
  data_sources, _manifest, app_facts, app_dir = load_artifacts(temp_dir)
  tasks = plan(data_sources)

  findings_by_goal: Dict[str, List[Dict[str, Any]]] = {
      g: [] for g in registry.goals()
  }

  code_tasks = [t for t in tasks if t.spec.kind == registry.CODE_SIGNAL]
  det_tasks = [t for t in tasks if t.spec.kind == registry.DETERMINISTIC]

  # Deterministic policies: no model call, except an optional evidence gate that
  # filters generic-pattern false positives.
  for task in det_tasks:
    state = snippets.build_state(app_dir, task.finding_str, task.data_type, app_facts)
    if task.spec.gate_battery is not None:
      try:
        gate = client.system_one(
            state, task.spec.gate_battery(task.data_type, _description(task.data_type)),
            model=model,
        )
        passed = (gate[task.spec.gate_key].noul or 0.0) >= task.spec.gate_threshold
      except Exception:  # pylint: disable=broad-exception-caught
        passed = True  # recall-safe: keep the finding if the gate call failed
      if not passed:
        continue
    try:
      finding = task.spec.compose_deterministic(task.data_type, task.finding_str, state)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      finding = _error_finding(task, state, exc)
    if finding:
      findings_by_goal[task.spec.goal].append(finding)

  if batched:
    _run_batched(code_tasks, app_dir, app_facts, client, model, findings_by_goal)
  else:
    _run_per_finding(code_tasks, app_dir, app_facts, client, model, findings_by_goal)

  written: List[str] = []
  for goal in registry.goals():
    out = {
        "domain": _GOAL_DOMAIN.get(goal, "Data Safety and Privacy"),
        "findings": findings_by_goal.get(goal, []),
    }
    with open(os.path.join(temp_dir, f"worker_{goal}.json"), "w", encoding="utf-8") as f:
      json.dump(out, f, indent=2, sort_keys=True)
    written.append(goal)
  return written


def _run_per_finding(tasks, app_dir, app_facts, client, model, findings_by_goal) -> None:
  for task in tasks:
    state = snippets.build_state(app_dir, task.finding_str, task.data_type, app_facts)
    battery = task.spec.make_battery(task.data_type, _description(task.data_type))
    try:
      answers = client.system_one(state, battery, model=model)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      findings_by_goal[task.spec.goal].append(_error_finding(task, state, exc))
      continue
    finding = _compose_task(task, state, answers, client.name)
    if finding:
      findings_by_goal[task.spec.goal].append(finding)


def _run_batched(tasks, app_dir, app_facts, client, model, findings_by_goal) -> None:
  by_file: Dict[str, List[Task]] = {}
  for task in tasks:
    by_file.setdefault(task.relpath, []).append(task)

  for relpath, file_tasks in sorted(by_file.items()):
    # Reuse the file-state builder; it only needs (data_type, finding_str).
    asks = [batch.Ask(t.spec.goal, t.data_type, None, t.finding_str, "") for t in file_tasks]
    state, per_task = batch.build_file_state(app_dir, relpath, asks, app_facts)

    questions: Dict[str, Any] = {}
    for i, task in enumerate(file_tasks):
      battery = task.spec.make_battery(task.data_type, _description(task.data_type))
      questions.update({f"a{i}__{qid}": qd for qid, qd in battery.items()})

    try:
      answers = client.system_one(state, questions, model=model)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      # One file's failure is isolated: mark its tasks for review, keep scanning.
      for i, task in enumerate(file_tasks):
        findings_by_goal[task.spec.goal].append(_error_finding(task, per_task[i], exc))
      continue

    for i, task in enumerate(file_tasks):
      prefix = f"a{i}__"
      sub = {qid[len(prefix):]: a for qid, a in answers.items() if qid.startswith(prefix)}
      finding = _compose_task(task, per_task[i], sub, client.name)
      if finding:
        findings_by_goal[task.spec.goal].append(finding)
