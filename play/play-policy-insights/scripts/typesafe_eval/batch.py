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

"""File-keyed request batching.

Jev has no cross-request cache: the state is re-sent in every request body. The
per-finding evaluator therefore re-sends a file's code once per finding in that
file (and again for each policy that touches it). Because Jev evaluates every
question in a request in parallel and in isolation over one shared state, the
fix is to send each file's code ONCE and fan out every policy question about
that file in a single request (the Speculative Fan-Out pattern).

This module re-pivots the per-goal findings that ``orchestrator.py init`` writes
(``input_worker_<goal>.json``) from "by policy" to "by file", builds one state
per file, asks every relevant battery in one namespaced request, then demuxes
the answers back into the same ``worker_<goal>.json`` schema the rest of the
pipeline consumes.
"""

from __future__ import annotations

import glob
import json
import os
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from typesafe_eval import evaluate
from typesafe_eval import questions as q
from typesafe_eval import snippets
from typesafe_eval.client import JevClient


class Ask:
  """One battery to run: a (goal, data_type, policy) about one finding string."""

  def __init__(self, goal, data_type, policy_id, finding_str, description):
    self.goal = goal
    self.data_type = data_type
    self.policy_id = policy_id
    self.finding_str = finding_str
    self.description = description

  def battery(self) -> Dict[str, Dict[str, Any]]:
    if self.policy_id and self.goal.startswith("permissions"):
      return q.permission_battery(self.policy_id, self.data_type)
    return q.data_safety_battery(self.data_type, self.description)


def plan_by_file(temp_dir: str) -> Tuple[Dict[str, List[Ask]], List[str], str]:
  """Groups model-requiring asks by source file.

  Returns ``(asks_by_file, goal_names, app_dir)``. Deterministic checks (like
  account deletion) are not included here; they are handled without a model.
  """
  asks_by_file: Dict[str, List[Ask]] = {}
  goal_names: List[str] = []
  app_dir = ""

  for input_path in sorted(glob.glob(os.path.join(temp_dir, "input_worker_*.json"))):
    goal = os.path.basename(input_path)[len("input_worker_"):-len(".json")]
    goal_names.append(goal)
    base_context = evaluate._load_json(input_path)  # pylint: disable=protected-access
    app_dir = app_dir or base_context.get("APP_DIR") or ""

    for data_type, finding_str, desc in evaluate._iter_findings(base_context):  # pylint: disable=protected-access
      description = desc or evaluate._taxonomy().get(data_type, {}).get("description", "")  # pylint: disable=protected-access
      policy_id = None
      if goal.startswith("permissions"):
        policy_id = evaluate.PERMISSION_POLICY.get(data_type)
        if not policy_id:
          continue
      elif goal.startswith("data_safety"):
        if data_type not in evaluate._taxonomy():  # pylint: disable=protected-access
          continue
      else:
        # user_account etc. — account deletion is deterministic, handled later.
        continue

      relpath, _ = snippets.parse_finding(finding_str)
      relpath = relpath or finding_str
      asks_by_file.setdefault(relpath, []).append(
          Ask(goal, data_type, policy_id, finding_str, description)
      )

  return asks_by_file, goal_names, app_dir


def build_file_state(
    app_dir: str, relpath: str, asks: List[Ask], app_facts: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
  """Builds one shared state for a file plus a per-ask mini-state for evidence.

  The file's code is included once (the union of the regions around each ask's
  matched pattern, plus the co-located data-flow lines). Per-ask mini-states are
  cheap local extractions used only to render evidence lines; they are not sent.
  """
  full = os.path.join(app_dir, relpath)
  content = ""
  if os.path.isfile(full):
    with open(full, "r", encoding="utf-8", errors="ignore") as f:
      content = f.read()
  lines = content.splitlines()

  context = 4
  regions = set()
  signals: List[Dict[str, Any]] = []
  per_ask: List[Dict[str, Any]] = []

  for ask in asks:
    _, pattern = snippets.parse_finding(ask.finding_str)
    pattern = pattern or ""
    hit = next((i for i, ln in enumerate(lines) if pattern and pattern in ln), None)
    if hit is not None:
      for j in range(max(0, hit - context), min(len(lines), hit + context + 1)):
        regions.add(j)
      matched_line = lines[hit].strip()
      line_no = hit + 1
    else:
      matched_line = ""
      line_no = None
    signals.append({"data_type": ask.data_type, "matched_pattern": pattern, "line": line_no})
    # Mini-state for evidence rendering only (reuses the single-finding shape).
    per_ask.append(snippets.build_state(app_dir, ask.finding_str, ask.data_type, app_facts))

  # Render the merged regions with line numbers, marking gaps.
  rendered = []
  prev = None
  for idx in sorted(regions):
    if prev is not None and idx > prev + 1:
      rendered.append("    ...")
    rendered.append(f"L{idx + 1}: {lines[idx]}")
    prev = idx
  code_snippet = "\n".join(rendered)

  co = snippets.co_located_signals(app_dir, relpath)
  sinks = co.get("network_transmission", []) + co.get("disclosure", [])
  related = snippets.matching_lines(content, sinks) if sinks else []
  if related:
    code_snippet += "\n\n// Related data-flow lines in the same file:\n" + "\n".join(related)

  state = {
      "file": relpath,
      "signals": signals,
      "code_snippet": code_snippet,
      "co_located_signals": co,
      "related_lines": related,
      "app": app_facts,
  }
  return state, per_ask


def _namespace(index: int, battery: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
  return {f"a{index}__{qid}": question for qid, question in battery.items()}


def _denamespace(index: int, answers) -> Dict[str, Any]:
  prefix = f"a{index}__"
  return {qid[len(prefix):]: a for qid, a in answers.items() if qid.startswith(prefix)}


def run_batched(
    temp_dir: str,
    client: JevClient,
    model: Optional[str] = None,
) -> List[str]:
  """One request per file; writes the same ``worker_<goal>.json`` files as ``run``."""
  asks_by_file, goal_names, app_dir = plan_by_file(temp_dir)

  # App facts are shared across the whole app.
  any_input = sorted(glob.glob(os.path.join(temp_dir, "input_worker_*.json")))
  base_context = evaluate._load_json(any_input[0]) if any_input else {}  # pylint: disable=protected-access
  app_facts = evaluate._app_facts(base_context, temp_dir)  # pylint: disable=protected-access

  findings_by_goal: Dict[str, List[Dict[str, Any]]] = {g: [] for g in goal_names}

  for relpath, asks in sorted(asks_by_file.items()):
    state, per_ask = build_file_state(app_dir, relpath, asks, app_facts)

    questions: Dict[str, Dict[str, Any]] = {}
    for i, ask in enumerate(asks):
      questions.update(_namespace(i, ask.battery()))

    answers = client.system_one(state, questions, model=model)

    for i, ask in enumerate(asks):
      sub = _denamespace(i, answers)
      mini_state = per_ask[i]
      if ask.goal.startswith("permissions"):
        finding = evaluate._compose_permission_finding(  # pylint: disable=protected-access
            ask.data_type, ask.policy_id, mini_state, sub, client.name
        )
      else:
        finding = evaluate._compose_data_safety_finding(  # pylint: disable=protected-access
            ask.data_type, ask.finding_str, mini_state, sub, client.name
        )
      if finding:
        findings_by_goal[ask.goal].append(finding)

  # Deterministic (no-model) account-deletion findings, mirroring evaluate.run.
  _add_account_deletion(temp_dir, app_dir, app_facts, findings_by_goal)

  written: List[str] = []
  for goal in goal_names:
    domain = {
        "permissions_and_apis": "Permissions and APIs",
        "user_account": "User Account and Identity",
    }.get(goal, "Data Safety and Privacy")
    out = {"domain": domain, "findings": findings_by_goal.get(goal, [])}
    with open(os.path.join(temp_dir, f"worker_{goal}.json"), "w", encoding="utf-8") as f:
      json.dump(out, f, indent=2, sort_keys=True)
    written.append(goal)
  return written


def _add_account_deletion(temp_dir, app_dir, app_facts, findings_by_goal) -> None:
  from typesafe_eval import templates
  path = os.path.join(temp_dir, "input_worker_user_account.json")
  if not os.path.exists(path):
    return
  base = evaluate._load_json(path)  # pylint: disable=protected-access
  for data_type, finding_str, _ in evaluate._iter_findings(base):  # pylint: disable=protected-access
    if data_type == "ACCOUNT_DELETION":
      state = snippets.build_state(app_dir, finding_str, data_type, app_facts)
      findings_by_goal.setdefault("user_account", []).append({
          "policy_id": "account_deletion",
          "issue_summary": templates.issue_summary("account_deletion"),
          "severity": "SUGGESTION",
          "files_involved": [state["signal"]["file"]],
          "evidence": evaluate._evidence_line(state),  # pylint: disable=protected-access
          "recommendation": templates.recommendation("account_deletion", "SUGGESTION"),
          "client": "deterministic",
      })
