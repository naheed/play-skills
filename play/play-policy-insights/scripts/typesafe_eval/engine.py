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

The engine owns the workflow; policies are data (``registry.py``). One run is a
fixed cascade (see ``docs/capability-based-evaluation.md``):

1. **Load** the *raw* deterministic artifacts ``orchestrator.py init`` produced
   (``data_safety_scan.json``, ``manifest_details.json``,
   ``play_store_info.json``).
2. **Filter candidates** (deterministic, free): prioritize the Play build
   flavor, drop string-catalog resources, bound each data type at
   ``MAX_CANDIDATES_PER_TYPE`` raw signals.
3. **Structure** (deterministic, free): index every candidate file — imports,
   symbol references, and the project's declared dependencies.
4. **Semantics** (model, cached): classify the imported packages, then the
   individual imports inside transfer-capable packages, and the declared
   dependencies onto the capability taxonomy. Results are memoized in a
   persistent, human-reviewable cache so the cost amortizes across apps.
5. **Triage** (deterministic, free): anchor each candidate at the occurrence
   whose enclosing scope is nearest a capability-labelled sink and keep the
   top ``MAX_FINDINGS_PER_TYPE`` per data type (and ``MAX_PER_FILE_PER_TYPE``
   per file). Everything dropped is recorded with its rank and reason.
6. **Policy** (model, batched by file): run the registry batteries against the
   enriched state and compose findings in code (three-way transfer decision,
   relevance gate, decision trace). Manifest-kind policies run with no model
   call; the Play-declaration cross-check runs last over confirmed transfers.
7. **Write** the same ``worker_<goal>.json`` schema the rest of the pipeline
   consumes, plus ``typesafe_triage.json`` with every counter a reviewer needs
   to audit what was and was not sent to the model.

Every stage isolates failures: a bad file, a failed classification batch, or a
failed battery becomes a MANUAL_REVIEW finding or an UNKNOWN profile, never a
crash and never a silent drop.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import re
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

from typesafe_eval import capabilities as caps
from typesafe_eval import constants
from typesafe_eval import context
from typesafe_eval import evaluate
from typesafe_eval import registry
from typesafe_eval import snippets
from typesafe_eval import structure
from typesafe_eval import templates
from typesafe_eval.client import JevClient

log = logging.getLogger("typesafe_eval.engine")

_FLAVOR_RE = re.compile(r"/src/([^/]+)/")

_GOAL_DOMAIN = {
    "permissions_and_apis": "Permissions and APIs",
    "user_account": "User Account and Identity",
    "data_safety": "Data Safety and Privacy",
}

TRIAGE_FILENAME = "typesafe_triage.json"


@dataclasses.dataclass
class Candidate:
  """One raw scanner signal that survived candidate filtering."""

  data_type: str
  finding_str: str
  relpath: str
  pattern: str
  order: int                                 # position in scanner output
  anchor: Optional[context.Anchor] = None    # filled by triage


@dataclasses.dataclass
class Task:
  """One (policy, candidate) unit of model work."""

  spec: registry.PolicySpec
  data_type: str
  finding_str: str
  relpath: str
  pattern: str = ""


@dataclasses.dataclass
class RunContext:
  """Everything the stages share for one app run."""

  temp_dir: str
  app_dir: str
  app_facts: Dict[str, Any]
  manifest: Dict[str, Any]
  files: Dict[str, structure.FileStructure] = dataclasses.field(default_factory=dict)
  profiles: Dict[str, caps.CapabilityProfile] = dataclasses.field(default_factory=dict)
  dependency_profiles: Dict[str, caps.CapabilityProfile] = dataclasses.field(default_factory=dict)
  counters: Dict[str, Any] = dataclasses.field(default_factory=dict)
  dropped: List[Dict[str, Any]] = dataclasses.field(default_factory=list)


# ---------------------------------------------------------------------------
# Stage 1: load
# ---------------------------------------------------------------------------


def _load_json(path: str) -> dict:
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception as exc:  # pylint: disable=broad-exception-caught
    log.debug("could not read %s: %s", path, exc)
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


# ---------------------------------------------------------------------------
# Stage 2: candidate filtering (deterministic)
# ---------------------------------------------------------------------------


def _excluded_flavors(data_sources: Dict[str, List[str]]) -> set:
  """Non-prioritized product flavors, only when a ``play`` flavor exists."""
  flavors = set()
  for findings in data_sources.values():
    if isinstance(findings, list):
      for f in findings:
        m = _FLAVOR_RE.search("/" + f)
        if m:
          flavors.add(m.group(1))
  prioritized = set(constants.PRIORITIZED_FLAVORS)
  return (flavors - prioritized) if ("play" in flavors) else set()


def _filter_candidates(
    data_sources: Dict[str, List[str]], ctx: Optional[RunContext] = None
) -> Dict[str, List[Candidate]]:
  """Stage 2: flavor + resource filtering and the raw per-type cost bound.

  Unlike the previous "first N in scanner order" cap, this keeps up to
  ``MAX_CANDIDATES_PER_TYPE`` signals so triage can *rank* them by sink
  proximity before the much smaller model cap is applied.
  """
  excluded = _excluded_flavors(data_sources)
  out: Dict[str, List[Candidate]] = {}
  raw = 0
  for data_type, findings in data_sources.items():
    if not isinstance(findings, list):
      continue
    kept: List[Candidate] = []
    for order, f in enumerate(findings):
      raw += 1
      path = "/" + f
      if any(f"/src/{flavor}/" in path for flavor in excluded):
        _drop(ctx, data_type, f, "non-prioritized build flavor")
        continue
      if any(frag in path for frag in constants.EXCLUDED_PATH_SUBSTRINGS):
        _drop(ctx, data_type, f, "excluded path (string-catalog resource or test source set)")
        continue
      if len(kept) >= constants.MAX_CANDIDATES_PER_TYPE:
        _drop(ctx, data_type, f, f"over MAX_CANDIDATES_PER_TYPE={constants.MAX_CANDIDATES_PER_TYPE}")
        continue
      relpath, pattern = snippets.parse_finding(f)
      kept.append(Candidate(data_type, f, relpath or f, pattern or "", order))
    if kept:
      out[data_type] = kept
  if ctx is not None:
    ctx.counters["raw_signals"] = raw
    ctx.counters["candidates"] = sum(len(v) for v in out.values())
    ctx.counters["excluded_flavors"] = sorted(excluded)
  log.info("candidates: %d raw signals -> %d candidates across %d data types",
           raw, sum(len(v) for v in out.values()), len(out))
  return out


def _drop(ctx: Optional[RunContext], data_type: str, finding_str: str, reason: str,
          **extra: Any) -> None:
  if ctx is None:
    return
  ctx.dropped.append({"data_type": data_type, "finding": finding_str, "reason": reason, **extra})


# ---------------------------------------------------------------------------
# Stage 3 + 4: structure and semantics
# ---------------------------------------------------------------------------


def _first_party_packages(
    manifest: Dict[str, Any], files: Dict[str, structure.FileStructure]
) -> Tuple[str, ...]:
  """Packages that are the app's own code (never classified as a sink).

  Two deterministic sources, both language-level facts rather than guesses:
  the manifest package (may be wrong when ``init`` picked up a library
  manifest) and every ``package`` declared by an analysed source file. An
  import is first-party when it *is* one of these packages, sits directly in
  one (``package_of(import)`` matches), or lies beneath one (``pkg.``). Sibling
  first-party libraries under an unrelated namespace are deliberately *not*
  excluded: whether they transmit is exactly the question the semantic layer
  should answer.
  """
  pkgs = {(manifest.get("package_name") or "").strip()}
  pkgs.update(fs.package for fs in files.values() if fs.package)
  return tuple(sorted(p for p in pkgs if p))


def _is_first_party(mod: str, packages: Sequence[str]) -> bool:
  pkg = structure.package_of(mod)
  return any(mod == p or pkg == p or mod.startswith(p + ".") for p in packages)


def _analyze_files(ctx: RunContext, candidates: Dict[str, List[Candidate]]) -> None:
  """Stage 3: structural index of every candidate file (deterministic)."""
  relpaths = sorted({c.relpath for cs in candidates.values() for c in cs})
  for rp in relpaths:
    ctx.files[rp] = structure.analyze_file(ctx.app_dir, rp)
  ctx.counters["files_analyzed"] = len(relpaths)
  ctx.counters["files_unreadable"] = sum(1 for fs in ctx.files.values() if not fs.lines)
  log.info("structure: %d files indexed (%d unreadable)",
           len(relpaths), ctx.counters["files_unreadable"])


def _classify_semantics(
    ctx: RunContext,
    client: JevClient,
    cache: Optional[caps.CapabilityCache],
    model: Optional[str],
) -> None:
  """Stage 4: capability profiles for imports (package -> class) and dependencies.

  Package-level first: a package the model confidently says provides no
  transfer capability prunes all of its classes in one answer (they inherit the
  package profile with ``source="package"``). Only packages that are transfer-
  capable or UNKNOWN are refined to class level, where the profile actually
  drives sink detection and proximity ranking.
  """
  first_party = _first_party_packages(ctx.manifest, ctx.files)
  imports: List[str] = []
  skipped_first_party = 0
  for fs in ctx.files.values():
    for mod in fs.imports:
      if _is_first_party(mod, first_party):
        skipped_first_party += 1
        continue
      if mod not in imports:
        imports.append(mod)
  packages = sorted({structure.package_of(m) for m in imports})
  ctx.counters["first_party_packages"] = list(first_party)
  ctx.counters["imports_first_party_skipped"] = skipped_first_party
  ctx.counters["imports_third_party"] = len(imports)
  ctx.counters["packages"] = len(packages)

  pkg_profiles = caps.classify(
      [{"identifier": p, "kind": "package"} for p in packages],
      client, cache, ctx.app_facts, model=model,
  )
  refine = [m for m in imports
            if (pkg_profiles.get(structure.package_of(m)) or _unknown(m)).is_transfer_sink]
  ctx.counters["imports_refined"] = len(refine)
  cls_profiles = caps.classify(
      [{"identifier": m, "kind": "import"} for m in refine],
      client, cache, ctx.app_facts, model=model,
  )
  for m in imports:
    if m in cls_profiles:
      ctx.profiles[m] = cls_profiles[m]
      continue
    pkg = pkg_profiles.get(structure.package_of(m))
    if pkg is None:
      ctx.profiles[m] = _unknown(m)
      continue
    ctx.profiles[m] = caps.CapabilityProfile(
        identifier=m, kind="import", probabilities=dict(pkg.probabilities),
        labels=list(pkg.labels), source=f"package:{pkg.source}", model=pkg.model,
        taxonomy_version=pkg.taxonomy_version, recorded_at=pkg.recorded_at,
    )

  deps = structure.dependency_inventory(ctx.app_dir) if ctx.app_dir else []
  ctx.dependency_profiles = caps.classify(
      [{"identifier": d.coordinate, "kind": "dependency"} for d in deps],
      client, cache, ctx.app_facts, model=model,
  )
  declared = sorted({
      l for p in ctx.dependency_profiles.values() for l in p.labels
  })
  # App-level context for the battery: which capability classes the project
  # declares at all (e.g. no ADVERTISING_SDK dependency anywhere).
  ctx.app_facts["declared_capabilities"] = declared
  ctx.counters["dependencies"] = len(deps)
  if cache is not None:
    ctx.counters["capability_cache"] = {"hits": cache.hits, "misses": cache.misses,
                                        "entries": len(cache), "path": cache.path}
  log.info("semantics: %d packages, %d imports refined, %d dependencies; declared caps=%s",
           len(packages), len(refine), len(deps), declared)


def _unknown(identifier: str) -> caps.CapabilityProfile:
  return caps.CapabilityProfile(identifier, "import", {}, [caps.UNKNOWN], "missing", None)


# ---------------------------------------------------------------------------
# Stage 5: triage (deterministic ranking + caps)
# ---------------------------------------------------------------------------


def _triage(ctx: RunContext, candidates: Dict[str, List[Candidate]]) -> Dict[str, List[Candidate]]:
  """Ranks candidates by sink proximity and applies the model caps.

  Rank key (``context.rank_key``): a sink reference inside the hit's own scope
  first, then nearest sink distance, then scanner order. Per-file and per-type
  caps then apply. Dropped candidates are recorded with their rank so a reviewer
  can see exactly what was not evaluated and why.
  """
  sinks_by_file: Dict[str, List[context.Sink]] = {}
  for rp, fs in ctx.files.items():
    sinks_by_file[rp] = context.file_sinks(fs, ctx.profiles)

  kept: Dict[str, List[Candidate]] = {}
  for data_type, cands in candidates.items():
    for c in cands:
      fs = ctx.files[c.relpath]
      c.anchor = context.anchor_signal(fs, c.pattern, data_type, sinks_by_file[c.relpath])
    ranked = sorted(cands, key=lambda c: context.rank_key(c.anchor, c.order))
    per_file: Dict[str, int] = {}
    out: List[Candidate] = []
    for rank, c in enumerate(ranked):
      why = None
      if len(out) >= constants.MAX_FINDINGS_PER_TYPE:
        why = f"over MAX_FINDINGS_PER_TYPE={constants.MAX_FINDINGS_PER_TYPE}"
      elif per_file.get(c.relpath, 0) >= constants.MAX_PER_FILE_PER_TYPE:
        why = f"over MAX_PER_FILE_PER_TYPE={constants.MAX_PER_FILE_PER_TYPE}"
      if why:
        _drop(ctx, data_type, c.finding_str, why, rank=rank, tier=c.anchor.tier,
              sink_in_scope=c.anchor.sink_in_scope, proximity=c.anchor.proximity,
              scope_capabilities=c.anchor.scope_capabilities)
        continue
      out.append(c)
      per_file[c.relpath] = per_file.get(c.relpath, 0) + 1
    if out:
      kept[data_type] = out
  ctx.counters["kept_per_type"] = {dt: len(v) for dt, v in sorted(kept.items())}
  ctx.counters["kept"] = sum(len(v) for v in kept.values())
  ctx.counters["files_with_sinks"] = sum(1 for s in sinks_by_file.values() if s)
  log.info("triage: kept %d of %d candidates (%d files have labelled sinks)",
           ctx.counters["kept"], ctx.counters.get("candidates", 0),
           ctx.counters["files_with_sinks"])
  return kept


# ---------------------------------------------------------------------------
# Backward-compatible helpers (older callers and tests)
# ---------------------------------------------------------------------------


def _reduce_noise(data_sources: Dict[str, List[str]]) -> Dict[str, List[str]]:
  """Legacy scanner-order cap (flavor, resource, per-file, per-type).

  Kept for callers that only have raw signals and no app source (e.g. ``plan``).
  The engine itself uses :func:`_filter_candidates` + :func:`_triage`.
  """
  excluded = _excluded_flavors(data_sources)
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
  """Turns raw signals into per-(policy, finding) tasks via the registry.

  Source-free planning (scanner order); the engine plans from triaged
  candidates instead (:func:`_plan_from_candidates`).
  """
  tasks: List[Task] = []
  specs = registry.code_signal_specs() + registry.deterministic_specs()
  for data_type, findings in _reduce_noise(data_sources).items():
    for finding_str in findings:
      relpath, pattern = snippets.parse_finding(finding_str)
      for spec in specs:
        if spec.applies_data_type(data_type):
          tasks.append(Task(spec, data_type, finding_str, relpath or finding_str, pattern or ""))
  return tasks


def _plan_from_candidates(kept: Dict[str, List[Candidate]]) -> List[Task]:
  tasks: List[Task] = []
  specs = registry.code_signal_specs() + registry.deterministic_specs()
  for data_type, cands in kept.items():
    for c in cands:
      for spec in specs:
        if spec.applies_data_type(data_type):
          tasks.append(Task(spec, data_type, c.finding_str, c.relpath, c.pattern))
  return tasks


# ---------------------------------------------------------------------------
# Stage 6: policy evaluation
# ---------------------------------------------------------------------------


def _description(data_type: str) -> str:
  return evaluate._taxonomy().get(data_type, {}).get("description", "")  # pylint: disable=protected-access


def _error_finding(task: Task, mini_state: Dict[str, Any], exc: Exception) -> Dict[str, Any]:
  """A recall-safe placeholder when evaluation fails: surface, do not drop."""
  file = (mini_state.get("signal") or {}).get("file", task.relpath)
  log.warning("evaluation failed for %s in %s: %s", task.data_type, file, exc)
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
      "decision_trace": {"evaluator_version": constants.EVALUATOR_VERSION,
                         "error": str(exc)[:200]},
  }


def _compose_task(task: Task, mini_state: Dict[str, Any], answers, client_name: str):
  try:
    return task.spec.compose(
        task.data_type, task.finding_str, mini_state, answers, client_name
    )
  except Exception as exc:  # pylint: disable=broad-exception-caught
    return _error_finding(task, mini_state, exc)


def _run_deterministic(ctx: RunContext, tasks: Sequence[Task], client: JevClient,
                       model: Optional[str], findings_by_goal) -> None:
  """Deterministic policies: no battery, but an optional false-positive gate."""
  for task in tasks:
    state = snippets.build_state(ctx.app_dir, task.finding_str, task.data_type, ctx.app_facts)
    if task.spec.gate_battery is not None:
      try:
        gate = client.system_one(
            state, task.spec.gate_battery(task.data_type, _description(task.data_type)),
            model=model,
        )
        passed = (gate[task.spec.gate_key].noul or 0.0) >= task.spec.gate_threshold
      except Exception as exc:  # pylint: disable=broad-exception-caught
        log.warning("gate call failed for %s (%s); keeping finding", task.data_type, exc)
        passed = True  # recall-safe: keep the finding if the gate call failed
      if not passed:
        _drop(ctx, task.data_type, task.finding_str, f"{task.spec.gate_key} gate below threshold")
        continue
    try:
      finding = task.spec.compose_deterministic(task.data_type, task.finding_str, state)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      finding = _error_finding(task, state, exc)
    if finding:
      findings_by_goal[task.spec.goal].append(finding)


def _run_manifest(ctx: RunContext, findings_by_goal) -> None:
  """Manifest-kind policies: app-level facts, no model call."""
  for spec in registry.manifest_specs():
    try:
      found = spec.compose_manifest(ctx.manifest) if spec.compose_manifest else []
    except Exception as exc:  # pylint: disable=broad-exception-caught
      log.warning("manifest policy %s failed: %s", spec.policy_id, exc)
      found = [{
          "policy_id": spec.policy_id,
          "issue_summary": "Manifest check failed; manual review required",
          "severity": "IMPORTANT", "files_involved": ["AndroidManifest.xml"],
          "evidence": str(exc)[:200], "recommendation": "Review the manifest manually.",
          "client": "error", "needs_manual_review": True,
      }]
    findings_by_goal[spec.goal].extend(found)
    ctx.counters.setdefault("manifest_findings", {})[spec.policy_id] = len(found)


def _file_state(ctx: RunContext, relpath: str, file_tasks: Sequence[Task]):
  fs = ctx.files.get(relpath) or structure.analyze_file(ctx.app_dir, relpath)
  asks = [(t.data_type, t.pattern) for t in file_tasks]
  return context.build_file_state(fs, asks, ctx.profiles, ctx.app_facts, ctx.app_dir)


def _run_batched(ctx: RunContext, tasks: Sequence[Task], client: JevClient,
                 model: Optional[str], findings_by_goal) -> None:
  """One request per (file, chunk of asks); question ids namespaced ``a<i>__``."""
  by_file: Dict[str, List[Task]] = {}
  for task in tasks:
    by_file.setdefault(task.relpath, []).append(task)

  requests = 0
  for relpath, file_tasks in sorted(by_file.items()):
    for start in range(0, len(file_tasks), constants.MAX_ASKS_PER_REQUEST):
      chunk = file_tasks[start:start + constants.MAX_ASKS_PER_REQUEST]
      state, per_task = _file_state(ctx, relpath, chunk)
      questions: Dict[str, Any] = {}
      for i, task in enumerate(chunk):
        battery = task.spec.make_battery(task.data_type, _description(task.data_type), task.pattern)
        questions.update({f"a{i}__{qid}": qd for qid, qd in battery.items()})
      requests += 1
      try:
        answers = client.system_one(state, questions, model=model)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        # One file's failure is isolated: mark its tasks for review, keep scanning.
        for i, task in enumerate(chunk):
          findings_by_goal[task.spec.goal].append(_error_finding(task, per_task[i], exc))
        continue
      for i, task in enumerate(chunk):
        prefix = f"a{i}__"
        sub = {qid[len(prefix):]: a for qid, a in answers.items() if qid.startswith(prefix)}
        finding = _compose_task(task, per_task[i], sub, client.name)
        if finding:
          findings_by_goal[task.spec.goal].append(finding)
        else:
          _drop(ctx, task.data_type, task.finding_str,
                f"{task.spec.policy_id}: compliant or relevance gate")
  ctx.counters["battery_requests"] = requests


def _run_per_finding(ctx: RunContext, tasks: Sequence[Task], client: JevClient,
                     model: Optional[str], findings_by_goal) -> None:
  """One request per (policy, finding); the state is the per-ask mini-state."""
  requests = 0
  for task in tasks:
    _, per_task = _file_state(ctx, task.relpath, [task])
    state = per_task[0]
    battery = task.spec.make_battery(task.data_type, _description(task.data_type), task.pattern)
    requests += 1
    try:
      answers = client.system_one(state, battery, model=model)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      findings_by_goal[task.spec.goal].append(_error_finding(task, state, exc))
      continue
    finding = _compose_task(task, state, answers, client.name)
    if finding:
      findings_by_goal[task.spec.goal].append(finding)
    else:
      _drop(ctx, task.data_type, task.finding_str,
            f"{task.spec.policy_id}: compliant or relevance gate")
  ctx.counters["battery_requests"] = requests


def _declared_types(store: dict) -> List[str]:
  """Flattens a Play declaration into declared type + category names."""
  ds = store.get("data_safety", {}) or {}
  declared = []
  for section in ("data_collected", "data_shared"):
    for cat in ds.get(section, []) or []:
      if cat.get("category"):
        declared.append(cat["category"])
      for t in cat.get("types", []) or []:
        if t.get("type"):
          declared.append(t["type"])
  return sorted(set(declared))


def _run_play_declaration(ctx: RunContext, spec, client, model, findings_by_goal) -> None:
  """Flag detected, *confirmed* transmitted data types the declaration omits.

  Only findings whose transfer decision is TRANSMITS participate: an UNCERTAIN
  transfer is already routed to manual review and must not additionally assert
  a declaration mismatch. Skips when there is no usable declaration (unpublished
  app, or a ``play_store_info.json`` without a ``data_safety`` block — a missing
  block is a scrape failure, not a "no data collected" declaration).
  """
  store = _load_json(os.path.join(ctx.temp_dir, "play_store_info.json"))
  if not store or not store.get("is_published", False):
    log.info("play_declaration: skipped (app not published / no store info)")
    return
  if "data_safety" not in store:
    log.info("play_declaration: skipped (store info has no data_safety block)")
    return
  declared = _declared_types(store)

  transmitted = {}
  for finding in list(findings_by_goal.get(spec.goal, [])):
    if (finding.get("is_transferred") and finding.get("psl_constant")
        and finding.get("transfer_decision", evaluate.TRANSMITS) == evaluate.TRANSMITS):
      transmitted.setdefault(finding["psl_constant"], finding)

  mismatches = 0
  for data_type, finding in sorted(transmitted.items()):
    name = evaluate._taxonomy().get(data_type, {}).get("data_type", data_type)  # pylint: disable=protected-access
    state = {
        "detected": {"data_type": data_type, "name": name,
                     "evidence": (finding.get("files_involved") or [""])[0]},
        "declaration": {"declared": declared,
                        "is_published": store.get("is_published")},
    }
    try:
      answers = client.system_one(state, spec.make_battery(data_type, name), model=model)
      covers = answers["declaration_covers"].noul or 0.0
    except Exception as exc:  # pylint: disable=broad-exception-caught
      log.warning("play_declaration coverage call failed for %s: %s", data_type, exc)
      continue  # a failed coverage check should not fabricate a mismatch
    if covers < constants.T_DECLARATION_COVERS:
      mismatches += 1
      findings_by_goal[spec.goal].append({
          "policy_id": spec.policy_id,
          "psl_constant": data_type,
          "issue_summary": templates.declaration_mismatch_summary(name),
          "severity": "IMPORTANT",
          "files_involved": finding.get("files_involved", []),
          "evidence": f"Detected transmission of {name}; declaration lists: "
                      f"{', '.join(declared) or '(none)'}",
          "recommendation": templates.declaration_mismatch_recommendation(name),
          "client": client.name,
          "kind": "play_declaration",
          "decision_trace": {
              "evaluator_version": constants.EVALUATOR_VERSION,
              "declaration_covers": round(covers, 4),
              "T_DECLARATION_COVERS": constants.T_DECLARATION_COVERS,
              "source_transfer_decision": finding.get("transfer_decision"),
          },
      })
  ctx.counters["play_declaration"] = {"transmitted_types": len(transmitted),
                                      "mismatches": mismatches}


# ---------------------------------------------------------------------------
# Stage 7: write
# ---------------------------------------------------------------------------


def _write_triage(ctx: RunContext, findings_by_goal, client: JevClient) -> str:
  """The observability record: what was evaluated, what was not, and why."""
  severities: Dict[str, int] = {}
  decisions: Dict[str, int] = {}
  for fs in findings_by_goal.values():
    for f in fs:
      severities[f.get("severity", "?")] = severities.get(f.get("severity", "?"), 0) + 1
      d = f.get("transfer_decision")
      if d:
        decisions[d] = decisions.get(d, 0) + 1
  out = {
      "evaluator_version": constants.EVALUATOR_VERSION,
      "client": client.name,
      "counters": ctx.counters,
      "findings_by_severity": severities,
      "transfer_decisions": decisions,
      "capabilities": caps.summarize(ctx.profiles),
      "dependency_capabilities": {
          k: v.labels for k, v in sorted(ctx.dependency_profiles.items())
      },
      "sinks_by_file": {
          rp: [{"symbol": s.symbol, "module": s.module, "capabilities": s.capabilities,
                "lines": [l + 1 for l in s.lines]}
               for s in context.file_sinks(fs, ctx.profiles)]
          for rp, fs in sorted(ctx.files.items())
          if context.file_sinks(fs, ctx.profiles)
      },
      "thresholds": {
          "T_TRANSMIT_LOW": constants.T_TRANSMIT_LOW,
          "T_TRANSMIT_HIGH": constants.T_TRANSMIT_HIGH,
          "T_RELEVANCE": constants.T_RELEVANCE,
          "T_CAPABILITY": constants.T_CAPABILITY,
          "provenance": constants.THRESHOLD_PROVENANCE,
      },
      "usage": {"requests": client.request_count,
                "input_tokens": client.total_input_tokens,
                "output_tokens": client.total_output_tokens},
      "dropped": ctx.dropped,
  }
  path = os.path.join(ctx.temp_dir, TRIAGE_FILENAME)
  with open(path, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, sort_keys=True, default=str)
  return path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run(
    temp_dir: str,
    client: JevClient,
    model: Optional[str] = None,
    batched: bool = True,
    capability_cache: Optional[caps.CapabilityCache] = None,
) -> List[str]:
  """Evaluates all registry policies for an app and writes worker files.

  Args:
    temp_dir: Scratch dir produced by ``orchestrator.py init``.
    client: The Jev client (HTTP or the offline heuristic stand-in).
    model: Model id recorded in the cache key and sent with each request.
    batched: One request per file chunk (default) or one per finding.
    capability_cache: Persistent capability memo. ``None`` disables caching
      (every identifier is classified in this run; used by hermetic tests).

  Returns:
    The goal names whose ``worker_<goal>.json`` was written.
  """
  data_sources, manifest, app_facts, app_dir = load_artifacts(temp_dir)
  ctx = RunContext(temp_dir, app_dir, app_facts, manifest)
  ctx.counters["evaluator_version"] = constants.EVALUATOR_VERSION
  ctx.counters["model"] = model
  log.info("run: app=%s package=%s app_dir=%s client=%s batched=%s",
           app_facts.get("name"), app_facts.get("package"), app_dir, client.name, batched)

  candidates = _filter_candidates(data_sources, ctx)
  _analyze_files(ctx, candidates)
  _classify_semantics(ctx, client, capability_cache, model)
  kept = _triage(ctx, candidates)
  tasks = _plan_from_candidates(kept)
  ctx.counters["tasks"] = len(tasks)

  findings_by_goal: Dict[str, List[Dict[str, Any]]] = {g: [] for g in registry.goals()}
  code_tasks = [t for t in tasks if t.spec.kind == registry.CODE_SIGNAL]
  det_tasks = [t for t in tasks if t.spec.kind == registry.DETERMINISTIC]

  _run_deterministic(ctx, det_tasks, client, model, findings_by_goal)
  _run_manifest(ctx, findings_by_goal)
  if batched:
    _run_batched(ctx, code_tasks, client, model, findings_by_goal)
  else:
    _run_per_finding(ctx, code_tasks, client, model, findings_by_goal)
  for spec in registry.play_declaration_specs():
    _run_play_declaration(ctx, spec, client, model, findings_by_goal)

  written: List[str] = []
  for goal in registry.goals():
    out = {
        "domain": _GOAL_DOMAIN.get(goal, "Data Safety and Privacy"),
        "findings": findings_by_goal.get(goal, []),
        "evaluator_version": constants.EVALUATOR_VERSION,
    }
    with open(os.path.join(temp_dir, f"worker_{goal}.json"), "w", encoding="utf-8") as f:
      json.dump(out, f, indent=2, sort_keys=True)
    written.append(goal)
  triage_path = _write_triage(ctx, findings_by_goal, client)
  log.info("run complete: %d findings, %d dropped, triage -> %s",
           sum(len(v) for v in findings_by_goal.values()), len(ctx.dropped), triage_path)
  return written
