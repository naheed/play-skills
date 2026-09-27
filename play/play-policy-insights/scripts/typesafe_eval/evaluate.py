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

"""Compose Jev answers into the existing ``worker_<goal>.json`` schema.

This is the Phase-2 replacement: instead of an agent reading ``prompt_worker_*``
and writing findings, this reads the per-goal input that ``orchestrator.py init``
already produced (``input_worker_<goal>.json``), asks Jev a fixed battery per
finding, and writes the same ``worker_<goal>.json`` the downstream
``aggregate`` / ``generate_report.py`` steps consume — so nothing else in the
pipeline changes.

All routing/threshold logic lives in code (``constants.py``); Jev only supplies
the calibrated per-question answers.
"""

from __future__ import annotations

import functools
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
from typesafe_eval import questions as q
from typesafe_eval import snippets
from typesafe_eval import templates
from typesafe_eval.client import JevAnswer
from typesafe_eval.client import JevClient

log = logging.getLogger("typesafe_eval.evaluate")

# Data types that map onto a permission-hygiene policy (Permissions & APIs goal).
PERMISSION_POLICY = {
    "PRECISE_LOCATION": "location_access_policy",
    "APPROX_LOCATION": "location_access_policy",
    "CONTACTS": "contacts_access_policy",
    "AUDIO": "audio_recording_policy",
}

# Taxonomy categories whose data is considered linked to a user by default.
_LINKED_CATEGORIES = {
    "Personal info",
    "Location",
    "Financial info",
    "Health and fitness",
    "Contacts",
    "Messages",
    "Photos and videos",
    "Audio files",
}


def _repo_root() -> str:
  return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@functools.lru_cache(maxsize=1)
def _taxonomy() -> Dict[str, dict]:
  path = os.path.join(_repo_root(), "resources", "policies.json")
  try:
    with open(path, "r", encoding="utf-8") as f:
      data = json.load(f)
    return data.get("data_safety_section", {}).get("taxonomy", {})
  except Exception:  # pylint: disable=broad-exception-caught
    return {}


# Transfer decisions produced by :func:`transfer_decision`.
TRANSMITS = "TRANSMITS"
LOCAL = "LOCAL"
UNCERTAIN = "UNCERTAIN"


def transfer_decision(p_transmit: float) -> str:
  """Three-way decision on the calibrated transfer probability.

  ``p >= T_TRANSMIT_HIGH`` -> TRANSMITS; ``p < T_TRANSMIT_LOW`` -> LOCAL;
  otherwise UNCERTAIN. UNCERTAIN findings are never silently downgraded: they are
  emitted at IMPORTANT and routed to MANUAL_REVIEW by the critic, so the report
  lands on "Needs review" rather than a false "Compliant". This is the fix for
  the single 0.55 cliff that turned 0.52/0.54 answers on real transmissions into
  local-only suggestions.
  """
  if p_transmit >= constants.T_TRANSMIT_HIGH:
    return TRANSMITS
  if p_transmit < constants.T_TRANSMIT_LOW:
    return LOCAL
  return UNCERTAIN


def derive_data_safety_severity(
    data_type: str, transmits: bool, disclosure_status: str, decision: str = ""
) -> str:
  """Severity for a data-safety finding, composed in code from Jev's booleans.

  Local-only or properly disclosed/exempt collection is a SUGGESTION (inventory).
  Undisclosed off-device transfer is CRITICAL for sensitive data types and
  IMPORTANT otherwise. An UNCERTAIN transfer is capped at IMPORTANT: it must be
  reviewed, but the evaluator does not assert a Critical it cannot support.
  """
  if decision == UNCERTAIN:
    if disclosure_status in ("DISCLOSED", "EXEMPT"):
      return "SUGGESTION"
    return "IMPORTANT"
  if not transmits:
    return "SUGGESTION"
  if disclosure_status in ("DISCLOSED", "EXEMPT"):
    return "SUGGESTION"
  return "CRITICAL" if data_type in constants.SENSITIVE_DATA_TYPES else "IMPORTANT"


def _decision_trace(
    state: Dict[str, Any],
    answers: Dict[str, JevAnswer],
    decision: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
  """Auditable record of *why* a finding was composed the way it was.

  Every score the decision used, the thresholds it was compared against (with
  provenance), the capability-labelled sinks in scope, the anchor the snippet
  was built from, and the evaluator version. Downstream ignores unknown keys, so
  this rides along in ``worker_<goal>.json`` and into the critic input.
  """
  anchor = state.get("anchor") or {}
  sinks = state.get("sinks") or []
  scores = {qid: a.noul for qid, a in answers.items() if a.type == "noul"}
  trace: Dict[str, Any] = {
      "evaluator_version": constants.EVALUATOR_VERSION,
      "scores": {k: (round(v, 4) if v is not None else None) for k, v in scores.items()},
      "thresholds": {
          "T_TRANSMIT_LOW": constants.T_TRANSMIT_LOW,
          "T_TRANSMIT_HIGH": constants.T_TRANSMIT_HIGH,
          "T_RELEVANCE": constants.T_RELEVANCE,
          "T_RELEVANCE_FLOOR": constants.T_RELEVANCE_FLOOR,
          "T_DISCLOSURE": constants.T_DISCLOSURE,
          "T_THIRD_PARTY": constants.T_THIRD_PARTY,
          "provenance": constants.THRESHOLD_PROVENANCE,
      },
      "anchor": {
          "line": (state.get("signal") or {}).get("line"),
          "all_lines": (state.get("signal") or {}).get("all_lines"),
          "scope": anchor.get("scope"),
          "sink_proximity": anchor.get("proximity"),
          "sink_in_scope": anchor.get("sink_in_scope"),
          "scope_capabilities": anchor.get("scope_capabilities"),
          "rank_tier": anchor.get("tier"),
          "lexical": anchor.get("lexical"),
      },
      "sinks": [
          {"symbol": s.get("symbol"), "capabilities": s.get("capabilities")} for s in sinks
      ],
  }
  if decision is not None:
    trace["transfer_decision"] = decision
  if extra:
    trace.update(extra)
  return trace


def _relevant(answers: Dict[str, JevAnswer]) -> Tuple[bool, Optional[float]]:
  """Semantic match gate. Missing answer (older batteries) counts as relevant."""
  a = answers.get("signal_relevant")
  if a is None or a.noul is None:
    return True, None
  return a.noul >= constants.T_RELEVANCE, a.noul


RELEVANT = "relevant"
RELEVANCE_LOW_WITH_SINK = "low_with_sink"
RELEVANCE_DROP = "drop"


def relevance_verdict(answers: Dict[str, JevAnswer], state: Dict[str, Any]) -> Tuple[str, Optional[float]]:
  """Soft relevance gate (WP2).

  The lexical pre-gate now removes coincidental substring hits before any model
  call, so ``signal_relevant`` is left with genuinely semantic questions
  (``record`` as a database row vs. an audio recording). A model judgement
  below ``T_RELEVANCE`` is allowed to *suppress* a finding only when the
  anchor's own scope has no capability-labelled egress or IPC sink (rank tier
  2 or 3). When such a sink is in scope the code demonstrably hands data to a
  transfer channel; the finding is kept, capped at IMPORTANT, flagged for
  manual review and traced as ``relevance="low"``. This follows the charter
  rule that a finding is never suppressed by judgement alone, and closed two
  labelled recall losses caused by relevance answers moving with batch
  composition. Rollback: ``constants.RELEVANCE_SOFT_GATE_ENABLED = False``.

  The soft path applies only to *uncertain* answers: when ``p`` is below
  ``T_RELEVANCE_FLOOR`` the model is confidently negative and the finding is
  dropped even with a sink in scope (a database ``record`` next to an HTTP
  client is not an audio recording). The floor keeps the review queue for
  genuinely ambiguous matches rather than lexical coincidences.

  Returns ``(verdict, p_relevant)`` with verdict one of :data:`RELEVANT`,
  :data:`RELEVANCE_LOW_WITH_SINK`, :data:`RELEVANCE_DROP`.
  """
  relevant, p = _relevant(answers)
  if relevant:
    return RELEVANT, p
  tier = (state.get("anchor") or {}).get("tier")
  if (
      constants.RELEVANCE_SOFT_GATE_ENABLED
      and tier is not None
      and tier <= 1
      and p is not None
      and p >= constants.T_RELEVANCE_FLOOR
  ):
    return RELEVANCE_LOW_WITH_SINK, p
  return RELEVANCE_DROP, p


def reconcile_disclosure_status(
    status: str, answers: Dict[str, JevAnswer], transmits: bool, user_initiated: bool
) -> Tuple[str, Optional[str]]:
  """Cross-checks the ``disclosure_status`` Choice against the battery's own Nouls.

  The battery asks the disclosure question twice in different forms: a Noul
  ``has_prominent_disclosure`` (P(a gate is shown before the data is used))
  and a three-way Choice ``disclosure_status``. When the two disagree the
  Choice is the less reliable of the pair (it moves with snippet composition;
  a wider anchor scope flipped a labelled media-sharing transfer from
  ``MISSING`` to ``DISCLOSED`` while ``has_prominent_disclosure`` stayed at
  0.18), so the composer falls back to the recall-safe reading:

  * ``DISCLOSED`` with ``has_prominent_disclosure < T_DISCLOSURE`` -> ``MISSING``.
    A disclosure the model itself does not believe exists cannot excuse the
    transfer; the finding is routed to review instead of being downgraded.
  * ``EXEMPT`` on an off-device transfer that is *not* user-initiated ->
    ``MISSING``. The Choice's own criterion for EXEMPT is "stays on-device or
    obvious core functionality the user initiated"; neither holds.

  Returns ``(status, note)`` where ``note`` is None when nothing changed and
  otherwise a short trace string (``"DISCLOSED->MISSING (p_disclosure=0.18)"``).
  ``LOCAL`` decisions never reach this function (they are EXEMPT in code).
  """
  a = answers.get("has_prominent_disclosure")
  p = a.noul if a is not None else None
  if status == "DISCLOSED" and p is not None and p < constants.T_DISCLOSURE:
    return "MISSING", f"DISCLOSED->MISSING (p_disclosure={p:.2f} < T_DISCLOSURE={constants.T_DISCLOSURE})"
  if status == "EXEMPT" and transmits and not user_initiated:
    return "MISSING", "EXEMPT->MISSING (transfer is not user-initiated)"
  return status, None


def derive_permission_severity(
    policy_id: str, is_core: bool, has_disclosure: bool, transmits: bool
) -> Optional[str]:
  """Severity for a permission-hygiene finding, or None when compliant.

  Core functionality with a disclosure is compliant (None). Core without a
  disclosure is a SUGGESTION to add one. A non-core use of a restricted
  permission is IMPORTANT, escalating to CRITICAL when data is also transmitted
  off-device without disclosure.
  """
  if is_core and has_disclosure:
    return None
  if is_core:
    return "SUGGESTION"
  if policy_id in constants.HIGH_RISK_PERMISSION_POLICIES:
    if transmits and not has_disclosure:
      return "CRITICAL"
    return "IMPORTANT"
  return "IMPORTANT"


def _load_json(path: str) -> dict:
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception:  # pylint: disable=broad-exception-caught
    return {}


def _app_facts(base_context: dict, temp_dir: str) -> Dict[str, Any]:
  """Assembles the small ``app`` block sent in every state."""
  store = _load_json(os.path.join(temp_dir, "play_store_info.json"))
  return {
      "name": base_context.get("APP_NAME"),
      "package": base_context.get("PACKAGE_NAME"),
      "target_sdk": base_context.get("TARGET_SDK"),
      "store_category": store.get("category"),
  }


_EVIDENCE_MATCHED_MAX = 96  # characters of the matched source line shown in evidence


def nearest_sink(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
  """The capability-labelled sink reference closest to the anchor, or None.

  Preference order: a sink line inside the anchor's own scope (the transfer
  happens in the same function), then the smallest line distance to the
  anchor line. Only sinks with a *transfer* capability count — a
  ``LOCAL_PERSISTENCE`` or ``USER_DISCLOSURE_UI`` symbol is not a sink for
  evidence purposes even though it is listed in ``state["sinks"]`` for the
  model. Returns ``{"symbol", "line", "capabilities", "in_scope", "distance"}``
  with a 1-based line.
  """
  signal = state.get("signal") or {}
  anchor_line = signal.get("line")
  scope = (state.get("anchor") or {}).get("scope") or [0, 0]
  transfer_caps = set(constants.SHARING_CAPABILITY_NAMES) | set(constants.RANK_STRONG_EGRESS_CAPABILITIES) | {"UNKNOWN"}
  best: Optional[Dict[str, Any]] = None
  best_key: Optional[Tuple[int, int, str]] = None
  for s in state.get("sinks") or []:
    caps_ = [c for c in (s.get("capabilities") or []) if c in transfer_caps]
    if not caps_:
      continue
    for ln in s.get("lines") or []:
      in_scope = bool(scope) and scope[0] <= ln <= scope[1]
      distance = abs(ln - anchor_line) if anchor_line is not None else 1 << 30
      key = (0 if in_scope else 1, distance, s.get("symbol") or "")
      if best_key is None or key < best_key:
        best_key = key
        best = {"symbol": s.get("symbol"), "line": ln, "capabilities": caps_,
                "in_scope": in_scope, "distance": distance}
  return best


def evidence_flow(state: Dict[str, Any]) -> Dict[str, Any]:
  """Machine-readable source -> sink evidence for one finding (WP3).

  ``source`` is the anchor: file, the matched line number, the enclosing
  scope (1-based inclusive) and the matched source text. ``sink`` is
  :func:`nearest_sink` or None. Downstream ignores unknown keys; WP7 appends
  the destination class here.
  """
  signal = state.get("signal") or {}
  scope = (state.get("anchor") or {}).get("scope") or None
  return {
      "source": {
          "file": signal.get("file"),
          "line": signal.get("line"),
          "scope": list(scope) if scope else None,
          "matched": (signal.get("matched_line") or "").strip()[:_EVIDENCE_MATCHED_MAX],
      },
      "sink": nearest_sink(state),
  }


def _evidence_line(state: Dict[str, Any]) -> str:
  """One-line, human-readable evidence (WP3 structured form).

  With a transfer sink in the file::

    source@<file>:L<start>-L<end> (L<line>: <matched>) -> sink@L<n> <Symbol> [<CAPS>]

  ``L<start>-L<end>`` is the anchor's enclosing scope, so a reviewer sees the
  function that performs the operation, not a single line; the sink is the
  nearest capability-labelled transfer reference (:func:`nearest_sink`),
  suffixed ``(out of scope)`` when it lies outside that function. Without a
  transfer sink the previous form is kept unchanged::

    <file>:L<line> — <matched>

  ``|`` and newlines never appear (the report renders this inside a Markdown
  table cell). The same data is available structurally as
  ``finding["evidence_flow"]``.
  """
  signal = state.get("signal", {})
  file = signal.get("file")
  line = signal.get("line")
  matched = (signal.get("matched_line") or "").strip().replace("|", "¦")
  if len(matched) > _EVIDENCE_MATCHED_MAX:
    matched = matched[:_EVIDENCE_MATCHED_MAX - 1] + "…"
  sink = nearest_sink(state)
  scope = (state.get("anchor") or {}).get("scope")
  if sink is None or not scope or line is None:
    where = f"{file}:L{line}" if line else str(file)
    return f"{where} — {matched}" if matched else str(where)
  caps_ = ", ".join(sink["capabilities"])
  span = f"L{scope[0]}-L{scope[1]}" if scope[0] != scope[1] else f"L{scope[0]}"
  src = f"source@{file}:{span} (L{line}: {matched})" if matched else f"source@{file}:{span} (L{line})"
  dst = f"sink@L{sink['line']} {sink['symbol']} [{caps_}]"
  if not sink["in_scope"]:
    dst += " (out of scope)"
  return f"{src} -> {dst}"


def _answers_log(answers: Dict[str, JevAnswer]) -> Dict[str, Any]:
  """Raw answer payload stored on each finding for auditability/reproducibility."""
  return {qid: a.to_dict() for qid, a in answers.items()}


def _compose_data_safety_finding(
    data_type: str,
    finding_str: str,
    state: Dict[str, Any],
    answers: Dict[str, JevAnswer],
    client_name: str,
) -> Dict[str, Any]:
  """Builds one ``goal_data_safety`` finding from the typed answers, or None.

  Returns None when the semantic match gate says the matched token does not
  actually concern this data type (a coincidental lexical hit).

  Decision logic (all in code; the model only supplies calibrated answers):

  1. ``signal_relevant`` < ``T_RELEVANCE`` -> drop (logged as a gate drop)
     unless an egress/IPC sink is in the anchor's scope, in which case the
     finding is kept for manual review (:func:`relevance_verdict`, WP2).
  2. ``transmits_offdevice`` -> three-way :func:`transfer_decision`.
  3. LOCAL: disclosure is EXEMPT by construction (nothing leaves the device).
     TRANSMITS: disclosure status as answered, cross-checked against the
     battery's own ``has_prominent_disclosure`` Noul and the user-initiated
     answer (:func:`reconcile_disclosure_status`, WP2); severity
     CRITICAL/IMPORTANT.
     UNCERTAIN: recall-safe — ``is_transferred`` is set True so the shared
     report routes it to review (a False value is treated as "compliant" and
     dropped from review), severity capped at IMPORTANT, ``needs_manual_review``
     set, and the critic never prunes it.
  4. Sharing: the model's ``is_third_party`` answer, OR-ed with the presence of a
     sharing-capable sink inside the anchor's own scope (IPC counts as sharing
     by policy direction).
  """
  tax = _taxonomy().get(data_type, {})
  category = tax.get("category", "Other")
  name = tax.get("data_type", data_type)

  verdict, p_relevant = relevance_verdict(answers, state)
  if verdict == RELEVANCE_DROP:
    log.info("relevance gate dropped %s in %s (p=%.2f, token=%r, tier=%s)", data_type,
             state["signal"]["file"], p_relevant or 0.0, state["signal"].get("matched_pattern"),
             (state.get("anchor") or {}).get("tier"))
    return None
  relevance_low = verdict == RELEVANCE_LOW_WITH_SINK
  if relevance_low:
    log.info("relevance low but sink in scope; keeping %s in %s for review (p=%.2f, token=%r)",
             data_type, state["signal"]["file"], p_relevant or 0.0,
             state["signal"].get("matched_pattern"))

  p_transmit = answers["transmits_offdevice"].noul or 0.0
  decision = transfer_decision(p_transmit)
  transmits = decision in (TRANSMITS, UNCERTAIN)
  user_initiated = (answers["user_initiated"].noul or 0.0) >= constants.T_USER_INITIATED

  sinks = state.get("sinks") or []
  scope = (state.get("anchor") or {}).get("scope") or [0, 0]
  sharing_in_scope = sorted({
      s["symbol"] for s in sinks
      if set(s.get("capabilities") or []) & set(constants.SHARING_CAPABILITY_NAMES)
      and any(scope[0] <= ln <= scope[1] for ln in s.get("lines") or [])
  })
  is_third_party = (
      (answers["is_third_party"].noul or 0.0) >= constants.T_THIRD_PARTY
  ) or (transmits and bool(sharing_in_scope))

  disclosure_status = answers["disclosure_status"].choice or "MISSING"
  disclosure_note: Optional[str] = None
  # Local-only data needs no disclosure by definition, so compose EXEMPT in code
  # rather than relying on the model to infer it (it reads the question literally
  # and reports MISSING when no gate is present, even for on-device data).
  if decision == LOCAL:
    disclosure_status = "EXEMPT"
  else:
    disclosure_status, disclosure_note = reconcile_disclosure_status(
        disclosure_status, answers, transmits, user_initiated)
    if disclosure_note:
      log.info("disclosure status reconciled for %s in %s: %s", data_type,
               state["signal"]["file"], disclosure_note)
  # Severity is derived in code from the atomic booleans, not read off Jev's
  # advisory Score (which is logged for comparison only).
  severity = derive_data_safety_severity(data_type, transmits, disclosure_status, decision)

  # A transmitted, undisclosed type is a prominent-disclosure risk; otherwise it
  # is inventory for the Data Safety section reconciliation.
  if transmits and disclosure_status == "MISSING":
    policy_id = "prominent_disclosure_policy"
  else:
    policy_id = "data_safety_section"

  if decision == UNCERTAIN:
    purpose = "Possible transfer (uncertain; manual review)"
  elif is_third_party:
    purpose = "Analytics or third-party sharing"
  elif transmits:
    purpose = "App functionality"
  else:
    purpose = "Local functionality only"

  summary = templates.issue_summary(policy_id, name, disclosure_status, transmits)
  if decision == UNCERTAIN:
    summary = f"{summary} [transfer uncertain: p={p_transmit:.2f}; verify]"
  if relevance_low:
    summary = f"{summary} [data-type match uncertain: p={p_relevant or 0.0:.2f}; verify]"
    if severity == "CRITICAL":
      severity = "IMPORTANT"

  sink_names = ", ".join(s["symbol"] for s in sinks[:5]) or "no labelled sink in file"
  claim = (
      f"{name} ({data_type}) is sent off-device or shared with another app "
      f"in {state['signal']['file']} (sinks: {sink_names})."
  )

  log.debug("compose %s in %s: p_transmit=%.2f decision=%s severity=%s third_party=%s",
            data_type, state["signal"]["file"], p_transmit, decision, severity, is_third_party)

  finding = {
      "psl_constant": data_type,
      "policy_id": policy_id,
      "issue_summary": summary,
      "severity": severity,
      "files_involved": [state["signal"]["file"]],
      "evidence": _evidence_line(state),
      "evidence_flow": evidence_flow(state),
      "evidence_snippet": state.get("code_snippet", ""),
      "recommendation": templates.recommendation(policy_id, severity),
      "is_transferred": transmits,
      "user_initiated": user_initiated,
      "is_third_party": is_third_party,
      "prominent_disclosure_status": disclosure_status,
      "purpose": purpose,
      "linked_to_user": category in _LINKED_CATEGORIES,
      # Fields the critic and the trace consume; downstream ignores unknown keys.
      "transfer_decision": decision,
      "claim": claim,
      "claim_kind": "transfer",
      "sinks": [{"symbol": s["symbol"], "capabilities": s["capabilities"]} for s in sinks],
      "client": client_name,
      "typesafe_answers": _answers_log(answers),
      "decision_trace": _decision_trace(
          state, answers, decision,
          {"sharing_sinks_in_scope": sharing_in_scope, "p_relevant": p_relevant,
           "relevance": "low" if relevance_low else "ok",
           "disclosure_reconciled": disclosure_note},
      ),
  }
  if decision == UNCERTAIN or relevance_low or disclosure_note:
    finding["needs_manual_review"] = True
  return finding


def _compose_permission_finding(
    data_type: str,
    policy_id: str,
    state: Dict[str, Any],
    answers: Dict[str, JevAnswer],
    client_name: str,
) -> Optional[Dict[str, Any]]:
  """Builds one ``goal_permissions_and_apis`` finding, or None if compliant/core.

  The relevance gate runs first: a permission-hygiene finding on a snippet that
  does not actually touch the restricted data (``record`` matching a DNS record
  type, an ``audio/*`` MIME filter) is dropped before severity is composed.
  A transfer in the UNCERTAIN band is treated as "may transmit" for the
  high-risk escalation, but the finding is marked for manual review.
  """
  verdict, p_relevant = relevance_verdict(answers, state)
  if verdict == RELEVANCE_DROP:
    log.info("relevance gate dropped %s (%s) in %s (p=%.2f, tier=%s)", data_type, policy_id,
             state["signal"]["file"], p_relevant or 0.0, (state.get("anchor") or {}).get("tier"))
    return None
  relevance_low = verdict == RELEVANCE_LOW_WITH_SINK

  is_core = (answers["is_core_functionality"].noul or 0.0) >= constants.T_CORE_FUNCTION
  has_disclosure = (
      answers["has_prominent_disclosure"].noul or 0.0
  ) >= constants.T_DISCLOSURE
  p_transmit = answers["transmits_offdevice"].noul or 0.0
  decision = transfer_decision(p_transmit)
  transmits = decision == TRANSMITS

  # Severity derived in code; None means compliant (emit nothing).
  severity = derive_permission_severity(
      policy_id, is_core, has_disclosure, transmits
  )
  if severity is None:
    return None
  summary = templates.issue_summary(policy_id, data_type)
  if relevance_low:
    summary = f"{summary} [data-type match uncertain: p={p_relevant or 0.0:.2f}; verify]"
    if severity == "CRITICAL":
      severity = "IMPORTANT"

  finding = {
      "policy_id": policy_id,
      "issue_summary": summary,
      "severity": severity,
      "files_involved": [state["signal"]["file"]],
      "evidence": _evidence_line(state),
      "evidence_flow": evidence_flow(state),
      "evidence_snippet": state.get("code_snippet", ""),
      "recommendation": templates.recommendation(policy_id, severity),
      "claim_kind": "generic",
      "sinks": [
          {"symbol": s["symbol"], "capabilities": s["capabilities"]}
          for s in (state.get("sinks") or [])
      ],
      "client": client_name,
      "typesafe_answers": _answers_log(answers),
      "decision_trace": _decision_trace(
          state, answers, decision,
          {"is_core": is_core, "has_disclosure": has_disclosure, "p_relevant": p_relevant,
           "relevance": "low" if relevance_low else "ok"},
      ),
  }
  if (decision == UNCERTAIN and severity != "SUGGESTION") or relevance_low:
    finding["needs_manual_review"] = True
  return finding


def _iter_findings(base_context: dict):
  """Yields ``(data_type, finding_string, description)`` from the goal input.

  Handles both ``data_sources`` shapes ``orchestrator.py init`` emits:

  - Permission goals: ``{data_type: ["<relpath> (Pattern: X)", ...]}``.
  - Data-safety chunks: ``{data_type: {"description": str, "findings": [...]}}``.
  """
  for data_type, entry in (base_context.get("data_sources") or {}).items():
    if isinstance(entry, dict):
      description = entry.get("description", "")
      findings = entry.get("findings", [])
    else:
      description = ""
      findings = entry
    if isinstance(findings, list):
      for finding_str in findings:
        yield data_type, finding_str, description


def evaluate_goal(
    goal_name: str,
    base_context: dict,
    app_dir: str,
    temp_dir: str,
    client: JevClient,
    model: Optional[str] = None,
) -> Dict[str, Any]:
  """Evaluates one goal's inputs into a ``worker_<goal>.json`` structure."""
  app_facts = _app_facts(base_context, temp_dir)
  findings: List[Dict[str, Any]] = []

  is_permissions = goal_name.startswith("permissions")
  is_data_safety = goal_name.startswith("data_safety")
  is_user_account = goal_name.startswith("user_account")

  for data_type, finding_str, chunk_description in _iter_findings(base_context):
    tax = _taxonomy().get(data_type, {})
    description = chunk_description or tax.get("description", "")

    if is_permissions:
      policy_id = PERMISSION_POLICY.get(data_type)
      if not policy_id:
        continue
      state = snippets.build_state(app_dir, finding_str, data_type, app_facts)
      answers = client.system_one(
          state, q.permission_battery(policy_id, data_type), model=model
      )
      finding = _compose_permission_finding(
          data_type, policy_id, state, answers, client.name
      )
      if finding:
        findings.append(finding)

    elif is_data_safety:
      if data_type not in _taxonomy():
        continue
      state = snippets.build_state(app_dir, finding_str, data_type, app_facts)
      answers = client.system_one(
          state,
          q.data_safety_battery(data_type, description),
          model=model,
      )
      findings.append(
          _compose_data_safety_finding(
              data_type, finding_str, state, answers, client.name
          )
      )

    elif is_user_account:
      # Account-deletion presence is a deterministic suggestion; no model needed.
      if data_type == "ACCOUNT_DELETION":
        state = snippets.build_state(app_dir, finding_str, data_type, app_facts)
        findings.append({
            "policy_id": "account_deletion",
            "issue_summary": templates.issue_summary("account_deletion"),
            "severity": "SUGGESTION",
            "files_involved": [state["signal"]["file"]],
            "evidence": _evidence_line(state),
            "recommendation": templates.recommendation(
                "account_deletion", "SUGGESTION"
            ),
            "client": "deterministic",
        })

  domain = {
      "permissions_and_apis": "Permissions and APIs",
      "user_account": "User Account and Identity",
  }.get(goal_name, "Data Safety and Privacy")

  return {"domain": domain, "findings": findings}


def run(
    temp_dir: str,
    client: JevClient,
    model: Optional[str] = None,
    goals: Optional[List[str]] = None,
) -> List[str]:
  """Per-finding evaluation via the registry engine (one request per finding).

  Kept as a thin wrapper so existing callers (CLI, benchmark) are unchanged; the
  ``goals`` argument is deprecated (the engine activates from the registry).
  """
  from typesafe_eval import engine  # lazy import avoids an import cycle
  return engine.run(temp_dir, client, model=model, batched=False)


def _critic_decision(supports: float, uncertain: bool = False) -> Dict[str, str]:
  """Turns the evidence probability into a routed verdict.

  Recall-weighted: only strong evidence of a false positive prunes; a middling
  probability goes to a human rather than being dropped. A finding whose
  transfer decision was UNCERTAIN is *never* pruned: strong evidence upgrades it
  to VERIFIED (the critic saw the flow the battery was unsure about), anything
  else stays MANUAL_REVIEW.
  """
  if uncertain:
    if supports >= constants.CONF_ACT:
      return {"action": "VERIFIED", "confidence": "Medium"}
    return {"action": "MANUAL_REVIEW", "confidence": "Low"}
  if supports >= constants.CONF_ACT:
    return {"action": "VERIFIED", "confidence": "High"}
  if supports >= constants.T_EVIDENCE_SUPPORTS:
    return {"action": "VERIFIED", "confidence": "Medium"}
  if supports < (1.0 - constants.CONF_ACT):
    return {"action": "PRUNED", "confidence": "High"}
  return {"action": "MANUAL_REVIEW", "confidence": "Low"}


def evaluate_critic_chunk(
    chunk: Dict[str, dict],
    client: JevClient,
    model: Optional[str] = None,
) -> Dict[str, dict]:
  """One cheap Noul per high-severity finding; routes it in code. Robust per finding.

  The critic sees the same enriched evidence the battery saw (enclosing scope
  plus capability-labelled sink lines), the atomic ``claim`` the finding rests
  on, and the sink list. For transfer claims it verifies only the transfer, not
  the disclosure. Findings that bypassed the model (``client`` == error) or that
  already carry ``needs_manual_review`` are routed without a call.
  """
  decisions: Dict[str, dict] = {}
  for fid, finding in chunk.items():
    uncertain = finding.get("transfer_decision") == UNCERTAIN
    if finding.get("client") == "error":
      decisions[fid] = {
          "action": "MANUAL_REVIEW", "confidence": "Low",
          "critic_justification": "evaluation error upstream; routed to review",
      }
      continue

    claim_kind = finding.get("claim_kind") or "generic"
    state = {
        "finding": {
            "issue_summary": finding.get("issue_summary", ""),
            "claim": finding.get("claim") or finding.get("issue_summary", ""),
            "evidence_snippet": finding.get("evidence_snippet")
            or finding.get("evidence", ""),
            "sinks": finding.get("sinks") or [],
            "policy_id": finding.get("policy_id", ""),
            "transfer_decision": finding.get("transfer_decision"),
        }
    }
    battery = q.critic_battery(claim_kind)
    qid = next(iter(battery))
    try:
      answers = client.system_one(state, battery, model=model)
      supports = answers[qid].noul or 0.0
      decision = _critic_decision(supports, uncertain=uncertain)
      decision["critic_justification"] = (
          f"{qid}={supports:.2f}" + ("; transfer band UNCERTAIN" if uncertain else "")
      )
      log.debug("critic %s: %s=%.2f -> %s", fid, qid, supports, decision["action"])
    except Exception as exc:  # pylint: disable=broad-exception-caught
      # Never drop a high-severity finding because the critic call failed.
      decision = {
          "action": "MANUAL_REVIEW",
          "confidence": "Low",
          "critic_justification": f"critic evaluation failed: {str(exc)[:120]}",
      }
    decisions[fid] = decision
  return decisions


def run_critic(
    temp_dir: str,
    client: JevClient,
    model: Optional[str] = None,
) -> List[str]:
  """Evaluates each ``input_critic_<i>.json`` into ``critic_output_<i>.json``."""
  written: List[str] = []
  for input_path in sorted(glob.glob(os.path.join(temp_dir, "input_critic_*.json"))):
    index = os.path.basename(input_path)[len("input_critic_"):-len(".json")]
    chunk = _load_json(input_path)
    decisions = evaluate_critic_chunk(chunk, client, model=model)
    out_path = os.path.join(temp_dir, f"critic_output_{index}.json")
    with open(out_path, "w", encoding="utf-8") as f:
      json.dump(decisions, f, indent=2, sort_keys=True)
    written.append(index)
  return written
