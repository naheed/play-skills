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

"""Policy registry — one declarative spec per policy.

This is the single source of truth for what the Jev evaluator checks. Adding a
policy means adding one :class:`PolicySpec` here (plus eval fixtures), instead of
editing five files. The engine (``engine.py``) iterates the registry; it does not
hard-code any policy.

Each spec declares an **evaluation kind**:

- ``code_signal`` — triggered by a scanner signal (a data type found in a file);
  evaluated against that file's code snippet. Most policies.
- ``manifest`` — triggered by an app-level manifest fact (a permission or
  component); evaluated once per app against ``manifest_details`` with no model
  call (e.g. foreground-service type/permission checks).
- ``deterministic`` — decided in code with no model call (e.g. presence checks,
  numeric SDK thresholds).
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from typesafe_eval import constants
from typesafe_eval import evaluate
from typesafe_eval import questions as q
from typesafe_eval import templates

CODE_SIGNAL = "code_signal"
MANIFEST = "manifest"
DETERMINISTIC = "deterministic"
PLAY_DECLARATION = "play_declaration"


@dataclasses.dataclass(frozen=True)
class PolicySpec:
  """One policy's activation, questions, and composition, in one place.

  Attributes:
    policy_id: The id in ``policies.json``.
    kind: One of CODE_SIGNAL / MANIFEST / DETERMINISTIC.
    goal: Which ``worker_<goal>.json`` grouping the finding routes to (only
      affects output file naming; ``aggregate`` globs all worker files).
    applies_data_type: (code_signal/deterministic) predicate over a scanner data
      type — does this policy care about it?
    make_battery: (code_signal) build the typed question battery for a data type.
    compose: (code_signal) build a finding from the answers, or None if compliant.
    compose_deterministic: (deterministic) build a finding with no model call.
  """

  policy_id: str
  kind: str
  goal: str
  applies_data_type: Callable[[str], bool] = lambda dt: False
  make_battery: Optional[Callable[..., Dict[str, Any]]] = None
  compose: Optional[Callable[..., Optional[Dict[str, Any]]]] = None
  compose_deterministic: Optional[Callable[..., Optional[Dict[str, Any]]]] = None
  # (manifest) build zero or more findings from ``manifest_details`` alone.
  compose_manifest: Optional[Callable[[Dict[str, Any]], List[Dict[str, Any]]]] = None
  # Optional false-positive gate for deterministic policies: a light model check
  # that must pass for the finding to be emitted. Filters generic-pattern FPs
  # (e.g. "deactivate" matching a proxy toggle) without a full battery.
  gate_battery: Optional[Callable[[str, str], Dict[str, Any]]] = None
  gate_key: str = ""
  gate_threshold: float = 0.5


# ---------------------------------------------------------------------------
# Spec factories
# ---------------------------------------------------------------------------


def _permission_spec(policy_id: str, data_types: Tuple[str, ...]) -> PolicySpec:
  """A restricted-permission hygiene policy over specific data types."""
  members = frozenset(data_types)
  return PolicySpec(
      policy_id=policy_id,
      kind=CODE_SIGNAL,
      goal="permissions_and_apis",
      applies_data_type=lambda dt: dt in members,
      make_battery=lambda dt, desc, token="": q.permission_battery(policy_id, dt, token),
      compose=lambda dt, finding_str, state, answers, client_name: (
          evaluate._compose_permission_finding(  # pylint: disable=protected-access
              dt, policy_id, state, answers, client_name
          )
      ),
  )


def _data_safety_spec() -> PolicySpec:
  """The data-safety / prominent-disclosure policy over all taxonomy types."""
  return PolicySpec(
      policy_id="data_safety_section",
      kind=CODE_SIGNAL,
      goal="data_safety",
      applies_data_type=lambda dt: dt in evaluate._taxonomy(),  # pylint: disable=protected-access
      make_battery=lambda dt, desc, token="": q.data_safety_battery(dt, desc, token),
      compose=lambda dt, finding_str, state, answers, client_name: (
          evaluate._compose_data_safety_finding(  # pylint: disable=protected-access
              dt, finding_str, state, answers, client_name
          )
      ),
  )


def _account_deletion_finding(data_type, finding_str, state) -> Dict[str, Any]:
  return {
      "policy_id": "account_deletion",
      "issue_summary": templates.issue_summary("account_deletion"),
      "severity": "SUGGESTION",
      "files_involved": [state["signal"]["file"]],
      "evidence": evaluate._evidence_line(state),  # pylint: disable=protected-access
      "recommendation": templates.recommendation("account_deletion", "SUGGESTION"),
      "client": "deterministic",
  }


def _play_declaration_spec() -> PolicySpec:
  """Cross-reference: detected off-device collection vs the Play declaration.

  This is the ``play_declaration`` kind — an app-level pass (not per-file) run by
  the engine after code-signal evaluation, using the developer's declaration
  (`play_store_info.json`, provided or scraped) as an additional input.
  """
  return PolicySpec(
      policy_id="data_safety_section",
      kind=PLAY_DECLARATION,
      goal="data_safety",
      make_battery=q.declaration_battery,
  )


def _fgs_permission_for_type(fgs_type: str) -> str:
  """``connectedDevice`` -> ``android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE``.

  Purely mechanical: the platform names the per-type permission by upper-snake
  casing the type token, so no table of types is needed.
  """
  snake = re.sub(r"(?<!^)(?=[A-Z])", "_", fgs_type).upper()
  return f"android.permission.FOREGROUND_SERVICE_{snake}"


def _foreground_service_findings(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
  """Deterministic foreground-service checks from the manifest alone.

  Android 14 (API 34) requires every foreground service to declare at least one
  ``foregroundServiceType`` and to hold the matching per-type permission. Both
  are mechanical facts a parser can check, so no model call is made. Services
  that pass are emitted as SUGGESTION inventory so a reviewer sees the declared
  types and can judge the justification (which *is* a judgment call, and is
  left to the human).
  """
  findings: List[Dict[str, Any]] = []
  try:
    target_sdk = int(manifest.get("target_sdk") or 0)
  except (TypeError, ValueError):
    target_sdk = 0
  permissions = set(manifest.get("permissions") or [])
  for svc in manifest.get("foreground_services") or []:
    name = svc.get("name") or "(unnamed service)"
    raw_type = (svc.get("type") or "").strip()
    types = [t for t in re.split(r"[|,\s]+", raw_type) if t]
    base = {
        "policy_id": "foreground_services_policy",
        "files_involved": ["AndroidManifest.xml"],
        "client": "deterministic",
        "kind": "manifest",
        "decision_trace": {
            "evaluator_version": constants.EVALUATOR_VERSION,
            "service": name, "types": types, "target_sdk": target_sdk,
        },
    }
    if target_sdk >= 34 and not types:
      findings.append({
          **base,
          "issue_summary": (
              f"Foreground service {name} declares no foregroundServiceType "
              f"(required when targeting API {target_sdk})"
          ),
          "severity": "IMPORTANT",
          "evidence": f"<service android:name=\"{name}\"> has no android:foregroundServiceType",
          "recommendation": (
              "Declare the specific foregroundServiceType(s) the service needs and "
              "the matching FOREGROUND_SERVICE_<TYPE> permission, or stop running "
              "it as a foreground service."
          ),
      })
      continue
    missing = [
        t for t in types
        if target_sdk >= 34 and _fgs_permission_for_type(t) not in permissions
    ]
    if missing:
      findings.append({
          **base,
          "issue_summary": (
              f"Foreground service {name} uses type(s) {', '.join(missing)} without "
              "the matching FOREGROUND_SERVICE_<TYPE> permission"
          ),
          "severity": "IMPORTANT",
          "evidence": f"types={types}; missing={[_fgs_permission_for_type(t) for t in missing]}",
          "recommendation": (
              "Add the per-type FOREGROUND_SERVICE_<TYPE> permission for each "
              "declared foregroundServiceType."
          ),
      })
    elif types:
      findings.append({
          **base,
          "issue_summary": (
              f"Foreground service {name} declares type(s) {', '.join(types)}; "
              "verify the use case matches the type's policy definition"
          ),
          "severity": "SUGGESTION",
          "evidence": f"<service android:name=\"{name}\" android:foregroundServiceType=\"{raw_type}\">",
          "recommendation": (
              "Confirm each declared type is used only for the purpose its policy "
              "allows, and that the Play Console foreground-service declaration matches."
          ),
      })
  return findings


def _foreground_service_spec() -> PolicySpec:
  return PolicySpec(
      policy_id="foreground_services_policy",
      kind=MANIFEST,
      goal="permissions_and_apis",
      compose_manifest=_foreground_service_findings,
  )


def _account_deletion_spec() -> PolicySpec:
  return PolicySpec(
      policy_id="account_deletion",
      kind=DETERMINISTIC,
      goal="user_account",
      applies_data_type=lambda dt: dt == "ACCOUNT_DELETION",
      compose_deterministic=_account_deletion_finding,
      # Light evidence gate: only emit when the snippet really deletes an account.
      gate_battery=q.account_deletion_gate,
      gate_key="is_account_deletion",
      gate_threshold=constants.T_ACCOUNT_DELETION,
  )


# ---------------------------------------------------------------------------
# The registry. Adding a policy = adding a spec here (+ eval fixtures).
# ---------------------------------------------------------------------------

REGISTRY: Tuple[PolicySpec, ...] = (
    _permission_spec("location_access_policy", ("PRECISE_LOCATION", "APPROX_LOCATION")),
    _permission_spec("contacts_access_policy", ("CONTACTS",)),
    _permission_spec("audio_recording_policy", ("AUDIO",)),
    _data_safety_spec(),
    _account_deletion_spec(),
    _foreground_service_spec(),
    _play_declaration_spec(),
)


def code_signal_specs() -> Tuple[PolicySpec, ...]:
  return tuple(s for s in REGISTRY if s.kind == CODE_SIGNAL)


def deterministic_specs() -> Tuple[PolicySpec, ...]:
  return tuple(s for s in REGISTRY if s.kind == DETERMINISTIC)


def manifest_specs() -> Tuple[PolicySpec, ...]:
  return tuple(s for s in REGISTRY if s.kind == MANIFEST)


def play_declaration_specs() -> Tuple[PolicySpec, ...]:
  return tuple(s for s in REGISTRY if s.kind == PLAY_DECLARATION)


def goals() -> Tuple[str, ...]:
  """Distinct worker-file groupings across the registry, for stable output."""
  seen = []
  for spec in REGISTRY:
    if spec.goal not in seen:
      seen.append(spec.goal)
  return tuple(seen)
