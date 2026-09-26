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
  component); evaluated once per app against ``manifest_details``. (Infra is in
  place; concrete manifest policies are added during coverage expansion.)
- ``deterministic`` — decided in code with no model call (e.g. presence checks,
  numeric SDK thresholds).
"""

from __future__ import annotations

import dataclasses
from typing import Any
from typing import Callable
from typing import Dict
from typing import Optional
from typing import Tuple

from typesafe_eval import evaluate
from typesafe_eval import questions as q
from typesafe_eval import templates

CODE_SIGNAL = "code_signal"
MANIFEST = "manifest"
DETERMINISTIC = "deterministic"


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
  make_battery: Optional[Callable[[str, str], Dict[str, Any]]] = None
  compose: Optional[Callable[..., Optional[Dict[str, Any]]]] = None
  compose_deterministic: Optional[Callable[..., Optional[Dict[str, Any]]]] = None


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
      make_battery=lambda dt, desc: q.permission_battery(policy_id, dt),
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
      make_battery=lambda dt, desc: q.data_safety_battery(dt, desc),
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


def _account_deletion_spec() -> PolicySpec:
  return PolicySpec(
      policy_id="account_deletion",
      kind=DETERMINISTIC,
      goal="user_account",
      applies_data_type=lambda dt: dt == "ACCOUNT_DELETION",
      compose_deterministic=_account_deletion_finding,
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
)


def code_signal_specs() -> Tuple[PolicySpec, ...]:
  return tuple(s for s in REGISTRY if s.kind == CODE_SIGNAL)


def deterministic_specs() -> Tuple[PolicySpec, ...]:
  return tuple(s for s in REGISTRY if s.kind == DETERMINISTIC)


def manifest_specs() -> Tuple[PolicySpec, ...]:
  return tuple(s for s in REGISTRY if s.kind == MANIFEST)


def goals() -> Tuple[str, ...]:
  """Distinct worker-file groupings across the registry, for stable output."""
  seen = []
  for spec in REGISTRY:
    if spec.goal not in seen:
      seen.append(spec.goal)
  return tuple(seen)
