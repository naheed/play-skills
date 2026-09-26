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

"""Deterministic ``issue_summary`` / ``recommendation`` generation.

Jev is not a generative model, and both of these fields are formulaic. This
module builds them in Python from the canonical policy names in
``resources/policies.json`` and the "Direct Actionable Recommendation" wording
already codified in the ``goal_*.md`` matrices, keyed by ``policy_id`` (and, for
data-safety findings, the ``data_type``). Jev supplies the decision; this fills
in the sentence.

Keeping this deterministic makes the report reproducible and removes the last
generative dependency from the default path. A generative model remains an
optional enhancement for bespoke, codebase-specific wording.
"""

from __future__ import annotations

import functools
import json
import os
from typing import Dict
from typing import Optional


def _repo_root() -> str:
  return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@functools.lru_cache(maxsize=1)
def _policies() -> Dict[str, dict]:
  path = os.path.join(_repo_root(), "resources", "policies.json")
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception:  # pylint: disable=broad-exception-caught
    return {}


def policy_name(policy_id: str) -> str:
  """Human-readable policy name from ``policies.json``, or the id as a fallback."""
  return _policies().get(policy_id, {}).get("name", policy_id)


# Recommendation wording per policy id. Where the remediation differs by
# severity, the value is a dict keyed by severity label; otherwise it is a single
# string. These strings mirror the "Direct Actionable Recommendation" column of
# the goal matrices so the two do not drift.
_RECOMMENDATIONS: Dict[str, object] = {
    "location_access_policy": {
        "CRITICAL": (
            "Remove background/precise location collection used for non-core"
            " purposes, or add a prominent in-app disclosure before requesting"
            " ACCESS_FINE_LOCATION."
        ),
        "IMPORTANT": (
            "Downgrade to ACCESS_COARSE_LOCATION if precise location is not"
            " essential, and add a prominent disclosure before the request."
        ),
        "SUGGESTION": (
            "Confirm the location scope is the minimum required and that the"
            " Data Safety declaration matches."
        ),
    },
    "contacts_access_policy": (
        "Migrate to the Android Contact Picker (Intent.ACTION_PICK_CONTACTS)"
        " instead of requesting broad READ_CONTACTS access."
    ),
    "audio_recording_policy": (
        "Use the system Microphone Button API or a SpeechRecognizer intent for"
        " occasional voice input instead of holding broad RECORD_AUDIO access."
    ),
    "prominent_disclosure_policy": (
        "Add a prominent disclosure and affirmative-consent gate before"
        " collecting or transmitting this data, and declare it in the Play"
        " Console Data Safety form."
    ),
    "data_safety_section": (
        "Update the Play Console Data Safety form so the declared collection"
        " matches the behavior detected in code."
    ),
    "account_deletion": (
        "Publish a web-based account deletion path and declare it in the Play"
        " Console Data Safety form to satisfy the account-deletion policy."
    ),
}

_DEFAULT_RECOMMENDATION = (
    "Review this behavior against the referenced policy and remediate or update"
    " the Play Console declaration as appropriate."
)


def recommendation(policy_id: str, severity: str) -> str:
  """Deterministic remediation text for ``policy_id`` at ``severity``."""
  entry = _RECOMMENDATIONS.get(policy_id, _DEFAULT_RECOMMENDATION)
  if isinstance(entry, dict):
    return entry.get(severity, next(iter(entry.values())))
  return entry


def issue_summary(
    policy_id: str,
    data_type: Optional[str] = None,
    disclosure_status: Optional[str] = None,
    transmitted: bool = False,
) -> str:
  """Deterministic, decision-aware one-line summary for a finding."""
  name = policy_name(policy_id)

  if policy_id == "data_safety_section":
    verb = "transmitted off-device" if transmitted else "accessed"
    if disclosure_status == "MISSING":
      return f"{data_type} is {verb} without a matching Data Safety declaration"
    return f"{data_type} is {verb}; verify the Data Safety declaration"

  if policy_id == "prominent_disclosure_policy":
    return f"{data_type} is collected without a prominent disclosure ({name})"

  if policy_id == "location_access_policy":
    return "Precise location access may not be justified or disclosed"

  if policy_id == "contacts_access_policy":
    return "Broad contacts access may be replaceable with the Contact Picker"

  if policy_id == "audio_recording_policy":
    return "Broad audio-recording access may not be justified"

  if policy_id == "account_deletion":
    return "Verify a web-based account deletion path is published"

  # Generic fallback keeps output well-formed for policies without a template.
  subject = f"{data_type} " if data_type else ""
  return f"{subject}may violate {name}".strip()
