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

"""The typed question batteries, in one reviewable place.

Each battery is a ``{question_id: question_dict}`` map ready to send to a
:class:`~typesafe_eval.client.JevClient`. Questions are written to be atomic and
literal, per Jev's guidance: one snap judgment each, with the exact condition in
``instructions`` and boundary cases in ``criteria``. Instructions reference state
fields by backticked path (e.g. ``code_snippet``) so the model knows exactly what
to judge.

Multi-factor policy calls (severity, disclosure status, "is this a violation?")
are *not* asked as a single broad question. They are decomposed into the atomic
questions below and combined in ``evaluate.py``.
"""

from __future__ import annotations

from typing import Any
from typing import Dict


def _noul(instructions: str, yes: str, no: str) -> Dict[str, Any]:
  return {
      "type": "noul",
      "instructions": instructions,
      "criteria": {"true": yes, "false": no},
  }


# Severity rubric shared by every domain so scores are comparable across findings.
_SEVERITY = {
    "type": "score",
    "instructions": (
        "Rate the Google Play policy risk of the behavior shown in "
        "`code_snippet` for the data type `signal.data_type`."
    ),
    "criteria": [
        "SUGGESTION: compliant or informational; no real policy risk.",
        "IMPORTANT: a real policy gap that should be fixed but is not severe.",
        "CRITICAL: a direct, high-risk violation likely to cause rejection.",
    ],
}

_DISCLOSURE_STATUS = {
    "type": "choice",
    "instructions": (
        "Classify the prominent-disclosure state for the data access in "
        "`code_snippet`, considering `co_located_signals.disclosure`."
    ),
    "criteria": {
        "DISCLOSED": (
            "A disclosure/consent gate is shown BEFORE the data is accessed or"
            " sent, and the user must accept to proceed."
        ),
        "MISSING": (
            "The data is accessed or transmitted with no prominent disclosure"
            " gate beforehand."
        ),
        "EXEMPT": (
            "No disclosure is required because the data stays on-device or the"
            " access is obvious core functionality the user initiated."
        ),
    },
}


def data_safety_battery(data_type: str, description: str) -> Dict[str, Dict[str, Any]]:
  """Battery for a single data-safety finding (one detected data type).

  Produces the typed inputs the existing ``worker_<goal>.json`` schema expects:
  the four data-safety booleans, a disclosure-status choice, and a severity
  score.
  """
  subject = f"`signal.data_type` ({data_type}: {description})"
  return {
      "transmits_offdevice": _noul(
          instructions=(
              f"Does `code_snippet` cause {subject} to leave the device — sent "
              "over the network, to a third-party SDK, or written to a shared "
              "log? Consider `co_located_signals.network_transmission`."
          ),
          yes="The data is transmitted off-device or shared to a third party.",
          no="The data is only used locally on the device.",
      ),
      "user_initiated": _noul(
          instructions=(
              "Is the data transfer in `code_snippet` triggered by an explicit "
              "user action (a tap on a clearly labeled control), rather than "
              "happening automatically in the background?"
          ),
          yes="An explicit user action triggers the transfer.",
          no="The transfer happens automatically without a user action.",
      ),
      "is_third_party": _noul(
          instructions=(
              "Does `code_snippet` send the data to a destination outside the "
              "developer's own control, such as an analytics/ads SDK or the "
              "Android share sheet?"
          ),
          yes="The sink is a third party outside the developer's control.",
          no="The sink is the developer's own backend, or there is no sink.",
      ),
      "has_prominent_disclosure": _noul(
          instructions=(
              "Does `code_snippet` (with `co_located_signals.disclosure`) show a "
              "prominent disclosure or consent dialog BEFORE the data is "
              "accessed, that the user must accept to continue?"
          ),
          yes="A gatekeeping disclosure is shown before access.",
          no="No disclosure gate is shown before access.",
      ),
      "disclosure_status": _DISCLOSURE_STATUS,
      "severity": _SEVERITY,
  }


def permission_battery(policy_id: str, data_type: str) -> Dict[str, Dict[str, Any]]:
  """Battery for a permission-hygiene finding (location, contacts, audio, ...).

  Focuses on whether a restricted permission is justified by core functionality
  and whether a scoped alternative should be used. Severity and disclosure reuse
  the shared rubrics.
  """
  return {
      "is_core_functionality": _noul(
          instructions=(
              f"Given the app `app.name` in store category `app.store_category`, "
              f"is access to `signal.data_type` ({data_type}) core to the app's "
              "primary purpose, rather than a secondary feature (ads, analytics, "
              "social sharing)?"
          ),
          yes="The access is essential to the app's core purpose.",
          no="The app would still work without this access; it is secondary.",
      ),
      "transmits_offdevice": _noul(
          instructions=(
              "Does `code_snippet` send `signal.data_type` off-device? Consider "
              "`co_located_signals.network_transmission`."
          ),
          yes="The data is transmitted off-device.",
          no="The data is used only locally.",
      ),
      "has_prominent_disclosure": _noul(
          instructions=(
              "Does `code_snippet` (with `co_located_signals.disclosure`) show a "
              "prominent disclosure before requesting or using the permission?"
          ),
          yes="A disclosure is shown before the permission is used.",
          no="No disclosure is shown before the permission is used.",
      ),
      "severity": _SEVERITY,
  }


def critic_battery() -> Dict[str, Dict[str, Any]]:
  """Battery for verifying one finding against its cited evidence.

  This is the citation-check pattern: a Noul asks whether the snippet actually
  supports the claim, and a Choice returns the verdict with a calibrated
  confidence that ``evaluate.py`` routes on.
  """
  return {
      "evidence_supports_claim": _noul(
          instructions=(
              "Does the code in `finding.evidence_snippet` actually support the "
              "claim in `finding.issue_summary`? Judge only what is visible; do "
              "not assume behavior hidden behind interfaces."
          ),
          yes="The snippet concretely supports the claimed violation.",
          no="The snippet does not support the claim, or is too abstract.",
      ),
      "critic_verdict": {
          "type": "choice",
          "instructions": (
              "Decide the verdict for the finding described in `finding`, based "
              "only on `finding.evidence_snippet`."
          ),
          "criteria": {
              "VERIFIED": "The evidence confirms the policy violation.",
              "MANUAL_REVIEW": (
                  "The code is ambiguous or abstract; a human must decide."
              ),
              "PRUNED": (
                  "The evidence does not support a violation; likely a false"
                  " positive."
              ),
          },
      },
  }
