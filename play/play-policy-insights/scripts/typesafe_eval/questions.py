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


def _severity(subject: str) -> Dict[str, Any]:
  return {
      "type": "score",
      "instructions": (
          f"Rate the Google Play policy risk of how {subject} is handled in "
          "`code_snippet`."
      ),
      "criteria": [
          "SUGGESTION: compliant or informational; no real policy risk.",
          "IMPORTANT: a real policy gap that should be fixed but is not severe.",
          "CRITICAL: a direct, high-risk violation likely to cause rejection.",
      ],
  }


def _relevance(subject: str, token: str = "") -> Dict[str, Any]:
  """Semantic match gate: does the snippet really handle this data type?

  Scanner patterns are lexical (``record`` matches a DNS record type, ``track``
  matches a network trace). One generic question per signal lets code drop the
  clear misfires before any policy question is composed, without per-type rules.

  The matched token is embedded literally when known: in a batched request the
  state carries a ``signals`` *list*, so a field path like
  ``signal.matched_pattern`` would not resolve for the model.

  WP2 wording change: an earlier version listed "a MIME type" among the
  *unrelated* uses. That taught the model that ``video/*`` inside an
  ``ACTION_VIEW``/``ACTION_SEND`` chooser is a coincidence, and a labelled
  media-sharing transfer was answered p=0.09-0.12 while its sibling MIME
  literals in the same ``switch`` passed. A MIME type or picker filter that
  selects, opens or shares files of that kind *is* handling the data type
  (sharing via intent is a transfer by policy); only a MIME string that never
  reaches any data (a constant table, a comment) is unrelated.
  """
  token_ref = f"the matched token `{token}`" if token else "the matched token"
  return _noul(
      instructions=(
          f"Does `code_snippet` actually read, hold, process, select, open or "
          f"share {subject}, as opposed to an unrelated use of {token_ref} (a "
          "different meaning of the word, a UI label, a comment, or an "
          "unrelated API)? A MIME type or file-picker filter used to pick, "
          "open or hand off files of that kind counts as handling the data "
          "type; a MIME string that never touches any data does not."
      ),
      yes="The snippet genuinely handles this data type.",
      no="The token is a coincidental match; this data type is not handled here.",
  )


def _disclosure_status(subject: str) -> Dict[str, Any]:
  return {
      "type": "choice",
      "instructions": (
          f"Classify the prominent-disclosure state for {subject} in "
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


def data_safety_battery(
    data_type: str, description: str, token: str = ""
) -> Dict[str, Dict[str, Any]]:
  """Battery for a single data-safety finding (one detected data type).

  Produces the typed inputs the existing ``worker_<goal>.json`` schema expects:
  the four data-safety booleans, a disclosure-status choice, and a severity
  score. Instructions embed the literal data type (and the scanner token that
  anchored the signal, when given) so the battery works whether the state holds
  one signal or a whole file's worth (see request batching).
  """
  subject = f"the data type {data_type} ({description})"
  return {
      "signal_relevant": _relevance(subject, token),
      "transmits_offdevice": _noul(
          instructions=(
              f"Does `code_snippet` cause {subject} to leave the device or the "
              "app's own sandbox — sent over the network, handed to a third-party "
              "SDK, or shared with another app via an intent, content provider, "
              "or the clipboard? `sinks` lists the imported symbols in this file "
              "and the capabilities they are known to provide; a sink labelled "
              "UNKNOWN may or may not transmit. `callees`, when present, lists "
              "the app's own helper files called from `code_snippet` together "
              "with the sinks those helpers reach (one call away) — data handed "
              "to such a helper reaches its sinks. Consider "
              "`co_located_signals.network_transmission`."
          ),
          yes="The data is transmitted off-device or shared with another party.",
          no="The data is only used locally on the device.",
      ),
      "user_initiated": _noul(
          instructions=(
              f"Is the transfer of {subject} in `code_snippet` triggered by an "
              "explicit user action (a tap on a clearly labeled control), rather "
              "than happening automatically in the background?"
          ),
          yes="An explicit user action triggers the transfer.",
          no="The transfer happens automatically without a user action.",
      ),
      "is_third_party": _noul(
          instructions=(
              f"Does `code_snippet` send {subject} to a destination outside the "
              "developer's own control — a sink whose capabilities in `sinks` "
              "include THIRD_PARTY_TELEMETRY, ADVERTISING_SDK, or IPC_SHARING, or "
              "any other party that is not the developer's own backend?"
          ),
          yes="The sink is a third party outside the developer's control.",
          no="The sink is the developer's own backend, or there is no sink.",
      ),
      "has_prominent_disclosure": _noul(
          instructions=(
              f"For {subject}, does `code_snippet` (with "
              "`co_located_signals.disclosure`) show a prominent disclosure or "
              "consent dialog BEFORE the data is accessed, that the user must "
              "accept to continue?"
          ),
          yes="A gatekeeping disclosure is shown before access.",
          no="No disclosure gate is shown before access.",
      ),
      "disclosure_status": _disclosure_status(subject),
      "severity": _severity(subject),
  }


def permission_battery(
    policy_id: str, data_type: str, token: str = ""
) -> Dict[str, Dict[str, Any]]:
  """Battery for a permission-hygiene finding (location, contacts, audio, ...).

  Focuses on whether a restricted permission is justified by core functionality
  and whether a scoped alternative should be used. Severity and disclosure reuse
  the shared rubrics. ``token`` is the scanner pattern that anchored the signal
  (embedded in the relevance gate; see :func:`_relevance`).
  """
  del policy_id  # the policy is applied in code (evaluate.py), not in the question
  subject = f"the data type {data_type}"
  return {
      "signal_relevant": _relevance(subject, token),
      "is_core_functionality": _noul(
          instructions=(
              f"Given the app `app.name` in store category `app.store_category`, "
              f"is access to {subject} core to the app's primary purpose, rather "
              "than a secondary feature (ads, analytics, social sharing)?"
          ),
          yes="The access is essential to the app's core purpose.",
          no="The app would still work without this access; it is secondary.",
      ),
      "transmits_offdevice": _noul(
          instructions=(
              f"Does `code_snippet` send {subject} off-device or to another app? "
              "`sinks` lists imported symbols and their known capabilities; "
              "`callees`, when present, lists the app's own helper files called "
              "from `code_snippet` and the sinks they reach one call away. "
              "Consider `co_located_signals.network_transmission`."
          ),
          yes="The data is transmitted off-device.",
          no="The data is used only locally.",
      ),
      "has_prominent_disclosure": _noul(
          instructions=(
              f"For {subject}, does `code_snippet` (with "
              "`co_located_signals.disclosure`) show a prominent disclosure "
              "before requesting or using the permission?"
          ),
          yes="A disclosure is shown before the permission is used.",
          no="No disclosure is shown before the permission is used.",
      ),
      "severity": _severity(subject),
  }


def declaration_battery(data_type: str, name: str) -> Dict[str, Dict[str, Any]]:
  """Does the developer's Play declaration cover a detected, transmitted type?

  Semantic coverage check (more robust than string equality): the declared
  categories/types are in `declaration.declared`; the detected type is
  `detected.name`. Used by the ``play_declaration`` evaluation kind.
  """
  return {
      "declaration_covers": _noul(
          instructions=(
              f"The app's code collects and transmits off-device: {name} "
              f"({data_type}). Does the developer's Play Data Safety declaration "
              "in `declaration.declared` disclose this data type, or a category "
              "that clearly includes it?"
          ),
          yes="The declaration discloses this data type or an equivalent category.",
          no="The declaration does not disclose this data type.",
      ),
  }


def account_deletion_gate(data_type: str, description: str) -> Dict[str, Dict[str, Any]]:
  """A single Noul that filters false-positive account-deletion signals.

  The scanner's ACCOUNT_DELETION patterns (e.g. ``deactivate``, ``delete``) match
  generic code — a proxy toggle, a local DB delete, a comment, a translation.
  This asks whether the snippet really implements *user account* deletion.
  """
  return {
      "is_account_deletion": _noul(
          instructions=(
              "Does `code_snippet` implement deletion of the user's ACCOUNT or "
              "profile/identity data — not merely logging out, deactivating a "
              "VPN/proxy/subscription/feature, deleting a local database record, "
              "or a UI string/translation?"
          ),
          yes="It deletes the user's account or profile/identity data.",
          no="It does something else (deactivate a feature, local delete, text).",
      ),
  }


def critic_battery(claim_kind: str = "generic") -> Dict[str, Dict[str, Any]]:
  """One cheap Noul that verifies only the *atomic* claim a finding rests on.

  The aggregate step routes non-SUGGESTION findings here (citation-check
  pattern) and ``evaluate.py`` turns the probability into VERIFIED /
  MANUAL_REVIEW / PRUNED in code.

  ``claim_kind == "transfer"`` (data-safety findings): the critic is asked only
  whether the evidence shows the data reaching an off-device or cross-app sink.
  It is deliberately *not* asked about disclosure: no single snippet can prove a
  disclosure is absent elsewhere in the app, so asking that question produced
  systematic false prunes of true transfers.

  Any other ``claim_kind``: the generic "does the evidence support the summary"
  question, used for permission-hygiene findings.
  """
  if claim_kind == "transfer":
    return {
        "evidence_shows_transfer": _noul(
            instructions=(
                "`finding.claim` states that a data type is sent off-device or "
                "shared with another app. Does `finding.evidence_snippet` show "
                "that data (or a value derived from it) reaching one of the sinks "
                "in `finding.sinks`, or any other network, third-party SDK, or "
                "cross-app call? Judge only what is visible in the snippet; do "
                "not require the disclosure to be visible."
            ),
            yes="The snippet shows the data reaching an off-device or cross-app sink.",
            no="The snippet shows only local use, or no flow to a sink is visible.",
        ),
    }
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
  }


# ---------------------------------------------------------------------------
# Once-per-app question (WP4)
# ---------------------------------------------------------------------------

#: Closed option set for ``declared_core_purpose``. Drawn from the policy
#: matrices that condition severity on the app's *primary* purpose
#: (all-files access, package visibility, exact alarms, default handlers,
#: accessibility, media). ``other`` is a real answer ("none of the listed
#: purposes"); ``unknown`` is the escape hatch that always means "not
#: justified" downstream. Adding an option requires a fixture app that
#: exercises it (plan §3, closed option lists).
APP_PURPOSE_OPTIONS: Dict[str, str] = {
    "file_manager": (
        "Browsing, copying, moving and opening arbitrary files across storage is"
        " the app's main job (file explorer, archive/FTP/SMB client)."
    ),
    "backup_or_antivirus": (
        "Whole-device backup/restore, anti-malware or device-cleaning is the main job."
    ),
    "alarm_or_timer": (
        "The app exists to fire alarms, timers or reminders at exact wall-clock times."
    ),
    "calendar": "Calendar or agenda management is the main job.",
    "messaging_default_handler": (
        "The app is meant to be the user's default SMS/MMS, dialer or call-screening app."
    ),
    "accessibility_tool": (
        "The app is an assistive tool for users with disabilities (screen reader,"
        " switch access, magnification, voice control)."
    ),
    "media_gallery_or_editor": (
        "Browsing, organising or editing the user's photos/videos/audio is the main job."
    ),
    "launcher": "The app replaces the home screen / app drawer.",
    "per_app_network_control": (
        "The app filters, routes or monitors other apps' network traffic (firewall,"
        " DNS changer, VPN-based blocker, traffic monitor)."
    ),
    "other": "A clear primary purpose that is none of the above (game, shopping, news, ...).",
    "unknown": "The facts given do not make the primary purpose clear.",
}


def app_purpose_battery() -> Dict[str, Dict[str, Any]]:
  """One Choice, asked once per app and cached by the profile digest.

  The state is ``{"app": {name, package, target_sdk, store_category,
  store_description}, "profile": <AppProfile.render_compact()>}``. The answer's
  option and calibrated confidence are placed in every later request's
  ``app.purpose`` line and read by ``evaluate.purpose_in`` when a policy's
  severity depends on the primary purpose (WP5+). Low confidence never
  lowers a severity: ``purpose_in`` returns False below
  ``constants.CONF_APP_PURPOSE``.
  """
  return {
      "declared_core_purpose": {
          "type": "choice",
          "instructions": (
              "From `app` (store listing facts) and `profile` (the merged Android "
              "manifest: permissions, components, launcher, file-handling and "
              "default-handler roles), what is this app's PRIMARY purpose — the "
              "job a user installs it for? Pick the single best option; choose "
              "`other` when the purpose is clear but not listed, and `unknown` "
              "only when the facts do not show it."
          ),
          "criteria": dict(APP_PURPOSE_OPTIONS),
      }
  }
