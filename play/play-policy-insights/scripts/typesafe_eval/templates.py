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
    "account_deletion": {
        # IMPORTANT: the WP11 lifecycle findings (identity provisioned without a
        # deletion path / deletion clears local state only).
        "IMPORTANT": (
            "Implement a discoverable in-app account deletion path (e.g. under"
            " Account settings) that removes the server-side account and every"
            " identifier the app registered (account, customer, device), then"
            " clears local state; publish the matching web deletion link and"
            " declare it in the Play Console Data Safety form."
        ),
        # SUGGESTION: the per-token presence spec and an unconfirmed lifecycle.
        "SUGGESTION": (
            "Publish a web-based account deletion path and declare it in the Play"
            " Console Data Safety form to satisfy the account-deletion policy."
        ),
    },
    # WP11: login_credentials (Play Console reviewer requirements).
    "login_credentials": {
        "IMPORTANT": (
            "Because the app gates features behind a login, complete the Play"
            " Console app-access setup: submit active, non-expiring reviewer"
            " credentials and provide the public account-deletion link."
        ),
        "SUGGESTION": (
            "Confirm whether the app gates any feature behind a login; if it does,"
            " submit reviewer credentials and the account-deletion link in the Play"
            " Console app-access section."
        ),
    },
    # WP5 wave-1 manifest policies. Wording mirrors the goal matrices.
    "all_files_access_policy": {
        "CRITICAL": (
            "Remove MANAGE_EXTERNAL_STORAGE from the Manifest. For document"
            " picking or local file saving, migrate to the Storage Access"
            " Framework (SAF) or app-specific directories."
        ),
        "IMPORTANT": (
            "MANAGE_EXTERNAL_STORAGE already covers every media file: drop the"
            " redundant media / legacy storage permissions, or drop the broad"
            " grant and keep only the scoped media permissions."
        ),
        "SUGGESTION": (
            "Complete the All files access declaration in the Play Console"
            " (App content) with the core use case, and confirm the permission"
            " is essential to that use case."
        ),
    },
    "package_visibility_policy": {
        "IMPORTANT": (
            "Remove QUERY_ALL_PACKAGES from the Manifest and declare the"
            " specific packages or intents the app needs in <queries>."
        ),
        "SUGGESTION": (
            "Complete the Package visibility declaration in the Play Console"
            " (App content) and confirm the broad query is essential to the"
            " app's core purpose."
        ),
    },
    "exact_alarm_policy": {
        "IMPORTANT": (
            "Replace USE_EXACT_ALARM with SCHEDULE_EXACT_ALARM (requested at"
            " runtime with a fallback to inexact scheduling), or use standard"
            " inexact AlarmManager / WorkManager scheduling."
        ),
        "SUGGESTION": (
            "Confirm exact alarms are user-facing (alarm, timer or calendar"
            " event), that SCHEDULE_EXACT_ALARM is checked at runtime with an"
            " inexact fallback, and that the Play Console declaration matches."
        ),
    },
    "target_api_level": {
        "CRITICAL": (
            "Raise targetSdk to the current Play requirement; below the"
            " existing-app floor the app stops being available to new users on"
            " newer devices and updates are rejected."
        ),
        "IMPORTANT": (
            "Raise targetSdk to the current Play requirement for new apps and"
            " updates before the next release; updates below it are rejected."
        ),
        "SUGGESTION": (
            "The target SDK could not be determined from Gradle or the"
            " manifest; verify it meets the current Play requirement."
        ),
    },
    # WP9 wave-2 storage policies. Wording mirrors the goal matrices.
    "photo_video_access_policy": {
        "IMPORTANT": (
            "Migrate one-off media selection to the Android Photo Picker"
            " (MediaStore.ACTION_PICK_IMAGES / ActivityResultContracts."
            "PickVisualMedia), which needs no permission, and cap"
            " READ_EXTERNAL_STORAGE at maxSdkVersion 32 or remove it."
        ),
        "SUGGESTION": (
            "Complete the Photo and Video Permissions declaration in the Play"
            " Console, cap READ_EXTERNAL_STORAGE at maxSdkVersion 32, and"
            " declare READ_MEDIA_VISUAL_USER_SELECTED alongside READ_MEDIA_IMAGES"
            " / READ_MEDIA_VIDEO so a partial grant persists."
        ),
    },
    "files_and_docs_policy": {
        "IMPORTANT": (
            "Adopt scoped storage: cap WRITE_EXTERNAL_STORAGE at maxSdkVersion 29,"
            " write app outputs to getExternalFilesDir() or a MediaStore"
            " collection, and open user documents through the Storage Access"
            " Framework (Intent.ACTION_OPEN_DOCUMENT) instead of the raw path."
        ),
        "SUGGESTION": (
            "Prefer app-specific directories (getExternalFilesDir) or"
            " SAF-scoped locations over folders created at the external-storage"
            " root, and drop requestLegacyExternalStorage once every build"
            " targets API 30+ (preserveLegacyExternalStorage covers upgrades)."
        ),
    },
    "foreground_services_policy": {
        "CRITICAL": (
            "Declare the specific android:foregroundServiceType(s) (and the"
            " PROPERTY_SPECIAL_USE_FGS_SUBTYPE property for specialUse) with"
            " the matching FOREGROUND_SERVICE_<TYPE> permission, or stop"
            " running the service in the foreground."
        ),
        "IMPORTANT": (
            "Re-align the foregroundServiceType with the app's core purpose,"
            " or move the work to WorkManager if a user-visible foreground"
            " presence is not justified."
        ),
        "SUGGESTION": (
            "Confirm each declared type is used only for the purpose its"
            " policy allows, remove unused FOREGROUND_SERVICE_<TYPE>"
            " permissions, and complete the Play Console foreground-service"
            " declaration for each type."
        ),
    },
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


def declaration_mismatch_summary(name: str) -> str:
  return f"{name} is collected and transmitted but not declared in Play Data Safety"


def declaration_mismatch_recommendation(name: str) -> str:
  return (
      f"Declare {name} in the Play Console Data Safety form (collection and, if "
      "applicable, sharing), or stop transmitting it off-device."
  )


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

  if policy_id == "login_credentials":
    return ("App gates features behind a login; Play Console reviewer credentials"
            " and an account-deletion link are required")

  # Generic fallback keeps output well-formed for policies without a template.
  subject = f"{data_type} " if data_type else ""
  return f"{subject}may violate {name}".strip()


# WP9: per-mode wording for the two storage code findings. ``mode`` values are
# the ones ``evaluate`` derives from the Noul (``full_library`` /
# ``user_selected`` / ``uncertain``; ``confirmed`` / ``uncertain`` / ``denied``).
_MEDIA_ACCESS_SUMMARY = {
    "full_library": "enumerates the media library under a broad media permission",
    "user_selected": "handles user-selected media while a broad media permission is held",
    "uncertain": "accesses media under a broad media permission (library vs user-selected unclear)",
}
_ROOT_FOLDER_SUMMARY = {
    "confirmed": "creates its own folder or files at the external-storage root",
    "uncertain": "may create a folder at the external-storage root (unclear)",
    "denied": "composes a path from the external-storage root and writes to it (model disagrees)",
}


def media_access_summary(data_type: str, mode: str, justified: bool) -> str:
  """Summary for a ``photo_video_access_policy`` code finding (WP9)."""
  what = _MEDIA_ACCESS_SUMMARY.get(mode, _MEDIA_ACCESS_SUMMARY["uncertain"])
  tail = ("; the core purpose qualifies — confirm the Play Console declaration" if justified
          else "; the core purpose does not qualify for broad media access — use the Photo Picker")
  return f"{data_type}: code {what}{tail}"


def root_folder_summary(mode: str, justified: bool) -> str:
  """Summary for a ``files_and_docs_policy`` code finding (WP9)."""
  what = _ROOT_FOLDER_SUMMARY.get(mode, _ROOT_FOLDER_SUMMARY["uncertain"])
  tail = (" (file-management purpose: scoped alternative suggested)" if justified
          else " (scoped storage mandate)")
  return f"App {what}{tail}"


# WP11: per-mode wording for the app-level ``account_deletion`` lifecycle
# finding. ``mode`` values are the ones ``engine._run_identity_lifecycle``
# derives (see ``constants`` WP11 block).
_LIFECYCLE_SUMMARY = {
    "no_deletion_path": (
        "App registers a server-side identity (account / customer / device) but no code"
        " path deletes or unregisters it"
    ),
    "persistence_unconfirmed": (
        "App appears to register a server-side identity with no deletion path (local"
        " persistence of the identity not confirmed)"
    ),
    "local_only": (
        "App registers a server-side identity; the deletion path found only clears local"
        " state and does not remove the identity on the server"
    ),
    "unconfirmed": (
        "App registers a server-side identity; the deletion path found could not be"
        " confirmed to delete the identity on the server"
    ),
}


def lifecycle_summary(mode: str) -> str:
  """Summary for the app-level ``account_deletion`` lifecycle finding (WP11)."""
  return _LIFECYCLE_SUMMARY.get(mode, _LIFECYCLE_SUMMARY["unconfirmed"])


_LOGIN_GATE_SUMMARY = {
    "app_account": (
        "App gates features behind a login to a developer-operated account; Play Console"
        " reviewer credentials and an account-deletion link are required"
    ),
    "third_party_sign_in_bridge": (
        "App gates features behind a third-party sign-in into a developer account; Play"
        " Console reviewer credentials and an account-deletion link are required"
    ),
    "unknown": (
        "Login-shaped code found but the kind of login gate is unclear; confirm whether"
        " reviewer credentials are required"
    ),
}


def login_gate_summary(gate_type: str) -> str:
  """Summary for a ``login_credentials`` finding (WP11)."""
  return _LOGIN_GATE_SUMMARY.get(gate_type, _LOGIN_GATE_SUMMARY["unknown"])
