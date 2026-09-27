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
import logging
import re
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from typesafe_eval import android_manifest
from typesafe_eval import constants
from typesafe_eval import evaluate
from typesafe_eval import questions as q
from typesafe_eval import structure
from typesafe_eval import templates

log = logging.getLogger("typesafe_eval.registry")

CODE_SIGNAL = "code_signal"
MANIFEST = "manifest"
DETERMINISTIC = "deterministic"
PLAY_DECLARATION = "play_declaration"


@dataclasses.dataclass
class ManifestInputs:
  """Everything a ``MANIFEST``-kind policy may read (WP5).

  Attributes:
    manifest: The orchestrator's ``manifest_details.json`` (legacy fallback;
      still the only input when ``profile`` is None, e.g. in old unit tests).
    profile: The evaluator-owned merged :class:`android_manifest.AppProfile`
      (WP1). Policies prefer it: it has every service (typed or not),
      ``<property>`` tags, ``<queries>``, ``maxSdkVersion`` and per-source-set
      attribution.
    app_purpose: The once-per-app ``declared_core_purpose`` answer (WP4), read
      only through :func:`evaluate.purpose_in`.
    app_dir: Application root, for the single code fact a manifest policy may
      need (``startForeground`` in a service class).
  """

  manifest: Dict[str, Any] = dataclasses.field(default_factory=dict)
  profile: Optional[android_manifest.AppProfile] = None
  app_purpose: Dict[str, Any] = dataclasses.field(default_factory=dict)
  app_dir: str = ""

  @property
  def target_sdk(self) -> Optional[int]:
    """Effective target SDK: profile first, then ``manifest_details``."""
    if self.profile is not None and self.profile.target_sdk is not None:
      return self.profile.target_sdk
    try:
      value = int(self.manifest.get("target_sdk") or 0)
    except (TypeError, ValueError):
      return None
    return value or None

  @property
  def lowest_target_sdk(self) -> Optional[int]:
    """Lowest ``targetSdk`` among the values Gradle declares (per flavour).

    Play judges every shipped build, so the *lowest* value is the one the
    target-API policy must check; ``profile.target_sdk`` is the highest.
    """
    if self.profile is not None and self.profile.target_sdk_values:
      return min(self.profile.target_sdk_values)
    return self.target_sdk

  def purpose_in(self, allowed) -> bool:
    return evaluate.purpose_in(self.app_purpose, allowed)

  def purpose_label(self) -> str:
    """``file_manager (p=0.92, model)`` / ``not established`` for evidence text."""
    ap = self.app_purpose or {}
    purpose = ap.get("purpose") or "unknown"
    if purpose == "unknown" or not ap:
      return "not established"
    established = evaluate.purpose_in(ap, {purpose})
    conf = float(ap.get("confidence") or 0.0)
    src = ap.get("source") or "unavailable"
    return f"{purpose} (p={conf:.2f}, {src}{'' if established else ', below CONF_APP_PURPOSE'})"


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
  # (manifest) build zero or more findings from the app-level inputs
  # (:class:`ManifestInputs`: profile, legacy manifest dict, app purpose).
  compose_manifest: Optional[Callable[[ManifestInputs], List[Dict[str, Any]]]] = None
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


def _manifest_finding(policy_id: str, severity: str, summary: str, evidence: str,
                      trace: Dict[str, Any], recommendation: Optional[str] = None,
                      needs_review: bool = False) -> Dict[str, Any]:
  """One deterministic app-level finding in the shape the report expects.

  Every manifest finding carries ``client = "deterministic"``, ``kind =
  "manifest"`` and a ``decision_trace`` with the facts the rule read, so a
  reviewer can reproduce the verdict from the triage file alone. ``|`` is
  neutralised in the text fields because the (read-only) report renders them
  inside Markdown table cells; the trace keeps the raw values.
  """
  finding = {
      "policy_id": policy_id,
      "issue_summary": summary.replace("|", "¦"),
      "severity": severity,
      "files_involved": ["AndroidManifest.xml"],
      "evidence": evidence.replace("|", "¦").replace("\n", " "),
      "recommendation": recommendation or templates.recommendation(policy_id, severity),
      "client": "deterministic",
      "kind": "manifest",
      "decision_trace": {"evaluator_version": constants.EVALUATOR_VERSION, **trace},
  }
  if needs_review:
    finding["needs_manual_review"] = True
  return finding


def _service_starts_foreground(app_dir: str, class_name: str) -> Tuple[Optional[str], List[int]]:
  """``(relpath, lines)`` of ``startForeground`` value references in the
  service's own class file, or ``(None, [])`` when the file is not found or
  never calls it. Only the class's own file is checked (a call inherited from
  a base class is not resolved), so a miss means "not confirmed", never
  "not a foreground service"."""
  if not app_dir:
    return None, []
  for relpath in structure.find_class_files(app_dir, class_name):
    lines = structure.value_reference_lines(app_dir, relpath, "startForeground")
    if lines:
      return relpath, lines
  return None, []


def _foreground_service_findings_profile(inputs: ManifestInputs) -> List[Dict[str, Any]]:
  """Foreground-service checks over the merged :class:`AppProfile` (WP5).

  Rules, all deterministic (``target`` = effective ``targetSdk``):

  1. Typeless service whose own class calls ``startForeground`` and
     ``target >= FGS_TYPE_REQUIRED_TARGET_SDK`` -> **CRITICAL** (the platform
     throws at runtime and Play rejects the declaration). Typeless services
     that never call ``startForeground`` are ordinary bound/started services
     and produce nothing. This is the branch the legacy input made
     unreachable (``manifest_details.foreground_services`` listed only typed
     services).
  2. ``specialUse`` without the ``PROPERTY_SPECIAL_USE_FGS_SUBTYPE``
     ``<property>`` -> **CRITICAL**.
  3. Declared type without its ``FOREGROUND_SERVICE_<TYPE>`` permission on
     ``target >= 34`` -> IMPORTANT (kept from v1).
  4. Declared type whose policy definition the *established* app purpose
     clearly falls outside (``constants.FGS_TYPE_MISALIGNED_PURPOSES``) ->
     IMPORTANT "type misalignment". Never fires for ``unknown`` / ``other`` /
     low-confidence purposes.
  5. Every typed service -> SUGGESTION inventory (Play Console declaration
     reminder), unchanged from v1.
  6. ``FOREGROUND_SERVICE_SPECIAL_USE`` permission with no ``specialUse``
     service in the Play build -> SUGGESTION (stray permission).
  Only components and permissions that ship in the Play build
  (``profile.ships_in_play_build``) are examined.
  """
  profile = inputs.profile
  assert profile is not None
  findings: List[Dict[str, Any]] = []
  target = inputs.target_sdk or 0
  pid = "foreground_services_policy"
  purpose = inputs.purpose_label()
  services = [s for s in profile.play_build_components("service") if s.is_active]
  shipped_permissions = {p.name for p in profile.permissions.values() if profile.ships_in_play_build(p)}
  special_use_seen = False
  for svc in services:
    types = list(svc.fgs_types)
    base_trace = {"service": svc.name, "types": types, "target_sdk": target,
                  "sources": list(svc.sources), "app_purpose": purpose}
    if not types:
      relpath, lines = _service_starts_foreground(inputs.app_dir, svc.name)
      if relpath and target >= constants.FGS_TYPE_REQUIRED_TARGET_SDK:
        log.info("fgs: typeless service %s calls startForeground at %s:%s (target %d) -> CRITICAL",
                 svc.name, relpath, lines[:3], target)
        findings.append(_manifest_finding(
            pid, "CRITICAL",
            f"Foreground service {svc.name} declares no foregroundServiceType "
            f"(required when targeting API {target})",
            f"<service android:name=\"{svc.name}\"> has no android:foregroundServiceType; "
            f"startForeground called at {relpath}:L{lines[0]}",
            {**base_trace, "start_foreground": {"file": relpath, "lines": lines[:5]}}))
      elif relpath:
        log.info("fgs: typeless service %s calls startForeground but target %d < %d; no finding",
                 svc.name, target, constants.FGS_TYPE_REQUIRED_TARGET_SDK)
      else:
        log.debug("fgs: typeless service %s: no startForeground in its class file; treated as a plain service", svc.name)
      continue
    if "specialUse" in types:
      special_use_seen = True
      if constants.FGS_SPECIAL_USE_PROPERTY not in svc.properties:
        findings.append(_manifest_finding(
            pid, "CRITICAL",
            f"Foreground service {svc.name} declares specialUse without the "
            "PROPERTY_SPECIAL_USE_FGS_SUBTYPE property",
            f"<service android:name=\"{svc.name}\" android:foregroundServiceType=\"{'|'.join(types)}\"> "
            f"lacks <property android:name=\"{constants.FGS_SPECIAL_USE_PROPERTY}\">",
            {**base_trace, "properties": dict(svc.properties)}))
    missing = [t for t in types
               if target >= constants.FGS_TYPE_REQUIRED_TARGET_SDK
               and _fgs_permission_for_type(t) not in shipped_permissions]
    if missing:
      findings.append(_manifest_finding(
          pid, "IMPORTANT",
          f"Foreground service {svc.name} uses type(s) {', '.join(missing)} without "
          "the matching FOREGROUND_SERVICE_<TYPE> permission",
          f"types={types}; missing={[_fgs_permission_for_type(t) for t in missing]}",
          {**base_trace, "missing_permissions": [_fgs_permission_for_type(t) for t in missing]},
          recommendation=("Add the per-type FOREGROUND_SERVICE_<TYPE> permission for each "
                          "declared foregroundServiceType.")))
    misaligned = [t for t in types
                  if inputs.purpose_in(constants.FGS_TYPE_MISALIGNED_PURPOSES.get(t, frozenset()))]
    if misaligned:
      log.info("fgs: %s type(s) %s misaligned with established purpose %s -> IMPORTANT",
               svc.name, misaligned, purpose)
      findings.append(_manifest_finding(
          pid, "IMPORTANT",
          f"Foreground service {svc.name} declares type(s) {', '.join(misaligned)} that do not "
          f"align with the app's core purpose ({(inputs.app_purpose or {}).get('purpose')})",
          f"<service android:name=\"{svc.name}\" android:foregroundServiceType=\"{'|'.join(types)}\">; "
          f"declared_core_purpose={purpose}",
          {**base_trace, "misaligned_types": misaligned}))
    findings.append(_manifest_finding(
        pid, "SUGGESTION",
        f"Foreground service {svc.name} declares type(s) {', '.join(types)}; "
        "verify the use case matches the type's policy definition",
        f"<service android:name=\"{svc.name}\" android:foregroundServiceType=\"{'|'.join(types)}\">",
        base_trace))
  special_perm = "android.permission.FOREGROUND_SERVICE_SPECIAL_USE"
  if special_perm in shipped_permissions and not special_use_seen:
    findings.append(_manifest_finding(
        pid, "SUGGESTION",
        "FOREGROUND_SERVICE_SPECIAL_USE is requested but no service declares the specialUse type",
        f"<uses-permission android:name=\"{special_perm}\"/> with no specialUse service in the Play build",
        {"permission": special_perm, "services": [s.name for s in services], "target_sdk": target},
        recommendation=("Remove the unused FOREGROUND_SERVICE_SPECIAL_USE permission, or declare the "
                        "specialUse type (with its subtype property) on the service that needs it.")))
  return findings


def _foreground_service_compose(inputs: ManifestInputs) -> List[Dict[str, Any]]:
  """Profile-based checks when a profile exists; legacy dict checks otherwise."""
  if inputs.profile is not None:
    return _foreground_service_findings_profile(inputs)
  return _foreground_service_findings(inputs.manifest)


def _foreground_service_spec() -> PolicySpec:
  return PolicySpec(
      policy_id="foreground_services_policy",
      kind=MANIFEST,
      goal="permissions_and_apis",
      compose_manifest=_foreground_service_compose,
  )


# ---------------------------------------------------------------------------
# WP5 wave-1 manifest policies (deterministic; purpose-conditioned severity)
# ---------------------------------------------------------------------------


def _shipped_permission(inputs: ManifestInputs, short_name: str) -> Optional[android_manifest.Permission]:
  """The requested permission if it ships in the Play build, else None.

  Falls back to the legacy ``manifest_details.permissions`` list (as a bare
  :class:`Permission`) when no profile is available.
  """
  if inputs.profile is not None:
    perm = inputs.profile.permission(short_name)
    if perm is not None and inputs.profile.ships_in_play_build(perm):
      return perm
    return None
  for name in inputs.manifest.get("permissions") or []:
    if str(name).rsplit(".", 1)[-1] == short_name:
      return android_manifest.Permission(name=str(name))
  return None


def _perm_evidence(perm: android_manifest.Permission) -> str:
  extra = []
  if perm.max_sdk is not None:
    extra.append(f'android:maxSdkVersion="{perm.max_sdk}"')
  if perm.sources:
    extra.append(f"sources={perm.sources}")
  return f'<uses-permission android:name="{perm.name}"/>' + (f" ({'; '.join(extra)})" if extra else "")


def _all_files_access_findings(inputs: ManifestInputs) -> List[Dict[str, Any]]:
  """All files access: ``MANAGE_EXTERNAL_STORAGE`` (WP5).

  - Purpose established and in ``ALL_FILES_ACCESS_PURPOSES`` -> SUGGESTION
    (Play Console declaration reminder).
  - Otherwise -> **CRITICAL**; an unknown / low-confidence purpose is treated
    as unjustified and additionally marked for review, since the severity
    rests on a fact the model could not establish.
  - Broad grant plus scoped media / legacy storage permissions -> one extra
    IMPORTANT (redundant scope).
  """
  pid = "all_files_access_policy"
  perm = _shipped_permission(inputs, "MANAGE_EXTERNAL_STORAGE")
  if perm is None:
    return []
  purpose = inputs.purpose_label()
  justified = inputs.purpose_in(constants.ALL_FILES_ACCESS_PURPOSES)
  established = purpose != "not established" and "below CONF_APP_PURPOSE" not in purpose
  trace = {"permission": perm.name, "app_purpose": purpose, "justified_by_purpose": justified,
           "allowed_purposes": sorted(constants.ALL_FILES_ACCESS_PURPOSES)}
  findings: List[Dict[str, Any]] = []
  if justified:
    log.info("all_files_access: MANAGE_EXTERNAL_STORAGE justified by purpose %s -> SUGGESTION", purpose)
    findings.append(_manifest_finding(
        pid, "SUGGESTION",
        "MANAGE_EXTERNAL_STORAGE is requested; the core purpose qualifies but the Play Console "
        "All files access declaration must match",
        f"{_perm_evidence(perm)}; declared_core_purpose={purpose}", trace))
  else:
    log.info("all_files_access: MANAGE_EXTERNAL_STORAGE with purpose %s -> CRITICAL", purpose)
    findings.append(_manifest_finding(
        pid, "CRITICAL",
        "MANAGE_EXTERNAL_STORAGE is requested but the app's core purpose does not qualify for "
        "All files access",
        f"{_perm_evidence(perm)}; declared_core_purpose={purpose}", trace,
        needs_review=not established))
  media = [p for p in (
      _shipped_permission(inputs, s) for s in sorted(constants.MEDIA_PERMISSION_SHORT_NAMES)) if p is not None]
  # A legacy storage permission capped at maxSdkVersion <= 32 is the documented
  # compatibility pattern and is not redundant with the broad grant.
  media = [p for p in media if not (p.short_name == "READ_EXTERNAL_STORAGE" and p.max_sdk is not None and p.max_sdk <= 32)]
  if media:
    findings.append(_manifest_finding(
        pid, "IMPORTANT",
        "MANAGE_EXTERNAL_STORAGE is requested alongside scoped media / storage permissions "
        "(redundant scope)",
        "; ".join(_perm_evidence(p) for p in [perm] + media),
        {**trace, "redundant_permissions": [p.name for p in media]}))
  return findings


def _package_visibility_findings(inputs: ManifestInputs) -> List[Dict[str, Any]]:
  """Package visibility: ``QUERY_ALL_PACKAGES`` (WP5).

  - Purpose established and in ``PACKAGE_VISIBILITY_PURPOSES`` and no
    ``<queries>`` element -> SUGGESTION (declaration reminder).
  - Purpose not in the set (or not established) -> IMPORTANT "use
    ``<queries>``" (review-marked when the purpose is not established).
  - ``<queries>`` present alongside the permission -> IMPORTANT (the app
    already enumerates its needs; the broad grant is redundant).
  """
  pid = "package_visibility_policy"
  perm = _shipped_permission(inputs, "QUERY_ALL_PACKAGES")
  if perm is None:
    return []
  purpose = inputs.purpose_label()
  justified = inputs.purpose_in(constants.PACKAGE_VISIBILITY_PURPOSES)
  established = purpose != "not established" and "below CONF_APP_PURPOSE" not in purpose
  queries = (inputs.profile.queries if inputs.profile is not None else {}) or {}
  declared_queries = {k: v for k, v in queries.items() if v}
  trace = {"permission": perm.name, "app_purpose": purpose, "justified_by_purpose": justified,
           "allowed_purposes": sorted(constants.PACKAGE_VISIBILITY_PURPOSES),
           "queries": declared_queries}
  if declared_queries:
    log.info("package_visibility: QUERY_ALL_PACKAGES with <queries> %s -> IMPORTANT", declared_queries)
    return [_manifest_finding(
        pid, "IMPORTANT",
        "QUERY_ALL_PACKAGES is requested although the manifest already declares specific <queries>",
        f"{_perm_evidence(perm)}; <queries>={declared_queries}", trace)]
  if justified:
    log.info("package_visibility: QUERY_ALL_PACKAGES justified by purpose %s -> SUGGESTION", purpose)
    return [_manifest_finding(
        pid, "SUGGESTION",
        "QUERY_ALL_PACKAGES is requested; the core purpose qualifies but the Play Console "
        "Package visibility declaration must match",
        f"{_perm_evidence(perm)}; declared_core_purpose={purpose}", trace)]
  log.info("package_visibility: QUERY_ALL_PACKAGES with purpose %s -> IMPORTANT", purpose)
  return [_manifest_finding(
      pid, "IMPORTANT",
      "QUERY_ALL_PACKAGES is requested but the app's core purpose does not qualify for broad "
      "package visibility",
      f"{_perm_evidence(perm)}; declared_core_purpose={purpose}", trace,
      needs_review=not established)]


def _exact_alarm_findings(inputs: ManifestInputs) -> List[Dict[str, Any]]:
  """Exact alarm: ``USE_EXACT_ALARM`` / ``SCHEDULE_EXACT_ALARM`` (WP5).

  - ``USE_EXACT_ALARM`` with purpose in ``EXACT_ALARM_PURPOSES`` -> SUGGESTION;
    otherwise IMPORTANT (review-marked when the purpose is not established).
  - ``SCHEDULE_EXACT_ALARM`` -> SUGGESTION (runtime check + inexact fallback
    reminder). Emitted once even when both permissions are present with
    ``maxSdkVersion`` splits.
  """
  pid = "exact_alarm_policy"
  findings: List[Dict[str, Any]] = []
  purpose = inputs.purpose_label()
  use_exact = _shipped_permission(inputs, "USE_EXACT_ALARM")
  if use_exact is not None:
    justified = inputs.purpose_in(constants.EXACT_ALARM_PURPOSES)
    established = purpose != "not established" and "below CONF_APP_PURPOSE" not in purpose
    trace = {"permission": use_exact.name, "app_purpose": purpose, "justified_by_purpose": justified,
             "allowed_purposes": sorted(constants.EXACT_ALARM_PURPOSES)}
    if justified:
      findings.append(_manifest_finding(
          pid, "SUGGESTION",
          "USE_EXACT_ALARM is requested; the core purpose qualifies but the Play Console "
          "declaration and user-facing alarm use must match",
          f"{_perm_evidence(use_exact)}; declared_core_purpose={purpose}", trace))
    else:
      log.info("exact_alarm: USE_EXACT_ALARM with purpose %s -> IMPORTANT", purpose)
      findings.append(_manifest_finding(
          pid, "IMPORTANT",
          "USE_EXACT_ALARM is requested but the app's core purpose is not an alarm, timer or "
          "calendar app",
          f"{_perm_evidence(use_exact)}; declared_core_purpose={purpose}", trace,
          needs_review=not established))
  schedule = _shipped_permission(inputs, "SCHEDULE_EXACT_ALARM")
  if schedule is not None:
    findings.append(_manifest_finding(
        pid, "SUGGESTION",
        "SCHEDULE_EXACT_ALARM is requested; confirm the runtime permission check and the "
        "inexact-alarm fallback",
        _perm_evidence(schedule), {"permission": schedule.name, "app_purpose": purpose}))
  return findings


def _target_api_level_findings(inputs: ManifestInputs) -> List[Dict[str, Any]]:
  """Target API level (WP5), a numeric rule with a dated provenance block.

  Checks the *lowest* ``targetSdk`` any shipped flavour declares:

  - ``< PLAY_EXISTING_APP_MIN_TARGET_SDK`` -> **CRITICAL** (the app stops being
    available to new users on newer devices; updates are rejected).
  - ``< PLAY_REQUIRED_TARGET_SDK`` -> IMPORTANT (updates are rejected).
  - unknown -> SUGGESTION marked for review (the fact could not be read; a
    silent pass would read as compliance).
  """
  pid = "target_api_level"
  lowest = inputs.lowest_target_sdk
  values = list(inputs.profile.target_sdk_values) if inputs.profile is not None else []
  provenance = (inputs.profile.sdk_provenance.get("target_sdk") if inputs.profile is not None else None) or "manifest_details.json"
  trace = {"target_sdk": lowest, "target_sdk_values": values, "provenance": provenance,
           "required": constants.PLAY_REQUIRED_TARGET_SDK,
           "existing_app_floor": constants.PLAY_EXISTING_APP_MIN_TARGET_SDK,
           "requirement_provenance": dict(constants.PLAY_TARGET_SDK_PROVENANCE)}
  if lowest is None:
    log.warning("target_api_level: targetSdk unknown; emitting review item")
    return [_manifest_finding(
        pid, "SUGGESTION", "Target SDK could not be determined; verify it meets the Play requirement",
        f"targetSdk unknown (provenance: {provenance})", trace, needs_review=True)]
  if lowest < constants.PLAY_EXISTING_APP_MIN_TARGET_SDK:
    severity = "CRITICAL"
  elif lowest < constants.PLAY_REQUIRED_TARGET_SDK:
    severity = "IMPORTANT"
  else:
    log.info("target_api_level: targetSdk %d meets the requirement (%d)", lowest, constants.PLAY_REQUIRED_TARGET_SDK)
    return []
  log.info("target_api_level: lowest targetSdk %d (values %s) -> %s", lowest, values, severity)
  which = f"lowest of {values}" if len(values) > 1 else "declared"
  return [_manifest_finding(
      pid, severity,
      f"targetSdk {lowest} is below the Play requirement of API {constants.PLAY_REQUIRED_TARGET_SDK} "
      f"(existing-app floor {constants.PLAY_EXISTING_APP_MIN_TARGET_SDK})",
      f"targetSdk={lowest} ({which}; {provenance}); Play requires >= {constants.PLAY_REQUIRED_TARGET_SDK} "
      f"for new apps and updates since {constants.PLAY_TARGET_SDK_PROVENANCE['effective_from']}",
      trace)]


def _manifest_spec(policy_id: str, compose: Callable[[ManifestInputs], List[Dict[str, Any]]]) -> PolicySpec:
  return PolicySpec(policy_id=policy_id, kind=MANIFEST, goal="permissions_and_apis",
                    compose_manifest=compose)


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
    # WP5 wave-1 manifest policies (deterministic, purpose-conditioned severity).
    _manifest_spec("all_files_access_policy", _all_files_access_findings),
    _manifest_spec("package_visibility_policy", _package_visibility_findings),
    _manifest_spec("exact_alarm_policy", _exact_alarm_findings),
    _manifest_spec("target_api_level", _target_api_level_findings),
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
