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

"""Evaluator-owned Android manifest parser and merged ``AppProfile`` (WP1).

Why this exists
---------------
``orchestrator.py init`` writes ``manifest_details.json`` with a handful of
facts (package, target SDK, permission names, *typed* foreground services).
Several policies the evaluator needs to cover -- foreground-service typing,
package visibility, all-files access, exact alarms, default-handler roles,
accessibility tools -- depend on manifest facts that file does not carry:
services *without* a ``foregroundServiceType``, ``maxSdkVersion`` on
permissions, ``requestLegacyExternalStorage``, ``<queries>``, ``<property>``
sub-tags, intent filters, and which product flavor contributed what. The
orchestrator is read-only for this work, so the evaluator parses the manifests
itself and keeps ``manifest_details.json`` as a fallback for the two facts it
carries reliably (``package_name``, ``target_sdk``).

What it produces
----------------
One :class:`AppProfile` per app. It is built once per run and stored on the
engine's ``RunContext``; policies read facts from it instead of re-parsing.

* **Module discovery.** Every ``AndroidManifest.xml`` under ``app_dir`` (minus
  ``structure.IGNORED_DIR_NAMES`` and test source sets) is grouped by *module
  root* -- the path prefix before ``/src/``. The **primary module** is the one
  that looks most like the shipped application: it declares a LAUNCHER
  activity, then has the most components. Other modules (benchmarks,
  libraries, wear/tv companions) are recorded in ``other_modules`` and logged,
  never merged, so library manifests cannot inject permissions or components.
* **Source-set merge.** Within the primary module, ``src/main`` is merged
  first, then every other source set (product flavors, build types) in sorted
  order. Each permission and component carries ``sources`` -- the source sets
  that declared it -- so a later policy can attribute a fact to the
  ``play`` flavor versus ``main``. Attribute conflicts follow the manifest
  merger's defaults: *main wins* unless the flavor's ``<application>`` lists
  the attribute in ``tools:replace``. ``tools:node="remove"`` is recorded in
  ``removed_in`` rather than deleting the entry (an entry removed by a
  flavor but declared by ``main`` is still active in other builds).
* **SDK and package fallbacks.** Modern projects put ``namespace`` /
  ``applicationId`` / ``targetSdk`` in Gradle rather than the manifest. The
  module's ``build.gradle`` / ``build.gradle.kts`` is scanned with narrow
  regexes for those literals; when they are variables (``libs.versions...``)
  the value stays unknown and ``manifest_details.json`` fills it in.
  ``sdk_provenance`` records where each value came from.
* **Resource resolution.** ``@string/...`` labels are resolved through
  :mod:`typesafe_eval.resources`; accessibility services get their
  ``android:isAccessibilityTool`` flag from the ``res/xml`` config referenced
  by their ``android.accessibilityservice`` meta-data.

What it deliberately does not do
--------------------------------
* No policy judgement. Helpers such as :meth:`AppProfile.launcher_activities`
  or :meth:`AppProfile.default_handler_roles` derive *platform* facts from
  platform intent constants; deciding whether a fact is a policy problem is
  the registry's job.
* No app, vendor or library names in logic. Roles are keyed by
  ``android.intent.action.*`` / ``android.provider.Telephony.*`` constants
  only.
* No ``manifest_details.json`` mutation; the orchestrator's file is read as a
  fallback and never written.

Everything is standard-library and deterministic. Parse failures are logged at
WARNING and recorded in ``AppProfile.warnings`` so a partial profile is still
returned (the engine must never abort because one flavor manifest is broken).
"""

from __future__ import annotations

import dataclasses
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

from typesafe_eval import constants
from typesafe_eval import resources
from typesafe_eval import structure

log = logging.getLogger("typesafe_eval.android_manifest")

ANDROID_NS = "http://schemas.android.com/apk/res/android"
TOOLS_NS = "http://schemas.android.com/tools"

MANIFEST_FILENAME = "AndroidManifest.xml"

# Source sets that are compiled only for tests; never part of the shipped APK.
_TEST_SOURCE_SET_RE = re.compile(r"^(test|androidTest|testFixtures|screenshotTest)", re.IGNORECASE)

# Gradle literals. Deliberately narrow: only numeric / quoted literals match, a
# variable reference leaves the value unknown and the fallback is used.
_GRADLE_INT_RE = {
    "target_sdk": re.compile(r"\btargetSdk(?:Version)?\s*(?:=|\(|\s)\s*(\d+)"),
    "min_sdk": re.compile(r"\bminSdk(?:Version)?\s*(?:=|\(|\s)\s*(\d+)"),
}
_GRADLE_STR_RE = {
    "namespace": re.compile(r"\bnamespace\s*(?:=|\(|\s)\s*[\"']([\w.]+)[\"']"),
    "application_id": re.compile(r"\bapplicationId\s*(?:=|\(|\s)\s*[\"']([\w.]+)[\"']"),
}

# Platform intent constants used to derive default-handler roles. These are
# framework identifiers, not app names, and are the same strings Play's policy
# text refers to when it describes "default SMS / Phone / Assistant handler".
_ROLE_ACTIONS: Dict[str, Tuple[str, ...]] = {
    "sms": (
        "android.provider.Telephony.SMS_DELIVER",
        "android.provider.Telephony.WAP_PUSH_DELIVER",
        "android.intent.action.RESPOND_VIA_MESSAGE",
    ),
    "dialer": ("android.intent.action.DIAL",),
    "assistant": ("android.intent.action.ASSIST",),
    "call_redirection": ("android.telecom.CallRedirectionService",),
    "call_screening": ("android.telecom.CallScreeningService",),
    "in_call": ("android.telecom.InCallService",),
}
_SMS_SCHEMES = ("sms", "smsto", "mms", "mmsto")
_SMS_RECEIVED_ACTIONS = (
    "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.WAP_PUSH_RECEIVED",
)
_ACCESSIBILITY_SERVICE_ACTION = "android.accessibilityservice.AccessibilityService"
_ACCESSIBILITY_META_DATA = "android.accessibilityservice"
_FILE_HANDLING_ACTIONS = (
    "android.intent.action.VIEW", "android.intent.action.EDIT",
    "android.intent.action.SEND", "android.intent.action.SEND_MULTIPLE",
    "android.intent.action.OPEN_DOCUMENT", "android.intent.action.GET_CONTENT",
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class IntentFilter:
  """One ``<intent-filter>``; ``data`` keeps the raw attribute dicts."""

  actions: List[str] = dataclasses.field(default_factory=list)
  categories: List[str] = dataclasses.field(default_factory=list)
  schemes: List[str] = dataclasses.field(default_factory=list)
  mime_types: List[str] = dataclasses.field(default_factory=list)
  hosts: List[str] = dataclasses.field(default_factory=list)
  source: str = "main"

  def to_dict(self) -> Dict[str, Any]:
    return {k: v for k, v in dataclasses.asdict(self).items() if v}


@dataclasses.dataclass
class Permission:
  """One ``<uses-permission>`` (or ``-sdk-23``) merged across source sets."""

  name: str
  max_sdk: Optional[int] = None
  min_sdk: Optional[int] = None
  flags: Optional[str] = None
  sdk23_only: bool = False
  sources: List[str] = dataclasses.field(default_factory=list)
  removed_in: List[str] = dataclasses.field(default_factory=list)

  @property
  def short_name(self) -> str:
    return self.name.rsplit(".", 1)[-1]

  def to_dict(self) -> Dict[str, Any]:
    return {k: v for k, v in dataclasses.asdict(self).items() if v not in (None, [], False)}


@dataclasses.dataclass
class Component:
  """An activity / service / receiver / provider merged across source sets.

  ``exported`` is ``None`` when the attribute is absent (the platform default
  then depends on intent filters and target SDK; policies decide what that
  means). ``fgs_types`` is the split ``android:foregroundServiceType``.
  ``properties`` are ``<property android:name android:value>`` sub-tags (the
  mechanism for ``PROPERTY_SPECIAL_USE_FGS_SUBTYPE``). ``meta_data`` are
  ``<meta-data>`` sub-tags (``name -> value|resource``).
  """

  kind: str
  name: str
  exported: Optional[bool] = None
  enabled: Optional[bool] = None
  permission: Optional[str] = None
  process: Optional[str] = None
  fgs_types: List[str] = dataclasses.field(default_factory=list)
  intent_filters: List[IntentFilter] = dataclasses.field(default_factory=list)
  properties: Dict[str, str] = dataclasses.field(default_factory=dict)
  meta_data: Dict[str, str] = dataclasses.field(default_factory=dict)
  authorities: List[str] = dataclasses.field(default_factory=list)
  grant_uri_permissions: Optional[bool] = None
  sources: List[str] = dataclasses.field(default_factory=list)
  removed_in: List[str] = dataclasses.field(default_factory=list)

  @property
  def is_active(self) -> bool:
    """False only when every declaring source set also removes it.

    A component declared by ``main`` and removed by one flavor still ships in
    every other build, so it stays active (recall over precision). A
    component known only through a ``tools:node="remove"`` (a library
    component the app strips) has no declaring source and is inactive.
    """
    if not self.removed_in:
      return True
    return any(s not in self.removed_in for s in self.sources)

  @property
  def actions(self) -> List[str]:
    return sorted({a for f in self.intent_filters for a in f.actions})

  @property
  def categories(self) -> List[str]:
    return sorted({c for f in self.intent_filters for c in f.categories})

  def has_action(self, *actions: str) -> bool:
    return any(a in self.actions for a in actions)

  def to_dict(self) -> Dict[str, Any]:
    d: Dict[str, Any] = {"kind": self.kind, "name": self.name, "sources": list(self.sources)}
    for key in ("exported", "enabled", "permission", "process", "grant_uri_permissions"):
      v = getattr(self, key)
      if v is not None:
        d[key] = v
    for key in ("fgs_types", "properties", "meta_data", "authorities", "removed_in"):
      v = getattr(self, key)
      if v:
        d[key] = v
    if self.intent_filters:
      d["intent_filters"] = [f.to_dict() for f in self.intent_filters]
    return d


@dataclasses.dataclass
class AccessibilityService:
  """A service bound with the platform accessibility action."""

  name: str
  config_resource: Optional[str] = None
  config_path: Optional[str] = None
  is_accessibility_tool: Optional[bool] = None
  description: Optional[str] = None
  sources: List[str] = dataclasses.field(default_factory=list)
  ships_in_play_build: bool = True

  def to_dict(self) -> Dict[str, Any]:
    return {k: v for k, v in dataclasses.asdict(self).items() if v is not None}


@dataclasses.dataclass
class AppProfile:
  """Merged, evaluator-owned manifest facts for one application.

  Attributes:
    app_dir: Application root the manifests were read from.
    module_root: Relative path of the primary module (``""`` for a single-
      module tree whose ``src/`` sits at the root).
    package_name: Effective application id. Provenance in
      ``sdk_provenance["package_name"]``.
    target_sdk / min_sdk: Effective values (Gradle first, then ``<uses-sdk>``,
      then ``manifest_details.json``). When Gradle declares several
      ``targetSdk`` values (per flavor) the *highest* is used and every value
      is listed in ``target_sdk_values``; policies that need the lowest
      shipped value can read that list.
    permissions: ``<uses-permission>`` entries merged by name.
    defined_permissions: ``<permission>`` names the app defines itself.
    features: ``<uses-feature>`` ``name -> required`` (None when unspecified).
    application: Selected ``<application>`` attributes (``label`` resolved to
      text when it is a string resource), plus ``application_sources`` with
      the source set that contributed each attribute.
    components: Every activity/service/receiver/provider (see
      :class:`Component`), including inactive ones (``is_active``).
    accessibility_services: Services bound with the accessibility action and
      the ``isAccessibilityTool`` flag from their config resource.
    queries: ``<queries>`` content: ``packages``, ``intents`` (actions),
      ``providers`` (authorities).
    meta_data: App-level ``<meta-data>`` ``name -> value|resource``.
    source_sets: The source sets merged, in merge order.
    other_modules: Module roots whose manifests were *not* merged.
    manifests: Relative paths of every manifest read (primary module only).
    warnings: Human-readable parse/merge anomalies (also logged).
    sdk_provenance: ``fact -> where it came from``.
  """

  app_dir: str = ""
  module_root: str = ""
  package_name: Optional[str] = None
  target_sdk: Optional[int] = None
  min_sdk: Optional[int] = None
  target_sdk_values: List[int] = dataclasses.field(default_factory=list)
  permissions: Dict[str, Permission] = dataclasses.field(default_factory=dict)
  defined_permissions: List[str] = dataclasses.field(default_factory=list)
  features: Dict[str, Optional[bool]] = dataclasses.field(default_factory=dict)
  application: Dict[str, Any] = dataclasses.field(default_factory=dict)
  application_sources: Dict[str, str] = dataclasses.field(default_factory=dict)
  components: List[Component] = dataclasses.field(default_factory=list)
  accessibility_services: List[AccessibilityService] = dataclasses.field(default_factory=list)
  queries: Dict[str, List[str]] = dataclasses.field(default_factory=lambda: {
      "packages": [], "intents": [], "providers": []})
  meta_data: Dict[str, str] = dataclasses.field(default_factory=dict)
  source_sets: List[str] = dataclasses.field(default_factory=list)
  other_modules: List[str] = dataclasses.field(default_factory=list)
  manifests: List[str] = dataclasses.field(default_factory=list)
  warnings: List[str] = dataclasses.field(default_factory=list)
  sdk_provenance: Dict[str, str] = dataclasses.field(default_factory=dict)
  resource_index: Optional[resources.ResourceIndex] = dataclasses.field(default=None, repr=False)

  # -- permission helpers ---------------------------------------------------

  def has_permission(self, name: str) -> bool:
    """True when ``name`` (full or short, e.g. ``QUERY_ALL_PACKAGES``) is requested."""
    return self.permission(name) is not None

  def permission(self, name: str) -> Optional[Permission]:
    if name in self.permissions:
      return self.permissions[name]
    short = name.rsplit(".", 1)[-1]
    for p in self.permissions.values():
      if p.short_name == short:
        return p
    return None

  def permissions_matching(self, prefix: str) -> List[Permission]:
    """Permissions whose short name starts with ``prefix`` (``FOREGROUND_SERVICE_``)."""
    return sorted((p for p in self.permissions.values() if p.short_name.startswith(prefix)),
                  key=lambda p: p.name)

  # -- source-set helpers ---------------------------------------------------

  def prioritized_source_sets(self) -> List[str]:
    """Source sets that make up the Play build.

    Mirrors the engine's candidate filtering (``engine._excluded_flavors``):
    when a ``play`` flavor exists only ``constants.PRIORITIZED_FLAVORS`` count;
    otherwise every source set is part of the shipped build.
    """
    if "play" in self.source_sets:
      return [s for s in self.source_sets if s in constants.PRIORITIZED_FLAVORS]
    return list(self.source_sets)

  def partial_sources(self, entry: Any) -> Optional[List[str]]:
    """The shipped source sets that declare ``entry`` when they are a strict subset (WP8).

    A permission or component declared only by a flavour (``play`` but not
    ``main``) affects one build variant; a reviewer needs to know which.
    Returns the declaring shipped source sets in merge order, or None when the
    entry is declared in every shipped source set, in ``main`` (which every
    variant merges), or has no source attribution at all (fallback profile).
    """
    sources = list(getattr(entry, "sources", None) or [])
    if not sources or "main" in sources:
      return None
    shipped = self.prioritized_source_sets()
    declaring = [s for s in shipped if s in sources]
    if not declaring or len(declaring) >= len(shipped):
      return None
    return declaring

  def ships_in_play_build(self, entry: Any) -> bool:
    """True when a :class:`Component` / :class:`Permission` is in the Play build.

    The Play build is the merge of :meth:`prioritized_source_sets`; an entry
    ships when one of those source sets declares it and none of them removes
    it (``tools:node="remove"``). An entry with no declaring source at all
    (fallback-only) is treated as shipping, so unknowns err towards recall; a
    removal-only entry (a library component the app strips) does not ship.
    """
    sources = list(getattr(entry, "sources", []) or [])
    removed = set(getattr(entry, "removed_in", []) or [])
    if not sources and not removed:
      return True
    if sources == ["manifest_details.json"]:
      return True
    prioritized = set(self.prioritized_source_sets())
    if removed & prioritized:
      return False
    return any(s in prioritized for s in sources)

  def play_build_components(self, kind: Optional[str] = None) -> List[Component]:
    return [c for c in self.components if (kind is None or c.kind == kind)
            and self.ships_in_play_build(c)]

  # -- component helpers ----------------------------------------------------

  def components_of(self, kind: str, include_inactive: bool = False) -> List[Component]:
    return [c for c in self.components if c.kind == kind and (include_inactive or c.is_active)]

  @property
  def activities(self) -> List[Component]:
    return self.components_of("activity")

  @property
  def services(self) -> List[Component]:
    return self.components_of("service")

  @property
  def receivers(self) -> List[Component]:
    return self.components_of("receiver")

  @property
  def providers(self) -> List[Component]:
    return self.components_of("provider")

  def launcher_activities(self) -> List[Component]:
    """Activities (or aliases) with MAIN + LAUNCHER/LEANBACK_LAUNCHER."""
    out = []
    for c in self.activities:
      for f in c.intent_filters:
        if "android.intent.action.MAIN" in f.actions and any(
            cat in f.categories for cat in ("android.intent.category.LAUNCHER",
                                            "android.intent.category.LEANBACK_LAUNCHER")):
          out.append(c)
          break
    return out

  def services_with_fgs_type(self) -> List[Component]:
    return [s for s in self.services if s.fgs_types]

  def services_without_fgs_type(self) -> List[Component]:
    return [s for s in self.services if not s.fgs_types]

  def exported_components(self) -> List[Component]:
    """Components that are explicitly exported or implicitly so (filters, no attr)."""
    return [c for c in self.components if c.is_active and (
        c.exported is True or (c.exported is None and c.intent_filters and c.kind != "provider"))]

  def default_handler_roles(self) -> Dict[str, List[str]]:
    """Platform roles the app can be the default handler for, from intent filters.

    Returns ``role -> [component names]``. Roles: ``sms``, ``dialer``,
    ``assistant``, ``home``, ``call_redirection``, ``call_screening``,
    ``in_call``. Derived only from framework action/category constants.
    """
    roles: Dict[str, List[str]] = {}

    def add(role: str, comp: Component) -> None:
      roles.setdefault(role, [])
      if comp.name not in roles[role]:
        roles[role].append(comp.name)

    for c in self.components:
      if not c.is_active:
        continue
      for role, actions in _ROLE_ACTIONS.items():
        if c.has_action(*actions):
          add(role, c)
      for f in c.intent_filters:
        if "android.intent.category.HOME" in f.categories and "android.intent.action.MAIN" in f.actions:
          add("home", c)
        if "android.intent.action.SENDTO" in f.actions and any(s in _SMS_SCHEMES for s in f.schemes):
          add("sms", c)
    return roles

  def sms_receivers(self) -> List[Component]:
    return [c for c in self.receivers if c.has_action(*_SMS_RECEIVED_ACTIONS)]

  def file_handling_activities(self) -> List[Component]:
    """Activities that accept files/documents via VIEW/EDIT/SEND/OPEN filters."""
    out = []
    for c in self.activities:
      for f in c.intent_filters:
        if any(a in _FILE_HANDLING_ACTIONS for a in f.actions) and (
            f.mime_types or "file" in f.schemes or "content" in f.schemes):
          out.append(c)
          break
    return out

  # -- serialisation ----------------------------------------------------------

  def summary(self) -> Dict[str, Any]:
    """Compact JSON-safe view written to ``typesafe_triage.json``."""
    return {
        "module_root": self.module_root,
        "package_name": self.package_name,
        "target_sdk": self.target_sdk,
        "target_sdk_values": self.target_sdk_values,
        "min_sdk": self.min_sdk,
        "sdk_provenance": self.sdk_provenance,
        "source_sets": self.source_sets,
        "prioritized_source_sets": self.prioritized_source_sets(),
        "manifests": self.manifests,
        "other_modules": self.other_modules,
        "permissions": {n: p.to_dict() for n, p in sorted(self.permissions.items())},
        "application": self.application,
        "application_sources": self.application_sources,
        "component_counts": {
            kind: len(self.components_of(kind)) for kind in ("activity", "service", "receiver", "provider")},
        "inactive_components": [c.name for c in self.components if not c.is_active],
        "flavor_only_components": [
            c.name for c in self.components if c.is_active and not self.ships_in_play_build(c)],
        "launcher_activities": [c.name for c in self.launcher_activities()],
        "services": [c.to_dict() for c in self.components_of("service", include_inactive=True)],
        "accessibility_services": [a.to_dict() for a in self.accessibility_services],
        "default_handler_roles": self.default_handler_roles(),
        "sms_receivers": [c.name for c in self.sms_receivers()],
        "file_handling_activities": [c.name for c in self.file_handling_activities()],
        "queries": self.queries,
        "features": self.features,
        "meta_data": self.meta_data,
        "warnings": self.warnings,
    }

  def to_dict(self) -> Dict[str, Any]:
    """Full JSON-safe view (every component)."""
    d = self.summary()
    d["components"] = [c.to_dict() for c in self.components]
    d["defined_permissions"] = self.defined_permissions
    return d

  def render_compact(self) -> str:
    """Deterministic, model-readable digest (used from WP4 for the per-app question).

    Stable ordering matters: WP4 keys its per-app cache on the sha256 of this
    text, so any change here invalidates that cache by design.
    """
    lines = [
        f"package: {self.package_name or 'unknown'}",
        f"targetSdk: {self.target_sdk if self.target_sdk is not None else 'unknown'}"
        f"; minSdk: {self.min_sdk if self.min_sdk is not None else 'unknown'}",
        f"label: {self.application.get('label') or 'unknown'}",
    ]
    flags = [k for k in ("request_legacy_external_storage", "preserve_legacy_external_storage",
                         "uses_cleartext_traffic", "allow_backup", "debuggable")
             if self.application.get(k) is True]
    if flags:
      lines.append("application flags: " + ", ".join(flags))
    perms = []
    for p in sorted(self.permissions.values(), key=lambda p: p.name):
      qual = []
      if p.max_sdk is not None:
        qual.append(f"maxSdk={p.max_sdk}")
      if p.min_sdk is not None:
        qual.append(f"minSdk={p.min_sdk}")
      if [s for s in p.sources if s != "main"]:
        qual.append("from=" + "+".join(p.sources))
      perms.append(p.short_name + (f" ({', '.join(qual)})" if qual else ""))
    lines.append("permissions: " + (", ".join(perms) if perms else "none"))
    counts = ", ".join(f"{k}={len(self.components_of(k))}"
                       for k in ("activity", "service", "receiver", "provider"))
    lines.append("components: " + counts)
    launchers = self.launcher_activities()
    if launchers:
      lines.append("launcher: " + ", ".join(c.name for c in launchers))
    for s in self.services:
      extra = []
      if s.fgs_types:
        extra.append("fgs=" + "|".join(s.fgs_types))
      if s.properties:
        extra.append("properties=" + ",".join(f"{k}={v}" for k, v in sorted(s.properties.items())))
      if s.actions:
        extra.append("actions=" + ",".join(s.actions))
      if not self.ships_in_play_build(s):
        extra.append("flavor-only=" + "+".join(s.sources))
      lines.append(f"service {s.name}" + (f" [{'; '.join(extra)}]" if extra else ""))
    for a in self.accessibility_services:
      lines.append(f"accessibility service {a.name}: isAccessibilityTool="
                   f"{a.is_accessibility_tool if a.is_accessibility_tool is not None else 'unknown'}"
                   + ("" if a.ships_in_play_build else f" (flavor-only: {'+'.join(a.sources)})"))
    roles = self.default_handler_roles()
    if roles:
      lines.append("default-handler roles: " + ", ".join(f"{r}({len(v)})" for r, v in sorted(roles.items())))
    if self.sms_receivers():
      lines.append("sms receivers: " + ", ".join(c.name for c in self.sms_receivers()))
    fh = self.file_handling_activities()
    if fh:
      lines.append(f"file-handling activities: {len(fh)}")
    exported = self.exported_components()
    if exported:
      lines.append(f"exported components: {len(exported)}")
    if any(self.queries.values()):
      lines.append("queries: " + "; ".join(f"{k}={','.join(v)}" for k, v in sorted(self.queries.items()) if v))
    if self.features:
      lines.append("features: " + ", ".join(
          f"{n}{'' if req is None else ('(required)' if req else '(optional)')}"
          for n, req in sorted(self.features.items())))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _split_manifest_path(relpath: str) -> Tuple[str, str]:
  """``(module_root, source_set)`` for a manifest relative path.

  ``app/src/play/AndroidManifest.xml`` -> ``("app", "play")``;
  ``src/main/AndroidManifest.xml`` -> ``("", "main")``; a legacy layout
  ``AndroidManifest.xml`` next to ``build.gradle`` -> ``(dirname, "main")``.
  """
  parts = relpath.split("/")
  if "src" in parts[:-1]:
    i = parts.index("src")
    module_root = "/".join(parts[:i])
    source_set = parts[i + 1] if i + 1 < len(parts) - 1 else "main"
    return module_root, source_set
  return "/".join(parts[:-1]), "main"


def discover_manifests(app_dir: str) -> Dict[str, List[Tuple[str, str]]]:
  """``module_root -> [(source_set, relpath), ...]`` for every shipped manifest."""
  found: Dict[str, List[Tuple[str, str]]] = {}
  for root, dirs, files in os.walk(app_dir):
    dirs[:] = sorted(d for d in dirs if d not in structure.IGNORED_DIR_NAMES)
    if MANIFEST_FILENAME in files:
      rel = os.path.relpath(os.path.join(root, MANIFEST_FILENAME), app_dir).replace(os.sep, "/")
      module_root, source_set = _split_manifest_path(rel)
      if _TEST_SOURCE_SET_RE.match(source_set):
        log.debug("manifest: skipping test source set %s", rel)
        continue
      found.setdefault(module_root, []).append((source_set, rel))
  for entries in found.values():
    # ``main`` first, then deterministic order for flavors/build types.
    entries.sort(key=lambda e: (e[0] != "main", e[0]))
  return found


def _a(elem: ET.Element, name: str, ns: str = ANDROID_NS) -> Optional[str]:
  return elem.get(f"{{{ns}}}{name}")


def _bool(value: Optional[str]) -> Optional[bool]:
  if value is None:
    return None
  v = value.strip().lower()
  if v == "true":
    return True
  if v == "false":
    return False
  return None


def _int(value: Optional[str]) -> Optional[int]:
  if value is None:
    return None
  try:
    return int(value.strip())
  except ValueError:
    return None


def _local(tag: str) -> str:
  return tag.split("}")[-1]


def _parse_manifest(path: str) -> Optional[ET.Element]:
  with open(path, "r", encoding="utf-8-sig") as f:
    return ET.fromstring(f.read())


def _score_module(root_elem: Optional[ET.Element]) -> Tuple[int, int, int]:
  """(has launcher, has <application>, component count) -- higher is more app-like."""
  if root_elem is None:
    return (0, 0, 0)
  app = root_elem.find("application")
  if app is None:
    return (0, 0, 0)
  comps = [c for c in app if _local(c.tag) in ("activity", "activity-alias", "service", "receiver", "provider")]
  launcher = 0
  for c in comps:
    for f in c.findall("intent-filter"):
      cats = {_a(x, "name") for x in f.findall("category")}
      if "android.intent.category.LAUNCHER" in cats or "android.intent.category.LEANBACK_LAUNCHER" in cats:
        launcher = 1
  return (launcher, 1, len(comps))


# ---------------------------------------------------------------------------
# Gradle fallback
# ---------------------------------------------------------------------------


def _read_gradle(app_dir: str, module_root: str) -> Dict[str, Any]:
  """Literal ``namespace`` / ``applicationId`` / ``targetSdk`` / ``minSdk`` values.

  Returns ``{"namespace", "application_id", "target_sdk_values", "min_sdk_values", "path"}``.
  """
  out: Dict[str, Any] = {"target_sdk_values": [], "min_sdk_values": []}
  base = os.path.join(app_dir, module_root) if module_root else app_dir
  for fn in ("build.gradle.kts", "build.gradle"):
    p = os.path.join(base, fn)
    if not os.path.isfile(p):
      continue
    try:
      with open(p, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    except OSError as exc:
      log.warning("manifest: could not read %s: %s", p, exc)
      continue
    # Strip comments so a commented-out ``targetSdkVersion`` does not count.
    text = re.sub(r"//.*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    out["path"] = os.path.relpath(p, app_dir).replace(os.sep, "/")
    for key, rx in _GRADLE_STR_RE.items():
      m = rx.search(text)
      if m and key not in out:
        out[key] = m.group(1)
    for key, rx in _GRADLE_INT_RE.items():
      vals = sorted({int(m.group(1)) for m in rx.finditer(text)})
      if vals:
        out[key + "_values"] = vals
    break
  return out


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


class _Merger:
  """Accumulates one module's manifests into an :class:`AppProfile`."""

  def __init__(self, profile: AppProfile):
    self.profile = profile
    self._components: Dict[Tuple[str, str], Component] = {}

  # -- helpers --

  def _qualify(self, name: Optional[str]) -> str:
    if not name:
      return ""
    if name.startswith(".") and self.profile.package_name:
      return self.profile.package_name + name
    return name

  def _warn(self, msg: str) -> None:
    self.profile.warnings.append(msg)
    log.warning("manifest: %s", msg)

  # -- top level --

  def merge(self, root: ET.Element, source_set: str, relpath: str) -> None:
    if _local(root.tag) != "manifest":
      self._warn(f"{relpath}: root element is <{_local(root.tag)}>, expected <manifest>")
      return
    pkg = root.get("package")
    if pkg and not self.profile.package_name:
      self.profile.package_name = pkg
      self.profile.sdk_provenance["package_name"] = f"manifest:{relpath}"
    for child in root:
      tag = _local(child.tag)
      if tag == "uses-sdk":
        self._merge_uses_sdk(child, relpath)
      elif tag in ("uses-permission", "uses-permission-sdk-23"):
        self._merge_permission(child, source_set, sdk23=(tag == "uses-permission-sdk-23"))
      elif tag == "permission":
        name = _a(child, "name")
        if name and name not in self.profile.defined_permissions:
          self.profile.defined_permissions.append(name)
      elif tag == "uses-feature":
        name = _a(child, "name")
        if name:
          self.profile.features.setdefault(name, _bool(_a(child, "required")))
      elif tag == "queries":
        self._merge_queries(child)
      elif tag == "application":
        self._merge_application(child, source_set)

  def _merge_uses_sdk(self, elem: ET.Element, relpath: str) -> None:
    t = _int(_a(elem, "targetSdkVersion"))
    m = _int(_a(elem, "minSdkVersion"))
    if t is not None and self.profile.target_sdk is None:
      self.profile.target_sdk = t
      self.profile.target_sdk_values = [t]
      self.profile.sdk_provenance["target_sdk"] = f"manifest:{relpath}"
    if m is not None and self.profile.min_sdk is None:
      self.profile.min_sdk = m
      self.profile.sdk_provenance["min_sdk"] = f"manifest:{relpath}"

  def _merge_permission(self, elem: ET.Element, source_set: str, sdk23: bool) -> None:
    name = _a(elem, "name")
    if not name:
      return
    removed = _a(elem, "node", TOOLS_NS) == "remove"
    perm = self.profile.permissions.get(name)
    if perm is None:
      perm = Permission(name=name, sdk23_only=sdk23)
      self.profile.permissions[name] = perm
    if removed:
      if source_set not in perm.removed_in:
        perm.removed_in.append(source_set)
      return
    if source_set not in perm.sources:
      perm.sources.append(source_set)
    for attr, key in (("maxSdkVersion", "max_sdk"), ("minSdkVersion", "min_sdk")):
      v = _int(_a(elem, attr))
      if v is None:
        continue
      cur = getattr(perm, key)
      if cur is None:
        setattr(perm, key, v)
      elif cur != v:
        self._warn(f"permission {name}: {attr} differs across source sets ({cur} vs {v} in {source_set})")
    flags = _a(elem, "usesPermissionFlags")
    if flags and not perm.flags:
      perm.flags = flags

  def _merge_queries(self, elem: ET.Element) -> None:
    q = self.profile.queries
    for child in elem:
      tag = _local(child.tag)
      if tag == "package":
        name = _a(child, "name")
        if name and name not in q["packages"]:
          q["packages"].append(name)
      elif tag == "intent":
        for act in child.findall("action"):
          name = _a(act, "name")
          if name and name not in q["intents"]:
            q["intents"].append(name)
      elif tag == "provider":
        auth = _a(child, "authorities")
        if auth and auth not in q["providers"]:
          q["providers"].append(auth)

  # -- <application> --

  _APP_ATTRS = {
      "name": ("name", str),
      "label": ("label", str),
      "requestLegacyExternalStorage": ("request_legacy_external_storage", bool),
      "preserveLegacyExternalStorage": ("preserve_legacy_external_storage", bool),
      "usesCleartextTraffic": ("uses_cleartext_traffic", bool),
      "allowBackup": ("allow_backup", bool),
      "debuggable": ("debuggable", bool),
      "networkSecurityConfig": ("network_security_config", str),
      "dataExtractionRules": ("data_extraction_rules", str),
      "fullBackupContent": ("full_backup_content", str),
      "hasFragileUserData": ("has_fragile_user_data", bool),
      "enableOnBackInvokedCallback": ("enable_on_back_invoked_callback", bool),
  }

  def _merge_application(self, elem: ET.Element, source_set: str) -> None:
    replace = {x.strip() for x in (_a(elem, "replace", TOOLS_NS) or "").split(",") if x.strip()}
    for attr, (key, typ) in self._APP_ATTRS.items():
      raw = _a(elem, attr)
      if raw is None:
        continue
      value: Any = _bool(raw) if typ is bool else raw
      if typ is str and key == "name":
        value = self._qualify(raw)
      existing = key in self.profile.application
      if existing and f"android:{attr}" not in replace:
        if self.profile.application[key] != value:
          self._warn(f"application {attr}: {source_set} declares {raw!r} but main wins "
                     f"(no tools:replace)")
        continue
      self.profile.application[key] = value
      self.profile.application_sources[key] = source_set
    for child in elem:
      tag = _local(child.tag)
      if tag == "meta-data":
        name = _a(child, "name")
        if name:
          self.profile.meta_data.setdefault(name, _a(child, "value") or _a(child, "resource") or "")
      elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        self._merge_component(child, "activity" if tag == "activity-alias" else tag, source_set)

  # -- components --

  def _merge_component(self, elem: ET.Element, kind: str, source_set: str) -> None:
    name = self._qualify(_a(elem, "name"))
    if not name:
      self._warn(f"<{kind}> without android:name in {source_set}")
      return
    key = (kind, name)
    comp = self._components.get(key)
    if comp is None:
      comp = Component(kind=kind, name=name)
      self._components[key] = comp
      self.profile.components.append(comp)
    if _a(elem, "node", TOOLS_NS) == "remove":
      if source_set not in comp.removed_in:
        comp.removed_in.append(source_set)
      return
    if source_set not in comp.sources:
      comp.sources.append(source_set)
    for attr, key_name, conv in (
        ("exported", "exported", _bool), ("enabled", "enabled", _bool),
        ("permission", "permission", str), ("process", "process", str),
        ("grantUriPermissions", "grant_uri_permissions", _bool)):
      raw = _a(elem, attr)
      if raw is not None and getattr(comp, key_name) is None:
        setattr(comp, key_name, conv(raw))
    fgs = _a(elem, "foregroundServiceType")
    if fgs:
      for t in fgs.split("|"):
        t = t.strip()
        if t and t not in comp.fgs_types:
          comp.fgs_types.append(t)
    auth = _a(elem, "authorities")
    if auth:
      for a in auth.split(";"):
        a = a.strip()
        if self.profile.package_name:
          a = a.replace("${applicationId}", self.profile.package_name)
        if a and a not in comp.authorities:
          comp.authorities.append(a)
    for child in elem:
      tag = _local(child.tag)
      if tag == "intent-filter":
        comp.intent_filters.append(self._parse_intent_filter(child, source_set))
      elif tag == "property":
        n = _a(child, "name")
        if n:
          comp.properties.setdefault(n, _a(child, "value") or _a(child, "resource") or "")
      elif tag == "meta-data":
        n = _a(child, "name")
        if n:
          comp.meta_data.setdefault(n, _a(child, "value") or _a(child, "resource") or "")

  @staticmethod
  def _parse_intent_filter(elem: ET.Element, source_set: str) -> IntentFilter:
    f = IntentFilter(source=source_set)
    for child in elem:
      tag = _local(child.tag)
      if tag == "action":
        n = _a(child, "name")
        if n and n not in f.actions:
          f.actions.append(n)
      elif tag == "category":
        n = _a(child, "name")
        if n and n not in f.categories:
          f.categories.append(n)
      elif tag == "data":
        for attr, bucket in (("scheme", f.schemes), ("mimeType", f.mime_types), ("host", f.hosts)):
          v = _a(child, attr)
          if v and v not in bucket:
            bucket.append(v)
    return f


# ---------------------------------------------------------------------------
# Accessibility config
# ---------------------------------------------------------------------------


def _accessibility_services(profile: AppProfile, index: resources.ResourceIndex) -> None:
  for s in profile.components_of("service", include_inactive=True):
    if not s.has_action(_ACCESSIBILITY_SERVICE_ACTION):
      continue
    entry = AccessibilityService(name=s.name, sources=list(s.sources),
                                 ships_in_play_build=profile.ships_in_play_build(s))
    ref = s.meta_data.get(_ACCESSIBILITY_META_DATA)
    if ref:
      entry.config_resource = ref
      m = re.match(r"^@xml/(?P<name>[\w.]+)$", ref.strip())
      if m and m.group("name") in index.xml_resources:
        entry.config_path = index.xml_resources[m.group("name")]
        try:
          root = _parse_manifest(os.path.join(profile.app_dir, entry.config_path))
          if root is not None:
            entry.is_accessibility_tool = _bool(_a(root, "isAccessibilityTool"))
            entry.description = index.resolve(_a(root, "description"))
        except (OSError, ET.ParseError) as exc:
          profile.warnings.append(f"accessibility config {entry.config_path}: {exc}")
          log.warning("manifest: accessibility config %s unreadable: %s", entry.config_path, exc)
      else:
        profile.warnings.append(f"accessibility config {ref} for {s.name} not found in res/xml")
    else:
      profile.warnings.append(f"accessibility service {s.name} has no {_ACCESSIBILITY_META_DATA} meta-data")
    profile.accessibility_services.append(entry)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def load_profile(app_dir: str, fallback: Optional[Dict[str, Any]] = None) -> AppProfile:
  """Builds the merged :class:`AppProfile` for ``app_dir``.

  Args:
    app_dir: Application root (the directory ``orchestrator.py init`` scanned).
    fallback: The orchestrator's ``manifest_details.json`` dict. Used only for
      ``package_name`` and ``target_sdk`` when neither Gradle nor the manifests
      provide them, and to cross-check disagreements (logged at WARNING).

  Returns:
    A profile, possibly empty (``manifests == []``) when no manifest exists;
    the engine then keeps working from ``manifest_details.json`` alone.
  """
  fallback = fallback or {}
  profile = AppProfile(app_dir=app_dir)
  if not app_dir or not os.path.isdir(app_dir):
    profile.warnings.append(f"app_dir {app_dir!r} is not a directory; profile is empty")
    log.warning("manifest: %s", profile.warnings[-1])
    _apply_fallback(profile, fallback)
    return profile

  modules = discover_manifests(app_dir)
  if not modules:
    profile.warnings.append("no AndroidManifest.xml found; profile built from manifest_details.json only")
    log.warning("manifest: %s", profile.warnings[-1])
    _apply_fallback(profile, fallback)
    return profile

  # Parse every module's main manifest once to pick the primary module.
  parsed: Dict[str, Dict[str, Optional[ET.Element]]] = {}
  scores: Dict[str, Tuple[int, int, int, int]] = {}
  for module_root, entries in modules.items():
    parsed[module_root] = {}
    for source_set, rel in entries:
      try:
        parsed[module_root][rel] = _parse_manifest(os.path.join(app_dir, rel))
      except (OSError, ET.ParseError) as exc:
        parsed[module_root][rel] = None
        profile.warnings.append(f"{rel}: parse error: {exc}")
        log.warning("manifest: %s could not be parsed: %s", rel, exc)
    best = max((_score_module(e) for e in parsed[module_root].values()), default=(0, 0, 0))
    # Shallower module roots win ties (``app`` over ``feature/x``).
    scores[module_root] = best + (-module_root.count("/"),)
  primary = max(scores, key=lambda m: (scores[m], m == "", m))
  profile.module_root = primary
  profile.other_modules = sorted(m for m in modules if m != primary)
  if profile.other_modules:
    log.info("manifest: primary module %r; not merging %d other module(s): %s",
             primary, len(profile.other_modules), ", ".join(profile.other_modules))

  # Gradle facts first so relative component names can be qualified during merge.
  gradle = _read_gradle(app_dir, primary)
  pkg = gradle.get("application_id") or gradle.get("namespace")
  if pkg:
    profile.package_name = pkg
    profile.sdk_provenance["package_name"] = f"gradle:{gradle.get('path')}"
  if gradle["target_sdk_values"]:
    profile.target_sdk_values = gradle["target_sdk_values"]
    profile.target_sdk = max(profile.target_sdk_values)
    profile.sdk_provenance["target_sdk"] = f"gradle:{gradle.get('path')}"
  if gradle["min_sdk_values"]:
    profile.min_sdk = min(gradle["min_sdk_values"])
    profile.sdk_provenance["min_sdk"] = f"gradle:{gradle.get('path')}"

  merger = _Merger(profile)
  for source_set, rel in modules[primary]:
    root = parsed[primary].get(rel)
    if root is None:
      continue
    merger.merge(root, source_set, rel)
    profile.manifests.append(rel)
    if source_set not in profile.source_sets:
      profile.source_sets.append(source_set)

  _apply_fallback(profile, fallback)
  _cross_check(profile, fallback)

  index = resources.build_index(app_dir, primary)
  profile.resource_index = index
  label = profile.application.get("label")
  if label:
    resolved = index.resolve(label)
    if resolved is not None and resolved != label:
      profile.application["label_resource"] = label
      profile.application["label"] = resolved
  _accessibility_services(profile, index)

  log.info("manifest: merged %d manifest(s) from module %r (%s): package=%s targetSdk=%s "
           "permissions=%d components=%d (%d inactive) launcher=%d fgs-typed=%d typeless=%d "
           "accessibility=%d warnings=%d",
           len(profile.manifests), primary, "+".join(profile.source_sets), profile.package_name,
           profile.target_sdk, len(profile.permissions), len(profile.components),
           sum(1 for c in profile.components if not c.is_active), len(profile.launcher_activities()),
           len(profile.services_with_fgs_type()), len(profile.services_without_fgs_type()),
           len(profile.accessibility_services), len(profile.warnings))
  return profile


def _apply_fallback(profile: AppProfile, fallback: Dict[str, Any]) -> None:
  if not profile.package_name and fallback.get("package_name"):
    profile.package_name = fallback["package_name"]
    profile.sdk_provenance["package_name"] = "manifest_details.json"
  if profile.target_sdk is None and fallback.get("target_sdk") is not None:
    profile.target_sdk = _int(str(fallback["target_sdk"]))
    profile.target_sdk_values = [profile.target_sdk] if profile.target_sdk is not None else []
    profile.sdk_provenance["target_sdk"] = "manifest_details.json"
  if not profile.permissions and fallback.get("permissions"):
    for name in fallback["permissions"]:
      profile.permissions[name] = Permission(name=name, sources=["manifest_details.json"])


def _cross_check(profile: AppProfile, fallback: Dict[str, Any]) -> None:
  """Logs disagreements with the orchestrator's summary; never changes the profile."""
  fb_pkg = fallback.get("package_name")
  if fb_pkg and profile.package_name and fb_pkg != profile.package_name:
    msg = (f"package_name disagreement: manifest_details.json={fb_pkg!r} vs "
           f"profile={profile.package_name!r} ({profile.sdk_provenance.get('package_name')})")
    profile.warnings.append(msg)
    log.warning("manifest: %s", msg)
  fb_t = _int(str(fallback.get("target_sdk"))) if fallback.get("target_sdk") is not None else None
  if fb_t is not None and profile.target_sdk is not None and fb_t != profile.target_sdk:
    msg = (f"target_sdk disagreement: manifest_details.json={fb_t} vs profile={profile.target_sdk} "
           f"({profile.sdk_provenance.get('target_sdk')})")
    profile.warnings.append(msg)
    log.warning("manifest: %s", msg)
  fb_perms = set(fallback.get("permissions") or [])
  ours = set(profile.permissions)
  if fb_perms and ours:
    missing = sorted(fb_perms - ours)
    extra = sorted(ours - fb_perms)
    if missing or extra:
      log.info("manifest: permission set differs from manifest_details.json "
               "(only in orchestrator: %s; only in profile: %s)", missing or "-", extra or "-")
  fb_fgs = {s.get("name"): s.get("type") for s in fallback.get("foreground_services") or []}
  for name, typ in fb_fgs.items():
    comp = next((c for c in profile.components if c.kind == "service"
                 and (c.name == name or c.name.endswith(name or "\0"))), None)
    if comp is None:
      log.info("manifest: orchestrator lists foreground service %s not found in profile", name)
    elif typ and set(typ.split("|")) != set(comp.fgs_types):
      log.info("manifest: foreground service %s types differ (orchestrator=%s profile=%s)",
               name, typ, "|".join(comp.fgs_types))
