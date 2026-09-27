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

"""Semantic layer: capability classification of libraries and APIs.

The evaluator must never decide *what a library does* from its name. Instead
this module defines a small, policy-derived **capability taxonomy** (what code
*can* do that matters under Play policy) and asks the model to map each
imported symbol or declared dependency onto it. The answers are memoized in a
persistent, human-reviewable cache so the cost amortizes across every app that
uses the same artifact.

Why capabilities instead of a library list:

- A list of libraries is a snapshot of one ecosystem at one moment; it fails on
  the next language, framework, or vendor and has to be maintained by hand.
- A capability is a stable property derived from policy language ("transferred
  off-device", "shared with a third party"). Libraries change; the taxonomy does
  not.
- The model already knows what widely used libraries do. Asking "does this
  provide network egress?" lets it generalize to artifacts nobody wrote down.

Design rules enforced here:

1. The definitions in :data:`CAPABILITIES` describe *behavior*, never products.
   The identifier lint in ``selftest.py`` rejects vendor/library names anywhere
   in this package outside test fixtures.
2. Uncertain classifications become :data:`UNKNOWN`, which downstream treats as
   a *possible* transfer sink (fail toward review, never toward silence).
3. Every profile records its provenance (``source``: ``model``/``human``/
   ``heuristic``, model id, taxonomy version). Human cache entries always win.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import logging
import os
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence

from typesafe_eval import constants
from typesafe_eval.client import JevAnswer
from typesafe_eval.client import JevClient

log = logging.getLogger("typesafe_eval.capabilities")

# Bump when a definition changes meaning; cached profiles are keyed by it.
TAXONOMY_VERSION = "1"

# ---------------------------------------------------------------------------
# The taxonomy. Definitions are the text the model sees; they must describe what
# the code does, in policy terms, and must not name any product or vendor.
# ---------------------------------------------------------------------------

NETWORK_EGRESS = "NETWORK_EGRESS"
THIRD_PARTY_TELEMETRY = "THIRD_PARTY_TELEMETRY"
ADVERTISING_SDK = "ADVERTISING_SDK"
IPC_SHARING = "IPC_SHARING"
LOCAL_PERSISTENCE = "LOCAL_PERSISTENCE"
LOGGING = "LOGGING"
USER_DISCLOSURE_UI = "USER_DISCLOSURE_UI"
UNKNOWN = "UNKNOWN"

CAPABILITIES: Dict[str, str] = {
    NETWORK_EGRESS: (
        "Sends bytes to a remote host over the network: HTTP/HTTPS clients and "
        "their request/annotation APIs, raw TCP/UDP sockets, gRPC, WebSocket, "
        "DNS resolvers, push messaging, or cloud/backend SDK write APIs."
    ),
    THIRD_PARTY_TELEMETRY: (
        "A software development kit operated by a party other than the app "
        "developer that reports crashes, errors, events, usage, performance, "
        "or device identifiers to that party's servers."
    ),
    ADVERTISING_SDK: (
        "Serves, mediates, attributes, or measures advertisements; typically "
        "collects device or advertising identifiers for that purpose."
    ),
    IPC_SHARING: (
        "Hands data to another application or to the system for other apps to "
        "read: share sheets, implicit intents delivered to other apps, exported "
        "content providers, broadcasts, the clipboard, or bound services outside "
        "the app's own package."
    ),
    LOCAL_PERSISTENCE: (
        "Writes data to app-private or device storage on the same device: "
        "databases, key-value preferences, files, caches, or key stores."
    ),
    LOGGING: (
        "Emits text to the system or console log for developers (not to a remote "
        "server)."
    ),
    USER_DISCLOSURE_UI: (
        "Presents dialogs, consent screens, or permission-rationale UI that the "
        "user must read and act on before continuing."
    ),
}

# Capabilities whose presence means data reaching them has left the device (or
# the app's own sandbox). IPC is included: per policy direction, handing data to
# another app counts as sharing and must be flagged.
TRANSFER_CAPABILITIES = frozenset(constants.TRANSFER_CAPABILITY_NAMES)

# Capabilities that additionally imply sharing with a party other than the
# developer (the Data Safety "shared" column and third-party disclosure rules).
SHARING_CAPABILITIES = frozenset(constants.SHARING_CAPABILITY_NAMES)

assert TRANSFER_CAPABILITIES <= set(CAPABILITIES), "constants/taxonomy drift"
assert SHARING_CAPABILITIES <= TRANSFER_CAPABILITIES, "sharing implies transfer"


@dataclasses.dataclass
class CapabilityProfile:
  """The classified capabilities of one identifier (import path or artifact).

  Attributes:
    identifier: The import module path or dependency coordinate.
    kind: ``"import"`` or ``"dependency"``.
    probabilities: Capability name -> probability the identifier provides it.
    labels: Capabilities at/above ``constants.T_CAPABILITY``; may include
      :data:`UNKNOWN` when nothing is confidently decided either way.
    source: ``"model"``, ``"heuristic"`` (offline stand-in), or ``"human"``.
    model: Model id that produced the answer (``None`` for human entries).
    taxonomy_version: The :data:`TAXONOMY_VERSION` the answer was produced under.
    recorded_at: ISO-8601 UTC timestamp.
  """

  identifier: str
  kind: str
  probabilities: Dict[str, float]
  labels: List[str]
  source: str
  model: Optional[str]
  taxonomy_version: str = TAXONOMY_VERSION
  recorded_at: str = ""

  @property
  def is_transfer_sink(self) -> bool:
    """True when any transfer capability is labelled, or the profile is UNKNOWN."""
    return bool(TRANSFER_CAPABILITIES & set(self.labels)) or UNKNOWN in self.labels

  @property
  def is_sharing_sink(self) -> bool:
    return bool(SHARING_CAPABILITIES & set(self.labels))

  def to_dict(self) -> Dict[str, Any]:
    return dataclasses.asdict(self)

  @classmethod
  def from_dict(cls, d: Dict[str, Any]) -> "CapabilityProfile":
    return cls(
        identifier=d["identifier"],
        kind=d.get("kind", "import"),
        probabilities=dict(d.get("probabilities", {})),
        labels=list(d.get("labels", [])),
        source=d.get("source", "model"),
        model=d.get("model"),
        taxonomy_version=d.get("taxonomy_version", TAXONOMY_VERSION),
        recorded_at=d.get("recorded_at", ""),
    )


def labels_from_probabilities(probs: Dict[str, float]) -> List[str]:
  """Applies the capability threshold; emits UNKNOWN when nothing is decided.

  A profile is UNKNOWN when no capability clears ``T_CAPABILITY`` *and* at least
  one transfer capability sits inside the indecision band
  ``[T_CAPABILITY_UNKNOWN_LOW, T_CAPABILITY)``. A symbol that the model
  confidently says does *nothing* transfer-related (all transfer probabilities
  below the low bound) is simply unlabelled, not UNKNOWN.
  """
  labels = sorted(c for c, p in probs.items() if p >= constants.T_CAPABILITY)
  if labels:
    return labels
  undecided = [
      c for c in TRANSFER_CAPABILITIES
      if constants.T_CAPABILITY_UNKNOWN_LOW <= probs.get(c, 0.0) < constants.T_CAPABILITY
  ]
  return [UNKNOWN] if undecided else []


# ---------------------------------------------------------------------------
# Persistent, reviewable cache
# ---------------------------------------------------------------------------


class CapabilityCache:
  """JSON-file memo of capability profiles, keyed by (taxonomy, model, identifier).

  The file is meant to be read and edited by humans: an entry with
  ``"source": "human"`` is authoritative and is never overwritten by the model.
  Entries produced under a different taxonomy version or model are ignored
  (they stay in the file for audit but are re-asked).
  """

  def __init__(self, path: Optional[str]) -> None:
    self.path = path
    self._data: Dict[str, Dict[str, Any]] = {}
    self.hits = 0
    self.misses = 0
    if path and os.path.exists(path):
      try:
        with open(path, "r", encoding="utf-8") as f:
          self._data = json.load(f)
        log.info("capability cache loaded: %d entries from %s", len(self._data), path)
      except (OSError, ValueError) as exc:
        log.warning("capability cache unreadable (%s); starting empty", exc)
        self._data = {}

  @staticmethod
  def key(identifier: str, model: Optional[str]) -> str:
    return f"{TAXONOMY_VERSION}|{model or '-'}|{identifier}"

  def get(self, identifier: str, model: Optional[str]) -> Optional[CapabilityProfile]:
    # Human overrides are model-independent.
    human = self._data.get(self.key(identifier, None))
    if human and human.get("source") == "human":
      self.hits += 1
      return CapabilityProfile.from_dict(human)
    entry = self._data.get(self.key(identifier, model))
    if entry is None:
      self.misses += 1
      return None
    self.hits += 1
    return CapabilityProfile.from_dict(entry)

  def put(self, profile: CapabilityProfile) -> None:
    k = self.key(profile.identifier, None if profile.source == "human" else profile.model)
    existing = self._data.get(k)
    if existing and existing.get("source") == "human":
      return
    self._data[k] = profile.to_dict()

  def save(self) -> None:
    if not self.path:
      return
    os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
    tmp = self.path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
      json.dump(self._data, f, indent=1, sort_keys=True)
    os.replace(tmp, self.path)
    log.debug("capability cache saved: %d entries -> %s", len(self._data), self.path)

  def __len__(self) -> int:
    return len(self._data)


def default_cache_path() -> Optional[str]:
  """``PPI_CAPABILITY_CACHE`` env var, else a per-user cache file."""
  env = os.environ.get(constants.CAPABILITY_CACHE_ENV)
  if env:
    return env
  return os.path.join(
      os.path.expanduser("~"), ".cache", "play_policy_insights", "capabilities.json"
  )


# ---------------------------------------------------------------------------
# Classification questions
# ---------------------------------------------------------------------------


def classification_state(batch: Sequence[Dict[str, str]], app_facts: Dict[str, Any]) -> Dict[str, Any]:
  """The state for one classification request: the symbols and the taxonomy."""
  return {
      "symbols": [
          {"id": i, "identifier": s["identifier"], "kind": s["kind"]}
          for i, s in enumerate(batch)
      ],
      "capability_definitions": CAPABILITIES,
      "app": {"package": app_facts.get("package")},
  }


def classification_battery(batch_size: int) -> Dict[str, Dict[str, Any]]:
  """One Noul per (symbol, capability), namespaced ``s<i>__<CAPABILITY>``.

  The question is phrased about what *such a library or API is generally known
  to do*, so the model draws on its knowledge of the artifact rather than on
  the app's code (which the finding battery evaluates separately).
  """
  questions: Dict[str, Dict[str, Any]] = {}
  for i in range(batch_size):
    for cap, definition in CAPABILITIES.items():
      questions[f"s{i}__{cap}"] = {
          "type": "noul",
          "instructions": (
              f"Consider the library, package, or platform API identified by "
              f"`symbols[{i}].identifier` (kind: `symbols[{i}].kind`). Based on "
              f"what such a library or API is generally known to do, does it "
              f"provide this capability — {cap}: {definition}"
          ),
          "criteria": {
              "true": f"Yes, it provides {cap} as defined.",
              "false": f"No, it does not provide {cap}; it does something else.",
          },
      }
  return questions


def _now() -> str:
  return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _profile_from_answers(
    index: int, symbol: Dict[str, str], answers: Dict[str, JevAnswer],
    client_name: str, model: Optional[str],
) -> CapabilityProfile:
  probs: Dict[str, float] = {}
  for cap in CAPABILITIES:
    a = answers.get(f"s{index}__{cap}")
    probs[cap] = round(float(a.noul), 4) if a is not None and a.noul is not None else 0.0
  return CapabilityProfile(
      identifier=symbol["identifier"],
      kind=symbol["kind"],
      probabilities=probs,
      labels=labels_from_probabilities(probs),
      source="heuristic" if client_name.startswith("heuristic") else "model",
      model=model,
      recorded_at=_now(),
  )


def _unknown_profile(symbol: Dict[str, str], model: Optional[str], reason: str) -> CapabilityProfile:
  """Recall-safe placeholder when classification fails: possible sink."""
  log.warning("capability classification failed for %s: %s", symbol["identifier"], reason)
  return CapabilityProfile(
      identifier=symbol["identifier"],
      kind=symbol["kind"],
      probabilities={},
      labels=[UNKNOWN],
      source="error",
      model=model,
      recorded_at=_now(),
  )


def classify(
    symbols: Iterable[Dict[str, str]],
    client: JevClient,
    cache: Optional[CapabilityCache],
    app_facts: Dict[str, Any],
    model: Optional[str] = None,
    batch_size: int = constants.CAPABILITY_BATCH_SIZE,
) -> Dict[str, CapabilityProfile]:
  """Returns ``identifier -> profile`` for every symbol, using the cache first.

  ``symbols`` are ``{"identifier": str, "kind": "import"|"dependency"}`` dicts.
  Misses are batched ``batch_size`` per request; a failed request marks every
  symbol in that batch UNKNOWN (never silently drops a potential sink).
  """
  unique: Dict[str, Dict[str, str]] = {}
  for s in symbols:
    if s["identifier"] not in unique:
      unique[s["identifier"]] = s

  profiles: Dict[str, CapabilityProfile] = {}
  misses: List[Dict[str, str]] = []
  for ident, sym in unique.items():
    hit = cache.get(ident, model) if cache else None
    if hit is not None:
      profiles[ident] = hit
    else:
      misses.append(sym)

  log.info("capabilities: %d identifiers, %d cached, %d to classify",
           len(unique), len(profiles), len(misses))

  for start in range(0, len(misses), batch_size):
    batch = misses[start:start + batch_size]
    state = classification_state(batch, app_facts)
    questions = classification_battery(len(batch))
    try:
      answers = client.system_one(state, questions, model=model)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      for sym in batch:
        profiles[sym["identifier"]] = _unknown_profile(sym, model, str(exc)[:160])
      continue
    for i, sym in enumerate(batch):
      profile = _profile_from_answers(i, sym, answers, client.name, model)
      profiles[sym["identifier"]] = profile
      if cache is not None:
        cache.put(profile)
      log.debug("capability %s -> %s", sym["identifier"], profile.labels or "(none)")
    if cache is not None:
      cache.save()

  return profiles


def summarize(profiles: Dict[str, CapabilityProfile]) -> Dict[str, Any]:
  """Observability counters for a run (logged and written to the trace file)."""
  by_label: Dict[str, int] = {}
  unknown = 0
  by_source: Dict[str, int] = {}
  for p in profiles.values():
    by_source[p.source] = by_source.get(p.source, 0) + 1
    if UNKNOWN in p.labels:
      unknown += 1
    for l in p.labels:
      by_label[l] = by_label.get(l, 0) + 1
  return {
      "identifiers": len(profiles),
      "unknown": unknown,
      "by_label": dict(sorted(by_label.items())),
      "by_source": dict(sorted(by_source.items())),
      "taxonomy_version": TAXONOMY_VERSION,
  }
