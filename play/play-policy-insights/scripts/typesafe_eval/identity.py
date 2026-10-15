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

"""Identity-lifecycle scan for the wave-3 user-account policies (WP11).

Two Play policies turn on facts about the *whole app* rather than about one
scanner token:

* ``account_deletion`` fails when an app **provisions** a server-side identity
  (registers an account, customer, device or installation and keeps the
  server-assigned id) and offers **no path that deletes it on the server**.
  The absence of a deletion path is invisible to a per-token scanner.
* ``login_credentials`` (Play Console app-access requirements) turns on
  whether the app has a login gate at all, and of which kind: a
  developer-operated account, the user's *own* remote-server credentials, a
  third-party sign-in bridge, or none.

This module supplies the **deterministic half** of both: one pass over every
shipped first-party source file (``scan_app``) that records, at identifier
boundaries and outside comments / imports, the lifecycle-shaped tokens listed
in :mod:`constants` (``IDENTITY_PROVISION_RE``, ``IDENTITY_DELETE_RE``,
``IDENTITY_TOKEN_RE``, ``NETWORK_SHAPE_RE``, ``PERSIST_SHAPE_RE``,
``LOGIN_SHAPE_RE``, ``USER_SERVER_SHAPE_RE``), and the assembly of those hits
into *provisioning sites*, *deletion candidates* and *login evidence*
(``assess``). Nothing here calls the model; the engine asks the two Nouls /
the one Choice on what this module found and composes the finding
(``engine._run_identity_lifecycle`` / ``engine._ask_login_gate``).

Design rules (the same as every deterministic layer in this package):

* **Closed, generic token lists.** Verbs are bound to identity nouns
  (``registerDevice``, ``deleteAccount``); bare ``register`` / ``delete`` are
  never matched. No product or library name appears; HTTP verbs and Android
  platform names are allowed.
* **Cost is bounded, evidence is not dropped.** ``MAX_LIFECYCLE_FILES`` caps
  the walk (and the scan reports ``truncated``); per-file hits are capped at
  ``MAX_LIFECYCLE_HITS_PER_FILE`` per kind, strongest lines first.
* **Every fact is traceable.** Each hit keeps its 0-based line and the code
  text; the engine writes the whole assessment to ``typesafe_triage.json``
  under ``identity_lifecycle`` / ``login_gate``.
* **Reads only.** The module never modifies scanner output or app files.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import re
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple

from typesafe_eval import capabilities as caps
from typesafe_eval import constants
from typesafe_eval import structure

log = logging.getLogger("typesafe_eval.identity")

# Hit kinds, in the order the state lists them.
PROVISION = "provision"
DELETE = "delete"
IDENTITY = "identity"
NETWORK = "network"
PERSIST = "persist"
LOGIN = "login"
USER_SERVER = "user_server"

_KIND_RES: Dict[str, "re.Pattern[str]"] = {
    PROVISION: re.compile(constants.IDENTITY_PROVISION_RE),
    DELETE: re.compile(constants.IDENTITY_DELETE_RE),
    IDENTITY: re.compile(constants.IDENTITY_TOKEN_RE),
    NETWORK: re.compile(constants.NETWORK_SHAPE_RE),
    PERSIST: re.compile(constants.PERSIST_SHAPE_RE),
    LOGIN: re.compile(constants.LOGIN_SHAPE_RE),
    USER_SERVER: re.compile(constants.USER_SERVER_SHAPE_RE),
}
# A file is scanned line by line only when its raw text contains one of the
# kinds that *activate* the policies; identity / network / persistence facts
# are gathered for those files (and their one-hop callees) only.
_ACTIVATING_KINDS = (PROVISION, DELETE, LOGIN)
# Capability labels that count as "the file reaches the network" / "writes
# locally" when the import was already classified by the capability layer.
_NETWORK_LABELS = frozenset({caps.NETWORK_EGRESS, caps.THIRD_PARTY_TELEMETRY})
_PERSIST_LABELS = frozenset({caps.LOCAL_PERSISTENCE})


@dataclasses.dataclass
class LifecycleHit:
  """One lifecycle-shaped token on one code line.

  Attributes:
    kind: One of the module constants (``provision`` ... ``user_server``).
    line: 0-based line in the file.
    token: The matched text (``registerDevice``, ``@DELETE(``).
    evidence: The stripped code line, truncated for the trace / state.
  """

  kind: str
  line: int
  token: str
  evidence: str

  def to_dict(self) -> Dict[str, Any]:
    return {"kind": self.kind, "line": self.line + 1, "token": self.token, "evidence": self.evidence}


@dataclasses.dataclass
class FileLifecycle:
  """Every lifecycle hit in one file, grouped by kind."""

  relpath: str
  hits: Dict[str, List[LifecycleHit]] = dataclasses.field(default_factory=dict)
  line_count: int = 0

  def of(self, kind: str) -> List[LifecycleHit]:
    return self.hits.get(kind, [])

  def has(self, kind: str) -> bool:
    return bool(self.hits.get(kind))

  def lines_of(self, kind: str) -> List[int]:
    return sorted({h.line for h in self.of(kind)})

  def tokens_of(self, kind: str) -> List[str]:
    return sorted({h.token for h in self.of(kind)})

  def to_dict(self) -> Dict[str, Any]:
    return {
        "file": self.relpath,
        "lines": self.line_count,
        **{kind: [h.to_dict() for h in hits] for kind, hits in sorted(self.hits.items())},
    }


@dataclasses.dataclass
class LifecycleScan:
  """Result of :func:`scan_app`: the activating files plus walk statistics."""

  files: Dict[str, FileLifecycle] = dataclasses.field(default_factory=dict)
  scanned: int = 0
  prefiltered: int = 0
  truncated: bool = False

  def with_kind(self, kind: str) -> List[FileLifecycle]:
    return [f for f in self.files.values() if f.has(kind)]

  def summary(self) -> Dict[str, Any]:
    return {
        "scanned": self.scanned,
        "activating_files": len(self.files),
        "prefiltered": self.prefiltered,
        "truncated": self.truncated,
        "files_with": {kind: len(self.with_kind(kind)) for kind in _KIND_RES},
    }


def scan_lines(relpath: str, lines: Sequence[str], kinds: Iterable[str] = tuple(_KIND_RES)) -> FileLifecycle:
  """Records every lifecycle-shaped token in ``lines`` for the given ``kinds``.

  Full-line comments and import lines are skipped (``structure.is_code_line``)
  and a trailing comment is removed (``structure.code_portion``) before the
  patterns run, so a verb mentioned in a doc comment never becomes a site.
  Hits per kind are capped at ``MAX_LIFECYCLE_HITS_PER_FILE`` (first
  occurrences kept; the cap bounds the state size, not what the engine
  decides -- a file with one provisioning call is a site exactly as a file
  with fifty).
  """
  out = FileLifecycle(relpath=relpath, line_count=len(lines))
  wanted = [(k, _KIND_RES[k]) for k in kinds if k in _KIND_RES]
  cap = constants.MAX_LIFECYCLE_HITS_PER_FILE
  for i, raw in enumerate(lines):
    if not raw or not structure.is_code_line(raw):
      continue
    line = structure.code_portion(raw)
    if not line.strip():
      continue
    for kind, rx in wanted:
      hits = out.hits.setdefault(kind, [])
      for m in rx.finditer(line):
        if len(hits) >= cap:
          break
        hits.append(LifecycleHit(kind, i, m.group(0), line.strip()[:160]))
  out.hits = {k: v for k, v in out.hits.items() if v}
  return out


def _read_lines(app_dir: str, relpath: str) -> List[str]:
  try:
    with open(os.path.join(app_dir, relpath), "r", encoding="utf-8", errors="ignore") as f:
      return f.read().splitlines()
  except OSError as exc:
    log.debug("identity scan: cannot read %s: %s", relpath, exc)
    return []


def scan_app(app_dir: str, relpaths: Iterable[str]) -> LifecycleScan:
  """Scans the shipped first-party files for lifecycle-shaped tokens.

  ``relpaths`` is normally ``FirstPartyIndex.package_by_file`` (every shipped
  ``.kt`` / ``.java`` / ``.cs`` class file, test and excluded-flavour sources
  already removed). A cheap whole-text pre-filter on the activating kinds
  (provision / delete / login) decides which files get the line-by-line
  scan; only those are kept in ``files``. ``MAX_LIFECYCLE_FILES`` bounds the
  walk; when it is hit the scan says so (``truncated``) and the engine
  records it in the triage counters.
  """
  scan = LifecycleScan()
  activating = [_KIND_RES[k] for k in _ACTIVATING_KINDS]
  for relpath in sorted(relpaths):
    if scan.scanned >= constants.MAX_LIFECYCLE_FILES:
      scan.truncated = True
      log.warning("identity scan: MAX_LIFECYCLE_FILES=%d reached; remaining files not scanned",
                  constants.MAX_LIFECYCLE_FILES)
      break
    scan.scanned += 1
    lines = _read_lines(app_dir, relpath)
    if not lines:
      continue
    text = "\n".join(lines)
    if not any(rx.search(text) for rx in activating):
      scan.prefiltered += 1
      continue
    fl = scan_lines(relpath, lines)
    if any(fl.has(k) for k in _ACTIVATING_KINDS):
      scan.files[relpath] = fl
  log.info("identity scan: %d files scanned, %d pre-filtered, %d activating (%s)%s",
           scan.scanned, scan.prefiltered, len(scan.files),
           {k: len(scan.with_kind(k)) for k in _ACTIVATING_KINDS},
           " [TRUNCATED]" if scan.truncated else "")
  return scan


# ---------------------------------------------------------------------------
# Assessment: sites, candidates and login evidence
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Reach:
  """How a file reaches a capability: in its own code, via a classified import, or one hop away."""

  source: Optional[str] = None      # "file" | "import" | "hop" | None
  detail: Optional[str] = None      # the token, import module or callee relpath

  @property
  def reached(self) -> bool:
    return self.source is not None

  def to_dict(self) -> Optional[Dict[str, str]]:
    return {"source": self.source, "detail": self.detail} if self.reached else None


@dataclasses.dataclass
class ProvisioningSite:
  """A file that registers a server-side identity and can reach the network."""

  relpath: str
  lines: List[int]
  tokens: List[str]
  identity_tokens: List[str]
  network: Reach
  persistence: Reach
  evidence: str

  @property
  def persisted(self) -> bool:
    return self.persistence.reached

  def to_dict(self) -> Dict[str, Any]:
    return {
        "file": self.relpath, "lines": [l + 1 for l in self.lines], "tokens": self.tokens,
        "identity_tokens": self.identity_tokens, "network": self.network.to_dict(),
        "persistence": self.persistence.to_dict(), "persisted": self.persisted, "evidence": self.evidence,
    }

  def to_state(self) -> Dict[str, Any]:
    """The compact, model-facing row (no reach details; those are trace)."""
    return {"file": self.relpath, "line": self.lines[0] + 1 if self.lines else None,
            "token": self.tokens[0] if self.tokens else None, "evidence": self.evidence}


@dataclasses.dataclass
class DeletionCandidate:
  """A file with a deletion-shaped call; ``remote_shaped`` when it can reach the network."""

  relpath: str
  lines: List[int]
  tokens: List[str]
  network: Reach
  persistence: Reach
  evidence: str

  @property
  def remote_shaped(self) -> bool:
    return self.network.reached

  def rank(self) -> Tuple[int, int, str]:
    """Strongest first: remote-shaped, then more deletion tokens, then path."""
    return (0 if self.remote_shaped else 1, -len(self.tokens), self.relpath)

  def to_dict(self) -> Dict[str, Any]:
    return {
        "file": self.relpath, "lines": [l + 1 for l in self.lines], "tokens": self.tokens,
        "remote_shaped": self.remote_shaped, "network": self.network.to_dict(),
        "persistence": self.persistence.to_dict(), "evidence": self.evidence,
    }


@dataclasses.dataclass
class LoginEvidence:
  """Login-shaped files for the once-per-app ``login_gate_type`` question."""

  files: List[Dict[str, Any]] = dataclasses.field(default_factory=list)   # {file, hits, tokens, remote_server_tokens}
  semantic_files: List[str] = dataclasses.field(default_factory=list)
  snippets: Dict[str, str] = dataclasses.field(default_factory=dict)

  @property
  def found(self) -> bool:
    return bool(self.files or self.semantic_files)

  def to_dict(self) -> Dict[str, Any]:
    return {"files": self.files, "semantic_files": self.semantic_files,
            "snippet_files": sorted(self.snippets)}


@dataclasses.dataclass
class Assessment:
  """Everything the engine composes on, plus the scan statistics for the trace."""

  provisioning: List[ProvisioningSite] = dataclasses.field(default_factory=list)
  deletions: List[DeletionCandidate] = dataclasses.field(default_factory=list)
  login: LoginEvidence = dataclasses.field(default_factory=LoginEvidence)
  scan: Dict[str, Any] = dataclasses.field(default_factory=dict)

  def to_dict(self) -> Dict[str, Any]:
    return {
        "scan": self.scan,
        "provisioning": [p.to_dict() for p in self.provisioning],
        "deletion_candidates": [d.to_dict() for d in sorted(self.deletions, key=lambda d: d.rank())],
        "login": self.login.to_dict(),
    }


# The engine supplies these three lookups so this module stays free of the
# run context: the structure of a file (imports + references), the capability
# labels of an import as already classified (never a new model call), and the
# first-party index for one-hop resolution.
StructureOf = Callable[[str], Optional[structure.FileStructure]]
LabelsOf = Callable[[str], Set[str]]


def _reach_in_file(fl: FileLifecycle, kind: str) -> Reach:
  hits = fl.of(kind)
  if hits:
    return Reach("file", hits[0].token)
  return Reach()


def _reach_by_import(fs: Optional[structure.FileStructure], labels_of: LabelsOf, wanted: frozenset) -> Reach:
  if fs is None:
    return Reach()
  for mod in fs.imports:
    if labels_of(mod) & wanted:
      return Reach("import", mod)
  return Reach()


def _hop_files(fs: Optional[structure.FileStructure], index: Optional[structure.FirstPartyIndex]) -> List[str]:
  """First-party files referenced anywhere in the caller (one hop).

  The whole file is used, not the provisioning scope: the network client a
  lifecycle call goes through is typically a constructor parameter or a
  field (``val api: AccountApi``) named far from the call site, and the
  member call (``api.registerDevice(...)``) does not repeat the class name.
  Activating files are few, so the over-approximation is cheap and on the
  recall side; the trace records which hop supplied the reach.
  """
  if fs is None or index is None:
    return []
  try:
    refs = structure.callee_references(fs, index, within=None, cap=constants.MAX_CALLEE_FILES_PER_CALLER)
  except Exception as exc:  # pylint: disable=broad-exception-caught
    log.debug("identity hop from %s failed: %s", fs.relpath, exc)
    return []
  return [r.relpath for r in refs if r.relpath != fs.relpath]


def _reach(fl: FileLifecycle, kind: str, wanted_labels: frozenset, fs: Optional[structure.FileStructure],
           structure_of: StructureOf, labels_of: LabelsOf, hops: Sequence[str],
           hop_cache: Dict[str, FileLifecycle]) -> Reach:
  """File -> classified import -> one first-party hop (file or import)."""
  r = _reach_in_file(fl, kind)
  if r.reached:
    return r
  r = _reach_by_import(fs, labels_of, wanted_labels)
  if r.reached:
    return r
  for hop in hops:
    hfl = hop_cache.get(hop)
    if hfl is None:
      hfs = structure_of(hop)
      hfl = scan_lines(hop, hfs.lines if hfs is not None else [], kinds=(NETWORK, PERSIST))
      hop_cache[hop] = hfl
    if hfl.has(kind):
      return Reach("hop", f"{hop}:L{hfl.of(kind)[0].line + 1}")
    if _reach_by_import(structure_of(hop), labels_of, wanted_labels).reached:
      return Reach("hop", hop)
  return Reach()


def _densest_window(lines: Sequence[str], hit_lines: Sequence[int], size: int) -> Tuple[int, int]:
  """The ``size``-line window containing the most hit lines (start, end-exclusive)."""
  if not hit_lines:
    return 0, min(size, len(lines))
  best = (0, hit_lines[0])
  for start in hit_lines:
    lo = max(0, start - size // 3)
    count = sum(1 for h in hit_lines if lo <= h < lo + size)
    if count > best[0]:
      best = (count, lo)
  lo = best[1]
  return lo, min(len(lines), lo + size)


def snippet(lines: Sequence[str], hit_lines: Sequence[int], size: int) -> str:
  """Numbered code window around the densest cluster of ``hit_lines``."""
  lo, hi = _densest_window(lines, sorted(hit_lines), size)
  return "\n".join(f"{i + 1:5d}| {lines[i]}" for i in range(lo, hi))


def assess(scan: LifecycleScan, structure_of: StructureOf, labels_of: LabelsOf,
           index: Optional[structure.FirstPartyIndex], semantic_files: Sequence[str] = ()) -> Assessment:
  """Turns a :class:`LifecycleScan` into sites, candidates and login evidence.

  * A **provisioning site** is an activating file with a provisioning verb,
    an identity token, and a network reach (in the file, through an import
    the capability layer labelled NETWORK_EGRESS / THIRD_PARTY_TELEMETRY, or
    one first-party hop away from the provisioning lines). Its
    ``persistence`` reach is computed the same way (LOCAL_PERSISTENCE).
  * A **deletion candidate** is an activating file with a deletion verb; it
    is ``remote_shaped`` when it reaches the network the same way. A
    candidate without network reach is kept (it is the partial-deletion
    trap's shape) and ranked after the remote-shaped ones.
  * **Login evidence** lists the login-shaped files (most hits first, capped
    at ``MAX_LOGIN_FILES``) with their ``remote_server_tokens`` count, the
    semantic USER_ACCOUNT files from the scanner, and a numbered snippet of
    the two densest files.
  """
  out = Assessment(scan=scan.summary())
  hop_cache: Dict[str, FileLifecycle] = {}
  for fl in scan.with_kind(PROVISION):
    if not fl.has(IDENTITY):
      log.debug("identity: %s has provisioning verbs %s but no identity token; not a site",
                fl.relpath, fl.tokens_of(PROVISION))
      continue
    fs = structure_of(fl.relpath)
    hops = _hop_files(fs, index)
    network = _reach(fl, NETWORK, _NETWORK_LABELS, fs, structure_of, labels_of, hops, hop_cache)
    if not network.reached:
      log.debug("identity: %s provisions %s but reaches no network sink; not a site",
                fl.relpath, fl.tokens_of(PROVISION))
      continue
    persistence = _reach(fl, PERSIST, _PERSIST_LABELS, fs, structure_of, labels_of, hops, hop_cache)
    first = fl.of(PROVISION)[0]
    out.provisioning.append(ProvisioningSite(
        fl.relpath, fl.lines_of(PROVISION), fl.tokens_of(PROVISION), fl.tokens_of(IDENTITY)[:6],
        network, persistence, f"{fl.relpath}:L{first.line + 1} {first.evidence}"))
  for fl in scan.with_kind(DELETE):
    fs = structure_of(fl.relpath)
    hops = _hop_files(fs, index)
    network = _reach(fl, NETWORK, _NETWORK_LABELS, fs, structure_of, labels_of, hops, hop_cache)
    persistence = _reach(fl, PERSIST, _PERSIST_LABELS, fs, structure_of, labels_of, hops, hop_cache)
    first = fl.of(DELETE)[0]
    out.deletions.append(DeletionCandidate(
        fl.relpath, fl.lines_of(DELETE), fl.tokens_of(DELETE), network, persistence,
        f"{fl.relpath}:L{first.line + 1} {first.evidence}"))
  out.deletions.sort(key=lambda d: d.rank())
  login_files = sorted(scan.with_kind(LOGIN), key=lambda f: (-len(f.of(LOGIN)), f.relpath))
  for fl in login_files[:constants.MAX_LOGIN_FILES]:
    out.login.files.append({
        "file": fl.relpath, "hits": len(fl.of(LOGIN)), "tokens": fl.tokens_of(LOGIN)[:8],
        "remote_server_tokens": len(fl.of(USER_SERVER)),
    })
  for fl in login_files[:2]:
    fs = structure_of(fl.relpath)
    if fs is not None and fs.lines:
      out.login.snippets[fl.relpath] = snippet(fs.lines, fl.lines_of(LOGIN), constants.LOGIN_SNIPPET_LINES)
  out.login.semantic_files = sorted({str(s) for s in semantic_files})[:constants.MAX_LOGIN_FILES * 2]
  log.info("identity: %d provisioning site(s) %s; %d deletion candidate(s) %s; login files %d, semantic %d",
           len(out.provisioning), [p.relpath for p in out.provisioning],
           len(out.deletions), [(d.relpath, d.remote_shaped) for d in out.deletions[:5]],
           len(out.login.files), len(out.login.semantic_files))
  return out


def deletion_state(cand: DeletionCandidate, fs: Optional[structure.FileStructure],
                   provisioning: Sequence[ProvisioningSite], app: Dict[str, Any]) -> Dict[str, Any]:
  """The model-facing state for the two deletion Nouls on one candidate."""
  lines = fs.lines if fs is not None else []
  return {
      "app": {k: app.get(k) for k in ("name", "package", "purpose") if app.get(k) is not None},
      "signal": {"file": cand.relpath, "lines": [l + 1 for l in cand.lines], "tokens": cand.tokens},
      "code_snippet": snippet(lines, cand.lines, constants.LIFECYCLE_SNIPPET_LINES) if lines else "",
      "network_indicators": [cand.network.to_dict()] if cand.network.reached else [],
      "persistence_indicators": [cand.persistence.to_dict()] if cand.persistence.reached else [],
      "provisioning": [p.to_state() for p in provisioning[:constants.MAX_PROVISIONING_IN_STATE]],
  }


def login_state(login: LoginEvidence, app: Dict[str, Any], declared_capabilities: Sequence[str]) -> Dict[str, Any]:
  """The model-facing state for the once-per-app ``login_gate_type`` Choice."""
  return {
      "app": {k: app.get(k) for k in ("name", "package", "purpose", "store_category") if app.get(k) is not None},
      "login_files": login.files,
      "semantic_files": login.semantic_files,
      "snippets": login.snippets,
      "declared_capabilities": list(declared_capabilities),
  }
