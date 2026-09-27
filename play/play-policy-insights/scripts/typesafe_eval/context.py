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

"""Builds the model-facing ``state`` for a file from structure + capabilities.

This replaces the original snippet builder for the engine path. Differences:

- **All occurrences, best scope.** Every occurrence of the scanner pattern is
  considered (not just the first, which is often a comment). The occurrence
  whose enclosing function is closest to a transfer-capable sink reference is
  chosen as the anchor, and its whole enclosing scope is the snippet.
- **Capability-typed sinks.** Instead of a hard-coded list of network words, the
  "related data-flow lines" are the lines that reference imported symbols the
  semantic layer labelled with a transfer capability (or UNKNOWN). The sink list
  with its capability labels is also sent explicitly as ``state.sinks`` so the
  model can reason "this goes to a THIRD_PARTY_TELEMETRY sink" regardless of
  which vendor it is.
- **Budgeted.** The merged snippet for a file is capped so batching several
  data types in one file cannot blow up the request.

Everything here is deterministic; the only inputs are the file's text, the
scanner pattern, and the capability profiles already computed.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

from typesafe_eval import capabilities as caps
from typesafe_eval import constants
from typesafe_eval import snippets
from typesafe_eval import structure

log = logging.getLogger("typesafe_eval.context")

# Total rendered snippet lines per file request before scopes are shrunk to
# windows around their hits.
MAX_SNIPPET_LINES_PER_FILE = 160
SHRUNK_WINDOW = 10


@dataclasses.dataclass
class Sink:
  """An imported symbol in the file that the semantic layer marked as a sink."""

  symbol: str
  module: str
  capabilities: List[str]
  lines: List[int]  # 0-based, every reference in the file (ranking uses all)

  def to_state(self, near: Sequence[int] = ()) -> Dict[str, Any]:
    """Model-facing view: at most ``MAX_SINK_REF_LINES_IN_STATE`` reference lines.

    ``near`` are the anchor lines (0-based) of the asks in this file; when the
    sink is referenced more often than the bound, the references closest to an
    anchor are listed (in file order) and ``omitted_lines`` says how many were
    left out. Ranking in :func:`anchor_signal` always uses the full list.
    """
    bound = constants.MAX_SINK_REF_LINES_IN_STATE
    shown = list(self.lines)
    if len(shown) > bound:
      if near:
        shown = sorted(sorted(shown, key=lambda ln: min(abs(ln - a) for a in near))[:bound])
      else:
        shown = shown[:bound]
    out: Dict[str, Any] = {
        "symbol": self.symbol,
        "module": self.module,
        "capabilities": self.capabilities,
        "lines": [i + 1 for i in shown],
    }
    if len(shown) < len(self.lines):
      out["omitted_lines"] = len(self.lines) - len(shown)
    return out


def file_sinks(
    fs: structure.FileStructure, profiles: Dict[str, caps.CapabilityProfile]
) -> List[Sink]:
  """Imported symbols in the file whose profile is a transfer sink.

  Imports that are never referenced by simple name (wildcard imports, aliased
  symbols the regex layer cannot follow) are still listed as *file-level* sinks
  with no line numbers: the model should know the file can reach that sink even
  if the exact call site was not located, and the ranking treats them as
  distant (no proximity) rather than absent.
  """
  out: List[Sink] = []
  for module in fs.imports:
    profile = profiles.get(module)
    if profile is None or not profile.is_transfer_sink:
      continue
    lines = list(fs.references.get(module, []))
    out.append(Sink(structure.simple_name(module), module, list(profile.labels), lines))
  out.sort(key=lambda s: (s.lines[0] if s.lines else 1 << 30, s.symbol))
  return out


def _strength(capabilities: Sequence[str]) -> int:
  """0 strong egress, 1 IPC, 2 UNKNOWN only, 3 no transfer sink (rank order)."""
  cs = set(capabilities)
  if cs & set(constants.RANK_STRONG_EGRESS_CAPABILITIES):
    return 0
  if caps.IPC_SHARING in cs:
    return 1
  if caps.UNKNOWN in cs:
    return 2
  return 3


@dataclasses.dataclass
class Callee:
  """A first-party file reached from the caller in one hop (WP6).

  Built once per caller file by :func:`file_callees`; the per-anchor view
  (which members are called from *this* scope and which of the callee's sinks
  they reach) is :class:`CalleeView`.

  Attributes:
    symbol: The class name as referenced in the caller (``Uploader``).
    relpath: The callee file, app-relative.
    lines: 0-based *caller* lines that reference the symbol.
    resolution: How the file was chosen (see :class:`structure.CalleeRef`).
    fs: The callee's structure (lines, imports, references).
    sinks: The callee's own capability-labelled sinks (:func:`file_sinks`),
      file-level.
    members_by_line: ``caller line -> members called`` (from the reference).
    member_scopes: ``member -> [(start, end)]`` 0-based end-exclusive bodies
      of that member's declarations in the callee (empty list when the member
      could not be located: inherited, generated, defined in an extension
      elsewhere).
  """

  symbol: str
  relpath: str
  lines: List[int]
  resolution: str
  fs: structure.FileStructure
  sinks: List[Sink]
  members_by_line: Dict[int, List[str]] = dataclasses.field(default_factory=dict)
  member_scopes: Dict[str, List[Tuple[int, int]]] = dataclasses.field(default_factory=dict)

  @property
  def capabilities(self) -> List[str]:
    """Union of the callee's file-level sink capabilities."""
    return sorted({c for s in self.sinks for c in s.capabilities})

  def lines_within(self, scope: Tuple[int, int]) -> List[int]:
    """Caller reference lines that fall inside ``scope`` (0-based, end-exclusive)."""
    return [ln for ln in self.lines if scope[0] <= ln < scope[1]]

  def view(self, scope: Tuple[int, int]) -> "CalleeView":
    """The hop as seen from one anchor scope (member-level when possible).

    Member granularity applies when *every* reference to the symbol inside
    ``scope`` names at least one member (``Uploader.send(x)``) and every such
    member was located in the callee: the view's sinks are the callee's sinks
    whose reference lines fall inside those members' bodies. Otherwise (a bare
    constructor call, a type position, or an unlocated member) the view falls
    back to the callee's file-level sinks -- the recall-safe direction -- and
    says so in ``granularity``.
    """
    call_lines = self.lines_within(scope)
    members: List[str] = []
    resolved = bool(call_lines)
    for ln in call_lines:
      named = self.members_by_line.get(ln) or []
      if not named:
        resolved = False
      for m in named:
        if m not in members:
          members.append(m)
    regions: set = set()
    for m in members:
      scopes = self.member_scopes.get(m) or []
      if not scopes:
        resolved = False
      for lo, hi in scopes:
        regions.update(range(lo, hi))
    if resolved and members:
      sinks = []
      for s in self.sinks:
        inside = [ln for ln in s.lines if ln in regions]
        if inside:
          sinks.append(Sink(s.symbol, s.module, list(s.capabilities), inside))
      return CalleeView(self, call_lines, members, "member", sinks, regions)
    return CalleeView(self, call_lines, members, "file", list(self.sinks), set())


@dataclasses.dataclass
class CalleeView:
  """One callee as reached from one anchor scope (WP6).

  Attributes:
    callee: The underlying :class:`Callee`.
    call_lines: 0-based caller lines inside the anchor scope that reference it.
    members: Member names called from the scope (may be empty).
    granularity: ``member`` (sinks limited to the called members' bodies) or
      ``file`` (the callee's file-level sinks; see :meth:`Callee.view`).
    sinks: The sinks this hop reaches, with reference lines in the callee.
    member_regions: 0-based callee lines of the called members' bodies (empty
      for file granularity); rendered as the callee snippet.
  """

  callee: Callee
  call_lines: List[int]
  members: List[str]
  granularity: str
  sinks: List[Sink]
  member_regions: set

  @property
  def symbol(self) -> str:
    return self.callee.symbol

  @property
  def relpath(self) -> str:
    return self.callee.relpath

  @property
  def capabilities(self) -> List[str]:
    """Union of the sink capabilities this hop reaches."""
    return sorted({c for s in self.sinks for c in s.capabilities})

  @property
  def strength(self) -> int:
    return _strength(self.capabilities)

  def to_state(self, snippet: str) -> Dict[str, Any]:
    """Model-facing view of the hop, self-describing so the battery can use it."""
    return {
        "file": self.relpath,
        "symbol": self.symbol,
        "hop": 1,
        "called_at": [ln + 1 for ln in self.call_lines],
        "members": list(self.members),
        "granularity": self.granularity,
        "capabilities": self.capabilities,
        "sinks": [s.to_state() for s in self.sinks],
        "code_snippet": snippet,
    }


def file_callees(
    fs: structure.FileStructure,
    refs: Sequence[structure.CalleeRef],
    callee_files: Dict[str, structure.FileStructure],
    profiles: Dict[str, caps.CapabilityProfile],
) -> List[Callee]:
  """Turns resolved callee references into :class:`Callee` objects with sinks.

  A reference whose file was not structurally indexed (``callee_files`` is the
  engine's cache) is skipped with a log line rather than analysed here, so the
  context layer stays free of filesystem access. Callees with *no* transfer
  sink are kept: "helper X reaches no known transfer sink" is information the
  model should see when the caller hands data to X. Every member the caller
  names on the symbol is located in the callee once here
  (:func:`structure.member_declaration_lines` + :func:`structure.declaration_scope`).
  """
  out: List[Callee] = []
  for ref in refs:
    cfs = callee_files.get(ref.relpath)
    if cfs is None:
      log.debug("callee %s -> %s referenced from %s has no structure; skipped",
                ref.symbol, ref.relpath, fs.relpath)
      continue
    member_scopes: Dict[str, List[Tuple[int, int]]] = {}
    for members in ref.members_by_line.values():
      for m in members:
        if m in member_scopes:
          continue
        decls = structure.member_declaration_lines(cfs.lines, m)
        member_scopes[m] = [structure.declaration_scope(cfs.lines, d) for d in decls]
    unlocated = sorted(m for m, sc in member_scopes.items() if not sc)
    if unlocated:
      log.debug("callee %s (%s): members %s not located; file-level fallback where they are called",
                ref.symbol, ref.relpath, unlocated)
    out.append(Callee(ref.symbol, ref.relpath, list(ref.lines), ref.resolution,
                      cfs, file_sinks(cfs, profiles), dict(ref.members_by_line), member_scopes))
  return out


def disclosure_symbols(
    fs: structure.FileStructure, profiles: Dict[str, caps.CapabilityProfile]
) -> List[str]:
  return sorted(
      structure.simple_name(m) for m in fs.references
      if profiles.get(m) is not None and caps.USER_DISCLOSURE_UI in profiles[m].labels
  )


@dataclasses.dataclass
class GuardState:
  """A guard flag of an anchor scope plus its located declaration (WP8)."""

  flag: structure.GuardFlag
  declaration: Optional[structure.Declaration]

  def to_state(self) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "flag": self.flag.identifier,
        "line": self.flag.line + 1,
        "runs_when": "false" if self.flag.negated else "true",
    }
    if self.declaration is not None:
      out["declaration"] = self.declaration.to_state()
      out["default_on"] = self.declaration.default_on
    else:
      out["declaration"] = None
      out["default_on"] = None
    return out


def anchor_guards(
    fs: structure.FileStructure, scope: Tuple[int, int],
    index: Optional[structure.FirstPartyIndex] = None, app_dir: str = "",
) -> List[GuardState]:
  """Guard flags of ``scope`` with their declarations resolved (WP8)."""
  out: List[GuardState] = []
  for flag in structure.guard_flags(fs.lines, scope):
    decl = structure.declaration_of(flag, fs, index, app_dir)
    out.append(GuardState(flag, decl))
  if out:
    log.info("guards in %s L%d-%d: %s", fs.relpath, scope[0] + 1, scope[1],
             [(g.flag.identifier, g.declaration.default_on if g.declaration else None,
               g.declaration.resolution if g.declaration else "unresolved") for g in out])
  return out


def resolved_strings(
    fs: structure.FileStructure, line_numbers: Sequence[int], resources: Any,
) -> Dict[str, Optional[str]]:
  """``R.string.<name>`` references on ``line_numbers`` resolved to default-locale text (WP8).

  ``resources`` is a ``resources.ResourceIndex`` (duck-typed: ``strings`` dict);
  a referenced name missing from the index maps to None so the model sees the
  reference exists but its text is unknown (a localisation-only or generated
  string). Capped at ``MAX_STRINGS_IN_STATE`` in order of appearance.
  """
  if resources is None:
    return {}
  names = structure.string_references(fs.lines, line_numbers)[: constants.MAX_STRINGS_IN_STATE]
  table = getattr(resources, "strings", {}) or {}
  out = {n: table.get(n) for n in names}
  if out:
    log.info("strings in %s: %d resolved, %d unresolved", fs.relpath,
             sum(1 for v in out.values() if v is not None), sum(1 for v in out.values() if v is None))
  return out


@dataclasses.dataclass
class Anchor:
  """Where a data-type signal is anchored in the file after occurrence selection."""

  data_type: str
  pattern: str
  hit_lines: List[int]          # all occurrences (0-based), capped
  chosen: Optional[int]         # the anchor occurrence
  scope: Tuple[int, int]        # (start, end) 0-based end-exclusive
  proximity: Optional[int]      # line distance to nearest sink ref; 0 = inside scope
  sink_in_scope: bool
  scope_capabilities: List[str] = dataclasses.field(default_factory=list)
  # WP2: how the pattern occurs in the file (``value`` / ``type_only`` /
  # ``substring_only`` / ``demoted_only`` / ``none`` / ``non_identifier``).
  # Recorded in the decision trace, never sent to the model.
  lexical_verdict: str = ""
  # WP6: first-party callees referenced inside the anchor's scope (as seen
  # from it), strongest reachable capability first, capped at
  # ``MAX_CALLEES_PER_ANCHOR``.
  callees: List["CalleeView"] = dataclasses.field(default_factory=list)
  # WP7: deterministic destination priors read from the chosen scope
  # (``structure.destination_hints``). Filled by :func:`build_file_state`
  # for the chosen occurrence only; sent to the model as
  # ``destination_hints`` and recorded in the trace.
  destination_hints: List[structure.DestinationHint] = dataclasses.field(default_factory=list)
  # WP8: boolean flags guarding the chosen scope with their declarations
  # (``structure.guard_flags`` / ``declaration_of``). Priors for the
  # ``consent_default_on`` Noul and the deterministic half of its double gate.
  guards: List["GuardState"] = dataclasses.field(default_factory=list)

  @property
  def destination_hint_kinds(self) -> List[str]:
    """Distinct hint kinds in the chosen scope (WP7), e.g. ``["USER_CHOSEN_DESTINATION"]``."""
    return sorted({h.kind for h in self.destination_hints})

  @property
  def guard_defaults(self) -> List[Optional[bool]]:
    """The ``default_on`` of every guard with a located declaration (WP8)."""
    return [g.declaration.default_on for g in self.guards if g.declaration is not None]

  @property
  def callee_capabilities(self) -> List[str]:
    """Union of the sink capabilities reachable through in-scope callees (WP6)."""
    return sorted({c for cal in self.callees for c in cal.capabilities})

  @property
  def callee_in_scope(self) -> bool:
    """True when an in-scope callee reaches at least one transfer sink (WP6)."""
    return any(cal.sinks for cal in self.callees)

  @property
  def reach_in_scope(self) -> bool:
    """A transfer sink is reachable from the anchor's function: directly
    (``sink_in_scope``) or through a one-hop first-party callee
    (``callee_in_scope``). Used by the cap exemption in triage."""
    return self.sink_in_scope or self.callee_in_scope

  @property
  def tier(self) -> int:
    """Ranking tier from the capabilities reachable from the anchor's scope.

    0: an explicit egress capability (network, telemetry, advertising) is
       referenced in the same function — the strongest static transfer signal.
    1: only IPC-capable symbols are in scope. IPC *is* a transfer/sharing
       channel by policy, but IPC-capable platform types (intents, activities,
       content resolvers) appear in nearly every Android file, so as a *ranking*
       signal they discriminate less than explicit egress. This affects which
       candidates reach the model first under a cap, never how a finding is
       judged once evaluated.
    2: only UNKNOWN-labelled symbols are in scope.
    3: no sink in scope (ranked by proximity to the nearest sink elsewhere).

    Since WP6 the capabilities of first-party callees referenced *inside* the
    scope count as well (the call site is in scope, the sink is one hop away);
    ``scope_capabilities`` keeps the same-file view and ``callee_capabilities``
    the hop view so the trace shows which one produced the tier.
    """
    scope_caps = set(self.scope_capabilities) | set(self.callee_capabilities)
    if scope_caps & set(constants.RANK_STRONG_EGRESS_CAPABILITIES):
      return 0
    if caps.IPC_SHARING in scope_caps:
      return 1
    if caps.UNKNOWN in scope_caps:
      return 2
    return 3


def _callees_in_scope(callees: Sequence[Callee], scope: Tuple[int, int], hit: int) -> List[CalleeView]:
  """Views of the callees referenced inside ``scope``, strongest first, nearest
  call site second, bounded by ``MAX_CALLEES_PER_ANCHOR`` (WP6)."""
  views = [c.view(scope) for c in callees if c.lines_within(scope)]
  views.sort(key=lambda v: (v.strength, min(abs(ln - hit) for ln in v.call_lines), v.symbol))
  return views[:constants.MAX_CALLEES_PER_ANCHOR]


def anchor_signal(
    fs: structure.FileStructure, pattern: str, data_type: str, sinks: Sequence[Sink],
    callees: Sequence[Callee] = (),
) -> Anchor:
  """Chooses the occurrence whose enclosing scope is nearest a sink reference.

  Among occurrences, the one with the strongest sink tier in its own scope
  wins; ties are broken by proximity to the nearest sink reference. With
  ``callees`` (WP6) a scope that calls a first-party helper reaching a sink
  gets that helper's capabilities in its tier, so ``upload()`` calling
  ``Uploader.send(loc)`` beats ``show()`` even though neither references a
  network symbol directly.
  """
  prefer_boundary = constants.LEXICAL_PREGATE_ENABLED
  hits = structure.all_occurrences(fs.lines, pattern, cap=constants.MAX_OCCURRENCES_RANKED,
                                   prefer_boundary=prefer_boundary)
  if prefer_boundary and structure.is_identifier_pattern(pattern):
    verdict = structure.lexical_hits(fs.lines, pattern).verdict
  else:
    verdict = "non_identifier" if pattern else "none"
  sink_lines = sorted({ln for s in sinks for ln in s.lines})
  caps_by_line: Dict[int, set] = {}
  for s in sinks:
    for ln in s.lines:
      caps_by_line.setdefault(ln, set()).update(s.capabilities)
  if not hits:
    return Anchor(data_type, pattern, [], None, (0, min(len(fs.lines), 2 * SHRUNK_WINDOW)),
                  None, False, [], lexical_verdict=verdict)

  best: Optional[Anchor] = None
  best_key: Optional[Tuple[int, int]] = None
  for h in hits:
    scope = structure.enclosing_scope(fs.lines, h, fs.language)
    inside = [s for s in sink_lines if scope[0] <= s < scope[1]]
    scope_caps = sorted({c for s in inside for c in caps_by_line.get(s, ())})
    if inside:
      prox: Optional[int] = 0
    else:
      prox = structure.sink_proximity([h], sink_lines)
    candidate = Anchor(data_type, pattern, hits, h, scope, prox, bool(inside), scope_caps,
                       lexical_verdict=verdict,
                       callees=_callees_in_scope(callees, scope, h) if callees else [])
    key = (candidate.tier, prox if prox is not None else 1 << 30)
    if best_key is None or key < best_key:
      best, best_key = candidate, key
  assert best is not None
  # The model-facing list is bounded; the chosen occurrence is always in it.
  listed = hits[:constants.MAX_HIT_LINES_IN_STATE]
  if best.chosen is not None and best.chosen not in listed:
    listed = listed[:-1] + [best.chosen]
  best.hit_lines = listed
  return best


def _render_snippet(fs: structure.FileStructure, anchors: Sequence[Anchor], sinks: Sequence[Sink]) -> Tuple[str, List[str]]:
  """Merges anchor scopes (budgeted) and appends sink-reference lines."""
  regions: set = set()
  for a in anchors:
    regions.update(range(a.scope[0], a.scope[1]))
  if len(regions) > MAX_SNIPPET_LINES_PER_FILE:
    regions = set()
    for a in anchors:
      if a.chosen is None:
        continue
      lo = max(a.scope[0], a.chosen - SHRUNK_WINDOW)
      hi = min(a.scope[1], a.chosen + SHRUNK_WINDOW + 1)
      regions.update(range(lo, hi))
  code = structure.render_lines(fs.lines, regions)

  # Sink-reference lines outside the rendered regions, nearest an anchor first
  # (a sink 3 lines below the hit is worth more to the model than the file's
  # first ``Intent`` 800 lines earlier), then listed in file order.
  anchor_lines = [a.chosen for a in anchors if a.chosen is not None]
  by_line: Dict[int, List[Sink]] = {}
  for s in sinks:
    for ln in s.lines:
      if ln not in regions:
        by_line.setdefault(ln, []).append(s)

  def _distance(ln: int) -> int:
    return min((abs(ln - a) for a in anchor_lines), default=ln)

  chosen_lines = sorted(sorted(by_line, key=_distance)[:constants.MAX_SINK_LINES_IN_STATE])
  related: List[str] = []
  for ln in chosen_lines:
    tags = "; ".join(f"{s.symbol} {s.capabilities}" for s in by_line[ln])
    related.append(f"L{ln + 1}: {fs.lines[ln].strip()}  // sink: {tags}")
  if related:
    code += "\n\n// Related data-flow lines in the same file (capability-labelled sinks):\n"
    code += "\n".join(related)
  return code, related


def _callee_regions(view: CalleeView) -> set:
  """0-based callee lines to render for one hop.

  Member granularity: the called members' bodies (the model sees the helper
  method the caller actually invokes). File granularity: the enclosing scope
  of every sink reference in the callee.
  """
  if view.granularity == "member":
    return set(view.member_regions)
  regions: set = set()
  for s in view.sinks:
    for ln in s.lines:
      lo, hi = structure.enclosing_scope(view.callee.fs.lines, ln, view.callee.fs.language)
      regions.update(range(lo, hi))
  return regions


def _callee_sink_lines_only(view: CalleeView) -> str:
  """The "sink lines only" fallback: one tagged line per sink reference."""
  by_line: Dict[int, List[Sink]] = {}
  for s in view.sinks:
    for ln in s.lines:
      by_line.setdefault(ln, []).append(s)
  out: List[str] = []
  for ln in sorted(by_line)[:constants.MAX_SINK_LINES_IN_STATE]:
    tags = "; ".join(f"{s.symbol} {s.capabilities}" for s in by_line[ln])
    out.append(f"L{ln + 1}: {view.callee.fs.lines[ln].strip()}  // sink: {tags}")
  return "\n".join(out)


def _callee_key(view: CalleeView) -> str:
  """Distinct hops per file request: one entry per (callee file, members called)."""
  return view.relpath + "#" + ",".join(view.members)


def _render_callees(anchors: Sequence[Anchor]) -> Tuple[str, Dict[str, str]]:
  """Renders the callee section appended to a file's snippet (WP6).

  For each distinct hop reached from any anchor, the callee lines chosen by
  :func:`_callee_regions` are rendered. When those regions together would
  exceed ``constants.MAX_CALLEE_SNIPPET_LINES`` only the sink reference lines
  are rendered; a hop that reaches no sink gets a one-line note (member
  granularity: "the called members reach no sink"; file granularity: "the
  file has no sink"). Returns ``(section, per_hop)`` with the per-hop
  snippets keyed by :func:`_callee_key` for ``CalleeView.to_state``.
  """
  distinct: Dict[str, CalleeView] = {}
  for a in anchors:
    for v in a.callees:
      distinct.setdefault(_callee_key(v), v)
  if not distinct:
    return "", {}
  regions = {k: _callee_regions(v) for k, v in distinct.items()}
  total = sum(len(r) for r in regions.values())
  sink_lines_only = total > constants.MAX_CALLEE_SNIPPET_LINES
  per_hop: Dict[str, str] = {}
  parts: List[str] = []
  for k, v in distinct.items():
    if not v.sinks:
      if v.granularity == "member":
        body = (f"// the called member(s) {', '.join(v.members)} reach no capability-labelled "
                f"transfer sink (file-level sinks of this callee: {v.callee.capabilities or 'none'})")
      else:
        body = "// no capability-labelled transfer sink in this file"
    elif sink_lines_only or not regions[k]:
      body = _callee_sink_lines_only(v)
    else:
      body = structure.render_lines(v.callee.fs.lines, regions[k])
    per_hop[k] = body
    called = ", ".join(f"L{ln + 1}" for ln in v.call_lines[:constants.MAX_HIT_LINES_IN_STATE])
    what = f".{'/'.join(v.members)}" if v.members else ""
    header = (f"// First-party callee {v.symbol}{what} ({v.relpath}), called at {called}; "
              f"reachable sinks: {v.capabilities or 'none'} [{v.granularity}-level]")
    parts.append(header + "\n" + body)
  log.debug("callee section: %d hop(s), %d region lines, sink_lines_only=%s",
            len(distinct), total, sink_lines_only)
  section = "\n\n// First-party callees reached from the snippet (one hop):\n" + "\n\n".join(parts)
  return section, per_hop


def build_file_state(
    fs: structure.FileStructure,
    asks: Sequence[Tuple[str, str]],
    profiles: Dict[str, caps.CapabilityProfile],
    app_facts: Dict[str, Any],
    app_dir: str = "",
    callees: Sequence[Callee] = (),
    first_party_index: Optional[structure.FirstPartyIndex] = None,
    resources: Any = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
  """One shared state for a file plus one mini-state per ask.

  Args:
    fs: The file's structure (lines, imports, references).
    asks: ``(data_type, pattern)`` pairs anchored in this file.
    profiles: Capability profiles for the file's imports.
    app_facts: The small ``app`` block sent in every state.
    app_dir: Used only to reuse the scanner's generic disclosure-word list.
    callees: First-party files referenced from this file with their own
      sinks (WP6, :func:`file_callees`). Only those referenced inside an
      anchor's scope are attached to that anchor and rendered.
    first_party_index: The app's class-name index (WP6); used by WP8 to find
      a guard flag's declaration one hop away through its receiver's type.
    resources: The default-locale ``resources.ResourceIndex`` (WP8); when
      given, ``R.string`` references in anchor scopes and on disclosure
      lines are resolved into ``state["strings"]``.

  Returns:
    ``(state, per_ask)`` where ``state`` is sent to the model and each
    ``per_ask`` mini-state carries what ``evaluate`` needs to compose the
    finding and its decision trace (signal, anchor, sinks, callees, own
    snippet). ``state["callees"]`` is present only when at least one anchor
    reaches a callee, so states of files without hops are byte-identical to
    the pre-WP6 form (cache-friendly).
  """
  sinks = file_sinks(fs, profiles)
  anchors = [anchor_signal(fs, pattern, dt, sinks, callees) for dt, pattern in asks]
  # WP7: destination priors are read from the chosen scope only (one pass per
  # ask, not per candidate occurrence) and keyed by the app's own domains.
  if constants.DESTINATION_HINTS_ENABLED:
    dev_domains = structure.developer_domains(str(app_facts.get("package") or ""))
    for a in anchors:
      if a.chosen is not None:
        a.destination_hints = structure.destination_hints(fs.lines, a.scope, dev_domains)
  # WP8: guards of the chosen scope with their declared defaults.
  if constants.GUARDS_ENABLED:
    for a in anchors:
      if a.chosen is not None:
        a.guards = anchor_guards(fs, a.scope, first_party_index, app_dir)
  code, related = _render_snippet(fs, anchors, sinks)
  callee_section, callee_snippets = _render_callees(anchors)
  code += callee_section

  def _callee_states(anchor_list: Sequence[Anchor]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for a in anchor_list:
      for v in a.callees:
        key = _callee_key(v)
        if key not in seen:
          seen[key] = v.to_state(callee_snippets.get(key, ""))
    return list(seen.values())

  all_callee_states = _callee_states(anchors)
  if all_callee_states:
    log.info("state for %s: %d hop(s) appended: %s", fs.relpath, len(all_callee_states),
             [(c["symbol"], c["members"], c["granularity"], c["capabilities"]) for c in all_callee_states])

  # The scanner's own generic co-location vocabulary (dialog/consent words,
  # request/fetch verbs) is merged in as a *secondary* hint. Capability-labelled
  # sinks are the primary transfer evidence; the scanner words only keep the
  # legacy signal visible when the semantic layer found no sink in the file.
  scanner_co = snippets.co_located_signals(app_dir, fs.relpath) if app_dir else {}
  disclosure = sorted(set(disclosure_symbols(fs, profiles)) | set(scanner_co.get("disclosure", [])))
  # Callee sinks (WP6) are listed as ``Callee.Sink`` so the hint stays honest
  # about where the channel lives; the offline heuristic client reads this
  # list as its "has network" signal, so hops are visible to it as well.
  callee_symbols = {f"{c['symbol']}.{s['symbol']}" for c in all_callee_states for s in c["sinks"]}
  network = sorted({s.symbol for s in sinks} | callee_symbols | set(scanner_co.get("network_transmission", [])))

  state: Dict[str, Any] = {
      "file": fs.relpath,
      "language": fs.language,
      "signals": [
          {"data_type": a.data_type, "matched_pattern": a.pattern,
           "line": (a.chosen + 1) if a.chosen is not None else None,
           "all_lines": [h + 1 for h in a.hit_lines]}
          for a in anchors
      ],
      "code_snippet": code,
      "sinks": [s.to_state(near=[a.chosen for a in anchors if a.chosen is not None]) for s in sinks],
      "co_located_signals": {"network_transmission": network, "disclosure": disclosure},
      "related_lines": related,
      "app": app_facts,
  }
  if all_callee_states:
    state["callees"] = all_callee_states
  # WP7: one flat list across asks, tagged by data type so the model can tell
  # which signal a hint belongs to in a batched request. Present only when a
  # hint exists (states without hints stay byte-identical to pre-WP7).
  hint_states = [
      {"data_type": a.data_type, **h.to_state()} for a in anchors for h in a.destination_hints
  ]
  if hint_states:
    state["destination_hints"] = hint_states
    log.info("state for %s: %d destination hint(s): %s", fs.relpath, len(hint_states),
             sorted({(h["data_type"], h["hint"], h["detail"]) for h in hint_states}))
  # WP8: guards (flat, tagged by data type) and resolved string resources.
  # Both present only when non-empty so unaffected states stay byte-identical.
  guard_states = [{"data_type": a.data_type, **g.to_state()} for a in anchors for g in a.guards]
  if guard_states:
    state["guards"] = guard_states
  strings: Dict[str, Optional[str]] = {}
  if constants.STRING_RESOLUTION_ENABLED and resources is not None:
    scope_lines: List[int] = []
    for a in anchors:
      if a.chosen is not None:
        scope_lines.extend(range(a.scope[0], a.scope[1]))
    # ``fs.references`` is keyed by import module; disclosure symbols are simple names.
    disclosure_set = set(disclosure)
    disclosure_lines = [i for module, refs in fs.references.items()
                        if structure.simple_name(module) in disclosure_set for i in refs]
    strings = resolved_strings(fs, scope_lines + disclosure_lines, resources)
    if strings:
      state["strings"] = strings

  per_ask: List[Dict[str, Any]] = []
  for a in anchors:
    own = structure.render_lines(fs.lines, range(a.scope[0], a.scope[1]))
    if related:
      own += "\n\n// Related data-flow lines in the same file (capability-labelled sinks):\n" + "\n".join(related)
    own_callees = _callee_states([a])
    if own_callees:
      own += _render_callees([a])[0]
    mini: Dict[str, Any] = {
        "signal": {
            "data_type": a.data_type,
            "matched_pattern": a.pattern,
            "file": fs.relpath,
            "line": (a.chosen + 1) if a.chosen is not None else None,
            "matched_line": fs.lines[a.chosen].strip() if a.chosen is not None else "",
            "all_lines": [h + 1 for h in a.hit_lines],
        },
        "code_snippet": own,
        "co_located_signals": state["co_located_signals"],
        "related_lines": related,
        "sinks": state["sinks"],
        "anchor": {
            "scope": [a.scope[0] + 1, a.scope[1]],
            "proximity": a.proximity,
            "sink_in_scope": a.sink_in_scope,
            "scope_capabilities": a.scope_capabilities,
            "tier": a.tier,
            "lexical": a.lexical_verdict,
            "callee_in_scope": a.callee_in_scope,
            "callee_capabilities": a.callee_capabilities,
            "destination_hints": a.destination_hint_kinds,
            "guard_defaults": a.guard_defaults,
        },
        "callees": own_callees,
        "app": app_facts,
        "permission": None,
    }
    if a.destination_hints:
      mini["destination_hints"] = [h.to_state() for h in a.destination_hints]
    if a.guards:
      mini["guards"] = [g.to_state() for g in a.guards]
    if strings:
      mini["strings"] = strings
    per_ask.append(mini)
  log.debug("state for %s: %d asks, %d sinks, %d callees, %d snippet chars",
            fs.relpath, len(asks), len(sinks), len(all_callee_states), len(code))
  return state, per_ask


def rank_key(anchor: Anchor, original_index: int) -> Tuple[int, int, int]:
  """Deterministic triage key: sink tier (see :attr:`Anchor.tier`), then
  proximity to the nearest sink, then scanner order."""
  prox = anchor.proximity if anchor.proximity is not None else 1 << 30
  return (anchor.tier, prox, original_index)
