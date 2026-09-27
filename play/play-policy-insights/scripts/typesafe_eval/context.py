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
  lines: List[int]  # 0-based

  def to_state(self) -> Dict[str, Any]:
    return {
        "symbol": self.symbol,
        "module": self.module,
        "capabilities": self.capabilities,
        "lines": [i + 1 for i in self.lines],
    }


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


def disclosure_symbols(
    fs: structure.FileStructure, profiles: Dict[str, caps.CapabilityProfile]
) -> List[str]:
  return sorted(
      structure.simple_name(m) for m in fs.references
      if profiles.get(m) is not None and caps.USER_DISCLOSURE_UI in profiles[m].labels
  )


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


def anchor_signal(
    fs: structure.FileStructure, pattern: str, data_type: str, sinks: Sequence[Sink]
) -> Anchor:
  """Chooses the occurrence whose enclosing scope is nearest a sink reference."""
  hits = structure.all_occurrences(fs.lines, pattern)
  sink_lines = sorted({ln for s in sinks for ln in s.lines})
  if not hits:
    return Anchor(data_type, pattern, [], None, (0, min(len(fs.lines), 2 * SHRUNK_WINDOW)),
                  None, False)

  best: Optional[Tuple[int, int, Tuple[int, int], Optional[int], bool]] = None
  for h in hits:
    scope = structure.enclosing_scope(fs.lines, h, fs.language)
    inside = [s for s in sink_lines if scope[0] <= s < scope[1]]
    if inside:
      prox: Optional[int] = 0
    else:
      prox = structure.sink_proximity([h], sink_lines)
    rank = prox if prox is not None else 1 << 30
    if best is None or rank < best[0]:
      best = (rank, h, scope, prox, bool(inside))
  assert best is not None
  _, chosen, scope, prox, inside = best
  return Anchor(data_type, pattern, hits, chosen, scope, prox, inside)


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

  related: List[str] = []
  seen: set = set()
  for s in sinks:
    for ln in s.lines:
      if ln in regions or ln in seen:
        continue
      seen.add(ln)
      related.append(f"L{ln + 1}: {fs.lines[ln].strip()}  // sink: {s.symbol} {s.capabilities}")
      if len(related) >= constants.MAX_SINK_LINES_IN_STATE:
        break
    if len(related) >= constants.MAX_SINK_LINES_IN_STATE:
      break
  if related:
    code += "\n\n// Related data-flow lines in the same file (capability-labelled sinks):\n"
    code += "\n".join(related)
  return code, related


def build_file_state(
    fs: structure.FileStructure,
    asks: Sequence[Tuple[str, str]],
    profiles: Dict[str, caps.CapabilityProfile],
    app_facts: Dict[str, Any],
    app_dir: str = "",
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
  """One shared state for a file plus one mini-state per ask.

  Args:
    fs: The file's structure (lines, imports, references).
    asks: ``(data_type, pattern)`` pairs anchored in this file.
    profiles: Capability profiles for the file's imports.
    app_facts: The small ``app`` block sent in every state.
    app_dir: Used only to reuse the scanner's generic disclosure-word list.

  Returns:
    ``(state, per_ask)`` where ``state`` is sent to the model and each
    ``per_ask`` mini-state carries what ``evaluate`` needs to compose the
    finding and its decision trace (signal, anchor, sinks, own snippet).
  """
  sinks = file_sinks(fs, profiles)
  anchors = [anchor_signal(fs, pattern, dt, sinks) for dt, pattern in asks]
  code, related = _render_snippet(fs, anchors, sinks)

  # The scanner's own generic co-location vocabulary (dialog/consent words,
  # request/fetch verbs) is merged in as a *secondary* hint. Capability-labelled
  # sinks are the primary transfer evidence; the scanner words only keep the
  # legacy signal visible when the semantic layer found no sink in the file.
  scanner_co = snippets.co_located_signals(app_dir, fs.relpath) if app_dir else {}
  disclosure = sorted(set(disclosure_symbols(fs, profiles)) | set(scanner_co.get("disclosure", [])))
  network = sorted({s.symbol for s in sinks} | set(scanner_co.get("network_transmission", [])))

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
      "sinks": [s.to_state() for s in sinks],
      "co_located_signals": {"network_transmission": network, "disclosure": disclosure},
      "related_lines": related,
      "app": app_facts,
  }

  per_ask: List[Dict[str, Any]] = []
  for a in anchors:
    own = structure.render_lines(fs.lines, range(a.scope[0], a.scope[1]))
    if related:
      own += "\n\n// Related data-flow lines in the same file (capability-labelled sinks):\n" + "\n".join(related)
    per_ask.append({
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
        },
        "app": app_facts,
        "permission": None,
    })
  log.debug("state for %s: %d asks, %d sinks, %d snippet chars",
            fs.relpath, len(asks), len(sinks), len(code))
  return state, per_ask


def rank_key(anchor: Anchor, original_index: int) -> Tuple[int, int, int]:
  """Deterministic triage key: sink-in-scope first, then proximity, then scanner order."""
  prox = anchor.proximity if anchor.proximity is not None else 1 << 30
  return (0 if anchor.sink_in_scope else 1, prox, original_index)
