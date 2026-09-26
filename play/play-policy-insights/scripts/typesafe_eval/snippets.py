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

"""Deterministic code-snippet extraction for the evaluator's state.

The static scanner (``scanner.py``) records each signal as the string
``"<relpath> (Pattern: <pattern>)"`` — a match *location*, not the surrounding
code. Jev judges what is in the ``state``, so to answer questions like "is this
location value transmitted off-device?" the model needs the actual code around
the match, plus any co-located network / disclosure signals from the same file.

This module reads the app source (offline, deterministic) to produce that
context. It never calls a model and never writes outside memory.
"""

from __future__ import annotations

import functools
import json
import os
import re
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

# ``"<relpath> (Pattern: <pattern>)"`` as emitted by scanner._scan_single_file.
_FINDING_RE = re.compile(r"^(?P<relpath>.*?)\s*\(Pattern:\s*(?P<pattern>.*?)\)\s*$")


def _repo_root() -> str:
  """The play-policy-insights skill directory (contains ``resources/``)."""
  return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@functools.lru_cache(maxsize=1)
def _scanner_config() -> dict:
  path = os.path.join(_repo_root(), "resources", "scanner_config.json")
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception:  # pylint: disable=broad-exception-caught
    return {}


def parse_finding(finding: str) -> Tuple[Optional[str], Optional[str]]:
  """Splits a scanner finding string into ``(relpath, pattern)``.

  Returns ``(None, None)`` if the string is not in the expected shape.
  """
  match = _FINDING_RE.match(finding.strip())
  if not match:
    return None, None
  return match.group("relpath").strip(), match.group("pattern").strip()


def _read_file(app_dir: str, relpath: str) -> Optional[str]:
  full = os.path.join(app_dir, relpath)
  if not os.path.isfile(full):
    return None
  try:
    with open(full, "r", encoding="utf-8", errors="ignore") as f:
      return f.read()
  except Exception:  # pylint: disable=broad-exception-caught
    return None


def extract_snippet(
    app_dir: str,
    relpath: str,
    pattern: str,
    context: int = 4,
) -> Dict[str, object]:
  """Returns the matched line plus ``context`` lines on each side.

  The result is a small dict suitable for embedding in a Jev ``state``:
  ``file``, ``line`` (1-indexed, or None if the pattern was not found), and
  ``snippet`` (the surrounding source, or "" when the file is unreadable).
  """
  content = _read_file(app_dir, relpath)
  if content is None:
    return {"file": relpath, "line": None, "snippet": ""}

  lines = content.splitlines()
  hit_index = None
  for i, line in enumerate(lines):
    if pattern in line:
      hit_index = i
      break

  if hit_index is None:
    # Pattern not on a single line (rare); return the file head as weak context.
    head = "\n".join(lines[: 2 * context + 1])
    return {"file": relpath, "line": None, "snippet": head, "matched_line": ""}

  start = max(0, hit_index - context)
  end = min(len(lines), hit_index + context + 1)
  snippet = "\n".join(lines[start:end])
  return {
      "file": relpath,
      "line": hit_index + 1,
      "snippet": snippet,
      "matched_line": lines[hit_index].strip(),
  }


def co_located_signals(app_dir: str, relpath: str) -> Dict[str, List[str]]:
  """Detects network-transmission and disclosure signals in the same file.

  Mirrors the scanner's own pattern lists so the two stay consistent. The
  returned patterns are what let a Noul distinguish "location is read" from
  "location is read and sent off-device".
  """
  content = _read_file(app_dir, relpath)
  result: Dict[str, List[str]] = {"network_transmission": [], "disclosure": []}
  if not content:
    return result

  categories = _scanner_config().get("signal_categories", {})
  for category in ("network_transmission", "disclosure"):
    group = categories.get(category, {})
    # These categories use the anonymous "-" bucket in scanner_config.json.
    patterns = group.get("-", []) if isinstance(group, dict) else []
    found = sorted({p for p in patterns if p in content})
    result[category] = found
  return result


def build_state(
    app_dir: str,
    finding: str,
    data_type: str,
    app_facts: Dict[str, object],
    permission: Optional[str] = None,
    context: int = 4,
) -> Dict[str, object]:
  """Assembles the compact ``state`` for a single-finding Jev request.

  Only the fields a question needs are included, per Jev's guidance to keep the
  state small and relevant (a large state full of irrelevant detail costs
  accuracy).
  """
  relpath, pattern = parse_finding(finding)
  if relpath is None:
    # Fall back to treating the whole string as the file path.
    relpath, pattern = finding, ""

  snippet = extract_snippet(app_dir, relpath, pattern, context=context)
  co = co_located_signals(app_dir, relpath)

  return {
      "signal": {
          "data_type": data_type,
          "matched_pattern": pattern,
          "file": snippet["file"],
          "line": snippet["line"],
          "matched_line": snippet.get("matched_line", ""),
      },
      "code_snippet": snippet["snippet"],
      "co_located_signals": co,
      "app": app_facts,
      "permission": permission,
  }
