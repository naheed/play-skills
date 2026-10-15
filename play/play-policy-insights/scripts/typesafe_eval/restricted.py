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

"""Deterministic prefilters for the wave-4 restricted-API Nouls (WP12).

The manifest rules in :mod:`typesafe_eval.registry` decide whether an SMS /
call-log permission or an accessibility service ships. This module only
decides which source files are worth one model question:

* ``sms`` — the file mentions an SMS-body or call-log platform API
  (``SmsMessage``, ``getMessageBody``, ``CallLog.Calls``, …).
* ``accessibility`` — the file handles an accessibility event
  (``AccessibilityEvent``, ``onAccessibilityEvent``, …).

Comments and string literals are skipped, the same way the identity scan
skips them. A file with no hit is never sent to the model. The identifiers
are platform APIs; the vendor-name lint covers this module.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional

from typesafe_eval import constants
from typesafe_eval import structure

log = logging.getLogger(__name__)

_RES = {
    "sms": re.compile(constants.SMS_CONTENT_RE),
    "accessibility": re.compile(constants.ACCESSIBILITY_EVENT_RE),
}


def scan(app_dir: str, relpaths: Iterable[str], kind: str) -> List[Dict[str, object]]:
  """Files of ``kind`` (``sms`` or ``accessibility``) with at least one hit.

  Returns the densest files first, at most ``MAX_WAVE4_CANDIDATES``, each as
  ``{"relpath", "lines", "tokens", "snippet"}``. ``lines`` are 1-based.
  Unreadable files are logged and skipped. Never raises for a single file.
  """
  rx = _RES.get(kind)
  if rx is None or not app_dir:
    log.info("wave4 scan: kind %s has no pattern or no app dir", kind)
    return []
  found: List[Dict[str, object]] = []
  scanned = 0
  for rel in relpaths:
    if scanned >= constants.MAX_WAVE4_FILES:
      log.info("wave4 scan %s: stopped at MAX_WAVE4_FILES=%d", kind, constants.MAX_WAVE4_FILES)
      break
    scanned += 1
    path = os.path.join(app_dir, rel)
    try:
      with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    except OSError as exc:
      log.warning("wave4 scan: unreadable %s (%s)", rel, exc)
      continue
    hits: List[int] = []
    tokens: List[str] = []
    for i, line in enumerate(lines):
      if not structure.is_code_line(line):
        continue
      for m in rx.finditer(structure.code_portion(line)):
        hits.append(i)
        if m.group(0) not in tokens:
          tokens.append(m.group(0))
        break
    if hits:
      found.append({
          "relpath": rel,
          "lines": [n + 1 for n in hits[:12]],
          "tokens": tokens[:8],
          "snippet": _window(lines, hits),
          "hit_count": len(hits),
      })
  found.sort(key=lambda h: (-int(h["hit_count"]), str(h["relpath"])))
  kept = found[:constants.MAX_WAVE4_CANDIDATES]
  log.info("wave4 scan %s: %d file(s) with hits, %d kept (scanned %d)", kind, len(found), len(kept), scanned)
  return kept


def _window(lines: List[str], hit_indexes: List[int]) -> str:
  """A window around the first hit, ``WAVE4_SNIPPET_LINES`` long."""
  if not lines or not hit_indexes:
    return ""
  size = constants.WAVE4_SNIPPET_LINES
  start = max(0, hit_indexes[0] - size // 4)
  end = min(len(lines), start + size)
  return "\n".join(f"{start + i + 1}|{lines[start + i]}" for i in range(end - start))


def state_for(hit: Dict[str, object], app: Optional[dict]) -> Dict[str, object]:
  """The question state for one prefilter hit."""
  return {
      "app": app or {},
      "signal": {"file": hit["relpath"], "lines": hit["lines"], "tokens": hit["tokens"]},
      "code_snippet": hit["snippet"],
  }
