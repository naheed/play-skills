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

"""The Data Safety data-type taxonomy, read from ``resources/policies.json``.

Every module that needs a type's category, display name or description goes
through :func:`load`; :func:`siblings` answers "which other types could this
signal really be?" for the ``data_type_confirmed`` Choice (WP10, lesson L7).

The taxonomy file is owned by the shared skill (read-only for the evaluator).
A missing or unreadable file yields an empty taxonomy: the evaluator then
composes with the scanner's raw type names and offers no sibling options,
which is the recall-safe degradation (nothing is dropped, nothing relabelled).
"""

from __future__ import annotations

import functools
import json
import logging
import os
from typing import Dict
from typing import List

from typesafe_eval import constants

log = logging.getLogger("typesafe_eval.taxonomy")


def _repo_root() -> str:
  """``play-policy-insights/`` (the parent of ``scripts/``)."""
  return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@functools.lru_cache(maxsize=1)
def load() -> Dict[str, dict]:
  """``{TYPE: {"category", "data_type", "description"}}`` from the shared policies file.

  Cached for the process; the file never changes during a run.
  """
  path = os.path.join(_repo_root(), "resources", "policies.json")
  try:
    with open(path, "r", encoding="utf-8") as f:
      data = json.load(f)
    tax = data.get("data_safety_section", {}).get("taxonomy", {})
    log.debug("taxonomy loaded from %s: %d types", path, len(tax))
    return tax
  except Exception as exc:  # pylint: disable=broad-exception-caught
    log.warning("taxonomy unavailable at %s (%s); composing with raw type names", path, exc)
    return {}


def category_of(data_type: str) -> str:
  return load().get(data_type, {}).get("category", "Other")


def display_name(data_type: str) -> str:
  return load().get(data_type, {}).get("data_type", data_type)


def description(data_type: str) -> str:
  return load().get(data_type, {}).get("description", "")


def siblings(data_type: str) -> Dict[str, str]:
  """Closed ``{TYPE: description}`` list of the types ``data_type`` is confused with (WP10).

  The documented cross-category confusions in
  ``constants.TYPE_CONFUSION_SIBLINGS`` come first (``USER_ACCOUNT`` offers
  ``DEVICE_ID``: they are the relabels the legacy adjudication actually made),
  then the other types of the same taxonomy category (``PHOTOS`` offers
  ``VIDEOS``, ``CRASH_LOGS`` offers ``PERFORMANCE_DIAGNOSTICS``), capped at
  ``MAX_TYPE_SIBLING_OPTIONS``. Only types that exist in the loaded taxonomy are
  offered, so a stale confusion entry can never relabel a finding to a type the
  report does not know. Empty for an unknown type or an unavailable taxonomy.
  """
  tax = load()
  if data_type not in tax:
    return {}
  category = tax[data_type].get("category")
  ordered: List[str] = [t for t in constants.TYPE_CONFUSION_SIBLINGS.get(data_type, ())
                        if t in tax and t != data_type]
  for t, v in tax.items():
    if v.get("category") == category and t != data_type and t not in ordered:
      ordered.append(t)
  ordered = ordered[: constants.MAX_TYPE_SIBLING_OPTIONS]
  return {t: f"{tax[t].get('data_type', t)}: {tax[t].get('description', '')}".strip(": ") for t in ordered}
