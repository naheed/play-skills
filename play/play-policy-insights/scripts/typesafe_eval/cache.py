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

"""A content-addressed result cache for Jev calls.

Jev has no server-side cache, so re-scanning the same commit (or iterating on the
eval set) re-pays for identical requests. This wraps any :class:`JevClient` and
memoizes answers keyed by ``sha256(model + questions + state)`` in a JSON file,
mirroring the ``JsonCache`` the TypeSafe cookbooks ship. A cache hit makes a
re-run free and byte-reproducible; a miss calls through and records the result.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any
from typing import Dict
from typing import Optional

from typesafe_eval.client import JevAnswer
from typesafe_eval.client import JevClient


def _key(model: Optional[str], state: Any, questions: Dict[str, Any]) -> str:
  payload = json.dumps(
      {"model": model, "state": state, "questions": questions},
      sort_keys=True,
      ensure_ascii=False,
  )
  return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ResultCache:
  """A JSON-file cache of serialized answers, keyed by request content."""

  def __init__(self, path: str) -> None:
    self.path = path
    self._data: Dict[str, Dict[str, Any]] = {}
    if os.path.exists(path):
      try:
        with open(path, "r", encoding="utf-8") as f:
          self._data = json.load(f)
      except Exception:  # pylint: disable=broad-exception-caught
        self._data = {}
    self.hits = 0
    self.misses = 0

  def get(self, key: str) -> Optional[Dict[str, JevAnswer]]:
    entry = self._data.get(key)
    if entry is None:
      return None
    return {qid: JevAnswer.from_dict(ans) for qid, ans in entry.items()}

  def put(self, key: str, answers: Dict[str, JevAnswer]) -> None:
    self._data[key] = {qid: ans.to_dict() for qid, ans in answers.items()}

  def save(self) -> None:
    tmp = self.path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
      json.dump(self._data, f, sort_keys=True)
    os.replace(tmp, self.path)


class CachingClient(JevClient):
  """Wraps a client, serving cached answers when the request content matches."""

  def __init__(self, inner: JevClient, cache: ResultCache) -> None:
    super().__init__()
    self.inner = inner
    self.cache = cache
    self.name = f"{inner.name}+cache"

  def system_one(
      self,
      state: Any,
      questions: Dict[str, Dict[str, Any]],
      model: Optional[str] = None,
  ) -> Dict[str, JevAnswer]:
    key = _key(model, state, questions)
    hit = self.cache.get(key)
    if hit is not None:
      self.cache.hits += 1
      return hit
    self.cache.misses += 1
    answers = self.inner.system_one(state, questions, model=model)
    # Mirror the inner client's usage counters so benchmarks stay accurate.
    self.request_count = self.inner.request_count
    self.total_input_tokens = self.inner.total_input_tokens
    self.total_output_tokens = self.inner.total_output_tokens
    self.cache.put(key, answers)
    self.cache.save()
    return answers

  def reset_usage(self) -> None:
    super().reset_usage()
    self.inner.reset_usage()
