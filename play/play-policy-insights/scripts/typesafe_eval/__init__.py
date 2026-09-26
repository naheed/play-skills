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

"""Hybrid TypeSafe (Jev) evaluator for play-policy-insights.

This package prototypes the "hybrid" architecture described in
``docs/typesafe-hybrid-architecture.md``: the deterministic Phase 1 triage
(``orchestrator.py init``) and the deterministic finalization
(``generate_report.py``) are kept as-is, while the *judgment* step of Phase 2 is
produced by asking TypeSafe's Jev model a fixed battery of typed questions and
composing the answers in code.

The package is intentionally dependency-free (standard library only) so it does
not change the offline, portable posture of the skill. The real Jev client talks
to the documented HTTP API with ``urllib``; an offline heuristic client is
provided for development and CI so the whole pipeline is runnable without a
network connection or an API key.
"""

from typesafe_eval.client import HeuristicJevClient
from typesafe_eval.client import HttpJevClient
from typesafe_eval.client import JevAnswer
from typesafe_eval.client import JevClient

__all__ = [
    "HeuristicJevClient",
    "HttpJevClient",
    "JevAnswer",
    "JevClient",
]
