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

"""Offline, hermetic unit checks for the evaluator.

Run with ``python -m typesafe_eval selftest``. These exercise the deterministic
pieces (snippet extraction, templates, HTTP request-build/response-parse, and
answer composition through the heuristic client) without any network access.
"""

from __future__ import annotations

import os
import tempfile

from typesafe_eval import evaluate
from typesafe_eval import questions as q
from typesafe_eval import snippets
from typesafe_eval import templates
from typesafe_eval.client import HeuristicJevClient
from typesafe_eval.client import HttpJevClient


_FAILURES = []


def _check(name: str, condition: bool, detail: str = "") -> None:
  status = "PASS" if condition else "FAIL"
  print(f"[{status}] {name}{(' - ' + detail) if detail and not condition else ''}")
  if not condition:
    _FAILURES.append(name)


def _test_parse_finding() -> None:
  relpath, pattern = snippets.parse_finding(
      "app/src/main/java/A.kt (Pattern: FusedLocationProviderClient)"
  )
  _check(
      "parse_finding",
      relpath == "app/src/main/java/A.kt" and pattern == "FusedLocationProviderClient",
      f"{relpath!r},{pattern!r}",
  )


def _test_snippet_and_colocation() -> None:
  with tempfile.TemporaryDirectory() as d:
    rel = "src/Loc.kt"
    os.makedirs(os.path.join(d, "src"))
    with open(os.path.join(d, rel), "w", encoding="utf-8") as f:
      f.write(
          "import okhttp3.OkHttpClient\n"
          "fun report() {\n"
          "  val loc = FusedLocationProviderClient()\n"
          "  http.newCall(request).execute()\n"
          "}\n"
      )
    snip = snippets.extract_snippet(d, rel, "FusedLocationProviderClient", context=2)
    _check("snippet_line_found", snip["line"] == 3, str(snip["line"]))
    _check(
        "snippet_has_context",
        "OkHttpClient" in snip["snippet"] and "newCall" in snip["snippet"],
    )
    co = snippets.co_located_signals(d, rel)
    _check(
        "colocation_network",
        any("http" in s for s in co["network_transmission"]) or bool(co["network_transmission"]),
        str(co["network_transmission"]),
    )


def _test_templates() -> None:
  _check(
      "policy_name",
      templates.policy_name("location_access_policy") == "Location Permissions",
  )
  rec = templates.recommendation("location_access_policy", "CRITICAL")
  _check("recommendation_severity_aware", "disclosure" in rec.lower())
  summ = templates.issue_summary(
      "data_safety_section", "Precise location", "MISSING", True
  )
  _check("issue_summary_data_safety", "Precise location" in summ, summ)


def _test_http_payload_and_parse() -> None:
  client = HttpJevClient(api_key="test-key")
  payload = client.build_payload(
      {"x": 1}, {"is_urgent": {"type": "noul", "instructions": "?"}}, model="jev-1.13.0"
  )
  _check(
      "http_build_payload",
      payload["model"] == "jev-1.13.0" and "is_urgent" in payload["questions"],
  )
  parsed = HttpJevClient.parse_response({
      "model": "jev-1.13.0",
      "answers": {
          "n": {"type": "noul", "noul": 0.95},
          "c": {
              "type": "choice",
              "choice": "billing",
              "probabilities": {"billing": 0.9, "tech": 0.1},
              "confidence": 0.8,
          },
          "s": {
              "type": "score",
              "score": 1.05,
              "legend": {"0": "a", "1": "b"},
              "probabilities": {"0": 0.1, "1": 0.9},
              "confidence": 0.9,
          },
      },
  })
  _check("parse_noul", abs((parsed["n"].noul or 0) - 0.95) < 1e-9)
  _check("parse_choice", parsed["c"].choice == "billing" and parsed["c"].confidence == 0.8)
  _check("parse_score", abs((parsed["s"].score or 0) - 1.05) < 1e-9)


def _test_heuristic_battery() -> None:
  client = HeuristicJevClient()
  state = {
      "signal": {"data_type": "PRECISE_LOCATION", "matched_pattern": "Fused"},
      "code_snippet": "val loc = Fused(); http.newCall(r)",
      "co_located_signals": {"network_transmission": ["http.newCall"], "disclosure": []},
      "app": {"name": "ShopDeluxe", "store_category": "Shopping"},
  }
  answers = client.system_one(
      state, q.data_safety_battery("PRECISE_LOCATION", "precise location")
  )
  _check("heuristic_transmit_high", (answers["transmits_offdevice"].noul or 0) >= 0.6)
  _check("heuristic_disclosure_low", (answers["has_prominent_disclosure"].noul or 1) < 0.5)
  _check("heuristic_status_missing", answers["disclosure_status"].choice == "MISSING")
  _check("heuristic_severity_critical", (answers["severity"].score or 0) >= 1.5)


def _test_compose_end_to_end() -> None:
  """Full compose path through a temp app + heuristic client."""
  with tempfile.TemporaryDirectory() as d:
    rel = "app/src/main/java/Loc.kt"
    os.makedirs(os.path.join(d, "app/src/main/java"))
    with open(os.path.join(d, rel), "w", encoding="utf-8") as f:
      f.write(
          "import okhttp3.OkHttpClient\n"
          "fun report() {\n"
          "  val loc = FusedLocationProviderClient()\n"
          "  http.newCall(request).execute()\n"
          "}\n"
      )
    base_context = {
        "APP_DIR": d,
        "APP_NAME": "ShopDeluxe",
        "PACKAGE_NAME": "com.example.shopdeluxe",
        "TARGET_SDK": 35,
        "data_sources": {
            "PRECISE_LOCATION": [f"{rel} (Pattern: FusedLocationProviderClient)"]
        },
    }
    with tempfile.TemporaryDirectory() as temp_dir:
      worker = evaluate.evaluate_goal(
          "data_safety_part_1", base_context, d, temp_dir, HeuristicJevClient()
      )
    findings = worker["findings"]
    _check("compose_one_finding", len(findings) == 1, str(len(findings)))
    if findings:
      f0 = findings[0]
      _check("compose_transmitted", f0["is_transferred"] is True)
      _check("compose_policy", f0["policy_id"] == "prominent_disclosure_policy", f0["policy_id"])
      _check("compose_has_summary", bool(f0["issue_summary"]))
      _check("compose_logs_answers", "typesafe_answers" in f0)


def main() -> int:
  _test_parse_finding()
  _test_snippet_and_colocation()
  _test_templates()
  _test_http_payload_and_parse()
  _test_heuristic_battery()
  _test_compose_end_to_end()
  print()
  if _FAILURES:
    print(f"{len(_FAILURES)} check(s) FAILED: {', '.join(_FAILURES)}")
    return 1
  print("All selftest checks passed.")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
