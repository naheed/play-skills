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

import json
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


def _test_batch_state_and_namespace() -> None:
  from typesafe_eval import batch
  with tempfile.TemporaryDirectory() as d:
    rel = "app/Loc.kt"
    os.makedirs(os.path.join(d, "app"))
    with open(os.path.join(d, rel), "w", encoding="utf-8") as f:
      f.write(
          "import okhttp3.OkHttpClient\n"
          "val loc = FusedLocationProviderClient()\n"
          "val lat = loc.latitude\n"
          "http.newCall(request).execute()\n"
          "val email_address = prefs.get(\"email\")\n"
      )
    asks = [
        batch.Ask("data_safety_part_1", "PRECISE_LOCATION",
                  None, f"{rel} (Pattern: FusedLocationProviderClient)", "loc"),
        batch.Ask("data_safety_part_1", "EMAIL",
                  None, f"{rel} (Pattern: email_address)", "email"),
    ]
    state, per_ask = batch.build_file_state(d, rel, asks, {"name": "X"})
    _check("batch_two_signals", len(state["signals"]) == 2, str(len(state["signals"])))
    _check("batch_snippet_has_both",
           "FusedLocationProviderClient" in state["code_snippet"]
           and "email_address" in state["code_snippet"])
    _check("batch_related_network", bool(state["related_lines"]))
    _check("batch_per_ask", len(per_ask) == 2)
    # Namespacing round-trips.
    ns = batch._namespace(1, {"transmits_offdevice": {"type": "noul"}})  # pylint: disable=protected-access
    _check("batch_namespace_key", "a1__transmits_offdevice" in ns)


def _write_scratch(d, scratch, data_sources):
  """Writes the minimal raw artifacts the engine reads."""
  os.makedirs(scratch, exist_ok=True)
  with open(os.path.join(scratch, "data_safety_scan.json"), "w", encoding="utf-8") as f:
    json.dump({"data_safety_scan": {"data_sources": data_sources}}, f)
  with open(os.path.join(scratch, "manifest_details.json"), "w", encoding="utf-8") as f:
    json.dump({"app_dir": d, "app_label": "Demo", "package_name": "com.x",
               "target_sdk": 35, "permissions": []}, f)
  with open(os.path.join(scratch, "play_store_info.json"), "w", encoding="utf-8") as f:
    json.dump({"category": "Shopping"}, f)


def _test_registry_and_plan() -> None:
  from typesafe_eval import registry
  from typesafe_eval import engine
  _check("registry_goals",
         set(["permissions_and_apis", "data_safety", "user_account"]).issubset(set(registry.goals())))
  tasks = engine.plan({"PRECISE_LOCATION": ["a.kt (Pattern: FusedLocationProviderClient)"]})
  policies = {t.spec.policy_id for t in tasks}
  _check("plan_multi_policy",
         "location_access_policy" in policies and "data_safety_section" in policies,
         str(policies))


def _test_engine_offline_and_robustness() -> None:
  import json as _json
  from typesafe_eval import engine
  from typesafe_eval.client import HeuristicJevClient, JevClient
  with tempfile.TemporaryDirectory() as d:
    rel = "app/Loc.kt"
    os.makedirs(os.path.join(d, "app"))
    with open(os.path.join(d, rel), "w", encoding="utf-8") as f:
      f.write("import okhttp3.OkHttpClient\n"
              "val loc = FusedLocationProviderClient()\n"
              "val lat = loc.latitude\n"
              "http.newCall(request).execute()\n")
    scratch = os.path.join(d, ".scratch")
    _write_scratch(d, scratch, {"PRECISE_LOCATION": [f"{rel} (Pattern: FusedLocationProviderClient)"]})

    engine.run(scratch, HeuristicJevClient(), batched=True)
    perms = _json.load(open(os.path.join(scratch, "worker_permissions_and_apis.json"), encoding="utf-8"))
    loc = [x for x in perms["findings"] if x["policy_id"] == "location_access_policy"]
    _check("engine_location_finding", len(loc) == 1 and loc[0]["severity"] == "CRITICAL")

    # Robustness: a client that always raises must not crash the scan.
    class _Failing(JevClient):
      name = "failing"
      def system_one(self, state, questions, model=None):
        raise RuntimeError("boom")
    engine.run(scratch, _Failing(), batched=True)
    perms = _json.load(open(os.path.join(scratch, "worker_permissions_and_apis.json"), encoding="utf-8"))
    errs = [x for x in perms["findings"] if x.get("client") == "error"]
    _check("engine_robust_error_finding",
           len(errs) >= 1 and errs[0].get("needs_manual_review") is True)


def _test_cache_roundtrip() -> None:
  from typesafe_eval.cache import ResultCache, CachingClient
  from typesafe_eval.client import JevAnswer, JevClient
  with tempfile.TemporaryDirectory() as d:
    class _Counting(JevClient):
      name = "counting"
      def __init__(self):
        super().__init__()
        self.calls = 0
      def system_one(self, state, questions, model=None):
        self.calls += 1
        return {"q": JevAnswer(type="noul", noul=0.9)}
    inner = _Counting()
    client = CachingClient(inner, ResultCache(os.path.join(d, "c.json")))
    q1 = {"q": {"type": "noul", "instructions": "?"}}
    a1 = client.system_one({"s": 1}, q1, model="m")
    a2 = client.system_one({"s": 1}, q1, model="m")
    _check("cache_serves_hit", inner.calls == 1 and (a2["q"].noul or 0) == 0.9,
           f"calls={inner.calls}")


def main() -> int:
  _test_parse_finding()
  _test_snippet_and_colocation()
  _test_templates()
  _test_http_payload_and_parse()
  _test_heuristic_battery()
  _test_compose_end_to_end()
  _test_batch_state_and_namespace()
  _test_registry_and_plan()
  _test_engine_offline_and_robustness()
  _test_cache_roundtrip()
  print()
  if _FAILURES:
    print(f"{len(_FAILURES)} check(s) FAILED: {', '.join(_FAILURES)}")
    return 1
  print("All selftest checks passed.")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
