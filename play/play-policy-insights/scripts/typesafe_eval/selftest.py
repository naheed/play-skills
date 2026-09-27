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
pieces (structure extraction, capability cache, context building, triage
ranking, three-way decision composition, critic routing, manifest checks,
templates, HTTP request-build/response-parse, and answer composition through
the heuristic client) without any network access.

Fixtures below name real library packages (e.g. an HTTP client) on purpose:
they are *test inputs* that the semantic layer must classify without a lookup
table. The identifier lint (:func:`_test_identifier_lint`) enforces that no
such name appears in the evaluator's own logic.
"""

from __future__ import annotations

import json
import os
import re
import tempfile

from typesafe_eval import evaluate
from typesafe_eval import questions as q
from typesafe_eval import snippets
from typesafe_eval import templates
from typesafe_eval.client import HeuristicJevClient
from typesafe_eval.client import HttpJevClient


_FAILURES = []

# A Kotlin file where the location value flows into a referenced network sink.
_KT_LOCATION_SINK = (
    "import okhttp3.OkHttpClient\n"
    "import okhttp3.Request\n"
    "fun report() {\n"
    "  val http = OkHttpClient()\n"
    "  val loc = FusedLocationProviderClient()\n"
    "  val lat = loc.latitude\n"
    "  http.newCall(Request.Builder().url(\"https://x/\" + lat).build()).execute()\n"
    "}\n"
)


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


def _write_scratch(d, scratch, data_sources, play_store_info=None):
  """Writes the minimal raw artifacts the engine reads."""
  os.makedirs(scratch, exist_ok=True)
  with open(os.path.join(scratch, "data_safety_scan.json"), "w", encoding="utf-8") as f:
    json.dump({"data_safety_scan": {"data_sources": data_sources}}, f)
  with open(os.path.join(scratch, "manifest_details.json"), "w", encoding="utf-8") as f:
    json.dump({"app_dir": d, "app_label": "Demo", "package_name": "com.x",
               "target_sdk": 35, "permissions": []}, f)
  with open(os.path.join(scratch, "play_store_info.json"), "w", encoding="utf-8") as f:
    json.dump(play_store_info or {"category": "Shopping"}, f)


def _test_play_declaration() -> None:
  from typesafe_eval import engine
  from typesafe_eval.client import HeuristicJevClient
  with tempfile.TemporaryDirectory() as d:
    rel = "app/Loc.kt"
    os.makedirs(os.path.join(d, "app"))
    with open(os.path.join(d, rel), "w", encoding="utf-8") as f:
      f.write(_KT_LOCATION_SINK)
    scratch = os.path.join(d, ".scratch")
    # Declaration discloses Email only, not Precise location.
    decl = {
        "category": "Shopping", "is_published": True,
        "data_safety": {"data_collected": [
            {"category": "Personal info", "types": [{"type": "Email address"}]}]},
    }
    _write_scratch(d, scratch,
                   {"PRECISE_LOCATION": [f"{rel} (Pattern: FusedLocationProviderClient)"]},
                   play_store_info=decl)
    engine.run(scratch, HeuristicJevClient(), batched=True)
    ds = json.load(open(os.path.join(scratch, "worker_data_safety.json"), encoding="utf-8"))
    mismatches = [x for x in ds["findings"] if x.get("kind") == "play_declaration"]
    _check("play_declaration_flags_undeclared",
           any(x.get("psl_constant") == "PRECISE_LOCATION" for x in mismatches),
           str([x.get("psl_constant") for x in mismatches]))


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
      f.write(_KT_LOCATION_SINK)
    scratch = os.path.join(d, ".scratch")
    _write_scratch(d, scratch, {"PRECISE_LOCATION": [f"{rel} (Pattern: FusedLocationProviderClient)"]})

    engine.run(scratch, HeuristicJevClient(), batched=True)
    perms = _json.load(open(os.path.join(scratch, "worker_permissions_and_apis.json"), encoding="utf-8"))
    loc = [x for x in perms["findings"] if x["policy_id"] == "location_access_policy"]
    _check("engine_location_finding", len(loc) == 1 and loc[0]["severity"] == "CRITICAL",
           str([(x["policy_id"], x["severity"]) for x in perms["findings"]]))
    ds = _json.load(open(os.path.join(scratch, "worker_data_safety.json"), encoding="utf-8"))
    loc_ds = [x for x in ds["findings"] if x.get("psl_constant") == "PRECISE_LOCATION"
              and x.get("kind") != "play_declaration"]
    _check("engine_ds_transmits",
           len(loc_ds) == 1 and loc_ds[0]["transfer_decision"] == "TRANSMITS"
           and loc_ds[0]["is_transferred"] is True,
           str([(x.get("transfer_decision"), x.get("is_transferred")) for x in loc_ds]))
    if loc_ds:
      trace = loc_ds[0].get("decision_trace") or {}
      _check("engine_ds_trace", trace.get("evaluator_version") and trace.get("sinks")
             and trace["anchor"].get("sink_in_scope") is True, str(trace.get("anchor")))
      _check("engine_ds_sink_labelled",
             any("NETWORK_EGRESS" in (s.get("capabilities") or []) for s in loc_ds[0]["sinks"]),
             str(loc_ds[0]["sinks"]))
    triage = _json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    _check("engine_triage_written",
           triage.get("counters", {}).get("kept") == 1 and "capabilities" in triage,
           str(triage.get("counters")))

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


def _test_reduce_noise() -> None:
  from typesafe_eval import engine
  from typesafe_eval import constants
  # Global cap per type and per-file cap (2); Play flavor prioritized.
  ds = {
      "NAME": [f"app/src/main/A{i}.kt (Pattern: name)" for i in range(constants.MAX_FINDINGS_PER_TYPE + 2)],
      "EMAIL": ["app/src/main/B.kt (Pattern: e)", "app/src/main/B.kt (Pattern: e)",
                "app/src/main/B.kt (Pattern: e)"],  # same file x3 -> capped to 2
      # A non-prioritized product flavor should be excluded in favor of "play".
      "AUDIO": ["app/src/nonplay/C.kt (Pattern: record)",
                "app/src/play/D.kt (Pattern: MediaRecorder)"],
      "ACCOUNT_DELETION": ["app/src/main/res/values-xx/strings.xml (Pattern: deactivate)"],
  }
  reduced = engine._reduce_noise(ds)
  _check("reduce_type_cap", len(reduced["NAME"]) == constants.MAX_FINDINGS_PER_TYPE, str(len(reduced["NAME"])))
  _check("reduce_per_file_cap", len(reduced["EMAIL"]) == 2, str(len(reduced["EMAIL"])))
  _check("reduce_flavor_excludes_nonplay",
         reduced["AUDIO"] == ["app/src/play/D.kt (Pattern: MediaRecorder)"],
         str(reduced["AUDIO"]))
  _check("reduce_excludes_values_strings", "ACCOUNT_DELETION" not in reduced,
         str(reduced.get("ACCOUNT_DELETION")))


def _test_account_deletion_gate() -> None:
  from typesafe_eval import engine
  from typesafe_eval.client import HeuristicJevClient
  with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "app"))
    # A generic "deactivate" match (proxy toggle) should be gated out; a real
    # deleteAccount should pass.
    with open(os.path.join(d, "app/Rpn.kt"), "w", encoding="utf-8") as f:
      f.write("fun deactivateRpn() { proxy.deactivate() }\n")
    with open(os.path.join(d, "app/Acct.kt"), "w", encoding="utf-8") as f:
      f.write("fun deleteAccount() { api.deleteAccount(userId) }\n")
    scratch = os.path.join(d, ".scratch")
    _write_scratch(d, scratch, {"ACCOUNT_DELETION": [
        "app/Rpn.kt (Pattern: deactivate)",
        "app/Acct.kt (Pattern: deleteAccount)",
    ]})
    engine.run(scratch, HeuristicJevClient(), batched=True)
    ua = json.load(open(os.path.join(scratch, "worker_user_account.json"), encoding="utf-8"))
    files = [(x.get("files_involved") or [""])[0] for x in ua["findings"]]
    _check("gate_keeps_real_deletion", any("Acct.kt" in f for f in files), str(files))
    _check("gate_drops_deactivate_fp", not any("Rpn.kt" in f for f in files), str(files))


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


def _test_structure_layer() -> None:
  from typesafe_eval import structure
  with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "gradle"))
    os.makedirs(os.path.join(d, "app"))
    with open(os.path.join(d, "app", "build.gradle.kts"), "w", encoding="utf-8") as f:
      f.write('dependencies {\n  implementation("com.example.net:client:1.2")\n'
              '  implementation(libs.analytics)\n  testImplementation("junit:junit:4.13")\n}\n')
    with open(os.path.join(d, "gradle", "libs.toml"), "w", encoding="utf-8") as f:
      f.write('[libraries]\nanalytics = { module = "com.vendor.sdk:analytics", version = "1" }\n'
              'ui = { group = "org.ui", name = "widgets", version.ref = "v" }\n')
    with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as f:
      f.write('{"dependencies": {"@scope/net": "^1", "left-pad": "1.0"}}\n')
    deps = {(x.ecosystem, x.coordinate) for x in structure.dependency_inventory(d)}
    _check("deps_gradle", ("maven", "com.example.net:client") in deps, str(deps))
    _check("deps_toml_module", ("maven", "com.vendor.sdk:analytics") in deps)
    _check("deps_toml_group_name", ("maven", "org.ui:widgets") in deps)
    _check("deps_npm_scoped", ("npm", "@scope/net") in deps)

  kt = ("package a.b\n"
        "import java.net.Socket\n"
        "import android.util.Log\n"
        "// Socket is used below\n"
        "class C {\n"
        "  fun send(x: String) {\n"
        "    val s = Socket(host, 21)\n"
        "    s.getOutputStream().write(x.toByteArray())\n"
        "  }\n"
        "  fun log(x: String) { Log.d(TAG, x) }\n"
        "}\n")
  lines = kt.splitlines()
  imports = structure.import_inventory(kt, "kotlin")
  _check("imports_kotlin", imports == ["java.net.Socket", "android.util.Log"], str(imports))
  refs = structure.symbol_references(lines, imports)
  _check("refs_skip_import_line", refs.get("java.net.Socket") == [6], str(refs))
  hits = structure.all_occurrences(lines, "Socket")
  _check("occurrences_demote_comment", hits == [6], str(hits))
  scope = structure.enclosing_scope(lines, 6, "kotlin")
  _check("enclosing_scope_method", scope == (5, 9), str(scope))
  # Control-flow headers end in ") {" like declarations but must not clip the
  # scope: a hit inside switch/if/for resolves to the enclosing function so a
  # sink called after the block is still "in scope" (WP2 recall fix).
  java_ctrl = (
      "class P {\n"                                   # 0
      "  public void onClick(int which) {\n"          # 1
      "    String mime;\n"                            # 2
      "    switch( which ) {\n"                       # 3
      "      case 1: mime = \"video/*\"; break;\n"    # 4
      "      default: mime = \"*/*\";\n"              # 5
      "    }\n"                                       # 6
      "    if (mime != null) {\n"                     # 7
      "      intent.setType(mime);\n"                 # 8
      "    }\n"                                       # 9
      "    startActivity(intent);\n"                  # 10
      "  }\n"                                         # 11
      "}\n")
  cl = java_ctrl.splitlines()
  _check("scope_skips_switch_header", structure.enclosing_scope(cl, 4, "java") == (1, 12),
         str(structure.enclosing_scope(cl, 4, "java")))
  _check("scope_skips_if_header", structure.enclosing_scope(cl, 8, "java") == (1, 12),
         str(structure.enclosing_scope(cl, 8, "java")))
  kt_ctrl = (
      "class Q {\n"                                   # 0
      "  fun pick(which: Int) {\n"                    # 1
      "    val mime = when (which) {\n"               # 2
      "      1 -> \"video/*\"\n"                      # 3
      "      else -> \"*/*\"\n"                       # 4
      "    }\n"                                       # 5
      "    for (i in 0 until 3) {\n"                  # 6
      "      Log.d(TAG, mime)\n"                      # 7
      "    }\n"                                       # 8
      "    startActivity(intent)\n"                   # 9
      "  }\n"                                         # 10
      "}\n")
  kl = kt_ctrl.splitlines()
  _check("scope_skips_when_header", structure.enclosing_scope(kl, 3, "kotlin") == (1, 11),
         str(structure.enclosing_scope(kl, 3, "kotlin")))
  _check("scope_skips_for_header", structure.enclosing_scope(kl, 7, "kotlin") == (1, 11),
         str(structure.enclosing_scope(kl, 7, "kotlin")))
  _check("decl_header_classifier",
         structure.is_declaration_header("  public void onClick(int w) {")
         and structure.is_declaration_header("  fun send(x: String) {")
         and structure.is_declaration_header("  } else if (x) {") is False
         and not structure.is_declaration_header("    switch( which ) {")
         and not structure.is_declaration_header("    while (running) {")
         and not structure.is_declaration_header("    val m = when (which) {")
         and not structure.is_declaration_header("    return if (ok) {")
         and not structure.is_declaration_header("    } catch (Exception e) {"))
  _check("package_of_dotted", structure.package_of("java.net.Socket") == "java.net")
  _check("wildcard_import_kept", structure.import_inventory("import java.net.*;\n", "java") == ["java.net.*"]
         and structure.package_of("java.net.*") == "java.net")
  _check("declared_package", structure.declared_package(kt) == "a.b")
  from typesafe_eval import engine
  fp = engine._first_party_packages({"package_name": "wrong.lib"},  # pylint: disable=protected-access
                                    {"x": structure.FileStructure("x", "kotlin", [], [], {}, "com.app.ui")})
  _check("first_party_from_declared_package",
         engine._is_first_party("com.app.ui.Foo", fp) and engine._is_first_party("com.app.ui.sub.Bar", fp)  # pylint: disable=protected-access
         and not engine._is_first_party("com.other.Foo", fp) and engine._is_first_party("wrong.lib.X", fp))  # pylint: disable=protected-access
  _check("package_of_dart", structure.package_of("package:http/http.dart") == "package:http")
  _check("package_of_npm_scoped", structure.package_of("@scope/pkg/sub") == "@scope/pkg")
  _check("package_of_dart_core", structure.package_of("dart:io") == "dart:io")
  dart = "import 'package:http/http.dart' as http;\nimport 'dart:io';\n"
  _check("imports_dart", structure.import_inventory(dart, "dart") == ["package:http/http.dart", "dart:io"])
  js = "import axios from 'axios';\nconst fs = require('fs');\nimport './local';\n"
  _check("imports_js_skips_relative", structure.import_inventory(js, "javascript") == ["axios", "fs"],
         str(structure.import_inventory(js, "javascript")))


def _test_capabilities_layer() -> None:
  from typesafe_eval import capabilities as caps
  from typesafe_eval import constants
  # Threshold -> labels, including the UNKNOWN indecision band.
  _check("labels_confident", caps.labels_from_probabilities({"NETWORK_EGRESS": 0.9}) == ["NETWORK_EGRESS"])
  _check("labels_unknown_band",
         caps.labels_from_probabilities({"NETWORK_EGRESS": 0.5, "LOGGING": 0.1}) == ["UNKNOWN"])
  _check("labels_confident_negative", caps.labels_from_probabilities({"NETWORK_EGRESS": 0.1}) == [])
  _check("unknown_is_sink",
         caps.CapabilityProfile("x", "import", {}, ["UNKNOWN"], "model", None).is_transfer_sink)
  _check("ipc_is_sharing", "IPC_SHARING" in caps.SHARING_CAPABILITIES
         and "IPC_SHARING" in caps.TRANSFER_CAPABILITIES)
  # Definitions must not name products: crude check that they are behavioural.
  _check("definitions_behavioural",
         all(len(v) > 40 and v[0].isupper() for v in caps.CAPABILITIES.values()))

  with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "caps.json")
    cache = caps.CapabilityCache(path)
    client = HeuristicJevClient()
    symbols = [{"identifier": "java.net.Socket", "kind": "import"},
               {"identifier": "java.util.List", "kind": "import"}]
    profiles = caps.classify(symbols, client, cache, {"package": "a.b"}, model="m")
    _check("classify_network", "NETWORK_EGRESS" in profiles["java.net.Socket"].labels,
           str(profiles["java.net.Socket"].labels))
    _check("classify_not_sink", not profiles["java.util.List"].is_transfer_sink,
           str(profiles["java.util.List"].labels))
    _check("classify_source_tagged", profiles["java.net.Socket"].source == "heuristic")
    calls = client.request_count
    cache2 = caps.CapabilityCache(path)
    caps.classify(symbols, client, cache2, {"package": "a.b"}, model="m")
    _check("cache_hit_no_call", client.request_count == calls and cache2.hits == 2,
           f"calls={client.request_count} hits={cache2.hits}")
    # A human entry wins over the model and survives a model re-answer.
    human = caps.CapabilityProfile("java.util.List", "import", {"IPC_SHARING": 1.0},
                                   ["IPC_SHARING"], "human", None)
    cache2.put(human)
    cache2.save()
    cache3 = caps.CapabilityCache(path)
    got = caps.classify(symbols, client, cache3, {"package": "a.b"}, model="m")
    _check("human_override_wins", got["java.util.List"].labels == ["IPC_SHARING"]
           and got["java.util.List"].source == "human")
    # Different taxonomy/model key -> re-asked, never silently reused.
    _check("cache_key_model_scoped", caps.CapabilityCache.key("x", "m1") != caps.CapabilityCache.key("x", "m2"))
    _check("t_capability_between", 0 < constants.T_CAPABILITY_UNKNOWN_LOW < constants.T_CAPABILITY <= 1)


def _test_context_anchor() -> None:
  from typesafe_eval import capabilities as caps
  from typesafe_eval import context
  from typesafe_eval import structure
  src = ("import java.net.Socket\n"
         "import java.util.Locale\n"
         "// getLastKnownLocation is documented here (comment, must not anchor)\n"
         "class A {\n"
         "  fun show() {\n"
         "    val l = getLastKnownLocation()\n"
         "    textView.text = l.toString()\n"
         "  }\n"
         "  fun upload() {\n"
         "    val l = getLastKnownLocation()\n"
         "    Socket(h, 80).getOutputStream().write(l.toString().toByteArray())\n"
         "  }\n"
         "}\n")
  with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "A.kt"), "w", encoding="utf-8") as f:
      f.write(src)
    fs = structure.analyze_file(d, "A.kt")
  profiles = {
      "java.net.Socket": caps.CapabilityProfile("java.net.Socket", "import", {"NETWORK_EGRESS": 0.95},
                                                ["NETWORK_EGRESS"], "model", "m"),
      "java.util.Locale": caps.CapabilityProfile("java.util.Locale", "import", {}, [], "model", "m"),
  }
  sinks = context.file_sinks(fs, profiles)
  _check("sinks_only_transfer", [s.symbol for s in sinks] == ["Socket"], str(sinks))
  anchor = context.anchor_signal(fs, "getLastKnownLocation", "PRECISE_LOCATION", sinks)
  _check("anchor_all_occurrences", anchor.hit_lines == [5, 9], str(anchor.hit_lines))
  _check("anchor_prefers_sink_scope", anchor.chosen == 9 and anchor.sink_in_scope, str(anchor))
  state, per = context.build_file_state(fs, [("PRECISE_LOCATION", "getLastKnownLocation")], profiles, {"name": "X"})
  _check("state_sinks_labelled", state["sinks"][0]["capabilities"] == ["NETWORK_EGRESS"])
  _check("state_snippet_is_upload_scope",
         "fun upload" in state["code_snippet"] and "fun show" not in state["code_snippet"],
         state["code_snippet"][:200])
  _check("per_ask_anchor", per[0]["anchor"]["sink_in_scope"] is True and per[0]["signal"]["line"] == 10)
  # Unreferenced (wildcard) transfer import is still a file-level sink.
  fs2 = structure.FileStructure("B.kt", "kotlin", ["import java.net.*", "val x = 1"], ["java.net"], {})
  p2 = {"java.net": caps.CapabilityProfile("java.net", "package", {"NETWORK_EGRESS": 0.9}, ["NETWORK_EGRESS"], "model", "m")}
  _check("file_level_sink_without_refs", [s.lines for s in context.file_sinks(fs2, p2)] == [[]])
  # Ranking: sink tier first (explicit egress > IPC > UNKNOWN > none), then
  # proximity, then scanner order.
  a_net = context.Anchor("T", "p", [1], 1, (0, 3), 0, True, ["NETWORK_EGRESS"])
  a_ipc = context.Anchor("T", "p", [1], 1, (0, 3), 0, True, ["IPC_SHARING"])
  a_unk = context.Anchor("T", "p", [1], 1, (0, 3), 0, True, ["UNKNOWN"])
  a_near = context.Anchor("T", "p", [1], 1, (0, 3), 4, False, [])
  a_far = context.Anchor("T", "p", [1], 1, (0, 3), None, False, [])
  ranked = sorted([(a_far, 0), (a_near, 1), (a_unk, 2), (a_ipc, 3), (a_net, 4)],
                  key=lambda t: context.rank_key(*t))
  _check("rank_key_order", [r[1] for r in ranked] == [4, 3, 2, 1, 0], str([r[1] for r in ranked]))
  _check("anchor_scope_caps_recorded", anchor.scope_capabilities == ["NETWORK_EGRESS"] and anchor.tier == 0)
  # Within one file, an occurrence next to an explicit egress sink beats one
  # next to an IPC sink even when both are "in scope".
  src2 = ("import java.net.Socket\nimport android.content.Intent\n"
          "fun share() {\n  val e = email()\n  startActivity(Intent().putExtra(\"e\", e))\n}\n"
          "fun upload() {\n  val e = email()\n  Socket(h, 1).getOutputStream().write(e)\n}\n")
  fs3 = structure.FileStructure("C.kt", "kotlin", src2.splitlines(),
                                ["java.net.Socket", "android.content.Intent"],
                                structure.symbol_references(src2.splitlines(), ["java.net.Socket", "android.content.Intent"]))
  p3 = dict(profiles)
  p3["android.content.Intent"] = caps.CapabilityProfile("android.content.Intent", "import", {"IPC_SHARING": 0.9}, ["IPC_SHARING"], "model", "m")
  a3 = context.anchor_signal(fs3, "email()", "EMAIL", context.file_sinks(fs3, p3))
  _check("anchor_prefers_egress_tier", a3.chosen == 7 and a3.tier == 0, str(a3))


def _test_three_way_decision() -> None:
  from typesafe_eval import constants
  from typesafe_eval.client import JevAnswer
  _check("decision_transmits", evaluate.transfer_decision(constants.T_TRANSMIT_HIGH) == "TRANSMITS")
  _check("decision_local", evaluate.transfer_decision(constants.T_TRANSMIT_LOW - 0.01) == "LOCAL")
  mid = (constants.T_TRANSMIT_LOW + constants.T_TRANSMIT_HIGH) / 2
  _check("decision_uncertain", evaluate.transfer_decision(mid) == "UNCERTAIN")

  def _answers(p_transmit, relevant=0.9):
    return {
        "signal_relevant": JevAnswer("noul", noul=relevant),
        "transmits_offdevice": JevAnswer("noul", noul=p_transmit),
        "user_initiated": JevAnswer("noul", noul=0.2),
        "is_third_party": JevAnswer("noul", noul=0.2),
        "has_prominent_disclosure": JevAnswer("noul", noul=0.1),
        "disclosure_status": JevAnswer("choice", choice="MISSING"),
        "severity": JevAnswer("score", score=1.0),
    }
  state = {
      "signal": {"data_type": "PRECISE_LOCATION", "matched_pattern": "loc", "file": "A.kt",
                 "line": 10, "matched_line": "val l = loc()", "all_lines": [3, 10]},
      "code_snippet": "L10: val l = loc()",
      "sinks": [{"symbol": "Intent", "capabilities": ["IPC_SHARING"], "lines": [11]}],
      "anchor": {"scope": [9, 12], "proximity": 0, "sink_in_scope": True},
      "app": {},
  }
  unc = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", state, _answers(mid), "test")  # pylint: disable=protected-access
  _check("uncertain_is_transferred_true", unc["is_transferred"] is True and unc["transfer_decision"] == "UNCERTAIN")
  _check("uncertain_severity_important", unc["severity"] == "IMPORTANT", unc["severity"])
  _check("uncertain_needs_review", unc.get("needs_manual_review") is True)
  _check("uncertain_summary_marked", "uncertain" in unc["issue_summary"].lower())
  _check("ipc_in_scope_is_sharing", unc["is_third_party"] is True, str(unc["decision_trace"].get("sharing_sinks_in_scope")))
  _check("trace_has_thresholds",
         unc["decision_trace"]["thresholds"]["T_TRANSMIT_HIGH"] == constants.T_TRANSMIT_HIGH
         and "provenance" in unc["decision_trace"]["thresholds"])
  loc = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", state, _answers(0.1), "test")  # pylint: disable=protected-access
  _check("local_exempt_suggestion", loc["is_transferred"] is False
         and loc["prominent_disclosure_status"] == "EXEMPT" and loc["severity"] == "SUGGESTION")
  tx = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", state, _answers(0.95), "test")  # pylint: disable=protected-access
  _check("transmits_critical", tx["severity"] == "CRITICAL" and tx["claim_kind"] == "transfer")
  gated = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", state, _answers(0.95, relevant=0.1), "test")  # pylint: disable=protected-access
  _check("relevance_gate_drops", gated is None)
  # WP2 soft gate: a low relevance answer cannot suppress a finding whose anchor
  # scope holds an egress/IPC sink; it is kept for review and capped at IMPORTANT.
  sink_state = {**state, "anchor": {**state["anchor"], "tier": 1}}
  uncertain_rel = (constants.T_RELEVANCE_FLOOR + constants.T_RELEVANCE) / 2  # inside the soft band
  soft = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", sink_state, _answers(0.95, relevant=uncertain_rel), "test")  # pylint: disable=protected-access
  _check("relevance_soft_gate_keeps_with_sink",
         soft is not None and soft.get("needs_manual_review") is True and soft["severity"] == "IMPORTANT"
         and soft["decision_trace"].get("relevance") == "low" and "match uncertain" in soft["issue_summary"],
         str(soft and (soft["severity"], soft["issue_summary"])))
  no_sink_state = {**state, "anchor": {**state["anchor"], "tier": 3}}
  _check("relevance_soft_gate_drops_without_sink",
         evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", no_sink_state, _answers(0.95, relevant=uncertain_rel), "test") is None)  # pylint: disable=protected-access
  # WP4 second condition: tier 3 anchor but the *file* references a strong egress
  # sink -> kept for review, traced distinctly. IPC-only or UNKNOWN file sinks do
  # not qualify (the tier-3 state above has only an Intent sink and is dropped).
  egress_file_state = {**no_sink_state, "sinks": [
      {"symbol": "Intent", "capabilities": ["IPC_SHARING"], "lines": [150]},
      {"symbol": "HttpClient", "capabilities": ["NETWORK_EGRESS"], "lines": [200]}]}
  fe = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", egress_file_state, _answers(0.95, relevant=uncertain_rel), "test")  # pylint: disable=protected-access
  _check("relevance_soft_gate_file_egress_keeps",
         fe is not None and fe.get("needs_manual_review") is True and fe["severity"] == "IMPORTANT"
         and fe["decision_trace"].get("relevance") == "low_file_egress" and "(out of scope)" in fe["evidence"],
         str(fe and (fe["severity"], fe["decision_trace"].get("relevance"), fe["evidence"])))
  unknown_file_state = {**no_sink_state, "sinks": [{"symbol": "Foo", "capabilities": ["UNKNOWN"], "lines": [200]}]}
  _check("relevance_soft_gate_file_unknown_drops",
         evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", unknown_file_state, _answers(0.95, relevant=uncertain_rel), "test") is None)  # pylint: disable=protected-access
  _check("relevance_soft_gate_file_egress_floor",
         evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", egress_file_state, _answers(0.95, relevant=constants.T_RELEVANCE_FLOOR / 2), "test") is None)  # pylint: disable=protected-access
  constants.RELEVANCE_SOFT_GATE_FILE_EGRESS = False
  try:
    _check("relevance_soft_gate_file_egress_flag_off",
           evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", egress_file_state, _answers(0.95, relevant=uncertain_rel), "test") is None)  # pylint: disable=protected-access
  finally:
    constants.RELEVANCE_SOFT_GATE_FILE_EGRESS = True
  perm_fe = evaluate._compose_permission_finding("PRECISE_LOCATION", "location_access_policy", egress_file_state, {  # pylint: disable=protected-access
      **_answers(0.95, relevant=uncertain_rel), "is_core_functionality": JevAnswer("noul", noul=0.1)}, "test")
  _check("relevance_soft_gate_file_egress_permission", perm_fe is not None and perm_fe.get("needs_manual_review") is True
         and perm_fe["decision_trace"].get("relevance") == "low_file_egress", str(perm_fe and perm_fe["decision_trace"].get("relevance")))
  # A confidently negative relevance answer (below the floor) is dropped even
  # with a sink in scope: the soft band is for uncertain matches only.
  _check("relevance_soft_gate_floor_drops_confident_negative",
         evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", sink_state,
                                               _answers(0.95, relevant=constants.T_RELEVANCE_FLOOR / 2), "test") is None)  # pylint: disable=protected-access
  _check("relevance_soft_gate_floor_inclusive",
         evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", sink_state,
                                               _answers(0.95, relevant=constants.T_RELEVANCE_FLOOR), "test") is not None)  # pylint: disable=protected-access
  _check("relevance_floor_traced",
         soft is not None and soft["decision_trace"]["thresholds"].get("T_RELEVANCE_FLOOR") == constants.T_RELEVANCE_FLOOR)
  constants.RELEVANCE_SOFT_GATE_ENABLED = False
  try:
    _check("relevance_soft_gate_flag_off",
           evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", sink_state, _answers(0.95, relevant=uncertain_rel), "test") is None)  # pylint: disable=protected-access
  finally:
    constants.RELEVANCE_SOFT_GATE_ENABLED = True
  perm_soft = evaluate._compose_permission_finding("PRECISE_LOCATION", "location_access_policy", sink_state, {  # pylint: disable=protected-access
      **_answers(0.95, relevant=uncertain_rel), "is_core_functionality": JevAnswer("noul", noul=0.1)}, "test")
  _check("relevance_soft_gate_permission", perm_soft is not None and perm_soft.get("needs_manual_review") is True
         and perm_soft["severity"] == "IMPORTANT", str(perm_soft and perm_soft["severity"]))
  perm = evaluate._compose_permission_finding("PRECISE_LOCATION", "location_access_policy", state, {  # pylint: disable=protected-access
      **_answers(mid), "is_core_functionality": JevAnswer("noul", noul=0.1)}, "test")
  _check("permission_uncertain_review", perm is not None and perm.get("needs_manual_review") is True
         and perm["claim_kind"] == "generic", str(perm and perm.get("severity")))
  # WP2: the disclosure Choice is cross-checked against the battery's own Noul.
  # DISCLOSED with P(disclosure) below T_DISCLOSURE falls back to MISSING and
  # keeps the prominent-disclosure routing + severity; a consistent DISCLOSED
  # (high Noul) is honoured; EXEMPT on a non-user-initiated transfer is MISSING.
  contradict = {**_answers(0.95), "disclosure_status": JevAnswer("choice", choice="DISCLOSED"),
                "has_prominent_disclosure": JevAnswer("noul", noul=0.18)}
  rec = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", state, contradict, "test")  # pylint: disable=protected-access
  _check("disclosure_reconciled_to_missing",
         rec["prominent_disclosure_status"] == "MISSING" and rec["policy_id"] == "prominent_disclosure_policy"
         and rec["severity"] == "CRITICAL" and rec.get("needs_manual_review") is True
         and "DISCLOSED->MISSING" in (rec["decision_trace"].get("disclosure_reconciled") or ""),
         str((rec["prominent_disclosure_status"], rec["policy_id"], rec["severity"])))
  consistent = {**contradict, "has_prominent_disclosure": JevAnswer("noul", noul=0.85)}
  ok = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", state, consistent, "test")  # pylint: disable=protected-access
  _check("disclosure_consistent_kept",
         ok["prominent_disclosure_status"] == "DISCLOSED" and ok["policy_id"] == "data_safety_section"
         and ok["decision_trace"].get("disclosure_reconciled") is None and not ok.get("needs_manual_review"),
         str((ok["prominent_disclosure_status"], ok["policy_id"])))
  exempt_bg = {**_answers(0.95), "disclosure_status": JevAnswer("choice", choice="EXEMPT")}
  bg = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", state, exempt_bg, "test")  # pylint: disable=protected-access
  _check("exempt_background_transfer_is_missing",
         bg["prominent_disclosure_status"] == "MISSING" and "EXEMPT->MISSING" in (bg["decision_trace"].get("disclosure_reconciled") or ""),
         str(bg["prominent_disclosure_status"]))
  exempt_user = {**exempt_bg, "user_initiated": JevAnswer("noul", noul=0.9)}
  ui = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", state, exempt_user, "test")  # pylint: disable=protected-access
  _check("exempt_user_initiated_kept", ui["prominent_disclosure_status"] == "EXEMPT"
         and ui["decision_trace"].get("disclosure_reconciled") is None, str(ui["prominent_disclosure_status"]))
  local_disc = {**contradict, "transmits_offdevice": JevAnswer("noul", noul=0.1)}
  ld = evaluate._compose_data_safety_finding("PRECISE_LOCATION", "A.kt (Pattern: loc)", state, local_disc, "test")  # pylint: disable=protected-access
  _check("local_stays_exempt_no_reconcile", ld["prominent_disclosure_status"] == "EXEMPT"
         and ld["decision_trace"].get("disclosure_reconciled") is None)


def _test_critic_routing() -> None:
  from typesafe_eval import constants
  from typesafe_eval.client import JevAnswer, JevClient
  _check("critic_prunes_confident_fp", evaluate._critic_decision(0.05)["action"] == "PRUNED")  # pylint: disable=protected-access
  _check("critic_uncertain_never_pruned",
         evaluate._critic_decision(0.05, uncertain=True)["action"] == "MANUAL_REVIEW")  # pylint: disable=protected-access
  _check("critic_uncertain_upgrade",
         evaluate._critic_decision(constants.CONF_ACT, uncertain=True)["action"] == "VERIFIED")  # pylint: disable=protected-access
  _check("critic_transfer_battery", "evidence_shows_transfer" in q.critic_battery("transfer"))
  _check("critic_generic_battery", "evidence_supports_claim" in q.critic_battery("generic"))

  class _Fixed(JevClient):
    name = "fixed"
    def __init__(self, p): super().__init__(); self.p = p; self.seen = []
    def system_one(self, state, questions, model=None):
      self.seen.append((state, list(questions)))
      return {qid: JevAnswer("noul", noul=self.p) for qid in questions}

  chunk = {
      "f1": {"issue_summary": "x", "severity": "CRITICAL", "claim_kind": "transfer",
             "claim": "loc sent", "evidence_snippet": "L1: send(loc)", "sinks": [{"symbol": "S"}],
             "transfer_decision": "TRANSMITS"},
      "f2": {"issue_summary": "y", "severity": "IMPORTANT", "client": "error"},
      "f3": {"issue_summary": "z", "severity": "IMPORTANT", "claim_kind": "transfer",
             "transfer_decision": "UNCERTAIN", "evidence_snippet": "L1: x"},
  }
  c = _Fixed(0.05)
  out = evaluate.evaluate_critic_chunk(chunk, c)
  _check("critic_error_upstream_review", out["f2"]["action"] == "MANUAL_REVIEW")
  _check("critic_prunes_fp_transfer", out["f1"]["action"] == "PRUNED")
  _check("critic_keeps_uncertain", out["f3"]["action"] == "MANUAL_REVIEW")
  _check("critic_asks_transfer_question",
         any("evidence_shows_transfer" in qs for _, qs in c.seen) and len(c.seen) == 2)
  _check("critic_state_has_claim_and_sinks",
         c.seen[0][0]["finding"]["claim"] == "loc sent" and c.seen[0][0]["finding"]["sinks"])


def _test_manifest_fgs() -> None:
  from typesafe_eval import registry
  manifest = {
      "target_sdk": 34,
      "permissions": ["android.permission.FOREGROUND_SERVICE",
                      "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE"],
      "foreground_services": [
          {"name": ".VpnSvc", "type": ""},
          {"name": ".DevSvc", "type": "connectedDevice"},
          {"name": ".LocSvc", "type": "location|dataSync"},
      ],
  }
  found = registry._foreground_service_findings(manifest)  # pylint: disable=protected-access
  by_name = {f["decision_trace"]["service"]: f for f in found}
  _check("fgs_missing_type_important", by_name[".VpnSvc"]["severity"] == "IMPORTANT")
  _check("fgs_type_with_permission_suggestion", by_name[".DevSvc"]["severity"] == "SUGGESTION")
  _check("fgs_missing_permission_important",
         by_name[".LocSvc"]["severity"] == "IMPORTANT" and "FOREGROUND_SERVICE_LOCATION" in by_name[".LocSvc"]["evidence"])
  _check("fgs_permission_mechanical",
         registry._fgs_permission_for_type("mediaPlayback") == "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK")  # pylint: disable=protected-access
  # Below API 34 the type checks do not apply (inventory only).
  found33 = registry._foreground_service_findings({**manifest, "target_sdk": 33})  # pylint: disable=protected-access
  _check("fgs_api33_no_important", all(f["severity"] == "SUGGESTION" for f in found33), str([f["severity"] for f in found33]))
  _check("fgs_spec_registered", any(s.policy_id == "foreground_services_policy" for s in registry.manifest_specs()))


def _test_triage_ranking() -> None:
  """A candidate in a file with a labelled sink outranks scanner order."""
  from typesafe_eval import constants
  from typesafe_eval import engine
  cap = constants.MAX_FINDINGS_PER_TYPE
  # n files match; only the LAST in scanner order has a network sink, the
  # second-to-last has only an IPC sink, the rest none. The two sink files are
  # exempt from the per-type budget (WP6 accounting), so ``cap`` tier-3 files
  # are asked in addition and the last two tier-3 files in scanner order drop.
  n = cap + 4
  with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "app"))
    for i in range(n):
      body = "fun f() {\n  val n = user.name\n"
      if i == n - 1:
        body = "import java.net.Socket\n" + body + "  Socket(h, 1).getOutputStream().write(n.toByteArray())\n"
      elif i == n - 2:
        body = "import android.content.Intent\n" + body + "  startActivity(Intent().putExtra(\"n\", n))\n"
      with open(os.path.join(d, f"app/F{i}.kt"), "w", encoding="utf-8") as f:
        f.write(body + "}\n")
    scratch = os.path.join(d, ".scratch")
    _write_scratch(d, scratch, {"NAME": [f"app/F{i}.kt (Pattern: name)" for i in range(n)]})
    engine.run(scratch, HeuristicJevClient(), batched=True)
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    ds = json.load(open(os.path.join(scratch, "worker_data_safety.json"), encoding="utf-8"))
    files = [(f.get("files_involved") or [""])[0] for f in ds["findings"]]
    _check("triage_keeps_sink_file", any(f"F{n-1}.kt" in f for f in files) and any(f"F{n-2}.kt" in f for f in files), str(files))
    _check("triage_caps_per_type", triage["counters"]["kept"] == cap + 2
           and triage["counters"].get("kept_budgeted") == cap, str(triage["counters"].get("kept")))
    dropped = [x for x in triage["dropped"] if "MAX_FINDINGS_PER_TYPE" in x["reason"]]
    _check("triage_records_dropped_with_rank",
           len(dropped) == 2 and all("rank" in x and "tier" in x for x in dropped)
           and all(x["tier"] == 3 for x in dropped), str(dropped))
    _check("triage_sink_file_indexed",
           triage["sinks_by_file"].get(f"app/F{n-1}.kt") and not triage["sinks_by_file"].get("app/F0.kt"))
    # Tier 0 (egress) and tier 1 (IPC) both survive and rank first; the two
    # scanner-order trailers without any sink are the ones dropped (ranks
    # cap+2, cap+3: the budget of ``cap`` tier-3 candidates is spent on the
    # earlier ones).
    _check("triage_egress_ranked_before_ipc",
           sorted(x["rank"] for x in dropped) == [cap + 2, cap + 3]
           and all(f"F{n-1}.kt" not in x["finding"] and f"F{n-2}.kt" not in x["finding"] for x in dropped),
           str([(x["finding"], x["rank"]) for x in dropped]))
    kept_findings = [f for f in ds["findings"] if f.get("kind") != "play_declaration"]
    tiers = {(f["files_involved"][0]): f["decision_trace"]["anchor"]["rank_tier"] for f in kept_findings}
    _check("triage_tiers_in_trace", tiers.get(f"app/F{n-1}.kt") == 0 and tiers.get(f"app/F{n-2}.kt") == 1
           and tiers.get("app/F0.kt") == 3, str(tiers))
    _check("triage_declared_caps_key", "dependency_capabilities" in triage)

  # WP2: the per-type cap only trims candidates with no sink in scope. When
  # more than MAX_FINDINGS_PER_TYPE candidates each have an IPC sink in their
  # own function, all of them reach the model (bounded by the candidate cap).
  with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "app"))
    m = cap + 1
    for i in range(m):
      body = ("import android.content.Intent\n"
              "fun f() {\n  val n = user.name\n  startActivity(Intent().putExtra(\"n\", n))\n}\n")
      with open(os.path.join(d, f"app/S{i}.kt"), "w", encoding="utf-8") as f:
        f.write(body)
    scratch = os.path.join(d, ".scratch")
    _write_scratch(d, scratch, {"NAME": [f"app/S{i}.kt (Pattern: name)" for i in range(m)]})
    engine.run(scratch, HeuristicJevClient(), batched=True)
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    _check("triage_cap_exempts_sink_in_scope",
           triage["counters"]["kept"] == m and triage["counters"].get("cap_exempt_sink_in_scope") == m
           and triage["counters"].get("kept_budgeted") == 0
           and not [x for x in triage["dropped"] if "MAX_FINDINGS_PER_TYPE" in x["reason"]],
           str((triage["counters"].get("kept"), triage["counters"].get("cap_exempt_sink_in_scope"))))
    constants.CAP_EXEMPTS_SINK_IN_SCOPE = False
    try:
      scratch2 = os.path.join(d, ".scratch2")
      _write_scratch(d, scratch2, {"NAME": [f"app/S{i}.kt (Pattern: name)" for i in range(m)]})
      engine.run(scratch2, HeuristicJevClient(), batched=True)
      triage2 = json.load(open(os.path.join(scratch2, engine.TRIAGE_FILENAME), encoding="utf-8"))
      _check("triage_cap_exempt_flag_off", triage2["counters"]["kept"] == cap
             and triage2["counters"].get("cap_exempt_sink_in_scope") == 0, str(triage2["counters"].get("kept")))
    finally:
      constants.CAP_EXEMPTS_SINK_IN_SCOPE = True


def _test_sink_visibility() -> None:
  """Every reference of a sink symbol is visible to ranking; the model view is bounded.

  Regression for a labelled MIME-sharing transfer whose ``startActivity`` was
  the 14th ``Intent`` reference in a large activity: the old 12-line cap in
  ``symbol_references`` hid it and the anchor ranked tier 3.
  """
  from typesafe_eval import capabilities as capsmod
  from typesafe_eval import constants
  from typesafe_eval import context
  from typesafe_eval import structure
  n_refs = constants.MAX_SINK_REF_LINES_IN_STATE + 6
  src = ["import android.content.Intent", "class A {"]
  for i in range(n_refs - 1):
    src += [f"  fun early{i}() {{", f"    val i{i} = Intent()", "  }"]
  src += ["  fun share(which: Int) {",
          "    var mime = \"\"",
          "    switch (which) {",
          "      case 1: mime = \"video/*\"; break;",
          "    }",
          "    startActivity(Intent.createChooser(intent, mime))",
          "  }", "}"]
  lines = src
  refs = structure.symbol_references(lines, ["android.content.Intent"])["android.content.Intent"]
  last = len(lines) - 3  # the startActivity line (0-based)
  _check("symbol_refs_not_truncated", len(refs) == n_refs and last in refs, str((len(refs), last in refs)))
  fs = structure.FileStructure("A.kt", "kotlin", lines, ["android.content.Intent"],
                               {"android.content.Intent": refs}, "a")
  profiles = {"android.content.Intent": capsmod.CapabilityProfile(
      "android.content.Intent", "import", {capsmod.IPC_SHARING: 0.9}, [capsmod.IPC_SHARING], "heuristic", None)}
  sinks = context.file_sinks(fs, profiles)
  anchor = context.anchor_signal(fs, "video/*", "VIDEOS", sinks)
  _check("anchor_sees_late_sink", anchor.sink_in_scope and anchor.tier == 1, str((anchor.sink_in_scope, anchor.tier, anchor.scope)))
  st = sinks[0].to_state(near=[anchor.chosen])
  _check("sink_state_bounded",
         len(st["lines"]) == constants.MAX_SINK_REF_LINES_IN_STATE and st.get("omitted_lines") == 6
         and (last + 1) in st["lines"], str((len(st["lines"]), st.get("omitted_lines"))))
  _check("sink_state_full_when_small", "omitted_lines" not in context.Sink("S", "m", [], [1, 2]).to_state())
  state, per_ask = context.build_file_state(fs, [("VIDEOS", "video/*")], profiles, {})
  _check("related_lines_nearest_anchor",
         all(r.startswith("L") for r in state["related_lines"])
         and len(state["related_lines"]) <= constants.MAX_SINK_LINES_IN_STATE
         and per_ask[0]["anchor"]["sink_in_scope"] is True,
         str(state["related_lines"][:2]))


def _test_identifier_lint() -> None:
  """No vendor / library name may drive evaluator logic (tests and fixtures excluded).

  The list below is illustrative, not exhaustive: it exists to catch the
  regression of reintroducing a lookup table. Capability *definitions* must
  describe behaviour; the model supplies the mapping from names to behaviour.
  """
  vendor_tokens = (
      "okhttp", "retrofit", "volley", "ktor", "crashlytics", "firebase", "admob",
      "sentry", "mixpanel", "amplitude", "appsflyer", "braze", "segment.io",
      "facebook", "timber", "glide", "picasso", "adjust.sdk", "unity3d", "bugsnag",
  )
  pkg_dir = os.path.dirname(os.path.abspath(__file__))
  excluded = {"selftest.py", "livetest.py"}
  offenders = []
  for name in sorted(os.listdir(pkg_dir)):
    if not name.endswith(".py") or name in excluded:
      continue
    with open(os.path.join(pkg_dir, name), "r", encoding="utf-8") as f:
      text = f.read().lower()
    for tok in vendor_tokens:
      if re.search(r"(?<![a-z])" + re.escape(tok) + r"(?![a-z])", text):
        offenders.append(f"{name}:{tok}")
  _check("identifier_lint_no_vendor_names", not offenders, ", ".join(offenders))


def _test_calibrate() -> None:
  from typesafe_eval import calibrate
  cases = [
      {"file": "a", "data_type": "T", "transfers": True, "p_transmit": 0.92},
      {"file": "b", "data_type": "T", "transfers": True, "p_transmit": 0.81},
      {"file": "c", "data_type": "T", "transfers": True, "p_transmit": 0.55},
      {"file": "d", "data_type": "T", "transfers": False, "p_transmit": 0.60},
      {"file": "e", "data_type": "T", "transfers": False, "p_transmit": 0.20},
      {"file": "f", "data_type": "T", "transfers": False, "p_transmit": 0.05},
  ]
  report = calibrate.calibrate({"cases": cases, "description": "synthetic"}, min_precision=0.9)
  band = report["band"]
  _check("calibrate_low_keeps_recall", band["T_TRANSMIT_LOW"] == 0.55, str(band))
  _check("calibrate_high_meets_precision", band["T_TRANSMIT_HIGH"] == 0.61, str(band))
  _check("calibrate_metrics", report["metrics"]["recall_at_high"] == round(2 / 3, 3)
         and report["metrics"]["abstention_rate"] == round(2 / 6, 3), str(report["metrics"]))
  _check("calibrate_reliability", report["reliability"]["brier"] is not None and report["reliability"]["ece"] is not None)
  _check("calibrate_small_set_warns", any("regression check" in w for w in report["warnings"]))
  _check("calibrate_provenance_block", set(report["provenance"]) >= {"model", "calibrated_on", "calibrated_at", "method", "note"})
  # Join from worker files.
  with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "worker_x.json"), "w", encoding="utf-8") as f:
      json.dump({"findings": [{"psl_constant": "T", "files_involved": ["app/A.kt"],
                               "decision_trace": {"scores": {"transmits_offdevice": 0.77}}}]}, f)
    joined = calibrate.join_probabilities([{"file": "A.kt", "data_type": "T", "transfers": True}], [d])
    _check("calibrate_joins_worker_probability", joined and joined[0]["p_transmit"] == 0.77, str(joined))


def _test_destination_class() -> None:
  """WP7: destination hints, the ``destination_class`` Choice and its composition.

  Covers: hint detection (preference/UI read, chooser, developer vs constant
  endpoint, camelCase part matching), the battery swap, every class in the
  composition table (developer backend, third-party SDK, IPC, confirmed and
  unconfirmed user-chosen, confirmed and uncorroborated platform, unknown),
  the double gate (confidence + corroboration), the rollback flag, the legacy
  ``is_third_party`` fallback, the heuristic client's prior, the state block
  (present only with hits), and the calibrate v2 report.
  """
  from typesafe_eval import calibrate
  from typesafe_eval import capabilities as caps
  from typesafe_eval import client as clientmod
  from typesafe_eval import constants
  from typesafe_eval import context
  from typesafe_eval import structure
  from typesafe_eval.client import JevAnswer

  # --- structure: hints -----------------------------------------------------
  src = (
      "import java.net.URL\n"
      "class Up {\n"
      "  fun send(d: String) {\n"
      "    val host = prefs.getString(\"server_host\", \"\")\n"
      "    val u = URL(\"https://api.example.com/v1\")\n"
      "    val other = URL(\"https://collector.elsewhere.net/e\")\n"
      "    post(host, d)\n"
      "  }\n"
      "  fun share(f: File) {\n"
      "    startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND), \"x\"))\n"
      "  }\n"
      "  fun noise() { val securityPrefs = getSharedPreferences(\"a\", 0); val t = binding.title.text }\n"
      "  // val host = prefs.getString(\"in a comment\")\n"
      "}\n"
  ).splitlines()
  doms = structure.developer_domains("com.example.app")
  _check("dest_dev_domains", doms[0] == "example.com" and structure.developer_domains("app") == [], str(doms))
  hints = structure.destination_hints(src, (2, 8), doms)
  kinds = [(h.kind, h.line + 1, h.detail) for h in hints]
  _check("dest_hint_pref_read", (structure.USER_CHOSEN_DESTINATION, 4, "preference_or_ui_field") in kinds, str(kinds))
  _check("dest_hint_dev_backend", (structure.DEVELOPER_BACKEND, 5, "api.example.com") in kinds, str(kinds))
  _check("dest_hint_constant_endpoint", (structure.CONSTANT_ENDPOINT, 6, "collector.elsewhere.net") in kinds, str(kinds))
  _check("dest_hint_chooser", any(h.kind == structure.USER_CHOSEN_DESTINATION and h.detail == "chooser"
                                  for h in structure.destination_hints(src, (8, 11))))
  _check("dest_hint_no_false_part", structure.destination_hints(src, (11, 12)) == [])
  _check("dest_hint_skips_comments", structure.destination_hints(src, (12, 13)) == [])
  _check("dest_hint_state_shape", set(hints[0].to_state()) == {"hint", "line", "detail", "evidence"})
  _check("dest_names_destination", structure._names_destination("serverUrl") and structure._names_destination("mHost")  # pylint: disable=protected-access
         and structure._names_destination("remote_addr") and not structure._names_destination("securityPrefs"))  # pylint: disable=protected-access

  # --- questions -------------------------------------------------------------
  battery = q.data_safety_battery("EMAIL", "email address")
  _check("dest_battery_swapped", "destination_class" in battery and "is_third_party" not in battery)
  _check("dest_options_closed", set(battery["destination_class"]["criteria"]) == set(q.DESTINATION_CLASS_OPTIONS)
         and "unknown" in q.DESTINATION_CLASS_OPTIONS and len(q.DESTINATION_CLASS_OPTIONS) == 6)
  _check("dest_question_names_hints", "destination_hints" in battery["destination_class"]["instructions"])

  # --- context: state block ---------------------------------------------------
  fs = structure.FileStructure("Up.kt", "kotlin", src, ["java.net.URL"],
                               structure.symbol_references(src, ["java.net.URL"]), "com.example.app")
  profiles = {"java.net.URL": caps.CapabilityProfile("java.net.URL", "import", {"NETWORK_EGRESS": 0.9}, ["NETWORK_EGRESS"], "model", "m")}
  state, per_ask = context.build_file_state(fs, [("EMAIL", "post(")], profiles, {"package": "com.example.app"})
  _check("dest_state_block", {h["hint"] for h in state.get("destination_hints", [])} >= {"USER_CHOSEN_DESTINATION", "DEVELOPER_BACKEND"}
         and state["destination_hints"][0]["data_type"] == "EMAIL", str(state.get("destination_hints")))
  _check("dest_per_ask_kinds", "USER_CHOSEN_DESTINATION" in per_ask[0]["anchor"]["destination_hints"]
         and per_ask[0]["destination_hints"], str(per_ask[0]["anchor"]))
  plain = "import java.net.URL\nclass P {\n  fun f() {\n    val e = email()\n    URL(x).openStream()\n  }\n}\n".splitlines()
  fs_plain = structure.FileStructure("P.kt", "kotlin", plain, ["java.net.URL"],
                                     structure.symbol_references(plain, ["java.net.URL"]), "com.example.app")
  state2, per_ask2 = context.build_file_state(fs_plain, [("EMAILS", "email()")], profiles, {"package": "com.example.app"})
  _check("dest_state_absent_without_hits", "destination_hints" not in state2 and "destination_hints" not in per_ask2[0]
         and per_ask2[0]["anchor"]["destination_hints"] == [], str(state2.get("destination_hints")))

  # --- evaluate: composition table -------------------------------------------
  def _answers(p_transmit, cls, conf=0.9, user_initiated=0.2):
    n = len(q.DESTINATION_CLASS_OPTIONS)
    probs = {o: (conf if o == cls else (1 - conf) / (n - 1)) for o in q.DESTINATION_CLASS_OPTIONS}
    return {
        "signal_relevant": JevAnswer("noul", noul=0.9),
        "transmits_offdevice": JevAnswer("noul", noul=p_transmit),
        "user_initiated": JevAnswer("noul", noul=user_initiated),
        "destination_class": JevAnswer("choice", choice=cls, probabilities=probs, confidence=conf),
        "has_prominent_disclosure": JevAnswer("noul", noul=0.1),
        "disclosure_status": JevAnswer("choice", choice="MISSING"),
        "severity": JevAnswer("score", score=1.0),
    }
  base = {
      "signal": {"data_type": "EMAILS", "matched_pattern": "email", "file": "Up.kt",
                 "line": 7, "matched_line": "post(host, d)", "all_lines": [7]},
      "code_snippet": "L7: post(host, d)",
      "sinks": [{"symbol": "URL", "capabilities": ["NETWORK_EGRESS"], "lines": [5, 6]}],
      "anchor": {"scope": [3, 8], "proximity": 0, "sink_in_scope": True, "tier": 0,
                 "scope_capabilities": ["NETWORK_EGRESS"], "destination_hints": ["USER_CHOSEN_DESTINATION"]},
      "destination_hints": [{"hint": "USER_CHOSEN_DESTINATION", "line": 4, "detail": "preference_or_ui_field", "evidence": "val host = ..."}],
      "app": {},
  }
  compose = evaluate._compose_data_safety_finding  # pylint: disable=protected-access
  dev = compose("EMAILS", "Up.kt (Pattern: email)", base, _answers(0.95, "developer_backend"), "test")
  _check("dest_dev_backend_collection", dev["policy_id"] == "prominent_disclosure_policy" and dev["severity"] == "CRITICAL"
         and dev["is_third_party"] is False and dev["destination_class"] == "developer_backend"
         and dev["purpose"] == "App functionality", str((dev["policy_id"], dev["severity"], dev["purpose"])))
  sdk = compose("EMAILS", "Up.kt (Pattern: email)", base, _answers(0.95, "third_party_sdk", conf=0.6), "test")
  _check("dest_sdk_is_sharing", sdk["is_third_party"] is True and sdk["severity"] == "CRITICAL"
         and sdk["purpose"] == "Analytics or third-party sharing"
         and sdk["decision_trace"]["destination"]["sharing_mass"] >= constants.T_SHARING_MASS)
  ipc = compose("EMAILS", "Up.kt (Pattern: email)", base, _answers(0.95, "other_app_ipc"), "test")
  _check("dest_ipc_is_sharing", ipc["is_third_party"] is True and ipc["purpose"] == "Shared with another app (IPC)")
  # Sharing is decided by the mass on the sharing classes, not by the argmax:
  # a flat distribution whose argmax happens to be a sharing class does not
  # flip ``is_third_party`` (review-flagged instead) ...
  def _with_probs(p_transmit, probs):
    cls = max(probs, key=probs.get)
    a = _answers(p_transmit, cls)
    a["destination_class"] = JevAnswer("choice", choice=cls, probabilities=probs, confidence=probs[cls])
    return a
  flat = _with_probs(0.95, {"third_party_sdk": 0.34, "developer_backend": 0.33, "unknown": 0.33})
  fl = compose("EMAILS", "Up.kt (Pattern: email)", base, flat, "test")
  _check("dest_flat_sharing_argmax_not_sharing",
         fl["is_third_party"] is False and fl["destination_class"] == "third_party_sdk"
         and fl["severity"] == "CRITICAL" and fl.get("needs_manual_review") is True
         and "[sharing unconfirmed: third party sdk mass=0.34; verify]" in fl["issue_summary"]
         and fl["decision_trace"]["destination"]["corroboration"] == "low_sharing_mass"
         and fl["purpose"] == "App functionality",
         str((fl["is_third_party"], fl["issue_summary"], fl["decision_trace"]["destination"])))
  # ... while mass split across the two sharing classes counts even when the
  # argmax is developer_backend.
  split = _with_probs(0.95, {"developer_backend": 0.40, "third_party_sdk": 0.30, "other_app_ipc": 0.30})
  sp = compose("EMAILS", "Up.kt (Pattern: email)", base, split, "test")
  _check("dest_split_sharing_mass_counts", sp["is_third_party"] is True and sp["destination_class"] == "developer_backend"
         and abs(sp["decision_trace"]["destination"]["sharing_mass"] - 0.60) < 1e-6
         and sp.get("needs_manual_review") is None, str(sp["decision_trace"]["destination"]))
  _check("dest_threshold_traced", sp["decision_trace"]["thresholds"]["T_SHARING_MASS"] == constants.T_SHARING_MASS)
  # Confirmed user-chosen (hint in scope + high confidence): inventory, EXEMPT.
  uc = compose("EMAILS", "Up.kt (Pattern: email)", base, _answers(0.95, "user_chosen_destination"), "test")
  _check("dest_user_chosen_confirmed_inventory",
         uc["policy_id"] == "data_safety_section" and uc["severity"] == "SUGGESTION"
         and uc["prominent_disclosure_status"] == "EXEMPT" and uc["is_transferred"] is True
         and uc.get("needs_manual_review") is None and uc["is_third_party"] is False
         and "[destination: user chosen destination]" in uc["issue_summary"],
         str((uc["policy_id"], uc["severity"], uc["prominent_disclosure_status"], uc["issue_summary"])))
  tr = uc["decision_trace"]["destination"]
  _check("dest_trace_confirmed_by_hint", tr["confirmed"] is True and tr["corroboration"] == "hint"
         and tr["applied"] is True and tr["hints"] == ["USER_CHOSEN_DESTINATION"], str(tr))
  _check("dest_trace_hints_listed", uc["decision_trace"]["destination_hints"][0]["hint"] == "USER_CHOSEN_DESTINATION")
  # Same class, no hint, not user-initiated: kept at CRITICAL for review.
  no_hint = {**base, "anchor": {**base["anchor"], "destination_hints": []}, "destination_hints": []}
  uc2 = compose("EMAILS", "Up.kt (Pattern: email)", no_hint, _answers(0.95, "user_chosen_destination"), "test")
  _check("dest_user_chosen_uncorroborated_kept",
         uc2["severity"] == "CRITICAL" and uc2["policy_id"] == "prominent_disclosure_policy"
         and uc2.get("needs_manual_review") is True and "unconfirmed" in uc2["issue_summary"]
         and uc2["decision_trace"]["destination"]["corroboration"] == "uncorroborated", str(uc2["issue_summary"]))
  # No hint but the battery says user-initiated: corroborated.
  uc3 = compose("EMAILS", "Up.kt (Pattern: email)", no_hint, _answers(0.95, "user_chosen_destination", user_initiated=0.9), "test")
  _check("dest_user_chosen_by_user_initiated", uc3["severity"] == "SUGGESTION"
         and uc3["decision_trace"]["destination"]["corroboration"] == "user_initiated")
  # Hint present but low confidence: kept.
  uc4 = compose("EMAILS", "Up.kt (Pattern: email)", base, _answers(0.95, "user_chosen_destination", conf=constants.CONF_DESTINATION_ACT - 0.01), "test")
  _check("dest_user_chosen_low_confidence_kept", uc4["severity"] == "CRITICAL"
         and uc4["decision_trace"]["destination"]["corroboration"] == "low_confidence")
  # Platform component: confirmed only without strong egress reachable.
  ipc_scope = {**no_hint, "sinks": [{"symbol": "ContentResolver", "capabilities": ["IPC_SHARING"], "lines": [5]}],
               "anchor": {**no_hint["anchor"], "scope_capabilities": ["IPC_SHARING"], "tier": 1}}
  pc = compose("EMAILS", "Up.kt (Pattern: email)", ipc_scope, _answers(0.95, "platform_component"), "test")
  _check("dest_platform_confirmed_no_egress", pc["severity"] == "SUGGESTION" and pc["prominent_disclosure_status"] == "EXEMPT"
         and pc["decision_trace"]["destination"]["corroboration"] == "no_egress_in_scope"
         and pc["purpose"] == "Platform component on the same device", str(pc["purpose"]))
  pc2 = compose("EMAILS", "Up.kt (Pattern: email)", no_hint, _answers(0.95, "platform_component"), "test")
  _check("dest_platform_with_egress_kept", pc2["severity"] == "CRITICAL" and pc2.get("needs_manual_review") is True
         and pc2["decision_trace"]["destination"]["corroboration"] == "uncorroborated")
  # Unknown on a transfer: review, never lowered.
  unk = compose("EMAILS", "Up.kt (Pattern: email)", no_hint, _answers(0.95, "unknown"), "test")
  _check("dest_unknown_review", unk["severity"] == "CRITICAL" and unk.get("needs_manual_review") is True
         and unk["purpose"] == "Transfer to an unresolved destination (manual review)")
  # UNCERTAIN transfer + confirmed user-chosen: inventory but still reviewed.
  mid = (constants.T_TRANSMIT_LOW + constants.T_TRANSMIT_HIGH) / 2
  ucm = compose("EMAILS", "Up.kt (Pattern: email)", base, _answers(mid, "user_chosen_destination"), "test")
  _check("dest_uncertain_user_chosen", ucm["severity"] == "SUGGESTION" and ucm.get("needs_manual_review") is True
         and ucm["transfer_decision"] == "UNCERTAIN")
  # LOCAL: destination moot (traced, not applied, no review flag from it).
  loc = compose("EMAILS", "Up.kt (Pattern: email)", no_hint, _answers(0.1, "unknown"), "test")
  _check("dest_local_moot", loc["severity"] == "SUGGESTION" and loc.get("needs_manual_review") is None
         and loc["decision_trace"]["destination"]["applied"] is False)
  # Sharing sink in scope still ORs in (pre-WP7 fact) even for developer_backend.
  ipc_dev = compose("EMAILS", "Up.kt (Pattern: email)", ipc_scope, _answers(0.95, "developer_backend"), "test")
  _check("dest_sharing_sink_in_scope_ors", ipc_dev["is_third_party"] is True)
  # ... but a confirmed, applied user-chosen destination clears it: the chooser
  # Intent is the sharing-capable sink, and the user picked the recipient.
  ipc_hint = {**ipc_scope, "anchor": {**ipc_scope["anchor"], "destination_hints": ["USER_CHOSEN_DESTINATION"]},
              "destination_hints": base["destination_hints"]}
  ipc_uc = compose("EMAILS", "Up.kt (Pattern: email)", ipc_hint, _answers(0.95, "user_chosen_destination"), "test")
  _check("dest_applied_user_chosen_not_sharing", ipc_uc["is_third_party"] is False
         and ipc_uc["decision_trace"]["destination"]["applied"] is True
         and ipc_uc["decision_trace"]["destination"]["sharing"] is False
         and "not sharing" in ipc_uc["decision_trace"]["destination_note"], str(ipc_uc["decision_trace"]["destination"]))
  # Unconfirmed user-chosen with an IPC sink in scope keeps the sharing flag.
  ipc_uc2 = compose("EMAILS", "Up.kt (Pattern: email)", ipc_scope, _answers(0.95, "user_chosen_destination", conf=0.5), "test")
  _check("dest_unconfirmed_user_chosen_keeps_sharing", ipc_uc2["is_third_party"] is True and ipc_uc2["severity"] == "CRITICAL")
  # Legacy fallback: an is_third_party Noul still composes.
  legacy = _answers(0.95, "developer_backend"); del legacy["destination_class"]
  legacy["is_third_party"] = JevAnswer("noul", noul=0.9)
  lg = compose("EMAILS", "Up.kt (Pattern: email)", no_hint, legacy, "test")
  _check("dest_legacy_noul_fallback", lg["is_third_party"] is True and lg["destination_class"] == "third_party_sdk"
         and lg["decision_trace"]["destination"]["legacy"] is True)
  legacy_mid = dict(legacy); legacy_mid["is_third_party"] = JevAnswer("noul", noul=(constants.T_THIRD_PARTY - 0.05))
  lgm = compose("EMAILS", "Up.kt (Pattern: email)", no_hint, legacy_mid, "test")
  _check("dest_legacy_keeps_T_THIRD_PARTY", lgm["is_third_party"] is False and lgm["destination_class"] == "developer_backend"
         and lgm.get("needs_manual_review") is None, str(lgm["decision_trace"]["destination"]))
  # Rollback flag: class traced, never applied, sharing = in-scope fact only.
  saved = constants.DESTINATION_CLASS_ENABLED
  constants.DESTINATION_CLASS_ENABLED = False
  try:
    off = compose("EMAILS", "Up.kt (Pattern: email)", base, _answers(0.95, "user_chosen_destination"), "test")
    off_sdk = compose("EMAILS", "Up.kt (Pattern: email)", base, _answers(0.95, "third_party_sdk"), "test")
    _check("dest_flag_off", off["severity"] == "CRITICAL" and off.get("needs_manual_review") is None
           and off["decision_trace"]["destination"]["applied"] is False and off_sdk["is_third_party"] is False
           and off["decision_trace"]["destination"]["enabled"] is False)
  finally:
    constants.DESTINATION_CLASS_ENABLED = saved

  # --- heuristic client prior --------------------------------------------------
  hc = clientmod.HeuristicJevClient()
  ans = hc.system_one(base, battery)
  _check("dest_heuristic_user_chosen", ans["destination_class"].choice == "user_chosen_destination"
         and ans["destination_class"].confidence >= constants.CONF_DESTINATION_ACT, str(ans["destination_class"]))
  ans2 = hc.system_one(no_hint, battery)
  _check("dest_heuristic_network_dev_backend", ans2["destination_class"].choice == "developer_backend")
  tele = {**no_hint, "sinks": [{"symbol": "Reporter", "capabilities": ["THIRD_PARTY_TELEMETRY"], "lines": [5]}]}
  _check("dest_heuristic_telemetry_sdk", hc.system_one(tele, battery)["destination_class"].choice == "third_party_sdk")
  _check("dest_heuristic_no_sink_unknown", hc.system_one({**no_hint, "sinks": []}, battery)["destination_class"].choice == "unknown")

  # --- calibrate v2 --------------------------------------------------------------
  cases = [
      {"file": "a", "data_type": "T", "transfers": True, "p_transmit": 0.92, "destination_class": "developer_backend",
       "run_destination_class": "developer_backend", "run_is_third_party": False},
      {"file": "b", "data_type": "T", "transfers": True, "p_transmit": 0.81, "destination_class": "third_party_sdk",
       "run_destination_class": "developer_backend", "run_is_third_party": False},
      {"file": "c", "data_type": "T", "transfers": True, "p_transmit": 0.55, "destination_class": "user_chosen_destination",
       "run_destination_class": "user_chosen_destination", "run_is_third_party": False, "run_destination_applied": True},
      {"file": "d", "data_type": "T", "transfers": False, "p_transmit": 0.60},
      {"file": "e", "data_type": "T", "transfers": False, "p_transmit": 0.20},
  ]
  report = calibrate.calibrate({"cases": cases, "description": "synthetic v2"}, min_precision=0.9)
  dest = report["destination"]
  _check("calibrate_v2_counts", dest["n_labelled"] == 3 and dest["n_scored"] == 3 and dest["accuracy"] == round(2 / 3, 3), str(dest))
  _check("calibrate_v2_per_class", dest["per_class"]["developer_backend"]["precision"] == 0.5
         and dest["per_class"]["third_party_sdk"]["recall"] == 0.0, str(dest["per_class"]))
  _check("calibrate_v2_sharing_regression", len(dest["sharing_regressions"]) == 1 and dest["sharing_regressions"][0]["file"] == "b"
         and any("lost the sharing flag" in w for w in report["warnings"]))
  _check("calibrate_v2_applied_downgrades", len(dest["applied_downgrades"]) == 1 and dest["applied_downgrades_wrong"] == 0)
  _check("calibrate_v2_by_class", set(report["reliability_by_class"]) == {"developer_backend", "third_party_sdk", "user_chosen_destination", "none"}
         and report["reliability_by_class"]["none"]["n"] == 2, str(report["reliability_by_class"]))
  _check("calibrate_v2_in_band", report["reliability_in_band"]["n"] == 2 and report["reliability_in_band"]["positives"] == 1,
         str(report["reliability_in_band"]))
  _check("calibrate_v2_band_from_lowest_positive", report["band"]["T_TRANSMIT_LOW"] == 0.55
         and report["recall_exempt_cases"] == [], str(report["band"]))
  # A platform_component transfer scoring low does not drag T_LOW down and is
  # not a LOCAL false negative; it still counts everywhere else.
  pc_cases = cases + [{"file": "f", "data_type": "T", "transfers": True, "p_transmit": 0.20,
                       "destination_class": "platform_component", "run_destination_class": "unknown", "run_is_third_party": False}]
  pc_report = calibrate.calibrate({"cases": pc_cases, "description": "synthetic v2 + platform"}, min_precision=0.9)
  _check("calibrate_v2_platform_recall_exempt",
         pc_report["band"]["T_TRANSMIT_LOW"] == 0.55
         and pc_report["recall_exempt_cases"] == [{"file": "f", "data_type": "T", "destination_class": "platform_component", "p_transmit": 0.2}]
         and pc_report["metrics"]["false_negatives_local"] == 0 and pc_report["metrics"]["recall_exempt_local"] == 1
         and pc_report["metrics"]["positives"] == 4 and pc_report["reliability_by_class"]["platform_component"]["n"] == 1
         and pc_report["destination"]["n_labelled"] == 4,
         str((pc_report["band"], pc_report["metrics"], pc_report["recall_exempt_cases"])))
  # The same case labelled as a collection class does constrain the band.
  dev_cases = cases + [{**pc_cases[-1], "destination_class": "developer_backend"}]
  _check("calibrate_v2_collection_class_constrains",
         calibrate.calibrate({"cases": dev_cases}, min_precision=0.9)["band"]["T_TRANSMIT_LOW"] == 0.20)
  v1 = calibrate.calibrate({"cases": [{k: v for k, v in c.items() if not k.startswith("run_") and k != "destination_class"} for c in cases]})
  _check("calibrate_v1_labels_still_work", v1["destination"]["n_labelled"] == 0 and "note" in v1["destination"])
  # Join carries the run's destination fields onto the case.
  with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "worker_x.json"), "w", encoding="utf-8") as f:
      json.dump({"findings": [{"psl_constant": "T", "files_involved": ["app/A.kt"], "destination_class": "other_app_ipc",
                               "is_third_party": True, "transfer_decision": "TRANSMITS", "severity": "IMPORTANT",
                               "decision_trace": {"scores": {"transmits_offdevice": 0.77},
                                                  "destination": {"class": "other_app_ipc", "confirmed": False, "applied": False}}}]}, f)
    joined = calibrate.join_probabilities([{"file": "A.kt", "data_type": "T", "transfers": True, "destination_class": "other_app_ipc"}], [d])
    _check("calibrate_v2_join_run_fields", joined and joined[0]["run_destination_class"] == "other_app_ipc"
           and joined[0]["run_is_third_party"] is True and joined[0]["run_destination_applied"] is False, str(joined))


def _test_app_purpose() -> None:
  """WP4: once-per-app purpose question — cache miss/hit, low confidence, failure, purpose_in."""
  from typesafe_eval import capabilities as capsmod
  from typesafe_eval import constants
  from typesafe_eval import engine
  from typesafe_eval.client import HeuristicJevClient, JevAnswer, JevClient

  class _Purpose(JevClient):
    name = "fixed-purpose"
    def __init__(self, purpose, confidence, fail=False):
      super().__init__(); self.purpose = purpose; self.confidence = confidence; self.fail = fail
      self.calls = 0; self.states = []; self.other_states = []
    def system_one(self, state, questions, model=None):
      if "declared_core_purpose" in questions:
        self.calls += 1; self.states.append(state)
        if self.fail:
          raise RuntimeError("boom")
        opts = list(questions["declared_core_purpose"]["criteria"])
        probs = {o: (self.confidence if o == self.purpose else (1 - self.confidence) / (len(opts) - 1)) for o in opts}
        return {"declared_core_purpose": JevAnswer("choice", choice=self.purpose, probabilities=probs, confidence=self.confidence)}
      self.other_states.append(state)
      return HeuristicJevClient().system_one(state, questions, model)

  _check("purpose_in_established", evaluate.purpose_in({"purpose": "file_manager", "confidence": 0.9, "source": "model"}, {"file_manager"}))
  _check("purpose_in_wrong_purpose", not evaluate.purpose_in({"purpose": "launcher", "confidence": 0.9, "source": "model"}, {"file_manager"}))
  _check("purpose_in_low_confidence", not evaluate.purpose_in(
      {"purpose": "file_manager", "confidence": constants.CONF_APP_PURPOSE - 0.01, "source": "model"}, {"file_manager"}))
  _check("purpose_in_unknown", not evaluate.purpose_in({"purpose": "unknown", "confidence": 0.99, "source": "model"}, {"unknown", "file_manager"}))
  _check("purpose_in_missing", not evaluate.purpose_in(None, {"file_manager"}) and not evaluate.purpose_in({}, {"file_manager"}))
  _check("purpose_in_human_pinned", evaluate.purpose_in({"purpose": "file_manager", "confidence": 0.0, "source": "human"}, {"file_manager"}))
  _check("purpose_options_closed", "unknown" in q.APP_PURPOSE_OPTIONS and "other" in q.APP_PURPOSE_OPTIONS
         and set(q.app_purpose_battery()["declared_core_purpose"]["criteria"]) == set(q.APP_PURPOSE_OPTIONS))

  with tempfile.TemporaryDirectory() as d:
    rel = "app/Loc.kt"
    os.makedirs(os.path.join(d, "app/src/main"))
    with open(os.path.join(d, rel), "w", encoding="utf-8") as f:
      f.write(_KT_LOCATION_SINK)
    with open(os.path.join(d, "app/src/main/AndroidManifest.xml"), "w", encoding="utf-8") as f:
      f.write('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">'
              '<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>'
              '<application android:label="Files"><activity android:name=".Main" android:exported="true">'
              '<intent-filter><action android:name="android.intent.action.MAIN"/>'
              '<category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>'
              '</application></manifest>')
    cache_path = os.path.join(d, "caps.json")
    scratch = os.path.join(d, ".scratch")
    _write_scratch(d, scratch, {"PRECISE_LOCATION": [f"{rel} (Pattern: FusedLocationProviderClient)"]},
                   play_store_info={"category": "Tools", "description": "A file manager. " * 60})
    client = _Purpose("file_manager", 0.92)
    engine.run(scratch, client, batched=True, capability_cache=capsmod.CapabilityCache(cache_path))
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    ap = triage.get("app_purpose") or {}
    _check("app_purpose_in_triage", ap.get("purpose") == "file_manager" and ap.get("source") == "model"
           and abs(ap.get("confidence", 0) - 0.92) < 1e-9 and ap.get("digest"), json.dumps(ap))
    _check("app_purpose_asked_once", client.calls == 1 and triage["counters"].get("app_purpose_requests") == 1, str(client.calls))
    st = client.states[0]
    _check("app_purpose_state_compact",
           set(st) == {"app", "profile"} and "MANAGE_EXTERNAL_STORAGE" in st["profile"]
           and st["app"]["store_description"].endswith("…") and len(st["app"]["store_description"]) <= 600,
           str(sorted(st))[:200])
    # Every later finding-level state carries the purpose label in its ``app``
    # block so the per-finding questions can see it. Symbol-classification states
    # (``capability_definitions``) deliberately carry only the package: symbol
    # capability is app-independent and the cross-app cache must stay purpose-free.
    later = [s for s in client.other_states if isinstance(s, dict) and isinstance(s.get("app"), dict)
             and "capability_definitions" not in s]
    classif = [s for s in client.other_states if isinstance(s, dict) and "capability_definitions" in s]
    _check("app_purpose_in_app_facts",
           later and all(s["app"].get("purpose") == "file_manager" for s in later),
           f"{len(later)} later states; purposes={sorted({str(s['app'].get('purpose')) for s in later})}")
    _check("app_purpose_not_in_classification_state",
           all("purpose" not in s["app"] for s in classif), f"{len(classif)} classification states")
    # Second run: cache hit, no model call, same answer.
    scratch2 = os.path.join(d, ".scratch2")
    _write_scratch(d, scratch2, {"PRECISE_LOCATION": [f"{rel} (Pattern: FusedLocationProviderClient)"]},
                   play_store_info={"category": "Tools", "description": "A file manager. " * 60})
    client2 = _Purpose("launcher", 0.99)
    engine.run(scratch2, client2, batched=True, capability_cache=capsmod.CapabilityCache(cache_path))
    triage2 = json.load(open(os.path.join(scratch2, engine.TRIAGE_FILENAME), encoding="utf-8"))
    _check("app_purpose_cache_hit", client2.calls == 0 and triage2["app_purpose"]["purpose"] == "file_manager"
           and triage2["app_purpose"]["source"] == "cache", json.dumps(triage2.get("app_purpose")))
    # Human pin in the cache wins over the model answer.
    cc = capsmod.CapabilityCache(cache_path)
    cc.put_app_answer(engine.APP_PURPOSE_QID, triage2["app_purpose"]["digest"], None,
                      {"purpose": "backup_or_antivirus", "confidence": 1.0, "source": "human"})
    cc.save()
    scratch3 = os.path.join(d, ".scratch3")
    _write_scratch(d, scratch3, {"PRECISE_LOCATION": [f"{rel} (Pattern: FusedLocationProviderClient)"]},
                   play_store_info={"category": "Tools", "description": "A file manager. " * 60})
    engine.run(scratch3, _Purpose("launcher", 0.99), batched=True, capability_cache=capsmod.CapabilityCache(cache_path))
    triage3 = json.load(open(os.path.join(scratch3, engine.TRIAGE_FILENAME), encoding="utf-8"))
    _check("app_purpose_human_pin", triage3["app_purpose"]["purpose"] == "backup_or_antivirus"
           and triage3["app_purpose"]["source"] == "human", json.dumps(triage3.get("app_purpose")))
    # Client failure degrades to unknown / unavailable and the run completes.
    scratch4 = os.path.join(d, ".scratch4")
    _write_scratch(d, scratch4, {"PRECISE_LOCATION": [f"{rel} (Pattern: FusedLocationProviderClient)"]})
    engine.run(scratch4, _Purpose("launcher", 0.99, fail=True), batched=True)
    triage4 = json.load(open(os.path.join(scratch4, engine.TRIAGE_FILENAME), encoding="utf-8"))
    _check("app_purpose_failure_degrades", triage4["app_purpose"]["purpose"] == "unknown"
           and triage4["app_purpose"]["source"] == "unavailable" and "app_purpose_error" in triage4["counters"]
           and os.path.exists(os.path.join(scratch4, "worker_data_safety.json")), json.dumps(triage4.get("app_purpose")))
    # Heuristic stand-in answers unknown with a peaked distribution.
    scratch5 = os.path.join(d, ".scratch5")
    _write_scratch(d, scratch5, {"PRECISE_LOCATION": [f"{rel} (Pattern: FusedLocationProviderClient)"]})
    engine.run(scratch5, HeuristicJevClient(), batched=True)
    triage5 = json.load(open(os.path.join(scratch5, engine.TRIAGE_FILENAME), encoding="utf-8"))
    _check("app_purpose_heuristic_unknown", triage5["app_purpose"]["purpose"] == "unknown"
           and triage5["app_purpose"]["source"] == "model", json.dumps(triage5.get("app_purpose")))


def _test_consent_defaults() -> None:
  """WP8: consent defaults (guards), string resources and flavour attribution.

  Covers: guard-flag parsing (bare / negated / dotted / member call /
  ``getBoolean`` inline default / multi-line condition; comparisons and
  literals are not guards; cap), declaration lookup (``inline`` /
  ``same_file`` / ``receiver_type`` one hop through the first-party index;
  test source never resolves), the ``consent_default_on`` battery question,
  the state blocks (``guards`` and ``strings`` present only when non-empty,
  disclosure-line strings included), the heuristic client's prior, the
  composition (raise / lower double gate / guard veto / low confidence /
  uncorroborated / disabled / not for applied destinations), the evidence
  suffix, ``AppProfile.partial_sources`` and ``engine._attribute_sources``.
  """
  from typesafe_eval import android_manifest as am
  from typesafe_eval import capabilities as caps
  from typesafe_eval import client as clientmod
  from typesafe_eval import constants
  from typesafe_eval import context
  from typesafe_eval import engine
  from typesafe_eval import resources
  from typesafe_eval import structure
  from typesafe_eval.client import JevAnswer

  # --- structure: guard flags -------------------------------------------------
  src = (
      "package com.w8.ui\n"
      "import java.net.URL\n"
      "import com.w8.settings.PersistentState\n"
      "class Reporter(private val ps: PersistentState) {\n"
      "  private var allow = true\n"
      "  var uploadEnabled: Boolean = false\n"
      "  // if (commentedOut) { never a guard }\n"
      "  fun send(report: String) {\n"
      "    if (!BuildConfig.DEBUG && ps.crashReportsEnabled) {\n"
      "      if (allow || count > 3) {\n"
      "        if (settings.isTelemetryOn()\n"
      "            && prefs.getBoolean(\"share_stats\", true)) {\n"
      "          URL(\"https://crash.example.com\").openConnection()\n"
      "        }\n"
      "      }\n"
      "    }\n"
      "    if (uploadEnabled) { post(report) }\n"
      "    if (report.isEmpty() || true || x == null) { return }\n"
      "    when (report.kind) { \"a\" -> post(report) }\n"
      "  }\n"
      "  fun disclose() { dialog.setMessage(R.string.crash_consent_body); title(R.string.crash_consent_title) }\n"
      "}\n"
  ).splitlines()
  flags = structure.guard_flags(src, (7, 20))
  by_id = {f.identifier: f for f in flags}
  _check("guard_flags_found",
         set(by_id) >= {"BuildConfig.DEBUG", "ps.crashReportsEnabled", "allow", "settings.isTelemetryOn",
                        "prefs.getBoolean(share_stats)"},
         str(sorted(by_id)))
  _check("guard_flags_negation", by_id["BuildConfig.DEBUG"].negated is True and by_id["allow"].negated is False)
  _check("guard_flags_call", by_id["settings.isTelemetryOn"].call is True and by_id["allow"].call is False)
  _check("guard_flags_inline_default", by_id["prefs.getBoolean(share_stats)"].inline_default is True)
  _check("guard_flags_multiline_condition", by_id["prefs.getBoolean(share_stats)"].line == 10, str(by_id["prefs.getBoolean(share_stats)"]))
  _check("guard_flags_not_comparisons_or_literals",
         not any(k in by_id for k in ("count", "true", "x", "null")), str(sorted(by_id)))
  _check("guard_flags_skips_comments", "commentedOut" not in by_id)
  _check("guard_flags_stdlib_predicates_not_flags", "report.isEmpty" not in by_id
         and structure.guard_flags(["if (list.isNullOrEmpty() || file.exists() || ctx.isFinishing) { x() }"], (0, 1)) == [])
  _check("guard_flags_when_subject_not_a_guard", "report.kind" not in by_id, str(sorted(by_id)))
  _check("guard_flags_receiver_name", by_id["ps.crashReportsEnabled"].receiver == "ps"
         and by_id["ps.crashReportsEnabled"].name == "crashReportsEnabled")
  _check("guard_flags_cap", len(flags) <= constants.MAX_GUARDS_IN_STATE
         and "uploadEnabled" in {f.identifier for f in structure.guard_flags(src, (16, 17))})
  _check("guard_flags_empty_scope", structure.guard_flags(src, (20, 22)) == [])
  # Python / bare Kotlin heads.
  py = ["if not self.upload_enabled:", "    send()", "elif telemetry and not debug:", "    pass"]
  py_ids = {(f.identifier, f.negated) for f in structure.guard_flags(py, (0, 4))}
  _check("guard_flags_python_heads", py_ids >= {("self.upload_enabled", True), ("telemetry", False), ("debug", True)}, str(py_ids))
  # Early-exit guards protect the code *after* them, so their sense is inverted.
  ee = (
      "fun init() {\n"
      "  if (!ps.reportingEnabled) {\n"
      "    Log.i(\"x\", \"disabled\")\n"
      "    return\n"
      "  }\n"
      "  if (optedOut) return\n"
      "  if (paused) { throw IllegalStateException() }\n"
      "  if (verbose) { Log.d(\"v\", \"...\") }\n"
      "  upload()\n"
      "}\n"
  ).splitlines()
  ee_flags = {f.identifier: f for f in structure.guard_flags(ee, (0, 10))}
  _check("guard_flags_early_exit_block", ee_flags["ps.reportingEnabled"].early_exit is True
         and ee_flags["ps.reportingEnabled"].negated is False, str(ee_flags.get("ps.reportingEnabled")))
  _check("guard_flags_early_exit_inline", ee_flags["optedOut"].early_exit is True and ee_flags["optedOut"].negated is True)
  _check("guard_flags_early_exit_throw", ee_flags["paused"].early_exit is True and ee_flags["paused"].negated is True)
  _check("guard_flags_no_early_exit_plain_block", ee_flags["verbose"].early_exit is False and ee_flags["verbose"].negated is False)
  py_ee = ["def f(self):", "    if not self.enabled:", "        return", "    send()"]
  py_ee_flags = {f.identifier: f for f in structure.guard_flags(py_ee, (0, 4))}
  _check("guard_flags_early_exit_python", py_ee_flags["self.enabled"].early_exit is True
         and py_ee_flags["self.enabled"].negated is False, str(py_ee_flags))

  # --- structure: declarations ----------------------------------------------
  with tempfile.TemporaryDirectory() as d:
    def write(rel, text):
      full = os.path.join(d, rel)
      os.makedirs(os.path.dirname(full), exist_ok=True)
      with open(full, "w", encoding="utf-8") as f:
        f.write(text)

    main_src = "app/src/main/java/com/w8"
    write(f"{main_src}/settings/PersistentState.kt",
          "package com.w8.settings\nclass PersistentState {\n"
          "  // crashReportsEnabled is documented here\n"
          "  var crashReportsEnabled by booleanPref(true)\n"
          "  var telemetry: Boolean = false\n}\n")
    write("app/src/test/java/com/w8/settings/PersistentState.kt",
          "package com.w8.settings\nclass PersistentState { var crashReportsEnabled = false }\n")
    caller_rel = f"{main_src}/ui/Reporter.kt"
    write(caller_rel, "\n".join(src) + "\n")
    index = structure.build_first_party_index(d)
    fs = structure.analyze_file(d, caller_rel)

    same = structure.declaration_of(by_id["allow"], fs, index, d)
    _check("decl_same_file_true", same is not None and same.resolution == "same_file" and same.default_on is True
           and same.line == 4, str(same))
    off = structure.declaration_of(by_id["uploadEnabled"], fs, index, d)
    _check("decl_same_file_false_typed", off is not None and off.default_on is False and off.initialiser == "false", str(off))
    inline = structure.declaration_of(by_id["prefs.getBoolean(share_stats)"], fs, index, d)
    _check("decl_inline", inline is not None and inline.resolution == "inline" and inline.default_on is True
           and inline.line == 10, str(inline))
    hop = structure.declaration_of(by_id["ps.crashReportsEnabled"], fs, index, d)
    _check("decl_receiver_type_one_hop",
           hop is not None and hop.resolution == "receiver_type" and hop.default_on is True
           and hop.relpath == f"{main_src}/settings/PersistentState.kt" and hop.line == 3
           and "by booleanPref(true)" in hop.text, str(hop))
    _check("decl_unresolved_platform_receiver",
           structure.declaration_of(by_id["settings.isTelemetryOn"], fs, index, d) is None)
    _check("decl_capitalised_receiver_not_first_party",
           structure.declaration_of(by_id["BuildConfig.DEBUG"], fs, index, d) is None)
    _check("decl_no_hop_without_index", structure.declaration_of(by_id["ps.crashReportsEnabled"], fs, None, "") is None)
    _check("decl_default_two_literals_none",
           structure._default_from_initialiser("if (a) true else false") is None  # pylint: disable=protected-access
           and structure._default_from_initialiser("getBoolean(k, false)") is False)  # pylint: disable=protected-access
    java = ["public class S {", "  private boolean upload = false;", "  int uploadCount = 3;",
            "  if (upload == true) {}", "}"]
    jd = structure._declaration_in_lines(java, "upload")  # pylint: disable=protected-access
    _check("decl_java_field", jd is not None and jd[0] == 1 and jd[2] == "false", str(jd))
    _check("decl_java_not_prefix_match", structure._declaration_in_lines(java, "uploadC") is None)  # pylint: disable=protected-access

    # --- context: guards + strings in the state --------------------------------
    net = caps.CapabilityProfile("java.net.URL", "import", {"NETWORK_EGRESS": 0.9}, ["NETWORK_EGRESS"], "model", "m")
    profiles = {"java.net.URL": net}
    res = resources.ResourceIndex(strings={"crash_consent_title": "Send crash reports?",
                                           "crash_consent_body": "Help us fix bugs by sending anonymous reports."})
    state, per_ask = context.build_file_state(
        fs, [("CRASH_LOGS", "report")], profiles, {"package": "com.w8"}, d,
        first_party_index=index, resources=res)
    guards = state.get("guards") or []
    gflags = {g["flag"]: g for g in guards}
    _check("state_guards_present", guards and all(g["data_type"] == "CRASH_LOGS" for g in guards)
           and set(gflags) >= {"ps.crashReportsEnabled"}, str(sorted(gflags)))
    crash_guard = gflags.get("ps.crashReportsEnabled", {})
    _check("state_guard_declaration_shape",
           crash_guard.get("default_on") is True and crash_guard.get("runs_when") == "true"
           and crash_guard.get("runs_by_default") is True and "early_exit" not in crash_guard
           and (crash_guard.get("declaration") or {}).get("resolution") == "receiver_type"
           and crash_guard["declaration"]["line"] == 4
           and set(crash_guard["declaration"]) == {"file", "line", "text", "initialiser", "default_on", "resolution"},
           str(crash_guard))
    # ``runs_by_default`` folds the flag's sense into the declared literal.
    gs_on = context.GuardState(structure.GuardFlag("f", 1, negated=False),
                               structure.Declaration("A.kt", 0, "var f = true", "true", True, "same_file"))
    gs_inv = context.GuardState(structure.GuardFlag("f", 1, negated=True, early_exit=True),
                                structure.Declaration("A.kt", 0, "var f = true", "true", True, "same_file"))
    gs_unk = context.GuardState(structure.GuardFlag("f", 1), structure.Declaration("A.kt", 0, "var f = g()", "g()", None, "same_file"))
    _check("state_runs_by_default", gs_on.runs_by_default is True and gs_inv.runs_by_default is False
           and gs_unk.runs_by_default is None and context.GuardState(structure.GuardFlag("f", 1), None).runs_by_default is None
           and gs_inv.to_state()["early_exit"] is True and gs_inv.to_state()["runs_when"] == "false")
    _check("state_mini_guard_defaults", True in per_ask[0]["anchor"]["guard_defaults"] and per_ask[0].get("guards"),
           str(per_ask[0]["anchor"]))
    # A same-file declaration inside the anchor's scope is a local: listed, but ``runs_by_default`` None.
    local_src = ["import java.net.URL", "class L {", "  var field = false", "  fun f(report: String) {",
                 "    var pending = false", "    if (pending) { URL(x).openStream() }", "    if (field) { URL(y).openStream() }", "  }", "}"]
    fs_local = structure.FileStructure("L.kt", "kotlin", local_src, ["java.net.URL"],
                                       structure.symbol_references(local_src, ["java.net.URL"]), "com.w8")
    lg = {g.flag.identifier: g for g in context.anchor_guards(fs_local, (3, 8))}
    _check("anchor_guards_local_declaration",
           lg["pending"].declaration is not None and lg["pending"].declaration.resolution == "local"
           and lg["pending"].is_local and lg["pending"].runs_by_default is None
           and lg["pending"].to_state()["declaration"]["default_on"] is False
           and lg["field"].declaration.resolution == "same_file" and lg["field"].runs_by_default is False,
           str({k: (v.declaration.resolution if v.declaration else None, v.runs_by_default) for k, v in lg.items()}))
    strings = state.get("strings") or {}
    _check("state_strings_from_scope_or_disclosure_lines",
           strings.get("crash_consent_title") == "Send crash reports?" or strings == {} or "crash_consent_body" in strings,
           str(strings))
    # Strings on the anchor lines resolve; unknown names map to None.
    fs_str = structure.FileStructure("D.kt", "kotlin",
                                     ["import java.net.URL", "fun f() {", "  show(R.string.crash_consent_title, R.string.missing_one)",
                                      "  URL(x).openStream()", "}"], ["java.net.URL"],
                                     structure.symbol_references(["import java.net.URL", "fun f() {", "  show()", "  URL(x).openStream()", "}"],
                                                                 ["java.net.URL"]), "com.w8")
    st2, pa2 = context.build_file_state(fs_str, [("CRASH_LOGS", "show(")], profiles, {"package": "com.w8"}, resources=res)
    _check("state_strings_resolved_and_unknown",
           st2.get("strings") == {"crash_consent_title": "Send crash reports?", "missing_one": None}
           and pa2[0].get("strings") == st2["strings"], str(st2.get("strings")))
    _check("state_strings_absent_without_resources",
           "strings" not in context.build_file_state(fs_str, [("CRASH_LOGS", "show(")], profiles, {"package": "com.w8"})[0])
    # A dialog builder chain puts the R.string arguments on the lines after the
    # disclosure symbol; the window reads them even when the anchor scope is elsewhere.
    dlg_src = ["import java.net.URL", "import androidx.appcompat.app.AlertDialog", "class D {",
               "  fun ask() {", "    AlertDialog.Builder(ctx)", "      .setTitle(R.string.crash_consent_title)",
               "      .setMessage(R.string.crash_consent_body)", "      .show()", "  }",
               "  fun send() {", "    val r = report()", "    URL(x).openStream()", "  }", "}"]
    dlg_profiles = dict(profiles)
    dlg_profiles["androidx.appcompat.app.AlertDialog"] = caps.CapabilityProfile(
        "androidx.appcompat.app.AlertDialog", "import", {"USER_DISCLOSURE_UI": 0.9}, ["USER_DISCLOSURE_UI"], "model", "m")
    fs_dlg = structure.FileStructure("D2.kt", "kotlin", dlg_src, ["java.net.URL", "androidx.appcompat.app.AlertDialog"],
                                     structure.symbol_references(dlg_src, ["java.net.URL", "androidx.appcompat.app.AlertDialog"]), "com.w8")
    st_dlg, _ = context.build_file_state(fs_dlg, [("CRASH_LOGS", "report()")], dlg_profiles, {"package": "com.w8"}, resources=res)
    _check("state_strings_disclosure_window",
           st_dlg.get("strings") == {"crash_consent_title": "Send crash reports?",
                                     "crash_consent_body": "Help us fix bugs by sending anonymous reports."},
           str(st_dlg.get("strings")))
    plain = ["import java.net.URL", "fun f() {", "  val r = report()", "  URL(x).openStream()", "}"]
    fs_plain = structure.FileStructure("P.kt", "kotlin", plain, ["java.net.URL"],
                                       structure.symbol_references(plain, ["java.net.URL"]), "com.w8")
    st3, pa3 = context.build_file_state(fs_plain, [("CRASH_LOGS", "report()")], profiles, {"package": "com.w8"}, resources=res)
    _check("state_guards_absent_without_conditions",
           "guards" not in st3 and "guards" not in pa3[0] and pa3[0]["anchor"]["guard_defaults"] == []
           and "strings" not in st3, str(st3.keys()))

  # --- questions -------------------------------------------------------------
  battery = q.data_safety_battery("CRASH_LOGS", "crash logs")
  _check("consent_battery_has_question", battery["consent_default_on"]["type"] == "noul"
         and "guards" in battery["consent_default_on"]["instructions"]
         and list(battery).index("consent_default_on") < list(battery).index("destination_class"))
  _check("consent_disclosure_questions_name_strings",
         "strings" in battery["has_prominent_disclosure"]["instructions"]
         and "strings" in battery["disclosure_status"]["instructions"])

  # --- heuristic client prior --------------------------------------------------
  prior = clientmod.HeuristicJevClient._consent_prior  # pylint: disable=protected-access
  _check("consent_prior_no_guards_default_on", prior({}) == 0.85)
  _check("consent_prior_any_off_wins", prior({"guards": [{"runs_by_default": True}, {"runs_by_default": False}]}) == 0.15)
  _check("consent_prior_unknown_half", prior({"guards": [{"runs_by_default": None}]}) == 0.5)
  hc = clientmod.HeuristicJevClient()
  ans = hc.system_one({"signal": {"data_type": "CRASH_LOGS"}, "guards": [{"runs_by_default": False}], "app": {}},
                      {"consent_default_on": battery["consent_default_on"]})
  _check("consent_prior_wired", abs(ans["consent_default_on"].noul - 0.15) < 1e-9, str(ans))

  # --- evaluate: composition ---------------------------------------------------
  def _answers(p_consent, p_transmit=0.95, status="MISSING", cls="developer_backend"):
    n = len(q.DESTINATION_CLASS_OPTIONS)
    probs = {o: (0.9 if o == cls else 0.1 / (n - 1)) for o in q.DESTINATION_CLASS_OPTIONS}
    a = {
        "signal_relevant": JevAnswer("noul", noul=0.9),
        "transmits_offdevice": JevAnswer("noul", noul=p_transmit),
        "user_initiated": JevAnswer("noul", noul=0.2),
        "destination_class": JevAnswer("choice", choice=cls, probabilities=probs, confidence=0.9),
        "has_prominent_disclosure": JevAnswer("noul", noul=0.9 if status == "DISCLOSED" else 0.1),
        "disclosure_status": JevAnswer("choice", choice=status),
        "severity": JevAnswer("score", score=0.6),
    }
    if p_consent is not None:
      a["consent_default_on"] = JevAnswer("noul", noul=p_consent)
    return a

  def _state(guards):
    s = {
        "signal": {"data_type": "CRASH_LOGS", "matched_pattern": "report", "file": "Reporter.kt",
                   "line": 13, "matched_line": "URL(...)", "all_lines": [13]},
        "code_snippet": "L13: URL(...)",
        "sinks": [{"symbol": "URL", "capabilities": ["NETWORK_EGRESS"], "lines": [13]}],
        "anchor": {"scope": [8, 19], "proximity": 0, "sink_in_scope": True, "tier": 0,
                   "scope_capabilities": ["NETWORK_EGRESS"], "destination_hints": [],
                   "guard_defaults": [g.get("runs_by_default") for g in guards if g.get("declaration")]},
        "app": {},
    }
    if guards:
      s["guards"] = guards
    return s

  on_guard = {"flag": "ps.crashReportsEnabled", "line": 9, "runs_when": "true", "default_on": True, "runs_by_default": True,
              "declaration": {"file": "settings/PersistentState.kt", "line": 4, "text": "var crashReportsEnabled by booleanPref(true)",
                              "initialiser": "booleanPref(true)", "default_on": True, "resolution": "receiver_type"}}
  off_guard = {"flag": "uploadEnabled", "line": 17, "runs_when": "true", "default_on": False, "runs_by_default": False,
               "declaration": {"file": "Reporter.kt", "line": 6, "text": "var uploadEnabled: Boolean = false",
                               "initialiser": "false", "default_on": False, "resolution": "same_file"}}
  # Declared true but the transfer runs when the flag is *false* (``if (!optOut) send()``).
  inverted_off_guard = {"flag": "optedIn", "line": 12, "runs_when": "false", "default_on": True, "runs_by_default": False,
                        "declaration": {"file": "Reporter.kt", "line": 7, "text": "var optedIn = true",
                                        "initialiser": "true", "default_on": True, "resolution": "same_file"}}
  computed_guard = {"flag": "ps.reportingEnabled", "line": 9, "runs_when": "true", "early_exit": True,
                    "default_on": None, "runs_by_default": None,
                    "declaration": {"file": "settings/PersistentState.kt", "line": 40,
                                    "text": "var reportingEnabled by booleanPref(\"k\").withDefault<Boolean>(Flavour.isStore())",
                                    "initialiser": "booleanPref(\"k\").withDefault<Boolean>(Flavour.isStore())",
                                    "default_on": None, "resolution": "receiver_type"}}
  unknown_guard = {"flag": "settings.isTelemetryOn", "line": 11, "runs_when": "true", "default_on": None,
                   "runs_by_default": None, "declaration": None}
  compose = evaluate._compose_data_safety_finding  # pylint: disable=protected-access
  # CRASH_LOGS is not a sensitive type: an undisclosed transfer starts IMPORTANT.
  base_f = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([]), _answers(None), "test")
  _check("consent_not_asked_no_change", base_f["severity"] == "IMPORTANT" and base_f["consent_default_on"] is None
         and base_f["decision_trace"]["consent"]["action"] == "none"
         and base_f["decision_trace"]["consent"]["corroboration"] == "not_applicable", str(base_f["decision_trace"]["consent"]))
  # Raise: default-on with a corroborating guard.
  raised = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([on_guard]), _answers(0.9), "test")
  _check("consent_raise_guard_default_on",
         raised["severity"] == "CRITICAL" and raised["consent_default_on"] is True
         and raised["decision_trace"]["consent"]["action"] == "raise"
         and raised["decision_trace"]["consent"]["corroboration"] == "guard_default_on"
         and raised["issue_summary"].endswith("[enabled by default]")
         and raised.get("needs_manual_review") is None
         and raised["policy_id"] == "prominent_disclosure_policy",
         str((raised["severity"], raised["issue_summary"], raised["decision_trace"]["consent"])))
  _check("consent_evidence_suffix",
         "[guard ps.crashReportsEnabled default=true @settings/PersistentState.kt:L4]" in raised["evidence"]
         and raised["evidence_flow"]["guards"][0]["flag"] == "ps.crashReportsEnabled", raised["evidence"])
  _check("consent_trace_shape",
         set(raised["decision_trace"]["consent"]) >= {"p_default_on", "guards", "guard_defaults", "default_on", "action", "corroboration", "enabled"}
         and raised["decision_trace"]["consent"]["guards"][0]["declaration"] == "settings/PersistentState.kt:L4"
         and raised["decision_trace"]["anchor"]["guard_defaults"] == [True]
         and raised["decision_trace"]["thresholds"]["T_CONSENT_DEFAULT_ON"] == constants.T_CONSENT_DEFAULT_ON,
         str(raised["decision_trace"]["consent"]))
  # Raise: unconditional (no guards) and model-only (unresolved guard).
  uncond = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([]), _answers(0.7), "test")
  _check("consent_raise_unconditional", uncond["severity"] == "CRITICAL"
         and uncond["decision_trace"]["consent"]["corroboration"] == "unconditional")
  model_only = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([unknown_guard]), _answers(0.7), "test")
  _check("consent_raise_model_only", model_only["severity"] == "CRITICAL"
         and model_only["decision_trace"]["consent"]["corroboration"] == "model_only"
         and "[guard settings.isTelemetryOn default=unknown]" in model_only["evidence"], model_only["evidence"])
  # Veto: model says default-on but a guard is declared default-off -> unchanged, review.
  veto = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([off_guard]), _answers(0.9), "test")
  _check("consent_vetoed_by_guard", veto["severity"] == "IMPORTANT" and veto["consent_default_on"] is None
         and veto["decision_trace"]["consent"]["corroboration"] == "vetoed_by_guard"
         and veto.get("needs_manual_review") is True
         and "[consent default unclear: model default-on vs guard default-off; verify]" in veto["issue_summary"],
         str((veto["severity"], veto["issue_summary"])))
  # Lower: double gate (confident opt-in AND a default-off guard).
  lowered = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([off_guard]), _answers(0.1), "test")
  _check("consent_lower_double_gate",
         lowered["severity"] == "SUGGESTION" and lowered["consent_default_on"] is False
         and lowered["decision_trace"]["consent"]["action"] == "lower"
         and lowered.get("needs_manual_review") is True
         and lowered["prominent_disclosure_status"] == "MISSING"
         and "[opt-in: uploadEnabled off by default; verify toggle text]" in lowered["issue_summary"],
         str((lowered["severity"], lowered["issue_summary"])))
  # The composer acts on ``runs_by_default``, not on the declared literal: a
  # flag declared true whose *false* value runs the transfer is an opt-in.
  inv = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([inverted_off_guard]), _answers(0.1), "test")
  _check("consent_lower_uses_runs_by_default", inv["severity"] == "SUGGESTION"
         and "[opt-in: optedIn off by default; verify toggle text]" in inv["issue_summary"]
         and "[guard optedIn default=true runs when false @Reporter.kt:L7]" in inv["evidence"],
         str((inv["issue_summary"], inv["evidence"])))
  inv_raise = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([inverted_off_guard]), _answers(0.9), "test")
  _check("consent_veto_uses_runs_by_default", inv_raise["severity"] == "IMPORTANT"
         and inv_raise["decision_trace"]["consent"]["corroboration"] == "vetoed_by_guard")
  # A default computed from an expression is unknown; the initialiser is quoted in the evidence.
  comp = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([computed_guard]), _answers(0.7), "test")
  _check("consent_computed_default_model_only", comp["severity"] == "CRITICAL"
         and comp["decision_trace"]["consent"]["corroboration"] == "model_only"
         and "default=unknown init=\"booleanPref('k').withDefault<Boolean>(Flavour.isStore())\"" in comp["evidence"]
         and "@settings/PersistentState.kt:L40" in comp["evidence"], comp["evidence"])
  # UNCERTAIN band: default-on is recorded but the IMPORTANT cap stands.
  capped = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([on_guard]), _answers(0.9, p_transmit=0.5), "test")
  _check("consent_uncertain_band_capped", capped["transfer_decision"] == "UNCERTAIN"
         and capped["severity"] == "IMPORTANT" and capped["consent_default_on"] is True
         and capped["decision_trace"]["consent"]["action"] == "none"
         and capped["decision_trace"]["consent"]["capped_by"] == "uncertain_band"
         and "[enabled by default]" not in capped["issue_summary"]
         and "capped at IMPORTANT" in capped["decision_trace"]["consent_note"],
         str((capped["severity"], capped["decision_trace"]["consent"])))
  capped_lower = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([off_guard]), _answers(0.1, p_transmit=0.5), "test")
  _check("consent_uncertain_band_lower_allowed", capped_lower["severity"] == "SUGGESTION"
         and capped_lower["decision_trace"]["consent"]["action"] == "lower")
  # Unresolved destination (unknown / unconfirmed non-collection): no raise, default-on recorded.
  unk = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([on_guard]), _answers(0.9, cls="unknown"), "test")
  _check("consent_unknown_destination_capped", unk["severity"] == "IMPORTANT" and unk["consent_default_on"] is True
         and unk["decision_trace"]["consent"]["capped_by"] == "unresolved_destination"
         and "[enabled by default]" not in unk["issue_summary"] and unk.get("needs_manual_review") is True
         and "destination (unknown) is unresolved" in unk["decision_trace"]["consent_note"],
         str((unk["severity"], unk["issue_summary"])))
  # user_chosen_destination at high confidence but without corroboration (no hint,
  # not user-initiated) is unconfirmed -> review, not a Critical.
  uc_state = _state([])
  uc_unconf = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", uc_state, _answers(0.9, cls="user_chosen_destination"), "test")
  _check("consent_unconfirmed_user_chosen_capped", uc_unconf["severity"] == "IMPORTANT"
         and uc_unconf["decision_trace"]["consent"]["capped_by"] == "unresolved_destination"
         and "unconfirmed" in uc_unconf["issue_summary"], str((uc_unconf["severity"], uc_unconf["issue_summary"])))
  # A local boolean declared inside the anchor's own scope never corroborates or vetoes.
  local_off = {"flag": "need_restore", "line": 15, "runs_when": "true", "default_on": False, "runs_by_default": None,
               "declaration": {"file": "Reporter.kt", "line": 12, "text": "boolean need_restore = false;",
                               "initialiser": "false", "default_on": False, "resolution": "local"}}
  loc = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([local_off]), _answers(0.9), "test")
  _check("consent_local_guard_does_not_veto", loc["severity"] == "CRITICAL"
         and loc["decision_trace"]["consent"]["corroboration"] == "model_only"
         and loc["decision_trace"]["consent"]["guard_defaults"] == []
         and "[guard need_restore default=false @Reporter.kt:L12]" in loc["evidence"], str(loc["decision_trace"]["consent"]))
  loc_low = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([local_off]), _answers(0.1), "test")
  _check("consent_local_guard_does_not_lower", loc_low["severity"] == "IMPORTANT"
         and loc_low["decision_trace"]["consent"]["corroboration"] == "uncorroborated")
  loc_and_field = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([local_off, on_guard]), _answers(0.9), "test")
  _check("consent_evidence_prefers_non_local", "[guard ps.crashReportsEnabled default=true @settings/PersistentState.kt:L4]"
         in loc_and_field["evidence"] and loc_and_field["decision_trace"]["consent"]["corroboration"] == "guard_default_on",
         loc_and_field["evidence"])
  # No lower without the deterministic half ...
  uncorr = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([unknown_guard]), _answers(0.1), "test")
  _check("consent_no_lower_without_guard", uncorr["severity"] == "IMPORTANT"
         and uncorr["decision_trace"]["consent"]["corroboration"] == "uncorroborated"
         and uncorr["consent_default_on"] is None)
  no_guard_low = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([]), _answers(0.1), "test")
  _check("consent_no_lower_unconditional", no_guard_low["severity"] == "IMPORTANT")
  # ... nor with a mid-band answer (low confidence either way).
  mid = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([off_guard]), _answers(0.4), "test")
  _check("consent_low_confidence_no_change", mid["severity"] == "IMPORTANT"
         and mid["decision_trace"]["consent"]["corroboration"] == "low_confidence")
  # Mixed guards: any default-off vetoes the raise.
  mixed = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([on_guard, off_guard]), _answers(0.9), "test")
  _check("consent_mixed_guards_veto", mixed["severity"] == "IMPORTANT"
         and mixed["decision_trace"]["consent"]["corroboration"] == "vetoed_by_guard")
  # Not applicable: disclosed transfer, local-only, and an applied non-collection destination.
  disclosed = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([on_guard]), _answers(0.9, status="DISCLOSED"), "test")
  _check("consent_not_for_disclosed", disclosed["severity"] == "SUGGESTION"
         and disclosed["decision_trace"]["consent"]["action"] == "none")
  local = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([on_guard]), _answers(0.9, p_transmit=0.05), "test")
  _check("consent_not_for_local", local["severity"] == "SUGGESTION" and local["decision_trace"]["consent"]["action"] == "none")
  applied_state = _state([on_guard])
  applied_state["anchor"]["destination_hints"] = ["USER_CHOSEN_DESTINATION"]
  applied_state["destination_hints"] = [{"hint": "USER_CHOSEN_DESTINATION", "line": 9, "detail": "chooser", "evidence": "x"}]
  applied = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", applied_state,
                    _answers(0.9, cls="user_chosen_destination"), "test")
  _check("consent_not_for_applied_destination", applied["severity"] == "SUGGESTION"
         and applied["decision_trace"]["consent"]["action"] == "none", str(applied["decision_trace"]["destination"]))
  # Sensitive type already CRITICAL: raise is a no-op on severity, still traced as default-on.
  sens_state = _state([on_guard])
  sens_state["signal"]["data_type"] = "EMAILS"
  sens = compose("EMAILS", "Reporter.kt (Pattern: report)", sens_state, _answers(0.9), "test")
  _check("consent_sensitive_already_critical", sens["severity"] == "CRITICAL" and sens["consent_default_on"] is True
         and sens["decision_trace"]["consent"]["action"] == "none")
  # Rollback flag.
  saved = constants.CONSENT_DEFAULT_ENABLED
  try:
    constants.CONSENT_DEFAULT_ENABLED = False
    off_f = compose("CRASH_LOGS", "Reporter.kt (Pattern: report)", _state([on_guard]), _answers(0.9), "test")
    _check("consent_disabled_traced_only", off_f["severity"] == "IMPORTANT" and off_f["consent_default_on"] is None
           and off_f["decision_trace"]["consent"]["enabled"] is False
           and off_f["decision_trace"]["consent"]["p_default_on"] == 0.9)
  finally:
    constants.CONSENT_DEFAULT_ENABLED = saved

  # --- android_manifest: partial_sources ---------------------------------------
  profile = am.AppProfile(source_sets=["main", "play", "fdroid"])
  profile.permissions = {
      "android.permission.ACCESS_FINE_LOCATION": am.Permission("android.permission.ACCESS_FINE_LOCATION", sources=["play"]),
      "android.permission.RECORD_AUDIO": am.Permission("android.permission.RECORD_AUDIO", sources=["main"]),
      "android.permission.READ_CONTACTS": am.Permission("android.permission.READ_CONTACTS", sources=["main", "play"]),
      "android.permission.INTERNET": am.Permission("android.permission.INTERNET"),
      "android.permission.GET_ACCOUNTS": am.Permission("android.permission.GET_ACCOUNTS", sources=["fdroid"]),
  }
  ps = profile.partial_sources
  _check("partial_sources_flavour_only", ps(profile.permissions["android.permission.ACCESS_FINE_LOCATION"]) == ["play"])
  _check("partial_sources_main_none", ps(profile.permissions["android.permission.RECORD_AUDIO"]) is None
         and ps(profile.permissions["android.permission.READ_CONTACTS"]) is None)
  _check("partial_sources_no_sources_none", ps(profile.permissions["android.permission.INTERNET"]) is None)
  _check("partial_sources_unshipped_flavour_none", ps(profile.permissions["android.permission.GET_ACCOUNTS"]) is None)
  no_play = am.AppProfile(source_sets=["main", "foss"])
  _check("partial_sources_all_shipped_none",
         no_play.partial_sources(am.Permission("x", sources=["main", "foss"])) is None
         and no_play.partial_sources(am.Permission("x", sources=["foss"])) == ["foss"])
  svc = am.Component("service", "com.w8.Svc", sources=["play"])
  profile.components = [svc]
  _check("partial_sources_component", ps(svc) == ["play"])

  # --- engine: attribution ------------------------------------------------------
  ctx = engine.RunContext(temp_dir="", app_dir="", app_facts={}, manifest={}, profile=profile)
  f_perm = {"policy_id": "x", "files_involved": ["AndroidManifest.xml"],
            "decision_trace": {"permission": "android.permission.ACCESS_FINE_LOCATION"}}
  engine._attribute_sources(ctx, f_perm, "x")  # pylint: disable=protected-access
  _check("attribute_sources_manifest_permission", f_perm.get("manifest_sources") == ["play"]
         and f_perm["decision_trace"]["manifest_sources"] == ["play"]
         and ctx.counters.get("manifest_sources_attributed") == 1, str(f_perm))
  f_svc = {"policy_id": "fgs", "decision_trace": {"service": "com.w8.Svc"}}
  engine._attribute_sources(ctx, f_svc, "fgs")  # pylint: disable=protected-access
  _check("attribute_sources_service", f_svc.get("manifest_sources") == ["play"])
  f_code = {"policy_id": "location_access_policy", "files_involved": ["a/B.kt"], "decision_trace": {}}
  engine._attribute_sources(ctx, f_code, "location_access_policy")  # pylint: disable=protected-access
  _check("attribute_sources_policy_permissions", f_code.get("manifest_sources") == ["play"], str(f_code))
  f_main = {"policy_id": "audio_recording_policy", "decision_trace": {}}
  engine._attribute_sources(ctx, f_main, "audio_recording_policy")  # pylint: disable=protected-access
  _check("attribute_sources_main_untouched", "manifest_sources" not in f_main
         and "manifest_sources" not in f_main["decision_trace"])
  f_other = {"policy_id": "photo_video_policy", "decision_trace": {}}
  engine._attribute_sources(ctx, f_other, "photo_video_policy")  # pylint: disable=protected-access
  _check("attribute_sources_unmapped_policy_untouched", "manifest_sources" not in f_other)
  ctx_none = engine.RunContext(temp_dir="", app_dir="", app_facts={}, manifest={})
  f_np = {"decision_trace": {"permission": "android.permission.ACCESS_FINE_LOCATION"}}
  engine._attribute_sources(ctx_none, f_np, "x")  # pylint: disable=protected-access
  _check("attribute_sources_no_profile_noop", "manifest_sources" not in f_np)
  saved_attr = constants.PERMISSION_ATTRIBUTION_ENABLED
  try:
    constants.PERMISSION_ATTRIBUTION_ENABLED = False
    f_off = {"decision_trace": {"permission": "android.permission.ACCESS_FINE_LOCATION"}}
    engine._attribute_sources(ctx, f_off, "x")  # pylint: disable=protected-access
    _check("attribute_sources_disabled_noop", "manifest_sources" not in f_off)
  finally:
    constants.PERMISSION_ATTRIBUTION_ENABLED = saved_attr


def _test_callee_resolution() -> None:
  """WP6: one-hop first-party callee resolution (index, state, ranking, evidence, engine)."""
  from typesafe_eval import capabilities as capsmod
  from typesafe_eval import constants
  from typesafe_eval import context
  from typesafe_eval import engine
  from typesafe_eval import structure
  from typesafe_eval.client import HeuristicJevClient, JevAnswer

  net_profile = capsmod.CapabilityProfile("okhttp3.OkHttpClient", "import", {"NETWORK_EGRESS": 0.95},
                                          ["NETWORK_EGRESS"], "model", "m")
  db_profile = capsmod.CapabilityProfile("androidx.room.Room", "import", {"LOCAL_PERSISTENCE": 0.9},
                                         ["LOCAL_PERSISTENCE"], "model", "m")
  intent_profile = capsmod.CapabilityProfile("android.content.Intent", "import", {"IPC_SHARING": 0.9},
                                             ["IPC_SHARING"], "model", "m")
  log_profile = capsmod.CapabilityProfile("android.util.Log", "import", {}, [], "model", "m")
  profiles = {"okhttp3.OkHttpClient": net_profile, "androidx.room.Room": db_profile,
              "android.content.Intent": intent_profile, "android.util.Log": log_profile}

  with tempfile.TemporaryDirectory() as d:
    def write(rel, text):
      full = os.path.join(d, rel)
      os.makedirs(os.path.dirname(full), exist_ok=True)
      with open(full, "w", encoding="utf-8") as f:
        f.write(text)

    src = "app/src/main/java/com/w6"
    # Helper that owns the network client (the "thin wrapper" the labelled set showed).
    write(f"{src}/net/Uploader.kt",
          "package com.w6.net\nimport okhttp3.OkHttpClient\nimport android.util.Log\n"
          "object Uploader {\n  fun send(payload: String) {\n    Log.d(\"u\", payload)\n"
          "    OkHttpClient().newCall(req(payload)).execute()\n  }\n}\n")
    # Helper that only persists locally.
    write(f"{src}/db/Store.kt",
          "package com.w6.db\nimport androidx.room.Room\nobject Store {\n  fun save(v: String) {\n"
          "    Room.databaseBuilder(ctx, Db::class.java, \"x\").build().dao().insert(v)\n  }\n}\n")
    # Helper that shares through IPC.
    write(f"{src}/share/Sharer.kt",
          "package com.w6.share\nimport android.content.Intent\nobject Sharer {\n  fun out(v: String) {\n"
          "    ctx.startActivity(Intent().putExtra(\"v\", v))\n  }\n}\n")
    # Same simple name in two flavours (ambiguity -> nearest / import resolution).
    write("app/src/free/java/com/w6/flavor/Flags.kt", "package com.w6.flavor\nobject Flags\n")
    write("app/src/paid/java/com/w6/flavor/Flags.kt", "package com.w6.flavor\nobject Flags\n")
    # An app class shadowing a platform name: callers importing android.util.Log must NOT resolve to it.
    write(f"{src}/util/Log.kt", "package com.w6.util\nobject Log\n")
    # Test source is never indexed.
    write("app/src/test/java/com/w6/Uploader.kt", "package com.w6\nobject Uploader\n")
    # Caller: two functions read the location; only ``sync`` hands it to the uploader.
    caller_rel = f"{src}/ui/Main.kt"
    write(caller_rel,
          "package com.w6.ui\nimport com.w6.net.Uploader\nimport com.w6.db.Store\nimport android.util.Log\n"
          "// Uploader is documented here; a comment must not count as a call\n"
          "class Main {\n"
          "  fun show() {\n    val l = getLastKnownLocation()\n    Store.save(l.toString())\n    Log.d(\"m\", l)\n  }\n"
          "  fun sync() {\n    val l = getLastKnownLocation()\n    Uploader.send(l.toString())\n  }\n"
          "  fun flags() { Flags.toString() }\n"
          "}\n")

    index = structure.build_first_party_index(d)
    _check("callee_index_names",
           set(index.by_name) >= {"Uploader", "Store", "Sharer", "Flags", "Log", "Main"}
           and index.by_name["Uploader"] == [f"{src}/net/Uploader.kt"]
           and len(index.by_name["Flags"]) == 2, str(index.by_name))
    _check("callee_index_packages", "com.w6.net" in index.packages and "com.w6" not in index.packages,
           str(index.packages))
    fs = structure.analyze_file(d, caller_rel)
    refs = structure.callee_references(fs, index)
    by_sym = {r.symbol: r for r in refs}
    _check("callee_refs_resolved",
           set(by_sym) == {"Uploader", "Store", "Flags"}, str(sorted(by_sym)))
    _check("callee_refs_import_resolution",
           by_sym["Uploader"].resolution == "import" and by_sym["Uploader"].relpath == f"{src}/net/Uploader.kt"
           and by_sym["Uploader"].lines == [13], str(by_sym["Uploader"]))
    _check("callee_refs_platform_shadow_skipped", "Log" not in by_sym, str(sorted(by_sym)))
    _check("callee_refs_ambiguous_nearest",
           by_sym["Flags"].resolution == "nearest" and by_sym["Flags"].relpath.startswith("app/src/"),
           str(by_sym["Flags"]))
    within = structure.callee_references(fs, index, within=range(11, 15))
    _check("callee_refs_within_scope_filter", [r.symbol for r in within] == ["Uploader"], str(within))

    # Same-package implicit import resolves without an import line.
    fs_same = structure.FileStructure("app/src/main/java/com/w6/net/Other.kt", "kotlin",
                                      ["package com.w6.net", "fun f() { Uploader.send(\"x\") }"], [], {}, "com.w6.net")
    same = index.resolve("Uploader", fs_same)
    _check("callee_resolve_same_package", same is not None and same.resolution == "same_package", str(same))
    _check("callee_resolve_self_excluded", index.resolve("Main", fs) is None)
    # Import from a package no first-party file declares: not a callee.
    fs_shadow = structure.FileStructure("app/X.kt", "kotlin", ["Log.d(\"a\", 1)"], ["android.util.Log"], {}, "com.w6.ui")
    _check("callee_resolve_foreign_import_none", index.resolve("Log", fs_shadow) is None)

    # --- member extraction and declaration lookup (member-level hop) ------------
    _check("callee_called_members",
           structure.called_members("    Uploader.send(l.toString())", "Uploader") == ["send"]
           and structure.called_members("Uploader(ctx).send(x); Uploader.INSTANCE.flush()", "Uploader") == ["send", "flush"]
           and structure.called_members("val u: Uploader = Uploader(ctx)", "Uploader") == []
           and structure.called_members("map(Uploader::send)", "Uploader") == ["send"]
           and structure.called_members("Uploader.Companion.make()", "Uploader") == ["make"])
    up_lines = callee_files_probe = structure.analyze_file(d, f"{src}/net/Uploader.kt").lines
    _check("callee_member_declaration_kotlin",
           structure.member_declaration_lines(up_lines, "send") == [4]
           and structure.declaration_scope(up_lines, 4) == (4, 8), str(structure.member_declaration_lines(up_lines, "send")))
    java_lines = ["public class Net {", "  private static int count;", "  public static void send(String p) {",
                  "    Client c = new Client();", "    c.post(p);", "  }", "  int other() { return send(1); }", "}"]
    _check("callee_member_declaration_java",
           structure.member_declaration_lines(java_lines, "send") == [2]
           and structure.declaration_scope(java_lines, 2) == (2, 6), str(structure.member_declaration_lines(java_lines, "send")))
    expr_lines = ["object K {", "  fun ping() = Client().get()", "  val endpoint = Client().url", "}"]
    _check("callee_member_declaration_expression_body",
           structure.member_declaration_lines(expr_lines, "ping") == [1] and structure.declaration_scope(expr_lines, 1) == (1, 2)
           and structure.member_declaration_lines(expr_lines, "endpoint") == [2])
    del callee_files_probe

    # --- context: state, anchor tier, snippet -----------------------------------
    callee_files = {r.relpath: structure.analyze_file(d, r.relpath) for r in refs}
    callees = context.file_callees(fs, refs, callee_files, profiles)
    by_callee = {c.symbol: c for c in callees}
    _check("callee_file_level_capabilities",
           by_callee["Uploader"].capabilities == ["NETWORK_EGRESS"] and by_callee["Store"].capabilities == []
           and by_callee["Uploader"].member_scopes.get("send") == [(4, 8)], str(by_callee["Uploader"].member_scopes))
    asks = [("PRECISE_LOCATION", "getLastKnownLocation")]
    state, per = context.build_file_state(fs, asks, profiles, {"name": "X"}, callees=callees)
    anchor = per[0]["anchor"]
    _check("callee_anchor_prefers_transfer_hop",
           per[0]["signal"]["line"] == 13 and anchor["tier"] == 0 and anchor["sink_in_scope"] is False
           and anchor["callee_in_scope"] is True and anchor["callee_capabilities"] == ["NETWORK_EGRESS"],
           json.dumps(anchor))
    _check("callee_state_block",
           len(state.get("callees") or []) == 1 and state["callees"][0]["symbol"] == "Uploader"
           and state["callees"][0]["hop"] == 1 and state["callees"][0]["called_at"] == [14]
           and state["callees"][0]["members"] == ["send"] and state["callees"][0]["granularity"] == "member"
           and state["callees"][0]["sinks"][0]["symbol"] == "OkHttpClient"
           and "fun send" in state["callees"][0]["code_snippet"], json.dumps(state.get("callees")))
    # Member granularity: a method that reaches no sink yields an empty hop even
    # though the callee file has a network client elsewhere.
    write(f"{src}/net/Mixed.kt",
          "package com.w6.net\nimport okhttp3.OkHttpClient\nobject Mixed {\n"
          "  fun format(v: String): String {\n    return v.trim()\n  }\n"
          "  fun post(v: String) {\n    OkHttpClient().newCall(v).execute()\n  }\n}\n")
    index_m = structure.build_first_party_index(d)
    fs_mixed = structure.FileStructure(
        caller_rel, "kotlin",
        ["package com.w6.ui", "import com.w6.net.Mixed", "class Main {",
         "  fun a() {", "    val l = getLastKnownLocation()", "    Mixed.format(l.toString())", "  }",
         "  fun b() {", "    val l = getLastKnownLocation()", "    Mixed.post(l.toString())", "  }",
         "  fun c() {", "    val l = getLastKnownLocation()", "    val m = Mixed", "    m.post(l.toString())", "  }", "}"],
        ["com.w6.net.Mixed"], {}, "com.w6.ui")
    refs_mixed = structure.callee_references(fs_mixed, index_m)
    callees_mixed = context.file_callees(fs_mixed, refs_mixed,
                                         {r.relpath: structure.analyze_file(d, r.relpath) for r in refs_mixed}, profiles)
    mixed = callees_mixed[0]
    va, vb, vc = mixed.view((3, 7)), mixed.view((7, 11)), mixed.view((11, 16))
    _check("callee_member_view_no_sink",
           va.granularity == "member" and va.members == ["format"] and va.sinks == [] and va.capabilities == [], str(va.members))
    _check("callee_member_view_with_sink",
           vb.granularity == "member" and vb.members == ["post"] and [s.symbol for s in vb.sinks] == ["OkHttpClient"]
           and vb.sinks[0].lines == [7], str(vb.sinks))
    _check("callee_file_fallback_without_member",
           vc.granularity == "file" and vc.members == [] and [s.symbol for s in vc.sinks] == ["OkHttpClient"], str(vc.granularity))
    state_mx, per_mx = context.build_file_state(fs_mixed, asks, profiles, {"name": "X"}, callees=callees_mixed)
    _check("callee_member_anchor_choice",
           per_mx[0]["signal"]["line"] == 9 and per_mx[0]["anchor"]["tier"] == 0
           and per_mx[0]["callees"][0]["members"] == ["post"], json.dumps(per_mx[0]["anchor"]))
    # An unlocated member (inherited/extension) falls back to file level.
    fs_unloc = structure.FileStructure(
        caller_rel, "kotlin", ["package com.w6.ui", "fun z() {", "  val l = getLastKnownLocation()", "  Mixed.inherited(l)", "}"],
        [], {}, "com.w6.ui")
    refs_unloc = structure.callee_references(fs_unloc, index_m)
    cal_unloc = context.file_callees(fs_unloc, refs_unloc,
                                     {r.relpath: structure.analyze_file(d, r.relpath) for r in refs_unloc}, profiles)[0]
    vu = cal_unloc.view((1, 5))
    _check("callee_unlocated_member_file_fallback",
           cal_unloc.member_scopes.get("inherited") == [] and vu.granularity == "file" and vu.members == ["inherited"]
           and vu.capabilities == ["NETWORK_EGRESS"], str(vu.granularity))
    _check("callee_snippet_section",
           "First-party callees reached from the snippet" in state["code_snippet"]
           and "OkHttpClient().newCall" in state["code_snippet"]
           and "First-party callee Uploader" in per[0]["code_snippet"], state["code_snippet"])
    _check("callee_network_hint", "Uploader.OkHttpClient" in state["co_located_signals"]["network_transmission"],
           str(state["co_located_signals"]))
    # Without callees the state is byte-identical to the pre-WP6 form.
    plain, plain_per = context.build_file_state(fs, asks, profiles, {"name": "X"})
    _check("callee_absent_state_unchanged",
           "callees" not in plain and plain_per[0]["callees"] == [] and plain_per[0]["anchor"]["tier"] == 3
           and "First-party callee" not in plain["code_snippet"], json.dumps(plain_per[0]["anchor"]))

    # Local-DB helper only: callee is shown with no transfer sink; tier stays 3.
    fs_local = structure.FileStructure(
        caller_rel, "kotlin",
        ["package com.w6.ui", "import com.w6.db.Store", "class Main {", "  fun show() {",
         "    val l = getLastKnownLocation()", "    Store.save(l.toString())", "  }", "}"],
        ["com.w6.db.Store"], {}, "com.w6.ui")
    refs_local = structure.callee_references(fs_local, index)
    callees_local = context.file_callees(fs_local, refs_local, callee_files, profiles)
    state_l, per_l = context.build_file_state(fs_local, asks, profiles, {"name": "X"}, callees=callees_local)
    _check("callee_local_helper_no_transfer",
           [c["symbol"] for c in state_l.get("callees") or []] == ["Store"]
           and state_l["callees"][0]["capabilities"] == [] and per_l[0]["anchor"]["tier"] == 3
           and per_l[0]["anchor"]["callee_in_scope"] is False
           and "no capability-labelled transfer sink" in state_l["code_snippet"], json.dumps(state_l.get("callees")))

    # --- evaluate: evidence, files, sharing, soft gate, composed decisions ------
    mini = per[0]
    sink = evaluate.nearest_sink(mini)
    _check("callee_nearest_sink_via",
           sink and sink["file"] == f"{src}/net/Uploader.kt" and sink["via"] == "Uploader"
           and sink["called_at"] == 14 and sink["symbol"] == "OkHttpClient" and sink["in_scope"] is True, str(sink))
    ev = evaluate._evidence_line(mini)  # pylint: disable=protected-access
    _check("callee_evidence_line",
           ev == (f"source@{caller_rel}:L12-L15 (L13: val l = getLastKnownLocation()) -> "
                  f"sink@{src}/net/Uploader.kt:L7 OkHttpClient [NETWORK_EGRESS] (via Uploader called at L14)"), ev)
    _check("callee_files_involved", evaluate.files_involved(mini) == [caller_rel, f"{src}/net/Uploader.kt"],
           str(evaluate.files_involved(mini)))
    _check("callee_file_egress_for_soft_gate", evaluate.file_has_strong_egress(mini) is True
           and evaluate.file_has_strong_egress(per_l[0]) is False)
    # Same-file in-scope sink still wins over a callee sink; out-of-scope same-file loses to callee.
    with_same = {**mini, "sinks": [{"symbol": "Socket", "capabilities": ["NETWORK_EGRESS"], "lines": [13]}]}
    with_far = {**mini, "sinks": [{"symbol": "Socket", "capabilities": ["NETWORK_EGRESS"], "lines": [90]}]}
    _check("callee_sink_preference_order",
           evaluate.nearest_sink(with_same)["symbol"] == "Socket" and evaluate.nearest_sink(with_far)["via"] == "Uploader")
    # IPC in the callee counts as sharing in scope.
    fs_share = structure.FileStructure(
        caller_rel, "kotlin",
        ["package com.w6.ui", "import com.w6.share.Sharer", "fun go() {", "  val e = email()",
         "  Sharer.out(e)", "}"], ["com.w6.share.Sharer"], {}, "com.w6.ui")
    refs_share = structure.callee_references(fs_share, index)
    callees_share = context.file_callees(fs_share, refs_share,
                                         {r.relpath: structure.analyze_file(d, r.relpath) for r in refs_share}, profiles)
    _, per_s = context.build_file_state(fs_share, [("EMAIL", "email()")], profiles, {"name": "X"}, callees=callees_share)
    _check("callee_ipc_sharing_in_scope", evaluate.sharing_sinks_in_scope(per_s[0]) == ["Sharer.Intent"]
           and per_s[0]["anchor"]["tier"] == 1, str(evaluate.sharing_sinks_in_scope(per_s[0])))

    def answers(p_transmit, relevant=0.9, third=0.1):
      return {
          "signal_relevant": JevAnswer("noul", noul=relevant),
          "transmits_offdevice": JevAnswer("noul", noul=p_transmit),
          "user_initiated": JevAnswer("noul", noul=0.2),
          "is_third_party": JevAnswer("noul", noul=third),
          "has_prominent_disclosure": JevAnswer("noul", noul=0.1),
          "disclosure_status": JevAnswer("choice", choice="MISSING", probabilities={"MISSING": 0.9}),
          "severity": JevAnswer("score", score=2.0, probabilities={"2": 1.0}),
      }
    composed = evaluate._compose_data_safety_finding(  # pylint: disable=protected-access
        "PRECISE_LOCATION", "x", mini, answers(0.9), "test")
    _check("callee_composed_transmits",
           composed["transfer_decision"] == "TRANSMITS" and composed["files_involved"][-1].endswith("Uploader.kt")
           and composed["decision_trace"]["callees"][0]["symbol"] == "Uploader"
           and composed["decision_trace"]["anchor"]["callee_capabilities"] == ["NETWORK_EGRESS"]
           and composed["evidence_flow"]["sink"]["via"] == "Uploader", json.dumps(composed["decision_trace"]))
    composed_local = evaluate._compose_data_safety_finding(  # pylint: disable=protected-access
        "PRECISE_LOCATION", "x", per_l[0], answers(0.1), "test")
    _check("callee_composed_local",
           composed_local["transfer_decision"] == "LOCAL" and composed_local["files_involved"] == [caller_rel]
           and composed_local["decision_trace"]["callees"][0]["sinks"] == []
           and "Uploader" not in composed_local["evidence"], json.dumps(composed_local["decision_trace"]))
    # Uncertain relevance is kept for review because the hop reaches strong egress.
    soft = evaluate._compose_data_safety_finding(  # pylint: disable=protected-access
        "PRECISE_LOCATION", "x", mini, answers(0.9, relevant=constants.T_RELEVANCE - 0.05), "test")
    _check("callee_soft_gate_keeps", soft is not None and soft["decision_trace"]["relevance"] == "low"
           and soft.get("needs_manual_review") is True, json.dumps(soft and soft["decision_trace"]))

    # --- caps: callees per anchor and the sink-lines-only fallback -------------
    many_refs = []
    for i in range(5):
      rel = f"{src}/h/Helper{i}.kt"
      filler = "\n".join(f"    val x{k} = v.length + {k}" for k in range(20))
      body = f"  fun f0(v: String) {{\n{filler}\n    OkHttpClient().newCall(v).execute()\n  }}"
      write(rel, f"package com.w6.h\nimport okhttp3.OkHttpClient\nobject Helper{i} {{\n{body}\n}}\n")
      many_refs.append(rel)
    index2 = structure.build_first_party_index(d)
    fs_many = structure.FileStructure(
        caller_rel, "kotlin",
        ["package com.w6.ui", "fun go() {", "  val l = getLastKnownLocation()"]
        + [f"  Helper{i}.f0(l)" for i in range(5)] + ["}"], [], {}, "com.w6.ui")
    refs_many = structure.callee_references(fs_many, index2)
    callees_many = context.file_callees(fs_many, refs_many,
                                        {r.relpath: structure.analyze_file(d, r.relpath) for r in refs_many}, profiles)
    state_m, per_m = context.build_file_state(fs_many, asks, profiles, {"name": "X"}, callees=callees_many)
    _check("callee_cap_per_anchor", len(state_m["callees"]) == constants.MAX_CALLEES_PER_ANCHOR
           and len(per_m[0]["callees"]) == constants.MAX_CALLEES_PER_ANCHOR, str(len(state_m["callees"])))
    _check("callee_sink_lines_only_fallback",
           all("// sink:" in c["code_snippet"] and "fun f" not in c["code_snippet"] for c in state_m["callees"]),
           state_m["callees"][0]["code_snippet"])
    _check("callee_refs_per_caller_cap",
           len(structure.callee_references(fs_many, index2, cap=2)) == 2)

    # --- index excludes non-prioritised flavours (SDK stub case) ---------------
    write("app/src/fdroid/java/com/vendor/billing/BillingClient.kt", "package com.vendor.billing\nclass BillingClient\n")
    idx_all = structure.build_first_party_index(d)
    idx_excl = structure.build_first_party_index(d, excluded_flavors=["fdroid", "free"])
    _check("callee_index_excludes_flavors",
           "BillingClient" in idx_all.by_name and "BillingClient" not in idx_excl.by_name
           and len(idx_excl.by_name["Flags"]) == 1 and idx_excl.by_name["Flags"][0].startswith("app/src/paid/"),
           str(idx_excl.by_name.get("Flags")))

    # --- triage budget: exempt candidates do not displace tier-3 ones ----------
    ctx_t = engine.RunContext(temp_dir="", app_dir="", app_facts={}, manifest={})
    cands = {}
    n_exempt, n_tier3 = 6, constants.MAX_FINDINGS_PER_TYPE + 4
    for i in range(n_exempt + n_tier3):
      rel = f"t/F{i}.kt"
      with_sink = i < n_exempt
      lines = ["import okhttp3.OkHttpClient" if with_sink else "import java.util.Locale",
               "fun go() {", "  val e = email()", "  OkHttpClient().post(e)" if with_sink else "  show(e)", "}"]
      imports = ["okhttp3.OkHttpClient"] if with_sink else ["java.util.Locale"]
      ctx_t.files[rel] = structure.FileStructure(rel, "kotlin", lines, imports,
                                                 structure.symbol_references(lines, imports), "t")
      cands.setdefault("EMAIL", []).append(engine.Candidate("EMAIL", f"{rel} (Pattern: email())", rel, "email()", i))
    ctx_t.profiles = {"okhttp3.OkHttpClient": net_profile,
                      "java.util.Locale": capsmod.CapabilityProfile("java.util.Locale", "import", {}, [], "model", "m")}
    kept_t = engine._triage(ctx_t, cands)  # pylint: disable=protected-access
    tier3_kept = [c for c in kept_t["EMAIL"] if not c.anchor.reach_in_scope]
    exempt_kept = [c for c in kept_t["EMAIL"] if c.anchor.reach_in_scope]
    over = [d for d in ctx_t.dropped if d["reason"].startswith("over MAX_FINDINGS_PER_TYPE")]
    _check("triage_budget_excludes_exempt",
           len(exempt_kept) == n_exempt and len(tier3_kept) == constants.MAX_FINDINGS_PER_TYPE
           and len(over) == n_tier3 - constants.MAX_FINDINGS_PER_TYPE
           and ctx_t.counters["kept_budgeted"] == constants.MAX_FINDINGS_PER_TYPE
           and ctx_t.counters["cap_exempt_sink_in_scope"] == n_exempt,
           f"{len(exempt_kept)} exempt, {len(tier3_kept)} budgeted, {len(over)} over, {ctx_t.counters.get('kept_budgeted')}")

    # --- engine integration (heuristic client, hermetic) -----------------------
    # The manifest gives the profile package ``com.w6``; helper packages beneath
    # it are first-party (never classified), so the hop is the only way the
    # network client in Uploader.kt becomes visible -- the real-app situation.
    write("app/src/main/AndroidManifest.xml",
          '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.w6">'
          '<uses-sdk android:targetSdkVersion="36"/><application/></manifest>')
    scratch = os.path.join(d, ".scratch")
    _write_scratch(d, scratch, {"PRECISE_LOCATION": [f"{caller_rel} (Pattern: getLastKnownLocation)"]})
    engine.run(scratch, HeuristicJevClient(), batched=True)
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    cr = triage["counters"].get("callee_resolution") or {}
    ds = json.load(open(os.path.join(scratch, "worker_data_safety.json"), encoding="utf-8"))
    loc = [x for x in ds["findings"] if x.get("psl_constant") == "PRECISE_LOCATION" and x.get("kind") != "play_declaration"]
    _check("callee_engine_counters",
           cr.get("enabled") is True and cr.get("callers_with_callees") == 1 and cr.get("callee_files", 0) >= 2
           and caller_rel in (triage["counters"].get("callee_refs") or {})
           and triage["counters"].get("imports_from_callees", 0) >= 1
           and triage["counters"].get("anchors_with_callees") == 1
           and triage["counters"].get("anchors_tier_raised_by_callee") == 1, json.dumps(cr))
    _check("callee_engine_finding_transmits",
           len(loc) == 1 and loc[0]["transfer_decision"] == "TRANSMITS"
           and "(via Uploader called at" in loc[0]["evidence"]
           and loc[0]["files_involved"][-1].endswith("Uploader.kt")
           and loc[0]["decision_trace"]["callees"][0]["members"] == ["send"]
           and loc[0]["decision_trace"]["callees"][0]["granularity"] == "member",
           str([(x.get("transfer_decision"), x.get("evidence")) for x in loc]))
    fp = triage["counters"].get("first_party_packages") or []
    _check("callee_engine_first_party_from_profile",
           "com.w6" in fp and "com.w6.net" not in fp and triage["counters"].get("imports_first_party_skipped", 0) >= 2
           and triage["counters"]["first_party_index"]["excluded_flavors"] == [], str(fp))

    # Rollback flag: no index, no hops, state as before.
    constants.CALLEE_RESOLUTION_ENABLED = False
    try:
      scratch2 = os.path.join(d, ".scratch2")
      _write_scratch(d, scratch2, {"PRECISE_LOCATION": [f"{caller_rel} (Pattern: getLastKnownLocation)"]})
      engine.run(scratch2, HeuristicJevClient(), batched=True)
      triage2 = json.load(open(os.path.join(scratch2, engine.TRIAGE_FILENAME), encoding="utf-8"))
      ds2 = json.load(open(os.path.join(scratch2, "worker_data_safety.json"), encoding="utf-8"))
      loc2 = [x for x in ds2["findings"] if x.get("psl_constant") == "PRECISE_LOCATION" and x.get("kind") != "play_declaration"]
      _check("callee_flag_off",
             (triage2["counters"].get("callee_resolution") or {}).get("enabled") is False
             and "first_party_index" not in triage2["counters"]
             and loc2 and "via Uploader" not in loc2[0]["evidence"], json.dumps(triage2["counters"].get("callee_resolution")))
    finally:
      constants.CALLEE_RESOLUTION_ENABLED = True


def _test_evidence_line() -> None:
  """WP3 structured evidence: golden strings for the sink / no-sink / out-of-scope cases."""
  base = {
      "signal": {"data_type": "PRECISE_LOCATION", "matched_pattern": "loc", "file": "app/A.kt",
                 "line": 10, "matched_line": "  val l = loc()  ", "all_lines": [3, 10]},
      "anchor": {"scope": [8, 14], "proximity": 0, "sink_in_scope": True, "tier": 0},
      "sinks": [
          {"symbol": "SharedPreferences", "capabilities": ["LOCAL_PERSISTENCE"], "lines": [9]},
          {"symbol": "Intent", "capabilities": ["IPC_SHARING"], "lines": [2, 40]},
          {"symbol": "HttpClient", "capabilities": ["NETWORK_EGRESS"], "lines": [12, 30]},
      ],
  }
  ev = evaluate._evidence_line(base)  # pylint: disable=protected-access
  _check("evidence_structured_golden",
         ev == "source@app/A.kt:L8-L14 (L10: val l = loc()) -> sink@L12 HttpClient [NETWORK_EGRESS]", ev)
  flow = evaluate.evidence_flow(base)
  _check("evidence_flow_fields",
         flow["source"] == {"file": "app/A.kt", "line": 10, "scope": [8, 14], "matched": "val l = loc()"}
         and flow["sink"]["symbol"] == "HttpClient" and flow["sink"]["line"] == 12 and flow["sink"]["in_scope"] is True,
         json.dumps(flow))
  # Persistence-only symbols are not evidence sinks; nearest transfer sink out of scope is marked.
  far = {**base, "anchor": {**base["anchor"], "sink_in_scope": False, "tier": 3},
         "sinks": [base["sinks"][0], {"symbol": "Intent", "capabilities": ["IPC_SHARING"], "lines": [40, 2]}]}
  ev_far = evaluate._evidence_line(far)  # pylint: disable=protected-access
  _check("evidence_out_of_scope_marked",
         ev_far == "source@app/A.kt:L8-L14 (L10: val l = loc()) -> sink@L2 Intent [IPC_SHARING] (out of scope)", ev_far)
  none = {**base, "sinks": [base["sinks"][0]]}
  ev_none = evaluate._evidence_line(none)  # pylint: disable=protected-access
  _check("evidence_no_sink_fallback", ev_none == "app/A.kt:L10 — val l = loc()", ev_none)
  _check("evidence_flow_no_sink", evaluate.evidence_flow(none)["sink"] is None)
  legacy = {"signal": {"file": "app/B.kt", "line": 4, "matched_line": "x | y"}}
  ev_legacy = evaluate._evidence_line(legacy)  # pylint: disable=protected-access
  _check("evidence_legacy_state_and_pipe_safe", ev_legacy == "app/B.kt:L4 — x ¦ y", ev_legacy)
  long = {**base, "signal": {**base["signal"], "matched_line": "x" * 200}}
  ev_long = evaluate._evidence_line(long)  # pylint: disable=protected-access
  _check("evidence_matched_truncated", "…" in ev_long and len(ev_long) < 220 and "\n" not in ev_long, str(len(ev_long)))


def _test_relevance_token_embedded() -> None:
  b = q.data_safety_battery("AUDIO", "audio files", token="record")
  _check("relevance_embeds_token", "`record`" in b["signal_relevant"]["instructions"])
  _check("relevance_no_state_path", "signal.matched_pattern" not in b["signal_relevant"]["instructions"])
  p = q.permission_battery("audio_recording_policy", "AUDIO", "MediaRecorder")
  _check("permission_relevance_first", next(iter(p)) == "signal_relevant" and "`MediaRecorder`" in p["signal_relevant"]["instructions"])


def _test_triage_diff() -> None:
  from typesafe_eval import triage_diff
  with tempfile.TemporaryDirectory() as d:
    a, b = os.path.join(d, "a"), os.path.join(d, "b")
    os.makedirs(a)
    os.makedirs(b)
    base = {"policy_id": "data_safety_section", "files_involved": ["app/A.kt"],
            "psl_constant": "NAME", "severity": "IMPORTANT", "transfer_decision": "UNCERTAIN"}
    fgs = {"policy_id": "foreground_services_policy", "files_involved": ["AndroidManifest.xml"],
           "severity": "SUGGESTION", "decision_trace": {"service": ".Svc"}}
    for path, findings in ((a, [base, fgs]), (b, [{**base, "severity": "CRITICAL", "transfer_decision": "TRANSMITS"},
                                                  {**fgs, "decision_trace": {"service": ".Other"}}])):
      with open(os.path.join(path, "worker_x.json"), "w", encoding="utf-8") as f:
        json.dump({"findings": findings}, f)
      with open(os.path.join(path, triage_diff.TRIAGE_FILENAME), "w", encoding="utf-8") as f:
        json.dump({"counters": {"kept": 3 if path == a else 2},
                   "dropped": [{"reason": "r1"}] + ([{"reason": "r2"}] if path == b else []),
                   "usage": {"requests": 5}}, f)
    same = triage_diff.diff(a, a)
    _check("triage_diff_self_identical", same["identical"] is True, str(same["summary"]))
    rep = triage_diff.diff(a, b)
    _check("triage_diff_changed_decision",
           rep["summary"]["changed"] == 1
           and rep["changed"][0]["changes"]["transfer_decision"] == ["UNCERTAIN", "TRANSMITS"],
           str(rep["changed"]))
    _check("triage_diff_manifest_keys_by_service",
           rep["summary"]["added"] == 1 and rep["summary"]["removed"] == 1, str(rep["summary"]))
    _check("triage_diff_drops_and_counters",
           rep["dropped_by_reason"].get("r2") == {"before": 0, "after": 1}
           and rep["counters"]["kept"] == {"before": 3, "after": 2}, str(rep["counters"]))
    _check("triage_diff_renders", "+1 -1 ~1" in triage_diff.render(rep))


_MANIFEST_MAIN = """\ufeff<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">
    <uses-sdk android:minSdkVersion="24" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" android:maxSdkVersion="28" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission-sdk-23 android:name="android.permission.POST_NOTIFICATIONS" />
    <uses-feature android:name="android.hardware.telephony" android:required="false" />
    <queries>
        <package android:name="com.example.other" />
        <intent><action android:name="android.intent.action.SEND" /></intent>
    </queries>
    <application android:name=".App" android:label="@string/app_name"
        android:requestLegacyExternalStorage="true">
        <meta-data android:name="app.meta" android:value="1" />
        <activity android:name=".Main" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".Compose">
            <intent-filter>
                <action android:name="android.intent.action.SENDTO" />
                <data android:scheme="smsto" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <data android:mimeType="text/plain" />
            </intent-filter>
        </activity>
        <service android:name=".Typeless" />
        <service android:name=".Typed" android:foregroundServiceType="specialUse">
            <property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="vpn" />
        </service>
        <service android:name=".A11y" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
            <meta-data android:name="android.accessibilityservice" android:resource="@xml/a11y" />
        </service>
        <receiver android:name=".Sms">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED" />
            </intent-filter>
        </receiver>
        <provider android:name="lib.InitProvider" android:authorities="${applicationId}.init" />
    </application>
</manifest>
"""

_MANIFEST_PLAY = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
    <application android:name=".AppPlay" tools:replace="android:name">
        <provider android:name="lib.InitProvider" android:authorities="x" tools:node="remove" />
        <service android:name=".Typed" android:foregroundServiceType="dataSync" />
    </application>
</manifest>
"""

_MANIFEST_FULL = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <service android:name=".FullOnly" />
    </application>
</manifest>
"""


_WP5_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.w5">
  <uses-sdk android:targetSdkVersion="{target}"/>
  {permissions}
  {queries}
  <application android:label="W5">
    <service android:name=".FgSvc"/>
    <service android:name=".PlainSvc"/>
    <service android:name=".DevSvc" android:foregroundServiceType="connectedDevice"/>
    <service android:name=".SpecialSvc" android:foregroundServiceType="specialUse">{property}</service>
  </application>
</manifest>
"""


def _test_wave1_manifest_policies() -> None:
  """WP5: deterministic wave-1 manifest policies over the AppProfile + purpose."""
  from typesafe_eval import android_manifest as am
  from typesafe_eval import constants
  from typesafe_eval import engine
  from typesafe_eval import registry
  from typesafe_eval.client import HeuristicJevClient

  def purpose(label, p=0.9, source="model"):
    return {"purpose": label, "confidence": p, "source": source}

  def perms(*names, **attrs):
    out = []
    for n in names:
      extra = "".join(f' android:{k}="{v}"' for k, v in attrs.get(n, {}).items())
      out.append(f'<uses-permission android:name="android.permission.{n}"{extra}/>')
    return "\n  ".join(out)

  def build(d, target=34, permissions="", queries="", prop="", start_foreground=True):
    def write(rel, text):
      p = os.path.join(d, rel)
      os.makedirs(os.path.dirname(p), exist_ok=True)
      with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    write("app/src/main/AndroidManifest.xml",
          _WP5_MANIFEST.format(target=target, permissions=permissions, queries=queries, property=prop))
    body = ("class FgSvc : Service() {\n  override fun onStartCommand(i: Intent?, f: Int, id: Int): Int {\n"
            "    // startForeground must be called quickly (comment only)\n"
            + ("    startForeground(1, buildNotification())\n" if start_foreground else "")
            + "    return START_STICKY\n  }\n}\n")
    write("app/src/main/java/com/w5/FgSvc.kt", body)
    write("app/src/main/java/com/w5/PlainSvc.kt", "class PlainSvc : Service() {\n  fun go() { startForegroundService(Intent()) }\n}\n")
    write("app/src/test/java/com/w5/FgSvc.kt", "class FgSvc { fun t() { startForeground(1, n) } }\n")
    return am.load_profile(d, {})

  def run(spec_id, inputs):
    spec = next(s for s in registry.manifest_specs() if s.policy_id == spec_id)
    return spec.compose_manifest(inputs)

  wave1 = {"foreground_services_policy", "package_visibility_policy", "all_files_access_policy",
           "exact_alarm_policy", "target_api_level"}
  from typesafe_eval import templates
  _check("wave1_specs_registered", wave1 <= {s.policy_id for s in registry.manifest_specs()}
         and all(pid in templates._policies() for pid in wave1),  # pylint: disable=protected-access
         str(sorted(s.policy_id for s in registry.manifest_specs())))

  with tempfile.TemporaryDirectory() as d:
    prof = build(d, target=34, permissions=perms("FOREGROUND_SERVICE", "FOREGROUND_SERVICE_CONNECTED_DEVICE",
                                                  "FOREGROUND_SERVICE_SPECIAL_USE", "MANAGE_EXTERNAL_STORAGE",
                                                  "QUERY_ALL_PACKAGES", "USE_EXACT_ALARM", "SCHEDULE_EXACT_ALARM"))
    _check("wave1_profile_reads_uses_sdk", prof.target_sdk == 34 and len(prof.services) == 4,
           f"{prof.target_sdk} {[s.name for s in prof.services]}")
    vpn = registry.ManifestInputs(profile=prof, app_purpose=purpose("per_app_network_control"), app_dir=d)
    fgs = run("foreground_services_policy", vpn)
    def svc_key(f):
      # The profile resolves ".FgSvc" to "com.w5.FgSvc"; key by the manifest-relative form.
      name = f["decision_trace"].get("service")
      return "." + name.rsplit(".", 1)[-1] if name else f["decision_trace"].get("permission")
    by = {}
    for f in fgs:
      by.setdefault(svc_key(f), []).append(f)
    _check("fgs_typeless_start_foreground_critical",
           [f["severity"] for f in by.get(".FgSvc", [])] == ["CRITICAL"]
           and "FgSvc.kt:L4" in by[".FgSvc"][0]["evidence"]
           and "src/test" not in by[".FgSvc"][0]["evidence"], str(by.get(".FgSvc")))
    _check("fgs_typeless_plain_service_silent", ".PlainSvc" not in by, str(sorted(by)))
    dev = sorted(f["severity"] for f in by.get(".DevSvc", []))
    _check("fgs_type_misaligned_important", dev == ["IMPORTANT", "SUGGESTION"]
           and any("align" in f["issue_summary"] for f in by[".DevSvc"]), str(by.get(".DevSvc")))
    sp = sorted(f["severity"] for f in by.get(".SpecialSvc", []))
    _check("fgs_special_use_without_property_critical", "CRITICAL" in sp and "SUGGESTION" in sp
           and any(constants.FGS_SPECIAL_USE_PROPERTY in f["evidence"] for f in by[".SpecialSvc"]), str(sp))
    _check("fgs_special_use_permission_present_no_stray",
           "android.permission.FOREGROUND_SERVICE_SPECIAL_USE" not in by)
    # Unknown purpose: no misalignment, only the inventory Suggestion.
    unk = run("foreground_services_policy", registry.ManifestInputs(profile=prof, app_purpose=purpose("unknown"), app_dir=d))
    _check("fgs_misalignment_needs_established_purpose",
           [f["severity"] for f in unk if svc_key(f) == ".DevSvc"] == ["SUGGESTION"])
    low = run("foreground_services_policy", registry.ManifestInputs(
        profile=prof, app_purpose=purpose("per_app_network_control", p=constants.CONF_APP_PURPOSE - 0.1), app_dir=d))
    _check("fgs_misalignment_low_confidence_silent",
           [f["severity"] for f in low if svc_key(f) == ".DevSvc"] == ["SUGGESTION"])
    # Below API 34 the typeless-service rule does not fire.
    p33 = build(d, target=33, permissions=perms("FOREGROUND_SERVICE"))
    f33 = run("foreground_services_policy", registry.ManifestInputs(profile=p33, app_purpose=purpose("unknown"), app_dir=d))
    _check("fgs_typeless_below_34_silent", not any(svc_key(f) == ".FgSvc" for f in f33))
    # No startForeground in the class -> no finding even on 34.
    pns = build(d, target=34, permissions=perms("FOREGROUND_SERVICE"), start_foreground=False)
    fns = run("foreground_services_policy", registry.ManifestInputs(profile=pns, app_purpose=purpose("unknown"), app_dir=d))
    _check("fgs_typeless_no_call_silent", not any(svc_key(f) == ".FgSvc" for f in fns))
    # Property present -> specialUse is fine; stray SPECIAL_USE permission -> Suggestion.
    pprop = build(d, target=34, permissions=perms("FOREGROUND_SERVICE", "FOREGROUND_SERVICE_SPECIAL_USE"),
                  prop=f'<property android:name="{constants.FGS_SPECIAL_USE_PROPERTY}" android:value="vpn"/>')
    fprop = run("foreground_services_policy", registry.ManifestInputs(profile=pprop, app_purpose=purpose("unknown"), app_dir=d))
    _check("fgs_special_use_with_property_ok",
           [f["severity"] for f in fprop if svc_key(f) == ".SpecialSvc"] == ["SUGGESTION"], str([f["severity"] for f in fprop]))
    pstray = build(d, target=34, permissions=perms("FOREGROUND_SERVICE", "FOREGROUND_SERVICE_SPECIAL_USE"))
    # Remove the specialUse service by rewriting the manifest without it.
    with open(os.path.join(d, "app/src/main/AndroidManifest.xml"), "r+", encoding="utf-8") as fh:
      txt = fh.read().replace('android:foregroundServiceType="specialUse"', "")
      fh.seek(0); fh.write(txt); fh.truncate()
    pstray = am.load_profile(d, {})
    fstray = run("foreground_services_policy", registry.ManifestInputs(profile=pstray, app_purpose=purpose("unknown"), app_dir=d))
    _check("fgs_stray_special_use_permission_suggestion",
           any(f["severity"] == "SUGGESTION" and "FOREGROUND_SERVICE_SPECIAL_USE" in f["issue_summary"] for f in fstray),
           str([f["issue_summary"] for f in fstray]))

    # --- all files access -------------------------------------------------
    afa_fm = run("all_files_access_policy", registry.ManifestInputs(profile=prof, app_purpose=purpose("file_manager")))
    _check("all_files_file_manager_suggestion", [f["severity"] for f in afa_fm] == ["SUGGESTION"]
           and not afa_fm[0].get("needs_manual_review"), str(afa_fm))
    afa_unk = run("all_files_access_policy", registry.ManifestInputs(profile=prof, app_purpose=purpose("unknown")))
    _check("all_files_unknown_critical_review", [f["severity"] for f in afa_unk] == ["CRITICAL"]
           and afa_unk[0].get("needs_manual_review") is True)
    afa_l = run("all_files_access_policy", registry.ManifestInputs(profile=prof, app_purpose=purpose("launcher")))
    _check("all_files_other_purpose_critical", [f["severity"] for f in afa_l] == ["CRITICAL"]
           and not afa_l[0].get("needs_manual_review"))
    afa_low = run("all_files_access_policy", registry.ManifestInputs(
        profile=prof, app_purpose=purpose("file_manager", p=constants.CONF_APP_PURPOSE - 0.1)))
    _check("all_files_low_confidence_critical_review", [f["severity"] for f in afa_low] == ["CRITICAL"]
           and afa_low[0].get("needs_manual_review") is True)
    afa_h = run("all_files_access_policy", registry.ManifestInputs(
        profile=prof, app_purpose=purpose("file_manager", p=0.0, source="human")))
    _check("all_files_human_pin_suggestion", [f["severity"] for f in afa_h] == ["SUGGESTION"])
    pmedia = build(d, target=34, permissions=perms("MANAGE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_EXTERNAL_STORAGE",
                                                    READ_EXTERNAL_STORAGE={"maxSdkVersion": "32"}))
    afa_m = run("all_files_access_policy", registry.ManifestInputs(profile=pmedia, app_purpose=purpose("file_manager")))
    _check("all_files_redundant_media_important",
           sorted(f["severity"] for f in afa_m) == ["IMPORTANT", "SUGGESTION"]
           and any("READ_MEDIA_IMAGES" in f["evidence"] and "READ_EXTERNAL_STORAGE" not in f["evidence"]
                   for f in afa_m if f["severity"] == "IMPORTANT"), str(afa_m))
    pnone = build(d, target=34, permissions=perms("INTERNET"))
    _check("all_files_absent_silent", run("all_files_access_policy", registry.ManifestInputs(profile=pnone, app_purpose=purpose("unknown"))) == [])

    # --- package visibility -----------------------------------------------
    pv_fm = run("package_visibility_policy", registry.ManifestInputs(profile=prof, app_purpose=purpose("file_manager")))
    _check("pkg_vis_file_manager_suggestion", [f["severity"] for f in pv_fm] == ["SUGGESTION"], str(pv_fm))
    pv_vpn = run("package_visibility_policy", vpn)
    _check("pkg_vis_network_control_suggestion", [f["severity"] for f in pv_vpn] == ["SUGGESTION"])
    pv_o = run("package_visibility_policy", registry.ManifestInputs(profile=prof, app_purpose=purpose("other")))
    _check("pkg_vis_other_important", [f["severity"] for f in pv_o] == ["IMPORTANT"] and not pv_o[0].get("needs_manual_review"))
    pv_u = run("package_visibility_policy", registry.ManifestInputs(profile=prof, app_purpose=purpose("unknown")))
    _check("pkg_vis_unknown_important_review", [f["severity"] for f in pv_u] == ["IMPORTANT"] and pv_u[0].get("needs_manual_review") is True)
    pq = build(d, target=34, permissions=perms("QUERY_ALL_PACKAGES"),
               queries='<queries><package android:name="com.other.app"/></queries>')
    pv_q = run("package_visibility_policy", registry.ManifestInputs(profile=pq, app_purpose=purpose("file_manager")))
    _check("pkg_vis_with_queries_important", [f["severity"] for f in pv_q] == ["IMPORTANT"]
           and "com.other.app" in pv_q[0]["evidence"], str(pv_q))

    # --- exact alarm ------------------------------------------------------
    ea_a = run("exact_alarm_policy", registry.ManifestInputs(profile=prof, app_purpose=purpose("alarm_or_timer")))
    _check("exact_alarm_alarm_app_suggestions", [f["severity"] for f in ea_a] == ["SUGGESTION", "SUGGESTION"], str(ea_a))
    ea_f = run("exact_alarm_policy", registry.ManifestInputs(profile=prof, app_purpose=purpose("file_manager")))
    _check("exact_alarm_other_purpose_important", sorted(f["severity"] for f in ea_f) == ["IMPORTANT", "SUGGESTION"]
           and any(f["severity"] == "IMPORTANT" and "USE_EXACT_ALARM" in f["evidence"] for f in ea_f))
    ea_c = run("exact_alarm_policy", registry.ManifestInputs(profile=prof, app_purpose=purpose("calendar")))
    _check("exact_alarm_calendar_ok", all(f["severity"] == "SUGGESTION" for f in ea_c))
    _check("exact_alarm_absent_silent", run("exact_alarm_policy", registry.ManifestInputs(profile=pnone, app_purpose=purpose("unknown"))) == [])

    # --- target API level -------------------------------------------------
    def tapi(target=None, values=None, profile_target=None):
      p = am.AppProfile(target_sdk=profile_target if profile_target is not None else target,
                        target_sdk_values=values or ([target] if target else []),
                        sdk_provenance={"target_sdk": "gradle:app/build.gradle"})
      return run("target_api_level", registry.ManifestInputs(profile=p, app_purpose={}))
    _check("target_api_below_floor_critical", [f["severity"] for f in tapi(constants.PLAY_EXISTING_APP_MIN_TARGET_SDK - 1)] == ["CRITICAL"])
    _check("target_api_one_behind_important", [f["severity"] for f in tapi(constants.PLAY_REQUIRED_TARGET_SDK - 1)] == ["IMPORTANT"])
    _check("target_api_meets_silent", tapi(constants.PLAY_REQUIRED_TARGET_SDK) == [] and tapi(constants.PLAY_REQUIRED_TARGET_SDK + 1) == [])
    lowest = tapi(values=[29, constants.PLAY_REQUIRED_TARGET_SDK], profile_target=constants.PLAY_REQUIRED_TARGET_SDK)
    _check("target_api_uses_lowest_flavor_value", [f["severity"] for f in lowest] == ["CRITICAL"]
           and "lowest of" in lowest[0]["evidence"], str(lowest))
    unknown = run("target_api_level", registry.ManifestInputs(profile=am.AppProfile(), manifest={}, app_purpose={}))
    _check("target_api_unknown_review", [f["severity"] for f in unknown] == ["SUGGESTION"] and unknown[0].get("needs_manual_review") is True)
    legacy = run("target_api_level", registry.ManifestInputs(manifest={"target_sdk": 30}, app_purpose={}))
    _check("target_api_legacy_manifest_fallback", [f["severity"] for f in legacy] == ["CRITICAL"])
    _check("target_api_provenance_dated", lowest[0]["decision_trace"]["requirement_provenance"].get("effective_from")
           and "read_on" in constants.PLAY_TARGET_SDK_PROVENANCE)

    # --- engine integration: findings reach the worker file with counters -----
    scratch = os.path.join(d, ".scratch")
    build(d, target=34, permissions=perms("FOREGROUND_SERVICE", "MANAGE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES"))
    _write_scratch(d, scratch, {})
    engine.run(scratch, HeuristicJevClient(), batched=True)
    worker = json.load(open(os.path.join(scratch, "worker_permissions_and_apis.json"), encoding="utf-8"))
    ids = sorted({f["policy_id"] for f in worker["findings"]})
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    mf = triage["counters"].get("manifest_findings") or {}
    _check("wave1_engine_integration",
           {"all_files_access_policy", "package_visibility_policy", "target_api_level", "foreground_services_policy"} <= set(ids)
           and mf.get("all_files_access_policy") == 1 and mf.get("target_api_level") == 1
           and all(f.get("kind") == "manifest" and f.get("client") == "deterministic"
                   for f in worker["findings"] if f["policy_id"] in wave1),
           f"{ids} {mf}")
    # Heuristic client answers `unknown`, so purpose-conditioned rules escalate and route to review.
    afa = [f for f in worker["findings"] if f["policy_id"] == "all_files_access_policy"]
    _check("wave1_unknown_purpose_escalates_in_run",
           afa and afa[0]["severity"] == "CRITICAL" and afa[0].get("needs_manual_review") is True, str(afa))


_WP9_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.w9">
  <uses-sdk android:minSdkVersion="{min_sdk}" android:targetSdkVersion="{target}"/>
  {permissions}
  <application android:label="W9"{application_attrs}>
    <activity android:name=".Main"/>
  </application>
</manifest>
"""

_JAVA_ROOT_FOLDER = """package com.w9;
import android.os.Environment;
import java.io.File;
import java.io.FileOutputStream;
public class Store {
  // Environment.getExternalStorageDirectory() in a comment is not a hint
  public static File tempDir(android.content.Context ctx) {
    File parent = ctx.getExternalFilesDir(null);
    if (parent == null)
      parent = new File(Environment.getExternalStorageDirectory().getAbsolutePath());
    File temp = new File(parent, "/temp/");
    temp.mkdirs();
    return temp;
  }
  public static String composeOnly(String sub) {
    return Environment.getExternalStorageDirectory().getAbsolutePath() + "/" + sub;
  }
  public static boolean isShared(String path) {
    return path.startsWith(Environment.getExternalStorageDirectory().getAbsolutePath());
  }
  public static File downloads() {
    File d = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
    new File(d, "report.txt").createNewFile();
    return d;
  }
  public static void appSpecific(android.content.Context ctx) {
    File f = new File(ctx.getExternalFilesDir(null), "cache.bin");
    f.mkdirs();
  }
}
"""

_JAVA_MEDIA = """package com.w9;
import android.provider.MediaStore;
import android.content.Intent;
public class Media {
  void scanAll(android.content.ContentResolver r) {
    android.database.Cursor c = r.query(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, null, null, null, null);
    while (c.moveToNext()) { index(c); }
  }
  void pickOne(android.app.Activity a) {
    Intent i = new Intent(MediaStore.ACTION_PICK_IMAGES);
    a.startActivityForResult(i, 7);
  }
  void constantOnly() {
    String s = MediaStore.Images.Media.EXTERNAL_CONTENT_URI.toString();
  }
}
"""


def _test_wave2_storage_policies() -> None:
  """WP9: photo_video_access_policy and files_and_docs_policy.

  Covers: the deterministic storage-path hints (``writes`` / ``composes`` /
  ``references``, public directory, app-specific directories and comments
  never hint, window stops at the block end) and media-access hints
  (``LIBRARY_QUERY`` needs collection + query, ``USER_PICK``); the manifest
  rules (uncapped legacy read on 33+, purpose-conditioned broad media,
  partial-access companion, uncapped legacy write on 30+,
  ``requestLegacyExternalStorage`` on 30+, flavour straddle notes, absent
  permissions are silent); the two batteries; the heuristic client's
  stand-ins; the compositions (justified user-selected -> None, justified
  full-library -> SUGGESTION, unjustified -> IMPORTANT, contradiction and
  unknown purpose -> review, relevance drop; root folder confirmed /
  uncertain / denied double gate, evidence at the hint line); the planner
  gates (``requires_permissions``, ``applies_file``, ``one_per_file``) and an
  end-to-end engine run.
  """
  from typesafe_eval import android_manifest as am
  from typesafe_eval import constants
  from typesafe_eval import context
  from typesafe_eval import engine
  from typesafe_eval import registry
  from typesafe_eval import structure
  from typesafe_eval import templates
  from typesafe_eval.client import HeuristicJevClient
  from typesafe_eval.client import JevAnswer

  # --- structure: storage-path hints -----------------------------------------
  lines = _JAVA_ROOT_FOLDER.splitlines()
  hints = structure.external_storage_paths(lines)
  by_line = {h.line + 1: h for h in hints}
  _check("storage_hint_write_detected", 10 in by_line and by_line[10].kind == structure.STORAGE_ROOT
         and by_line[10].writes and by_line[10].composes and by_line[10].strength == "writes"
         and "mkdirs" in by_line[10].evidence, str([(h.line + 1, h.strength, h.evidence) for h in hints]))
  _check("storage_hint_compose_only", 16 in by_line and by_line[16].strength == "composes")
  _check("storage_hint_reference_only", 19 in by_line and by_line[19].strength == "references")
  _check("storage_hint_public_directory", 22 in by_line and by_line[22].kind == structure.PUBLIC_DIRECTORY
         and by_line[22].writes)
  _check("storage_hint_comment_and_app_specific_skipped", 6 not in by_line and 27 not in by_line
         and len(hints) == 4, str(sorted(by_line)))
  _check("storage_hint_to_state_shape",
         set(hints[0].to_state()) == {"hint", "line", "composes", "writes", "strength", "evidence"})
  fs = structure.FileStructure("Store.java", "java", lines, [], {}, "com.w9")
  ranked = context.file_storage_hints(fs, [11])
  _check("storage_hints_ranked_strongest_first", [h.strength for h in ranked] == ["writes", "writes", "composes", "references"]
         and ranked[0].line + 1 == 10, str([(h.line + 1, h.strength) for h in ranked]))
  _check("storage_write_gate_true", context.has_storage_write_hint(fs) is True)
  fs_ref = structure.FileStructure("Ref.java", "java", [
      "class R {", "  boolean shared(String p) {", "    return p.startsWith(Environment.getExternalStorageDirectory().getPath());",
      "  }", "}"], [], {}, "com.w9")
  _check("storage_write_gate_reference_only_false", context.has_storage_write_hint(fs_ref) is False)
  _check("storage_hint_window_stops_at_block_end",
         structure.external_storage_paths(["File r = Environment.getExternalStorageDirectory();", "}", "x.mkdir();"])[0].writes is False)

  # --- structure: media hints -----------------------------------------------
  mlines = _JAVA_MEDIA.splitlines()
  scan = structure.media_access_hints(mlines, (4, 8))
  pick = structure.media_access_hints(mlines, (8, 12))
  const = structure.media_access_hints(mlines, (12, 15))
  _check("media_hint_library_query", [h.kind for h in scan] == [structure.LIBRARY_QUERY] and scan[0].line + 1 == 6, str(scan))
  _check("media_hint_user_pick", [h.kind for h in pick] == [structure.USER_PICK]
         and pick[0].detail == "ACTION_PICK_IMAGES" and pick[0].line + 1 == 10, str(pick))
  _check("media_hint_collection_without_query_silent", const == [], str(const))

  # --- structure: trailing-comment mentions are not value uses ---------------
  _check("code_portion_strips_trailing_comment",
         structure.code_portion('String TAG = "A";  // MediaStore') == 'String TAG = "A";  '
         and structure.code_portion('String u = "http://host/x"; int y = 1;') == 'String u = "http://host/x"; int y = 1;'
         and structure.code_portion("int a = b /* MediaStore */ + c;") == "int a = b "
         and structure.code_portion("char c = '/'; // x") == "char c = '/'; ")
  lex = structure.lexical_hits(['String TAG = "Adapter";    // MediaStore',
                                'Uri u = MediaStore.Files.getContentUri("external");',
                                'String s = "see MediaStore";'], "MediaStore")
  _check("lexical_trailing_comment_mention_demoted",
         lex.demoted_lines == [0] and lex.value_lines == [1, 2] and lex.ranked_lines()[0] == 1, str(lex))

  # --- manifest rules -------------------------------------------------------
  def purpose(label, p=0.9, source="model"):
    return {"purpose": label, "confidence": p, "source": source}

  def perms(*names, **attrs):
    out = []
    for n in names:
      extra = "".join(f' android:{k}="{v}"' for k, v in attrs.get(n, {}).items())
      out.append(f'<uses-permission android:name="android.permission.{n}"{extra}/>')
    return "\n  ".join(out)

  def build(d, target=34, min_sdk=21, permissions="", application_attrs=""):
    p = os.path.join(d, "app/src/main/AndroidManifest.xml")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
      f.write(_WP9_MANIFEST.format(target=target, min_sdk=min_sdk, permissions=permissions,
                                   application_attrs=application_attrs))
    return am.load_profile(d, {})

  def run(spec_id, inputs):
    spec = next(s for s in registry.manifest_specs() if s.policy_id == spec_id)
    return spec.compose_manifest(inputs)

  def rules(found):
    return sorted((f["decision_trace"].get("rule"), f["severity"]) for f in found)

  wave2 = {"photo_video_access_policy", "files_and_docs_policy"}
  _check("wave2_specs_registered", wave2 <= {s.policy_id for s in registry.manifest_specs()}
         and wave2 <= {s.policy_id for s in registry.code_signal_specs()}
         and all(pid in templates._policies() for pid in wave2))  # pylint: disable=protected-access

  with tempfile.TemporaryDirectory() as d:
    p_legacy = build(d, target=34, permissions=perms("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"),
                     application_attrs=' android:requestLegacyExternalStorage="true"')
    pv = run("photo_video_access_policy", registry.ManifestInputs(profile=p_legacy, app_purpose=purpose("file_manager")))
    _check("pv_uncapped_legacy_read_on_34_important_plus_purpose_suggestion",
           rules(pv) == [("broad_media_purpose", "SUGGESTION"), ("legacy_read_uncapped_on_33_plus", "IMPORTANT")]
           and any('maxSdkVersion="32"' in f["issue_summary"] for f in pv)
           and any("no READ_MEDIA_*" in f["evidence"] for f in pv), str(pv))
    fd = run("files_and_docs_policy", registry.ManifestInputs(profile=p_legacy, app_purpose=purpose("file_manager")))
    _check("fd_uncapped_write_important_and_legacy_flag_suggestion",
           rules(fd) == [("legacy_storage_flag_on_30_plus", "SUGGESTION"), ("legacy_write_uncapped_on_30_plus", "IMPORTANT")]
           and any("source set main" in f["evidence"] for f in fd), str(fd))
    _check("wave2_manifest_findings_shape", all(f.get("kind") == "manifest" and f.get("client") == "deterministic"
                                                  and "AndroidManifest.xml" in f["files_involved"] for f in pv + fd))
    p_other = registry.ManifestInputs(profile=p_legacy, app_purpose=purpose("launcher"))
    pv_o = run("photo_video_access_policy", p_other)
    _check("pv_other_purpose_important_no_review",
           rules(pv_o) == [("broad_media_purpose", "IMPORTANT"), ("legacy_read_uncapped_on_33_plus", "IMPORTANT")]
           and not any(f.get("needs_manual_review") for f in pv_o), str(pv_o))
    pv_u = run("photo_video_access_policy", registry.ManifestInputs(profile=p_legacy, app_purpose=purpose("unknown")))
    _check("pv_unknown_purpose_important_review",
           any(f["decision_trace"].get("rule") == "broad_media_purpose" and f["severity"] == "IMPORTANT"
               and f.get("needs_manual_review") is True for f in pv_u), str(pv_u))
    # Capped legacy permissions and a 32 target are quiet on the cap rules.
    p_capped = build(d, target=34, permissions=perms(
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VISUAL_USER_SELECTED",
        READ_EXTERNAL_STORAGE={"maxSdkVersion": "32"}, WRITE_EXTERNAL_STORAGE={"maxSdkVersion": "29"}))
    pv_c = run("photo_video_access_policy", registry.ManifestInputs(profile=p_capped, app_purpose=purpose("media_gallery_or_editor")))
    _check("pv_capped_legacy_with_media_perms_gallery_suggestion_only",
           rules(pv_c) == [("broad_media_purpose", "SUGGESTION")]
           and "READ_MEDIA_IMAGES" in pv_c[0]["evidence"] and "READ_EXTERNAL_STORAGE" in pv_c[0]["evidence"], str(pv_c))
    fd_c = run("files_and_docs_policy", registry.ManifestInputs(profile=p_capped, app_purpose=purpose("media_gallery_or_editor")))
    _check("fd_capped_write_no_flag_silent", fd_c == [], str(fd_c))
    p_no_vus = build(d, target=34, permissions=perms("READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO"))
    pv_v = run("photo_video_access_policy", registry.ManifestInputs(profile=p_no_vus, app_purpose=purpose("media_gallery_or_editor")))
    _check("pv_missing_visual_user_selected_suggestion",
           rules(pv_v) == [("broad_media_purpose", "SUGGESTION"), ("missing_visual_user_selected", "SUGGESTION")]
           and any("READ_MEDIA_VISUAL_USER_SELECTED" in f["issue_summary"] for f in pv_v), str(pv_v))
    p_vus_only = build(d, target=34, permissions=perms("READ_MEDIA_VISUAL_USER_SELECTED"))
    _check("pv_visual_user_selected_alone_silent",
           run("photo_video_access_policy", registry.ManifestInputs(profile=p_vus_only, app_purpose=purpose("launcher"))) == [])
    p32 = build(d, target=32, permissions=perms("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"),
                application_attrs=' android:requestLegacyExternalStorage="true"')
    pv_32 = run("photo_video_access_policy", registry.ManifestInputs(profile=p32, app_purpose=purpose("launcher")))
    _check("pv_target_32_no_cap_rule", rules(pv_32) == [("broad_media_purpose", "IMPORTANT")], str(pv_32))
    p29 = build(d, target=29, permissions=perms("WRITE_EXTERNAL_STORAGE"),
                application_attrs=' android:requestLegacyExternalStorage="true"')
    _check("fd_target_29_silent", run("files_and_docs_policy", registry.ManifestInputs(profile=p29, app_purpose={})) == [])
    p33min = build(d, target=34, min_sdk=33, permissions=perms("READ_EXTERNAL_STORAGE"))
    pv_m = run("photo_video_access_policy", registry.ManifestInputs(profile=p33min, app_purpose=purpose("launcher")))
    _check("pv_min_sdk_33_legacy_inert_everywhere",
           rules(pv_m) == [("legacy_read_uncapped_on_33_plus", "IMPORTANT")] and "grants nothing" in pv_m[0]["evidence"], str(pv_m))
    p_none = build(d, target=34, permissions=perms("INTERNET"))
    _check("wave2_absent_permissions_silent",
           run("photo_video_access_policy", registry.ManifestInputs(profile=p_none, app_purpose=purpose("launcher"))) == []
           and run("files_and_docs_policy", registry.ManifestInputs(profile=p_none, app_purpose={})) == [])
    # Flavour straddle: one build still targets 29.
    p_legacy.target_sdk_values = [29, 34]
    fd_s = run("files_and_docs_policy", registry.ManifestInputs(profile=p_legacy, app_purpose={}))
    _check("fd_straddle_note", all("targeting API 29 still uses it" in f["evidence"] for f in fd_s) and len(fd_s) == 2, str(fd_s))
    pv_s = run("photo_video_access_policy", registry.ManifestInputs(profile=p_legacy, app_purpose=purpose("file_manager")))
    _check("pv_straddle_note", any("targeting API 29 still uses it" in f["evidence"]
                                   for f in pv_s if f["decision_trace"].get("rule") == "legacy_read_uncapped_on_33_plus"), str(pv_s))
    p_legacy.target_sdk_values = [34]

    # --- batteries and heuristic stand-ins -------------------------------------
    pvb = q.photo_video_battery("PHOTOS", "MediaStore")
    fdb = q.files_and_docs_battery("FILES_AND_DOCS", "*/*")
    _check("wave2_battery_shapes", list(pvb) == ["signal_relevant", "accesses_full_media_library"]
           and list(fdb) == ["creates_root_level_external_folder"]
           and "media_access_hints" in pvb["accesses_full_media_library"]["instructions"]
           and "external_storage_paths" in fdb["creates_root_level_external_folder"]["instructions"])
    heur = HeuristicJevClient()
    st_lib = {"signal": {"data_type": "PHOTOS"}, "media_access_hints": [{"hint": "LIBRARY_QUERY"}],
              "external_storage_paths": [{"strength": "writes"}], "co_located_signals": {}, "app": {}}
    st_pick = {"signal": {"data_type": "PHOTOS"}, "media_access_hints": [{"hint": "USER_PICK"}],
               "external_storage_paths": [{"strength": "references"}], "co_located_signals": {}, "app": {}}
    a_lib = heur.system_one(st_lib, {**pvb, **fdb})
    a_pick = heur.system_one(st_pick, {**pvb, **fdb})
    a_none = heur.system_one({"signal": {}, "co_located_signals": {}, "app": {}}, {**pvb, **fdb})
    _check("wave2_heuristic_priors",
           a_lib["accesses_full_media_library"].noul == 0.85 and a_lib["creates_root_level_external_folder"].noul == 0.85
           and a_pick["accesses_full_media_library"].noul == 0.15 and a_pick["creates_root_level_external_folder"].noul == 0.15
           and a_none["accesses_full_media_library"].noul == 0.5 and a_none["creates_root_level_external_folder"].noul == 0.5)

    # --- composition: photo_video ------------------------------------------------
    def pv_answers(p_full, relevant=0.9):
      return {"signal_relevant": JevAnswer("noul", noul=relevant),
              "accesses_full_media_library": JevAnswer("noul", noul=p_full)}

    def pv_state(hints=()):
      return {"signal": {"data_type": "PHOTOS", "matched_pattern": "MediaStore", "file": "Media.java", "line": 6,
                         "matched_line": "r.query(MediaStore.Images.Media.EXTERNAL_CONTENT_URI)", "all_lines": [6]},
              "code_snippet": "L6: r.query(...)", "sinks": [],
              "anchor": {"scope": [5, 8], "proximity": None, "sink_in_scope": False, "tier": 3, "media_hints": list(hints)},
              "media_access_hints": [{"hint": h, "line": 6, "detail": h, "evidence": "..."} for h in hints],
              "app": {}}

    gallery, other, unknown = purpose("media_gallery_or_editor"), purpose("launcher"), purpose("unknown")
    _check("pv_code_justified_user_selected_none",
           evaluate.compose_photo_video_finding("PHOTOS", pv_state(["USER_PICK"]), pv_answers(0.1), "t", gallery) is None)
    f_full = evaluate.compose_photo_video_finding("PHOTOS", pv_state(["LIBRARY_QUERY"]), pv_answers(0.9), "t", gallery)
    _check("pv_code_justified_full_library_suggestion",
           f_full is not None and f_full["severity"] == "SUGGESTION" and f_full["media_access_mode"] == "full_library"
           and not f_full.get("needs_manual_review") and f_full["decision_trace"]["media_access"]["corroborated"] is True
           and "[media hints: LIBRARY_QUERY]" in f_full["evidence"] and f_full["psl_constant"] == "PHOTOS", str(f_full))
    f_pick_other = evaluate.compose_photo_video_finding("PHOTOS", pv_state(["USER_PICK"]), pv_answers(0.1), "t", other)
    _check("pv_code_unjustified_user_selected_important",
           f_pick_other is not None and f_pick_other["severity"] == "IMPORTANT" and f_pick_other["media_access_mode"] == "user_selected"
           and not f_pick_other.get("needs_manual_review") and "Photo Picker" in f_pick_other["issue_summary"], str(f_pick_other))
    f_unc = evaluate.compose_photo_video_finding("PHOTOS", pv_state(), pv_answers(0.5), "t", other)
    _check("pv_code_uncertain_important_review",
           f_unc["severity"] == "IMPORTANT" and f_unc["media_access_mode"] == "uncertain" and f_unc.get("needs_manual_review") is True)
    f_unc_g = evaluate.compose_photo_video_finding("PHOTOS", pv_state(), pv_answers(0.5), "t", gallery)
    _check("pv_code_uncertain_justified_suggestion_review",
           f_unc_g["severity"] == "SUGGESTION" and f_unc_g.get("needs_manual_review") is True)
    f_contra = evaluate.compose_photo_video_finding("PHOTOS", pv_state(["USER_PICK"]), pv_answers(0.9), "t", gallery)
    _check("pv_code_contradiction_reviewed",
           f_contra is not None and f_contra.get("needs_manual_review") is True
           and f_contra["decision_trace"]["media_access"]["contradicted"] is True and "disagrees" in f_contra["issue_summary"], str(f_contra))
    f_contra_pick = evaluate.compose_photo_video_finding("PHOTOS", pv_state(["LIBRARY_QUERY"]), pv_answers(0.1), "t", gallery)
    _check("pv_code_justified_user_selected_but_query_hint_kept_for_review",
           f_contra_pick is not None and f_contra_pick["severity"] == "SUGGESTION" and f_contra_pick.get("needs_manual_review") is True)
    f_unknown = evaluate.compose_photo_video_finding("PHOTOS", pv_state(), pv_answers(0.9), "t", unknown)
    _check("pv_code_unknown_purpose_important_review",
           f_unknown["severity"] == "IMPORTANT" and f_unknown.get("needs_manual_review") is True
           and f_unknown["decision_trace"]["app_purpose"] == "not established")
    _check("pv_code_relevance_drop",
           evaluate.compose_photo_video_finding("PHOTOS", pv_state(), pv_answers(0.9, relevant=0.05), "t", other) is None)
    _check("pv_code_mode_bands", evaluate.media_access_mode(constants.T_FULL_MEDIA_LIBRARY) == "full_library"
           and evaluate.media_access_mode(1 - constants.T_FULL_MEDIA_LIBRARY) == "user_selected"
           and evaluate.media_access_mode(0.5) == "uncertain" and evaluate.media_access_mode(None) == "uncertain")

    # --- composition: files_and_docs ----------------------------------------------
    def fd_answers(p_root):
      return {"creates_root_level_external_folder": JevAnswer("noul", noul=p_root)}

    def fd_state(strengths=("writes",)):
      hs = [{"hint": "STORAGE_ROOT", "line": 10 + i, "composes": s != "references", "writes": s == "writes",
             "strength": s, "evidence": "parent = new File(Environment.getExternalStorageDirectory()) … temp.mkdirs();"}
            for i, s in enumerate(strengths)]
      st = {"signal": {"data_type": "FILES_AND_DOCS", "matched_pattern": "*/*", "file": "Store.java", "line": 40,
                       "matched_line": 'setType("*/*")', "all_lines": [40]},
            "code_snippet": "L40: ...", "sinks": [], "anchor": {"scope": [38, 42], "proximity": None, "sink_in_scope": False, "tier": 3},
            "app": {}}
      if hs:
        st["external_storage_paths"] = hs
      return st

    fm = purpose("file_manager")
    _check("fd_code_no_hint_none", evaluate.compose_files_and_docs_finding("FILES_AND_DOCS", fd_state(()), fd_answers(0.9), "t", other) is None)
    f_conf = evaluate.compose_files_and_docs_finding("FILES_AND_DOCS", fd_state(), fd_answers(0.9), "t", other)
    _check("fd_code_confirmed_other_important",
           f_conf is not None and f_conf["severity"] == "IMPORTANT" and f_conf["root_folder_mode"] == "confirmed"
           and not f_conf.get("needs_manual_review") and f_conf["evidence"].startswith("Store.java:L10 — ")
           and "[STORAGE_ROOT, writes]" in f_conf["evidence"] and f_conf["files_involved"] == ["Store.java"], str(f_conf))
    f_conf_fm = evaluate.compose_files_and_docs_finding("FILES_AND_DOCS", fd_state(), fd_answers(0.9), "t", fm)
    _check("fd_code_confirmed_file_manager_suggestion",
           f_conf_fm["severity"] == "SUGGESTION" and not f_conf_fm.get("needs_manual_review")
           and "scoped alternative" in f_conf_fm["issue_summary"], str(f_conf_fm))
    f_conf_u = evaluate.compose_files_and_docs_finding("FILES_AND_DOCS", fd_state(), fd_answers(0.9), "t", unknown)
    _check("fd_code_confirmed_unknown_purpose_review", f_conf_u["severity"] == "IMPORTANT" and f_conf_u.get("needs_manual_review") is True)
    f_unc = evaluate.compose_files_and_docs_finding("FILES_AND_DOCS", fd_state(("composes",)), fd_answers(0.5), "t", other)
    _check("fd_code_uncertain_suggestion_review",
           f_unc["severity"] == "SUGGESTION" and f_unc["root_folder_mode"] == "uncertain" and f_unc.get("needs_manual_review") is True)
    _check("fd_code_denied_without_write_none",
           evaluate.compose_files_and_docs_finding("FILES_AND_DOCS", fd_state(("composes",)), fd_answers(0.1), "t", other) is None)
    f_den = evaluate.compose_files_and_docs_finding("FILES_AND_DOCS", fd_state(("writes", "composes")), fd_answers(0.1), "t", other)
    _check("fd_code_denied_with_write_double_gate_review",
           f_den is not None and f_den["severity"] == "SUGGESTION" and f_den["root_folder_mode"] == "denied"
           and f_den.get("needs_manual_review") is True and "model disagrees" in f_den["issue_summary"]
           and f_den["decision_trace"]["root_folder"]["deterministic_write"] is True, str(f_den))

    # --- planner gates and end-to-end run -----------------------------------------
    scratch = os.path.join(d, ".scratch")
    for rel, body in (("app/src/main/java/com/w9/Store.java", _JAVA_ROOT_FOLDER),
                      ("app/src/main/java/com/w9/Media.java", _JAVA_MEDIA),
                      ("app/src/main/java/com/w9/Ref.java", "package com.w9;\nimport android.os.Environment;\nclass Ref {\n  boolean shared(String p) {\n    return p.startsWith(Environment.getExternalStorageDirectory().getPath());\n  }\n}\n")):
      path = os.path.join(d, rel)
      os.makedirs(os.path.dirname(path), exist_ok=True)
      with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    sources = {
        "FILES_AND_DOCS": ["app/src/main/java/com/w9/Store.java (Pattern: getExternalStorageDirectory)",
                           "app/src/main/java/com/w9/Store.java (Pattern: createNewFile)",
                           "app/src/main/java/com/w9/Ref.java (Pattern: getExternalStorageDirectory)"],
        "MEDIA": ["app/src/main/java/com/w9/Media.java (Pattern: MediaStore)"],
        "PHOTOS": ["app/src/main/java/com/w9/Media.java (Pattern: MediaStore.Images)"],
    }
    # No storage / media permission ships: the code specs are gated, the manifest rules are silent.
    build(d, target=34, permissions=perms("INTERNET"))
    _write_scratch(d, scratch, sources)
    engine.run(scratch, HeuristicJevClient(), batched=True)
    worker = json.load(open(os.path.join(scratch, "worker_permissions_and_apis.json"), encoding="utf-8"))
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    pv_f = [f for f in worker["findings"] if f["policy_id"] == "photo_video_access_policy"]
    gated = triage["counters"].get("planner_gated") or {}
    _check("wave2_permission_gate_blocks_photo_video",
           pv_f == [] and gated.get("photo_video_access_policy", 0) >= 2
           and any("ships in the Play build" in dd.get("reason", "") for dd in triage.get("dropped", [])), f"{gated} {pv_f}")
    fd_code = [f for f in worker["findings"] if f["policy_id"] == "files_and_docs_policy" and f.get("kind") != "manifest"]
    _check("wave2_files_code_not_permission_gated_but_file_gated",
           len(fd_code) == 1 and fd_code[0]["files_involved"] == ["app/src/main/java/com/w9/Store.java"]
           and gated.get("files_and_docs_policy", 0) >= 1
           and any("structural activation" in dd.get("reason", "") for dd in triage.get("dropped", [])), str(fd_code))
    _check("wave2_one_per_file", (triage["counters"].get("tasks_per_policy") or {}).get("files_and_docs_policy") == 1
           and any("asked once per file" in dd.get("reason", "") for dd in triage.get("dropped", [])),
           str(triage["counters"].get("tasks_per_policy")))
    # With the permissions: manifest rules fire and the media code question is asked once for the file.
    build(d, target=34, permissions=perms("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"),
          application_attrs=' android:requestLegacyExternalStorage="true"')
    _write_scratch(d, scratch, sources)
    engine.run(scratch, HeuristicJevClient(), batched=True)
    worker = json.load(open(os.path.join(scratch, "worker_permissions_and_apis.json"), encoding="utf-8"))
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    pv_f = [f for f in worker["findings"] if f["policy_id"] == "photo_video_access_policy"]
    fd_f = [f for f in worker["findings"] if f["policy_id"] == "files_and_docs_policy"]
    _check("wave2_engine_manifest_findings",
           sorted(f["severity"] for f in pv_f if f.get("kind") == "manifest") == ["IMPORTANT", "IMPORTANT"]
           and sorted(f["severity"] for f in fd_f if f.get("kind") == "manifest") == ["IMPORTANT", "SUGGESTION"],
           str([(f["policy_id"], f.get("kind"), f["severity"]) for f in pv_f + fd_f]))
    pv_code = [f for f in pv_f if f.get("kind") != "manifest"]
    fd_code = [f for f in fd_f if f.get("kind") != "manifest"]
    _check("wave2_engine_code_findings",
           len(pv_code) == 1 and pv_code[0]["severity"] == "IMPORTANT" and pv_code[0].get("needs_manual_review") is True
           and pv_code[0]["media_access_mode"] == "full_library"
           and len(fd_code) == 1 and fd_code[0]["root_folder_mode"] == "confirmed" and fd_code[0]["severity"] == "IMPORTANT"
           and "Store.java:L10" in fd_code[0]["evidence"], str([(f["policy_id"], f["severity"], f.get("media_access_mode"), f.get("root_folder_mode"), f["evidence"]) for f in pv_code + fd_code]))
    _check("wave2_engine_tasks_per_policy",
           (triage["counters"].get("tasks_per_policy") or {}).get("photo_video_access_policy") == 1
           and (triage["counters"].get("tasks_per_policy") or {}).get("files_and_docs_policy") == 1,
           str(triage["counters"].get("tasks_per_policy")))
    # State blocks are present only where the deterministic hints exist.
    fs_store = structure.analyze_file(d, "app/src/main/java/com/w9/Store.java")
    st, mini = context.build_file_state(fs_store, [("FILES_AND_DOCS", "getExternalStorageDirectory")], {}, {})
    _check("wave2_state_storage_block", len(st.get("external_storage_paths") or []) == 4
           and st["external_storage_paths"][0]["strength"] == "writes"
           and mini[0]["external_storage_paths"] == st["external_storage_paths"] and "media_access_hints" not in st)
    fs_media = structure.analyze_file(d, "app/src/main/java/com/w9/Media.java")
    st_m, mini_m = context.build_file_state(fs_media, [("PHOTOS", "EXTERNAL_CONTENT_URI")], {}, {})
    _check("wave2_state_media_block", [h["hint"] for h in st_m.get("media_access_hints") or []] == ["LIBRARY_QUERY"]
           and mini_m[0]["anchor"]["media_hints"] == ["LIBRARY_QUERY"] and "external_storage_paths" not in st_m,
           str(st_m.get("media_access_hints")))
    fs_ref2 = structure.analyze_file(d, "app/src/main/java/com/w9/Ref.java")
    st_r, _ = context.build_file_state(fs_ref2, [("FILES_AND_DOCS", "getExternalStorageDirectory")], {}, {})
    _check("wave2_state_reference_only_hint_listed_but_not_activating",
           [h["strength"] for h in st_r.get("external_storage_paths") or []] == ["references"]
           and context.has_storage_write_hint(fs_ref2) is False)


def _test_data_type_confirmed() -> None:
  """WP10 (L7): the ``data_type_confirmed`` Choice and its composition.

  Covers: sibling lists (confusions first, same category next, capped, only
  taxonomy types, empty for unknown); the question shape and its place in the
  battery; the heuristic stand-in; composition -- not read below the band,
  ``as_labelled`` / low confidence unchanged, a raising relabel applies in
  full, a lowering relabel is one step + review, ``NOT_PERSONAL`` keeps the
  finding capped at IMPORTANT + review, ``unknown`` reviews, a non-taxonomy
  answer is ignored, the consent raise is capped on a disputed type, the
  feature flag; the engine counters; and the calibrate confusion table with a
  relabelled finding joining through ``scanner_data_type``.
  """
  from typesafe_eval import calibrate
  from typesafe_eval import constants
  from typesafe_eval import taxonomy
  from typesafe_eval.client import HeuristicJevClient
  from typesafe_eval.client import JevAnswer

  # --- taxonomy siblings ------------------------------------------------------
  sib = taxonomy.siblings("USER_ACCOUNT")
  _check("siblings_confusions_first_then_category",
         list(sib)[:2] == ["DEVICE_ID", "NAME"] and "EMAIL" in sib
         and len(sib) <= constants.MAX_TYPE_SIBLING_OPTIONS and "USER_ACCOUNT" not in sib, str(list(sib)))
  _check("siblings_same_category", list(taxonomy.siblings("PHOTOS")) == ["FILES_AND_DOCS", "VIDEOS"],
         str(list(taxonomy.siblings("PHOTOS"))))
  _check("siblings_unknown_type_empty", taxonomy.siblings("NOT_A_TYPE") == {})
  _check("taxonomy_helpers", taxonomy.category_of("PHOTOS") == "Photos and videos"
         and taxonomy.display_name("CRASH_LOGS") == "Crash logs" and taxonomy.description("NOPE") == ""
         and evaluate._taxonomy() is taxonomy.load())  # pylint: disable=protected-access

  # --- question and battery -----------------------------------------------------
  battery = q.data_safety_battery("USER_ACCOUNT", "user ids", token="uid")
  qd = battery["data_type_confirmed"]
  _check("type_question_in_battery_after_relevance",
         list(battery)[:3] == ["signal_relevant", "data_type_confirmed", "transmits_offdevice"])
  _check("type_question_shape", qd["type"] == "choice"
         and list(qd["criteria"])[0] == "as_labelled" and list(qd["criteria"])[-2:] == ["NOT_PERSONAL", "unknown"]
         and "DEVICE_ID" in qd["criteria"] and "`uid`" in qd["instructions"]
         and "Android app UID" in qd["criteria"]["NOT_PERSONAL"], str(qd)[:300])
  explicit = q.data_safety_battery("PHOTOS", "photos", siblings={"VIDEOS": "Videos: v"})["data_type_confirmed"]
  _check("type_question_explicit_siblings", list(explicit["criteria"]) == ["as_labelled", "VIDEOS", "NOT_PERSONAL", "unknown"])
  heur = HeuristicJevClient()
  ans = heur.system_one({"signal": {"data_type": "USER_ACCOUNT", "matched_pattern": "uid"}, "co_located_signals": {}, "app": {}},
                        {"data_type_confirmed": qd})
  _check("type_heuristic_confirms_label", ans["data_type_confirmed"].choice == "as_labelled"
         and ans["data_type_confirmed"].confidence > constants.CONF_TYPE_CONFIRM)

  # --- composition --------------------------------------------------------------
  def answers(p_transmit=0.95, answer="as_labelled", conf=0.9, status="MISSING", p_consent=None, cls="developer_backend"):
    n = len(q.DESTINATION_CLASS_OPTIONS)
    dprobs = {o: (0.9 if o == cls else 0.1 / (n - 1)) for o in q.DESTINATION_CLASS_OPTIONS}
    a = {
        "signal_relevant": JevAnswer("noul", noul=0.9),
        "transmits_offdevice": JevAnswer("noul", noul=p_transmit),
        "user_initiated": JevAnswer("noul", noul=0.2),
        "destination_class": JevAnswer("choice", choice=cls, probabilities=dprobs, confidence=0.9),
        "has_prominent_disclosure": JevAnswer("noul", noul=0.1),
        "disclosure_status": JevAnswer("choice", choice=status),
        "severity": JevAnswer("score", score=0.6),
        "data_type_confirmed": JevAnswer("choice", choice=answer, probabilities={answer: conf}, confidence=conf),
    }
    if p_consent is not None:
      a["consent_default_on"] = JevAnswer("noul", noul=p_consent)
    return a

  def state(dt="USER_ACCOUNT"):
    return {
        "signal": {"data_type": dt, "matched_pattern": "uid", "file": "Adapter.kt", "line": 13,
                   "matched_line": "post(uid)", "all_lines": [13]},
        "code_snippet": "L13: post(uid)",
        "sinks": [{"symbol": "URL", "capabilities": ["NETWORK_EGRESS"], "lines": [13]}],
        "anchor": {"scope": [8, 19], "proximity": 0, "sink_in_scope": True, "tier": 0,
                   "scope_capabilities": ["NETWORK_EGRESS"], "destination_hints": []},
        "app": {},
    }

  compose = evaluate._compose_data_safety_finding  # pylint: disable=protected-access
  f = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(), "test")
  tc = f["decision_trace"]["type_confirmation"]
  _check("type_as_labelled_unchanged", f["severity"] == "IMPORTANT" and f["psl_constant"] == "USER_ACCOUNT"
         and f["confirmed_type"] == "USER_ACCOUNT" and f["data_type_confirmed"] == "as_labelled"
         and tc["read"] is True and tc["action"] == "as_labelled" and not f.get("needs_manual_review")
         and f["decision_trace"]["thresholds"]["CONF_TYPE_CONFIRM"] == constants.CONF_TYPE_CONFIRM, str(tc))
  f = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(p_transmit=0.1, answer="NOT_PERSONAL"), "test")
  _check("type_not_read_below_band", f["decision_trace"]["type_confirmation"]["read"] is False
         and f["data_type_confirmed"] is None and f["severity"] == "SUGGESTION" and not f.get("needs_manual_review"))
  f = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(answer="NOT_PERSONAL", conf=0.6), "test")
  _check("type_low_confidence_traced_only", f["decision_trace"]["type_confirmation"]["action"] == "as_labelled"
         and f["data_type_confirmed"] == "NOT_PERSONAL" and f["severity"] == "IMPORTANT" and not f.get("needs_manual_review"))
  f = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(answer="NOT_PERSONAL", conf=0.85), "test")
  _check("type_not_personal_kept_capped_review", f["severity"] == "IMPORTANT" and f["psl_constant"] == "USER_ACCOUNT"
         and f["confirmed_type"] == "NOT_PERSONAL" and f.get("needs_manual_review") is True
         and "[type disputed: not personal data per model conf=0.85; verify]" in f["issue_summary"]
         and f["decision_trace"]["type_confirmation"]["action"] == "not_personal"
         and "not personal" in f["decision_trace"]["type_note"], str(f["issue_summary"]))
  # A sensitive type (CRITICAL when undisclosed) answered not personal: capped at IMPORTANT, never dropped.
  f = compose("PRECISE_LOCATION", "Geo.kt (Pattern: lat)", state("PRECISE_LOCATION"), answers(answer="NOT_PERSONAL", conf=0.9), "test")
  _check("type_not_personal_caps_critical", f is not None and f["severity"] == "IMPORTANT"
         and f.get("needs_manual_review") is True and f["psl_constant"] == "PRECISE_LOCATION")
  # Relabel at the same sensitivity (USER_ACCOUNT -> DEVICE_ID, both IMPORTANT when
  # undisclosed): type, claim, category and linkage follow the confirmed type.
  f = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(answer="DEVICE_ID", conf=0.9), "test")
  _check("type_relabel_same_sensitivity_applies", f["psl_constant"] == "DEVICE_ID" and f["scanner_data_type"] == "USER_ACCOUNT"
         and f["severity"] == "IMPORTANT" and not f.get("needs_manual_review")
         and "[type: USER_ACCOUNT -> DEVICE_ID conf=0.90]" in f["issue_summary"]
         and "Device or other IDs" in f["claim"] and f["confirmed_type"] == "DEVICE_ID"
         and f["linked_to_user"] is False, str(f["issue_summary"]))
  # Relabel that raises (EMAIL, not sensitive -> EMAILS, sensitive): applies in full.
  f = compose("EMAIL", "Mail.kt (Pattern: email)", state("EMAIL"), answers(answer="EMAILS", conf=0.9), "test")
  _check("type_relabel_raise_applies_in_full", f["psl_constant"] == "EMAILS" and f["severity"] == "CRITICAL"
         and f["decision_trace"]["type_confirmation"]["lowered"] is False and not f.get("needs_manual_review"),
         str((f["psl_constant"], f["severity"])))
  # Relabel that lowers (EMAILS -> EMAIL): one step, review, still in the report.
  f = compose("EMAILS", "Mail.kt (Pattern: mail)", state("EMAILS"), answers(answer="EMAIL", conf=0.9), "test")
  _check("type_relabel_lower_one_step_review", f["psl_constant"] == "EMAIL" and f["severity"] == "IMPORTANT"
         and f["decision_trace"]["type_confirmation"]["lowered"] is True and f.get("needs_manual_review") is True
         and "; verify]" in f["issue_summary"] and f["linked_to_user"] is True, str(f["issue_summary"]))
  f = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(answer="unknown", conf=0.9), "test")
  _check("type_unknown_review", f["severity"] == "IMPORTANT" and f["psl_constant"] == "USER_ACCOUNT"
         and f.get("needs_manual_review") is True and "[type unclear" in f["issue_summary"])
  f = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(answer="NOT_A_TYPE", conf=0.9), "test")
  _check("type_non_taxonomy_answer_ignored", f["psl_constant"] == "USER_ACCOUNT" and f["severity"] == "IMPORTANT"
         and f["decision_trace"]["type_confirmation"]["action"] == "as_labelled" and not f.get("needs_manual_review"))
  # Consent raise is capped while the type is disputed; applies when it is confirmed.
  f = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(answer="NOT_PERSONAL", conf=0.9, p_consent=0.9), "test")
  _check("type_disputed_caps_consent_raise", f["severity"] == "IMPORTANT"
         and f["decision_trace"]["consent"]["capped_by"] == "disputed_type"
         and "data type is disputed" in f["decision_trace"]["consent_note"], str(f["decision_trace"]["consent"]))
  f = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(answer="as_labelled", conf=0.9, p_consent=0.9), "test")
  _check("type_confirmed_consent_raise_applies", f["severity"] == "CRITICAL" and f["decision_trace"]["consent"]["action"] == "raise")
  # Below the band with a disputed answer the type is moot, no review flag from it.
  _check("type_mode_bands", evaluate.compose_type_confirmation(
      "USER_ACCOUNT", answers(answer="NOT_PERSONAL", conf=0.9), False, "EXEMPT", evaluate.LOCAL)[0].read is False)
  # Feature flag.
  saved = constants.DATA_TYPE_CONFIRMED_ENABLED
  constants.DATA_TYPE_CONFIRMED_ENABLED = False
  try:
    f = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(answer="NOT_PERSONAL", conf=0.9), "test")
    _check("type_disabled_traced_only", f["severity"] == "IMPORTANT" and not f.get("needs_manual_review")
           and f["decision_trace"]["type_confirmation"]["enabled"] is False
           and f["decision_trace"]["type_confirmation"]["read"] is False)
  finally:
    constants.DATA_TYPE_CONFIRMED_ENABLED = saved

  # --- calibrate: confusion table and rejoin through scanner_data_type ---------
  with tempfile.TemporaryDirectory() as d:
    relabelled = compose("USER_ACCOUNT", "Adapter.kt (Pattern: uid)", state(), answers(answer="DEVICE_ID", conf=0.9), "test")
    disputed = compose("APPROX_LOCATION", "Geo.kt (Pattern: loc)", state("APPROX_LOCATION"), answers(answer="NOT_PERSONAL", conf=0.9), "test")
    kept = compose("CRASH_LOGS", "Rep.kt (Pattern: report)", state("CRASH_LOGS"), answers(), "test")
    local = compose("EMAIL", "Mail.kt (Pattern: email)", state("EMAIL"), answers(p_transmit=0.1), "test")
    for fnd, file in ((relabelled, "Adapter.kt"), (disputed, "Geo.kt"), (kept, "Rep.kt"), (local, "Mail.kt")):
      fnd["files_involved"] = [f"src/{file}"]
    with open(os.path.join(d, "worker_data_safety.json"), "w", encoding="utf-8") as fh:
      json.dump({"findings": [relabelled, disputed, kept, local]}, fh)
    labels = {"schema_version": 2, "cases": [
        {"file": "Adapter.kt", "data_type": "USER_ACCOUNT", "transfers": True, "destination_class": "developer_backend",
         "confirmed_type": "DEVICE_ID"},
        {"file": "Geo.kt", "data_type": "APPROX_LOCATION", "transfers": True, "destination_class": "developer_backend"},
        {"file": "Rep.kt", "data_type": "CRASH_LOGS", "transfers": True, "destination_class": "developer_backend",
         "confirmed_type": "PERFORMANCE_DIAGNOSTICS"},
        {"file": "Mail.kt", "data_type": "EMAIL", "transfers": False, "confirmed_type": "NOT_PERSONAL"},
    ]}
    rep = calibrate.calibrate(labels, rejoin=True, worker_dirs=[d])
    t = rep["type_confirmation"]
    _check("calibrate_relabelled_finding_rejoins", rep["missing_positives"] == [] and rep["unmatched_cases"] == []
           and any(c["file"] == "Adapter.kt" and c["run_confirmed_type"] == "DEVICE_ID" for c in rep["cases"]), str(rep["unmatched_cases"]))
    _check("calibrate_type_confusion", t["n_scored"] == 4 and t["n_labelled_confirmed_type"] == 3
           and t["confusion"]["DEVICE_ID"] == {"DEVICE_ID": 1}
           and t["confusion"]["APPROX_LOCATION"] == {"NOT_PERSONAL": 1}
           and t["confusion"]["PERFORMANCE_DIAGNOSTICS"] == {"CRASH_LOGS": 1}
           and t["not_read"] == 1 and t["accuracy"] == 0.25, str(t))
    _check("calibrate_missed_and_wrong_relabels",
           [m["file"] for m in t["missed_relabels"]] == ["Rep.kt"]
           and [w["file"] for w in t["wrong_relabels"]] == ["Geo.kt"]
           and any("relabelled or disputed" in w for w in rep["warnings"]), str((t["missed_relabels"], t["wrong_relabels"])))


_KT_PROVISION_API = """package com.x.net
import java.net.HttpURLConnection
interface AccountApi {
  // registerDevice is documented here; the comment must not count
  @POST("/d/reg")
  suspend fun registerDevice(accountId: String?, deviceId: String?): Response
  @GET("/d/status")
  suspend fun status(accountId: String): Response
}
"""

_KT_PROVISION_CALLER = """package com.x.iab
import com.x.net.AccountApi
import android.content.SharedPreferences
class Identity(val api: AccountApi, val prefs: SharedPreferences) {
  suspend fun ensure(): String {
    val existing = prefs.getString("cid", null)
    val response = api.registerDevice(existing, null)
    val accountId = response.body().get("cid").asString
    prefs.edit().putString("cid", accountId).apply()
    return accountId
  }
}
"""

_KT_REMOTE_DELETE = """package com.x.iab
import com.x.net.AccountApi
class AccountRemover(val api: AccountApi) {
  @DELETE("/d/acc")
  suspend fun deleteAccount(accountId: String): Boolean {
    val ok = api.status(accountId)
    return ok != null
  }
}
"""

_KT_LOCAL_DELETE = """package com.x.ui
import android.content.SharedPreferences
class SignOut(val prefs: SharedPreferences) {
  fun removeUser() {
    prefs.edit().clear().apply()
  }
}
"""

_KT_LOGIN_SCREEN = """package com.x.ui
class LoginActivity {
  fun signIn(user: String, password: String) {
    val host = "example.invalid"
    val port = 22
    authenticate(user, password)
  }
  fun authenticate(u: String, p: String) {}
}
"""

_KT_RECEIVER_ONLY = """package com.x.ui
import android.content.Context
class Plain(val ctx: Context) {
  fun start() { ctx.registerReceiver(null, null) }  // registerDevice in a trailing comment
  fun stop() { ctx.unregisterReceiver(null) }
}
"""


def _test_identity_lifecycle() -> None:
  """WP11: deterministic identity-lifecycle scan, sites/candidates, and the two app-level policies."""
  from typesafe_eval import capabilities as capsmod
  from typesafe_eval import constants
  from typesafe_eval import engine
  from typesafe_eval import identity
  from typesafe_eval import templates
  from typesafe_eval.client import HeuristicJevClient, JevAnswer, JevClient

  # --- scan_lines: verbs bound to nouns, comments skipped, shapes recorded.
  fl = identity.scan_lines("Api.kt", _KT_PROVISION_API.splitlines())
  _check("identity_scan_provision_verbs", fl.tokens_of(identity.PROVISION) == ["registerDevice"]
         and fl.lines_of(identity.PROVISION) == [5], str(fl.to_dict()))
  _check("identity_scan_network_shape", fl.has(identity.NETWORK) and "@POST(" in fl.tokens_of(identity.NETWORK)
         and "HttpURLConnection" not in fl.tokens_of(identity.NETWORK), str(fl.tokens_of(identity.NETWORK)))
  _check("identity_scan_identity_tokens", "accountId" in fl.tokens_of(identity.IDENTITY)
         and "deviceId" in fl.tokens_of(identity.IDENTITY), str(fl.tokens_of(identity.IDENTITY)))
  plain = identity.scan_lines("Plain.kt", _KT_RECEIVER_ONLY.splitlines())
  _check("identity_scan_receiver_not_provisioning", not plain.has(identity.PROVISION) and not plain.has(identity.DELETE),
         str(plain.to_dict()))
  rem = identity.scan_lines("Rem.kt", _KT_REMOTE_DELETE.splitlines())
  _check("identity_scan_delete_verbs", set(rem.tokens_of(identity.DELETE)) >= {"deleteAccount", "@DELETE("},
         str(rem.tokens_of(identity.DELETE)))
  caller = identity.scan_lines("Identity.kt", _KT_PROVISION_CALLER.splitlines())
  _check("identity_scan_persist_shape", caller.has(identity.PERSIST) and "putString(" in caller.tokens_of(identity.PERSIST)
         and not caller.has(identity.NETWORK), str(caller.to_dict()))
  login = identity.scan_lines("Login.kt", _KT_LOGIN_SCREEN.splitlines())
  _check("identity_scan_login_shapes", {"signIn", "password", "authenticate"} <= set(login.tokens_of(identity.LOGIN))
         and len(login.of(identity.USER_SERVER)) == 2, str(login.to_dict()))
  _check("identity_hits_capped", len(identity.scan_lines("X.kt", ["val password = 1"] * 40).of(identity.LOGIN))
         == constants.MAX_LIFECYCLE_HITS_PER_FILE)

  class _Lifecycle(JevClient):
    name = "fixed-lifecycle"
    def __init__(self, remote=0.1, local=0.1, gate=None, gate_conf=0.9, fail=False):
      super().__init__(); self.remote = remote; self.local = local; self.gate = gate
      self.gate_conf = gate_conf; self.fail = fail; self.lifecycle_states = []; self.gate_states = []
    def system_one(self, state, questions, model=None):
      if "is_remote_delete" in questions:
        self.lifecycle_states.append(state)
        if self.fail:
          raise RuntimeError("boom")
        return {"is_remote_delete": JevAnswer("noul", noul=self.remote),
                "clears_local_state_only": JevAnswer("noul", noul=self.local)}
      if "login_gate_type" in questions:
        self.gate_states.append(state)
        opts = list(questions["login_gate_type"]["criteria"])
        g = self.gate or "unknown"
        probs = {o: (self.gate_conf if o == g else (1 - self.gate_conf) / (len(opts) - 1)) for o in opts}
        return {"login_gate_type": JevAnswer("choice", choice=g, probabilities=probs, confidence=self.gate_conf)}
      return HeuristicJevClient().system_one(state, questions, model)

  def _app(d, files):
    for rel, text in files.items():
      os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
      with open(os.path.join(d, rel), "w", encoding="utf-8") as f:
        f.write(text)

  def _run(d, client, semantic=None):
    scratch = os.path.join(d, ".scratch")
    _write_scratch(d, scratch, {})
    if semantic is not None:
      p = os.path.join(scratch, "data_safety_scan.json")
      doc = json.load(open(p, encoding="utf-8")); doc["semantic_files"] = {"USER_ACCOUNT": semantic}
      json.dump(doc, open(p, "w", encoding="utf-8"))
    engine.run(scratch, client, batched=True, capability_cache=capsmod.CapabilityCache(os.path.join(d, "caps.json")))
    worker = json.load(open(os.path.join(scratch, "worker_user_account.json"), encoding="utf-8"))["findings"]
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    return worker, triage

  base = "app/src/main/java/com/x/"
  prov_files = {base + "net/AccountApi.kt": _KT_PROVISION_API, base + "iab/Identity.kt": _KT_PROVISION_CALLER,
                base + "ui/Plain.kt": _KT_RECEIVER_ONLY}

  # (a) provisioning (network one hop away, persisted in the caller), no deletion -> IMPORTANT no_deletion_path.
  with tempfile.TemporaryDirectory() as d:
    _app(d, prov_files)
    worker, triage = _run(d, _Lifecycle())
    ad = [f for f in worker if f["policy_id"] == "account_deletion" and f.get("kind") == "identity_lifecycle"]
    _check("lifecycle_no_deletion_path_important", len(ad) == 1 and ad[0]["severity"] == "IMPORTANT"
           and ad[0]["lifecycle_mode"] == "no_deletion_path" and not ad[0].get("needs_manual_review"),
           json.dumps([(f.get("lifecycle_mode"), f["severity"]) for f in ad]))
    il = triage["identity_lifecycle"]
    sites = il["assessment"]["provisioning"]
    _check("lifecycle_site_reach_traced", il["outcome"] == "no_deletion_path" and len(sites) == 2
           and any(s["file"].endswith("Identity.kt") and s["network"]["source"] == "hop" and s["persisted"] for s in sites)
           and any(s["file"].endswith("AccountApi.kt") and s["network"]["source"] == "file" for s in sites),
           json.dumps(sites)[:400])
    _check("lifecycle_counters", triage["counters"]["identity_lifecycle"]["provisioning_sites"] == 2
           and triage["counters"]["identity_lifecycle"]["deletion_candidates"] == 0
           and triage["counters"]["identity_lifecycle"]["scanned"] == 3, json.dumps(triage["counters"]["identity_lifecycle"]))
    _check("lifecycle_login_not_asked", triage["login_gate"]["source"] == "not_asked"
           and not [f for f in worker if f["policy_id"] == "login_credentials"], json.dumps(triage["login_gate"]))

  # (b) provisioning without any persistence shape -> SUGGESTION + review.
  with tempfile.TemporaryDirectory() as d:
    _app(d, {base + "net/AccountApi.kt": _KT_PROVISION_API})
    worker, triage = _run(d, _Lifecycle())
    ad = [f for f in worker if f.get("kind") == "identity_lifecycle"]
    _check("lifecycle_persistence_unconfirmed_suggestion", len(ad) == 1 and ad[0]["severity"] == "SUGGESTION"
           and ad[0]["lifecycle_mode"] == "persistence_unconfirmed" and ad[0].get("needs_manual_review") is True,
           json.dumps(ad)[:300])

  # (c) remote delete confirmed -> compliant, traced, no finding.
  with tempfile.TemporaryDirectory() as d:
    _app(d, {**prov_files, base + "iab/AccountRemover.kt": _KT_REMOTE_DELETE, base + "ui/SignOut.kt": _KT_LOCAL_DELETE})
    client = _Lifecycle(remote=0.9, local=0.1)
    worker, triage = _run(d, client)
    il = triage["identity_lifecycle"]
    _check("lifecycle_remote_delete_confirmed", il["outcome"] == "remote_delete_confirmed"
           and not [f for f in worker if f.get("kind") == "identity_lifecycle"]
           and il["confirmed"]["file"].endswith("AccountRemover.kt") and il["confirmed"]["remote_shaped"],
           json.dumps(il.get("asked")))
    cands = il["assessment"]["deletion_candidates"]
    _check("lifecycle_candidates_ranked_remote_first", [c["file"].split("/")[-1] for c in cands] == ["AccountRemover.kt", "SignOut.kt"]
           and cands[0]["remote_shaped"] and not cands[1]["remote_shaped"], json.dumps(cands)[:300])
    st = client.lifecycle_states[0]
    _check("lifecycle_state_shape", set(st) == {"app", "signal", "code_snippet", "network_indicators", "persistence_indicators", "provisioning"}
           and st["signal"]["file"].endswith("AccountRemover.kt") and "deleteAccount" in st["code_snippet"]
           and len(st["provisioning"]) == 2 and st["network_indicators"], str(sorted(st)))
    _check("lifecycle_asked_once_when_confirmed", len(client.lifecycle_states) == 1
           and triage["counters"]["identity_lifecycle"]["requests"] == 1)

  # (d) local-only deletion -> IMPORTANT local_only (no review); (e) neither -> IMPORTANT unconfirmed + review;
  # (f) client failure -> IMPORTANT + review with the error traced.
  with tempfile.TemporaryDirectory() as d:
    _app(d, {**prov_files, base + "ui/SignOut.kt": _KT_LOCAL_DELETE})
    worker, triage = _run(d, _Lifecycle(remote=0.1, local=0.9))
    ad = [f for f in worker if f.get("kind") == "identity_lifecycle"]
    _check("lifecycle_local_only_important", len(ad) == 1 and ad[0]["severity"] == "IMPORTANT"
           and ad[0]["lifecycle_mode"] == "local_only" and not ad[0].get("needs_manual_review")
           and any(p.endswith("SignOut.kt") for p in ad[0]["files_involved"]), json.dumps(ad)[:300])
  with tempfile.TemporaryDirectory() as d:
    _app(d, {**prov_files, base + "ui/SignOut.kt": _KT_LOCAL_DELETE})
    worker, triage = _run(d, _Lifecycle(remote=0.3, local=0.3))
    ad = [f for f in worker if f.get("kind") == "identity_lifecycle"]
    _check("lifecycle_unconfirmed_review", len(ad) == 1 and ad[0]["severity"] == "IMPORTANT"
           and ad[0]["lifecycle_mode"] == "unconfirmed" and ad[0].get("needs_manual_review") is True, json.dumps(ad)[:300])
  with tempfile.TemporaryDirectory() as d:
    _app(d, {**prov_files, base + "ui/SignOut.kt": _KT_LOCAL_DELETE})
    worker, triage = _run(d, _Lifecycle(fail=True))
    ad = [f for f in worker if f.get("kind") == "identity_lifecycle"]
    _check("lifecycle_failure_keeps_finding", len(ad) == 1 and ad[0]["severity"] == "IMPORTANT"
           and ad[0].get("needs_manual_review") is True and "error" in triage["identity_lifecycle"]["asked"][0],
           json.dumps(triage["identity_lifecycle"].get("asked")))

  # (g) no provisioning -> nothing, even with a deletion-shaped call and a login screen.
  with tempfile.TemporaryDirectory() as d:
    _app(d, {base + "ui/SignOut.kt": _KT_LOCAL_DELETE, base + "ui/LoginActivity.kt": _KT_LOGIN_SCREEN})
    client = _Lifecycle(gate="user_remote_server_credentials", gate_conf=0.93)
    worker, triage = _run(d, client, semantic=["login.xml"])
    _check("lifecycle_no_provisioning_no_finding", triage["identity_lifecycle"]["outcome"] == "no_provisioning"
           and not [f for f in worker if f.get("kind") == "identity_lifecycle"] and not client.lifecycle_states)
    lg = triage["login_gate"]
    _check("login_gate_user_server_recorded_no_finding", lg["gate_type"] == "user_remote_server_credentials"
           and lg["source"] == "model" and not [f for f in worker if f["policy_id"] == "login_credentials"]
           and triage["counters"]["login_gate_outcome"] == "user_remote_server_credentials", json.dumps(lg)[:300])
    st = client.gate_states[0]
    _check("login_gate_state_shape", set(st) == {"app", "login_files", "semantic_files", "snippets", "declared_capabilities"}
           and st["semantic_files"] == ["login.xml"] and st["login_files"][0]["file"].endswith("LoginActivity.kt")
           and st["login_files"][0]["remote_server_tokens"] == 2 and "signIn" in next(iter(st["snippets"].values())),
           json.dumps(st)[:400])
    # Same evidence again -> cache hit, no second model call.
    client2 = _Lifecycle(gate="app_account", gate_conf=0.95)
    scratch = os.path.join(d, ".scratch")
    engine.run(scratch, client2, batched=True, capability_cache=capsmod.CapabilityCache(os.path.join(d, "caps.json")))
    triage2 = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    _check("login_gate_cached", triage2["login_gate"]["source"] == "cache"
           and triage2["login_gate"]["gate_type"] == "user_remote_server_credentials" and not client2.gate_states,
           json.dumps(triage2["login_gate"])[:200])

  # (h) app account -> IMPORTANT login_credentials; (i) unknown / low confidence -> SUGGESTION + review;
  # (j) none -> nothing.
  for gate, conf, expect in (("app_account", 0.9, ("IMPORTANT", False)),
                             ("third_party_sign_in_bridge", 0.9, ("IMPORTANT", False)),
                             ("app_account", constants.CONF_LOGIN_GATE - 0.05, ("SUGGESTION", True)),
                             ("unknown", 0.9, ("SUGGESTION", True)),
                             ("none", 0.9, None)):
    with tempfile.TemporaryDirectory() as d:
      _app(d, {base + "ui/LoginActivity.kt": _KT_LOGIN_SCREEN})
      worker, triage = _run(d, _Lifecycle(gate=gate, gate_conf=conf))
      lc = [f for f in worker if f["policy_id"] == "login_credentials"]
      if expect is None:
        _check(f"login_gate_{gate}_no_finding", not lc, json.dumps(lc)[:200])
      else:
        _check(f"login_gate_{gate}_{conf:.2f}", len(lc) == 1 and lc[0]["severity"] == expect[0]
               and bool(lc[0].get("needs_manual_review")) == expect[1] and lc[0]["login_gate_type"] == gate
               and lc[0]["kind"] == "login_gate" and lc[0]["files_involved"][0].endswith("LoginActivity.kt"),
               json.dumps(lc)[:300])

  # Templates and rollback flags.
  _check("lifecycle_templates", templates.lifecycle_summary("local_only") != templates.lifecycle_summary("no_deletion_path")
         and templates.lifecycle_summary("bogus") == templates.lifecycle_summary("unconfirmed")
         and "reviewer" in templates.recommendation("login_credentials", "IMPORTANT")
         and "in-app" in templates.recommendation("account_deletion", "IMPORTANT")
         and "login" in templates.login_gate_summary("app_account"))
  _check("lifecycle_batteries_closed", set(q.account_deletion_lifecycle_battery()) == {"is_remote_delete", "clears_local_state_only"}
         and set(q.login_gate_battery()["login_gate_type"]["criteria"]) == set(q.LOGIN_GATE_OPTIONS)
         and {"unknown", "none", "user_remote_server_credentials"} <= set(q.LOGIN_GATE_OPTIONS))
  old = constants.IDENTITY_LIFECYCLE_ENABLED, constants.LOGIN_GATE_ENABLED
  try:
    constants.IDENTITY_LIFECYCLE_ENABLED = False
    constants.LOGIN_GATE_ENABLED = False
    with tempfile.TemporaryDirectory() as d:
      _app(d, {**prov_files, base + "ui/LoginActivity.kt": _KT_LOGIN_SCREEN})
      worker, triage = _run(d, _Lifecycle(gate="app_account"))
      _check("lifecycle_rollback_flags", not [f for f in worker if f.get("kind") in ("identity_lifecycle", "login_gate")]
             and triage["identity_lifecycle"] == {} and triage["login_gate"]["source"] == "not_asked", json.dumps(worker)[:200])
  finally:
    constants.IDENTITY_LIFECYCLE_ENABLED, constants.LOGIN_GATE_ENABLED = old


def _test_app_profile() -> None:
  """WP1: evaluator-owned manifest parsing and source-set merge."""
  from typesafe_eval import android_manifest as am
  with tempfile.TemporaryDirectory() as d:
    def write(rel, text):
      p = os.path.join(d, rel)
      os.makedirs(os.path.dirname(p), exist_ok=True)
      with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    write("app/src/main/AndroidManifest.xml", _MANIFEST_MAIN)
    write("app/src/play/AndroidManifest.xml", _MANIFEST_PLAY)
    write("app/src/full/AndroidManifest.xml", _MANIFEST_FULL)
    write("app/src/androidTest/AndroidManifest.xml", "<manifest><uses-permission /></manifest>")
    write("app/src/main/res/values/strings.xml",
          '<resources><string name="app_name">Demo App</string></resources>')
    write("app/src/main/res/xml/a11y.xml",
          '<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android" '
          'android:isAccessibilityTool="true" />')
    write("app/build.gradle.kts",
          'android {\n  namespace = "com.demo"\n  defaultConfig {\n    applicationId = "com.demo"\n'
          '    minSdk = 24\n    targetSdk = 35\n  }\n  // targetSdk = 99 (comment must not count)\n}\n')
    # A library module with its own manifest must not be merged.
    write("lib/src/main/AndroidManifest.xml",
          '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
          '<uses-permission android:name="android.permission.CAMERA" /></manifest>')
    # A malformed flavor manifest degrades to a warning, not a crash.
    write("app/src/tv/AndroidManifest.xml", "<manifest><application></manifest>")

    p = am.load_profile(d, {"package_name": "wrong.pkg", "target_sdk": 34,
                            "permissions": ["android.permission.INTERNET"]})
    _check("profile_primary_module", p.module_root == "app" and p.other_modules == ["lib"],
           f"{p.module_root} {p.other_modules}")
    _check("profile_gradle_package_and_sdk",
           p.package_name == "com.demo" and p.target_sdk == 35 and p.min_sdk == 24
           and p.sdk_provenance["target_sdk"].startswith("gradle:"), str(p.sdk_provenance))
    _check("profile_source_sets_main_first", p.source_sets[0] == "main" and "play" in p.source_sets
           and "androidTest" not in p.source_sets, str(p.source_sets))
    _check("profile_library_not_merged", not p.has_permission("CAMERA"))
    internet = p.permission("INTERNET")
    _check("profile_duplicate_permission_two_sources",
           internet is not None and internet.sources == ["main", "play"], str(internet))
    _check("profile_permission_max_sdk", p.permission("WRITE_EXTERNAL_STORAGE").max_sdk == 28)
    _check("profile_permission_sdk23", p.permission("POST_NOTIFICATIONS").sdk23_only is True)
    _check("profile_flavor_only_permission",
           p.permission("QUERY_ALL_PACKAGES").sources == ["play"])
    _check("profile_tools_replace_wins",
           p.application.get("name") == "com.demo.AppPlay" and p.application_sources["name"] == "play",
           str(p.application))
    _check("profile_label_resolved", p.application.get("label") == "Demo App"
           and p.application.get("label_resource") == "@string/app_name", str(p.application))
    _check("profile_legacy_storage_flag", p.application.get("request_legacy_external_storage") is True)
    typeless = [s.name for s in p.services_without_fgs_type()]
    _check("profile_typeless_service_present", "com.demo.Typeless" in typeless, str(typeless))
    typed = next(s for s in p.services if s.name == "com.demo.Typed")
    _check("profile_fgs_types_union_and_property",
           set(typed.fgs_types) == {"specialUse", "dataSync"}
           and typed.properties.get("android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE") == "vpn",
           str(typed.to_dict()))
    removed = next(c for c in p.components if c.name == "lib.InitProvider")
    _check("profile_tools_node_remove", removed.removed_in == ["play"] and removed.is_active is True
           and not p.ships_in_play_build(removed), str(removed.to_dict()))
    _check("profile_authority_placeholder", removed.authorities == ["com.demo.init"], str(removed.authorities))
    full_only = next(c for c in p.components if c.name == "com.demo.FullOnly")
    _check("profile_flavor_only_component_not_in_play_build",
           full_only.is_active and not p.ships_in_play_build(full_only)
           and "com.demo.FullOnly" in p.summary()["flavor_only_components"])
    _check("profile_launcher", [c.name for c in p.launcher_activities()] == ["com.demo.Main"])
    roles = p.default_handler_roles()
    _check("profile_sms_role_from_smsto", roles.get("sms") == ["com.demo.Compose"], str(roles))
    _check("profile_sms_receiver", [c.name for c in p.sms_receivers()] == ["com.demo.Sms"])
    _check("profile_file_handling", [c.name for c in p.file_handling_activities()] == ["com.demo.Compose"])
    _check("profile_accessibility_tool_flag",
           len(p.accessibility_services) == 1 and p.accessibility_services[0].is_accessibility_tool is True
           and p.accessibility_services[0].config_path.endswith("res/xml/a11y.xml"),
           str([a.to_dict() for a in p.accessibility_services]))
    _check("profile_queries", p.queries["packages"] == ["com.example.other"]
           and p.queries["intents"] == ["android.intent.action.SEND"], str(p.queries))
    _check("profile_features", p.features.get("android.hardware.telephony") is False)
    _check("profile_meta_data", p.meta_data.get("app.meta") == "1")
    _check("profile_malformed_manifest_is_warning",
           any("tv/AndroidManifest.xml" in w and "parse error" in w for w in p.warnings)
           and "app/src/tv/AndroidManifest.xml" not in p.manifests, str(p.warnings))
    _check("profile_cross_check_warns_on_package_disagreement",
           any("package_name disagreement" in w for w in p.warnings), str(p.warnings))
    digest = p.render_compact()
    _check("profile_render_compact_stable", digest == p.render_compact()
           and "QUERY_ALL_PACKAGES (from=play)" in digest and "flavor-only=full" in digest, digest)
    json.dumps(p.to_dict())  # JSON-safe for the triage record.

    # No manifest at all: fallback-only profile, no crash.
    os.makedirs(os.path.join(d, "bare"))
    empty = am.load_profile(os.path.join(d, "bare"), {"package_name": "fb.pkg", "target_sdk": 33,
                                                      "permissions": ["android.permission.CAMERA"]})
    _check("profile_fallback_only", empty.manifests == [] and empty.package_name == "fb.pkg"
           and empty.target_sdk == 33 and empty.has_permission("CAMERA")
           and empty.sdk_provenance["package_name"] == "manifest_details.json", str(empty.summary()))
    missing = am.load_profile(os.path.join(d, "nope"), {})
    _check("profile_missing_app_dir", missing.manifests == [] and missing.warnings)


def _test_lexical_pregate() -> None:
  """WP2: identifier-boundary matching, type positions, engine drop + recall check."""
  from typesafe_eval import structure
  from typesafe_eval import engine
  from typesafe_eval import constants
  from typesafe_eval.client import HeuristicJevClient

  def cols(line, pat):
    return structure.boundary_columns(line, pat)

  # Legacy false positives (lesson L1): mid-word / foreign stems must NOT match.
  _check("lex_foreign_stem_dob", cols("val x = dobiti(y)", "dob") == [])
  _check("lex_foreign_stem_fico", cols('text = "gráfico"', "fico") == [])
  _check("lex_grace_not_race", cols("val grace = 1", "race") == [])
  _check("lex_multimap_not_imap", cols("val m = HashMultimap.create()", "imap") == [])
  _check("lex_trace_not_race", cols("Trace.beginSection(x)", "race") == [])
  _check("lex_fluid_not_uid", cols("val fluidity = 2", "uid") == [])
  # Genuine identifier words at every boundary class survive.
  _check("lex_snake", cols("val full_name = user.name", "full_name") == [4])
  _check("lex_camel_prefix", cols("audio.startRecord()", "record") == [11])
  _check("lex_camel_suffix", cols("val recordAudio = true", "record") == [4])
  _check("lex_pascal_compound", cols("val r = AudioRecord(src)", "record") == [13])
  _check("lex_kebab", cols('"user-dob-field"', "dob") == [6])
  _check("lex_dotted", cols("MediaStore.Images.Media.EXTERNAL_CONTENT_URI", "MediaStore.Images") == [0])
  _check("lex_whole_word", cols("uid = Binder.getCallingUid()", "uid") == [0, 23])
  _check("lex_camel_uid", cols("val appUid = info.uid", "uid") == [7, 18])
  # English derivations are still the word (recall side).
  _check("lex_suffix_er", cols("val mr = MediaRecorder()", "record") == [14])
  _check("lex_suffix_ing", cols("recorder.startRecording()", "record") == [0, 14])
  _check("lex_suffix_s", cols("val logins = 3", "login") == [4])
  _check("lex_prefix_re", cols("relogin()", "login") == [2])
  _check("lex_prefix_capitalised", cols('menu.add(0, OP_RELOGIN, 0, "Relogin")', "login") == [30])
  _check("lex_uuid_not_uid", cols("makeUriFromUuid(ctx, id)", "uid") == [])
  _check("lex_dirsfx_not_sfx", cols("R.string.sz_dirsfx", "sfx") == [])
  # Type vs value positions.
  T = structure.is_type_position
  _check("lex_type_class_header", T("class LogRecordAdapter : Base()", 9, 6))
  _check("lex_type_kotlin_annotation", T("private val rec: LogRecord? = null", 20, 6))
  _check("lex_type_generic", T("val items: List<LogRecord> = emptyList()", 19, 6))
  _check("lex_type_java_decl", T("    LogRecord rec = new LogRecord();", 7, 6))
  _check("lex_value_java_new", not T("    LogRecord rec = new LogRecord();", 27, 6))
  _check("lex_value_param_name", not T("fun format(record: LogRecord): String", 11, 6))
  _check("lex_value_call", not T("audio.record(buffer)", 6, 6))
  _check("lex_value_ctor", not T("val r = AudioRecord(src)", 13, 6))
  lines = ["import java.util.logging.LogRecord",
           "class Fmt : Formatter() {",
           "  override fun format(record: LogRecord): String = record.message",
           "}"]
  lex = structure.lexical_hits(lines, "record")
  _check("lex_hits_value_and_demoted", lex.verdict == "value" and lex.demoted_lines == [0]
         and lex.value_lines == [2], str(lex))
  lex2 = structure.lexical_hits(["val x = dobiti()", "// record here", "val y = dobro"], "dob")
  _check("lex_hits_substring_only", lex2.verdict == "substring_only" and "substring" in lex2.examples, str(lex2))
  lex3 = structure.lexical_hits(["private val rec: AudioRecord? = null", "rec?.startRecording()"], "record")
  _check("lex_hits_type_then_value", lex3.verdict == "value", str(lex3))
  _check("lex_non_identifier_passthrough", not structure.is_identifier_pattern("audio/*")
         and structure.is_identifier_pattern("MediaStore.Images"))
  # all_occurrences prefers boundary value hits for the anchor.
  occ = structure.all_occurrences(["val grace = 1", "val race = user.race", "// race"], "race")
  _check("lex_all_occurrences_prefers_boundary", occ[0] == 1 and 0 in occ, str(occ))
  # ...and the scanner's exact spelling ahead of the capitalised variant.
  lexe = structure.lexical_hits(["b.aboutStackTrace.setOnClickListener(this)",
                                 'copyToClipboard("stack_trace", text)'], "trace")
  _check("lex_exact_case_ranked_first", lexe.exact_value_lines == [1] and lexe.ranked_lines() == [1, 0],
         str(lexe))
  # Anchor ranking sees every occurrence: the sink-adjacent one is sixth in file order.
  from typesafe_eval import context as ctxmod
  from typesafe_eval import capabilities as capsmod
  many = ["import okhttp3.OkHttpClient", "class A {"]
  for i in range(5):
    many += [f"  fun f{i}() {{", f"    val stackTrace{i} = x", "  }"]
  many += ["  fun share() {", "    val t = trace_text", "    http.newCall(t).execute()", "  }", "}"]
  fs = structure.FileStructure("A.kt", "kotlin", many, ["okhttp3.OkHttpClient"],
                               {"okhttp3.OkHttpClient": [len(many) - 3]})
  prof = {"okhttp3.OkHttpClient": capsmod.CapabilityProfile(
      "okhttp3.OkHttpClient", "import", {capsmod.NETWORK_EGRESS: 0.95}, [capsmod.NETWORK_EGRESS],
      "heuristic", None)}
  sinks = ctxmod.file_sinks(fs, prof)
  a = ctxmod.anchor_signal(fs, "trace", "PERFORMANCE_DIAGNOSTICS", sinks)
  _check("lex_anchor_ranks_all_occurrences", a.chosen == len(many) - 4 and a.sink_in_scope
         and a.chosen in a.hit_lines and len(a.hit_lines) <= constants.MAX_HIT_LINES_IN_STATE,
         f"chosen={a.chosen} hits={a.hit_lines}")

  # End to end: the substring-only candidate is dropped with a recorded reason,
  # the genuine one is evaluated, and the pruned file's imports are not classified.
  with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "app"))
    with open(os.path.join(d, "app", "Loc.kt"), "w", encoding="utf-8") as f:
      f.write(_KT_LOCATION_SINK)
    with open(os.path.join(d, "app", "Noise.kt"), "w", encoding="utf-8") as f:
      f.write("package com.x.noise\nimport okhttp3.OkHttpClient\n"
              "fun grace() { val g = HashMultimap.create<String, String>(); dobiti(g) }\n")
    scratch = os.path.join(d, ".scratch")
    _write_scratch(d, scratch, {
        "PRECISE_LOCATION": ["app/Loc.kt (Pattern: FusedLocationProviderClient)"],
        "RACE_ETHNICITY": ["app/Noise.kt (Pattern: race)"],
        "EMAILS": ["app/Noise.kt (Pattern: imap)"],
        "PERSONAL_INFO_OTHER": ["app/Noise.kt (Pattern: dob)"],
        "FILES_AND_DOCS": ["app/Noise.kt (Pattern: */*)"],
    })
    engine.run(scratch, HeuristicJevClient(), batched=True)
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    drops = [x for x in triage["dropped"] if x["reason"] == "no identifier-boundary match"]
    _check("lex_engine_drops_recorded",
           sorted(x["data_type"] for x in drops) == ["EMAILS", "PERSONAL_INFO_OTHER", "RACE_ETHNICITY"]
           and all(x.get("example") for x in drops), str(drops))
    stats = triage["counters"]["lexical_pregate"]
    _check("lex_engine_counters", stats["dropped_substring_only"] == 3 and stats["kept_value"] == 1
           and stats["kept_non_identifier"] == 1 and stats["files_pruned"] == 0, str(stats))
    ds = json.load(open(os.path.join(scratch, "worker_data_safety.json"), encoding="utf-8"))
    _check("lex_engine_genuine_survives",
           any(x.get("psl_constant") == "PRECISE_LOCATION" for x in ds["findings"])
           and not any(x.get("psl_constant") == "RACE_ETHNICITY" for x in ds["findings"]))
    loc = [x for x in ds["findings"] if x.get("psl_constant") == "PRECISE_LOCATION" and x.get("decision_trace")]
    _check("lex_trace_has_verdict", bool(loc) and loc[0]["decision_trace"]["anchor"].get("lexical") == "value",
           str(loc[0]["decision_trace"]["anchor"] if loc else None))
    # Without the MIME candidate the noise file is pruned entirely.
    _write_scratch(d, scratch, {
        "PRECISE_LOCATION": ["app/Loc.kt (Pattern: FusedLocationProviderClient)"],
        "RACE_ETHNICITY": ["app/Noise.kt (Pattern: race)"],
    })
    engine.run(scratch, HeuristicJevClient(), batched=True)
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    _check("lex_engine_prunes_file", triage["counters"]["lexical_pregate"]["files_pruned"] == 1
           and "com.x.noise" in triage["counters"]["first_party_packages"],
           str(triage["counters"]))
    # Rollback flag restores the old behaviour.
    constants.LEXICAL_PREGATE_ENABLED = False
    try:
      engine.run(scratch, HeuristicJevClient(), batched=True)
      triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
      _check("lex_engine_flag_off", triage["counters"]["lexical_pregate"] == {"enabled": False}
             and not any(x["reason"] == "no identifier-boundary match" for x in triage["dropped"]))
    finally:
      constants.LEXICAL_PREGATE_ENABLED = True
    # Localisation catalogs are excluded by suffix.
    _write_scratch(d, scratch, {"NAME": ["app/l10n/intl_de.arb (Pattern: full_name)",
                                         "app/po/de.po (Pattern: full_name)"]})
    engine.run(scratch, HeuristicJevClient(), batched=True)
    triage = json.load(open(os.path.join(scratch, engine.TRIAGE_FILENAME), encoding="utf-8"))
    _check("lex_catalog_suffix_excluded",
           sum(1 for x in triage["dropped"] if x["reason"] == "excluded path (localisation catalog)") == 2,
           str(triage["dropped"]))

  # calibrate --rejoin fails when a labelled transfer has no finding.
  from typesafe_eval import calibrate
  with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "worker_x.json"), "w", encoding="utf-8") as f:
      json.dump({"findings": [{"psl_constant": "NAME", "files_involved": ["a/B.kt"],
                               "decision_trace": {"scores": {"transmits_offdevice": 0.9}}}]}, f)
    labels = {"worker_dirs": [d], "cases": [
        {"file": "B.kt", "data_type": "NAME", "transfers": True, "p_transmit": 0.2},
        {"file": "Gone.kt", "data_type": "NAME", "transfers": True, "p_transmit": 0.9},
        {"file": "Neg.kt", "data_type": "NAME", "transfers": False}]}
    rep = calibrate.calibrate(labels, rejoin=True)
    _check("calibrate_rejoin_uses_run_probability",
           rep["metrics"]["n"] == 1 and rep["rejoined"] is True, str(rep["metrics"]))
    _check("calibrate_rejoin_missing_positive",
           [u["file"] for u in rep["missing_positives"]] == ["Gone.kt"]
           and len(rep["unmatched_cases"]) == 2, str(rep["unmatched_cases"]))
    rep2 = calibrate.calibrate(labels, rejoin=False)
    _check("calibrate_stored_probabilities_still_default", rep2["metrics"]["n"] == 2
           and not rep2["missing_positives"], str(rep2["metrics"]))
    path = os.path.join(d, "labels.json")
    with open(path, "w", encoding="utf-8") as f:
      json.dump(labels, f)
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
      rc = calibrate.main(path, rejoin=True)
    _check("calibrate_rejoin_exit_code", rc == 2)


def main() -> int:
  _test_triage_diff()
  _test_app_profile()
  _test_wave1_manifest_policies()
  _test_wave2_storage_policies()
  _test_data_type_confirmed()
  _test_identity_lifecycle()
  _test_lexical_pregate()
  _test_parse_finding()
  _test_snippet_and_colocation()
  _test_templates()
  _test_http_payload_and_parse()
  _test_heuristic_battery()
  _test_compose_end_to_end()
  _test_batch_state_and_namespace()
  _test_registry_and_plan()
  _test_reduce_noise()
  _test_account_deletion_gate()
  _test_play_declaration()
  _test_engine_offline_and_robustness()
  _test_cache_roundtrip()
  _test_structure_layer()
  _test_capabilities_layer()
  _test_context_anchor()
  _test_three_way_decision()
  _test_critic_routing()
  _test_manifest_fgs()
  _test_triage_ranking()
  _test_sink_visibility()
  _test_identifier_lint()
  _test_calibrate()
  _test_evidence_line()
  _test_app_purpose()
  _test_callee_resolution()
  _test_destination_class()
  _test_consent_defaults()
  _test_relevance_token_embedded()
  print()
  if _FAILURES:
    print(f"{len(_FAILURES)} check(s) FAILED: {', '.join(_FAILURES)}")
    return 1
  print("All selftest checks passed.")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
