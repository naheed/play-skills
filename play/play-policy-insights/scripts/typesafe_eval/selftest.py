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
  _test_relevance_token_embedded()
  print()
  if _FAILURES:
    print(f"{len(_FAILURES)} check(s) FAILED: {', '.join(_FAILURES)}")
    return 1
  print("All selftest checks passed.")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
