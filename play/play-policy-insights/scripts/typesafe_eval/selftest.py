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
  n = cap + 2
  with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "app"))
    # n files match; only the LAST in scanner order has a network sink, the
    # second-to-last has only an IPC sink, the rest none.
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
    _check("triage_caps_per_type", triage["counters"]["kept"] == cap, str(triage["counters"].get("kept")))
    dropped = [x for x in triage["dropped"] if "MAX_FINDINGS_PER_TYPE" in x["reason"]]
    _check("triage_records_dropped_with_rank",
           len(dropped) == 2 and all("rank" in x and "tier" in x for x in dropped)
           and all(x["tier"] == 3 for x in dropped), str(dropped))
    _check("triage_sink_file_indexed",
           triage["sinks_by_file"].get(f"app/F{n-1}.kt") and not triage["sinks_by_file"].get("app/F0.kt"))
    # Tier 0 (egress) and tier 1 (IPC) both survive; the two scanner-order
    # leaders without any sink are the ones dropped (ranks cap, cap+1).
    _check("triage_egress_ranked_before_ipc",
           sorted(x["rank"] for x in dropped) == [cap, cap + 1]
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
           triage["counters"]["kept"] == m and triage["counters"].get("cap_exempt_sink_in_scope") == 1
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
  _test_relevance_token_embedded()
  print()
  if _FAILURES:
    print(f"{len(_FAILURES)} check(s) FAILED: {', '.join(_FAILURES)}")
    return 1
  print("All selftest checks passed.")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
