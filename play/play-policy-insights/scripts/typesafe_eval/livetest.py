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

"""Live smoke test for the real TypeSafe (Jev) HTTP path.

Guarded by ``TYPESAFE_API_KEY``: when the key is absent the test SKIPs with exit
code 0 so it is safe to run in offline CI. When the key is present it makes two
small real calls and asserts the responses are well-formed:

1. A single documented ``Noul`` (no app code) — proves connectivity, auth, and
   response parsing.
2. One data-safety battery over a tiny synthetic snippet — proves the batteries
   round-trip through the real model and return the expected answer types.

Only synthetic sample code is ever sent.
"""

from __future__ import annotations

import os
import sys

from typesafe_eval import constants
from typesafe_eval import questions as q
from typesafe_eval.client import HttpJevClient


def main(model: str = constants.DEFAULT_MODEL) -> int:
  if not os.environ.get(constants.API_KEY_ENV):
    print(f"SKIP: {constants.API_KEY_ENV} not set; live smoke test skipped.")
    return 0

  failures = []

  def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}"
          f"{('' if ok else ' - ' + detail)}")
    if not ok:
      failures.append(name)

  client = HttpJevClient(model=model)

  # 1. Minimal documented Noul; no app code involved.
  try:
    ans = client.system_one(
        state="Help! My payouts have been failing for 3 days.",
        questions={"is_urgent": {"type": "noul", "instructions": "Does this convey urgency?"}},
        model=model,
    )
    noul = ans["is_urgent"].noul
    check("noul_connectivity", noul is not None and 0.0 <= noul <= 1.0, str(noul))
    check("noul_is_urgent_high", (noul or 0.0) > 0.5, str(noul))
  except Exception as exc:  # pylint: disable=broad-exception-caught
    check("noul_connectivity", False, repr(exc))

  # 2. One data-safety battery over a synthetic transmitted-location snippet.
  try:
    state = {
        "signal": {"data_type": "PRECISE_LOCATION", "matched_pattern": "lastLocation"},
        "code_snippet": (
            "val loc = fusedClient.lastLocation.await()\n"
            "val body = \"{\\\"lat\\\":${loc.latitude}}\"\n"
            "http.newCall(Request.Builder().url(\"https://a.example/collect\")"
            ".post(body).build()).execute()"
        ),
        "co_located_signals": {"network_transmission": ["http.newCall"], "disclosure": []},
        "app": {"name": "Demo", "store_category": "Shopping"},
    }
    ans = client.system_one(
        state, q.data_safety_battery("PRECISE_LOCATION", "precise location"), model=model
    )
    check("battery_types",
          ans["transmits_offdevice"].type == "noul"
          and ans["disclosure_status"].type == "choice"
          and ans["severity"].type == "score")
    check("battery_disclosure_missing",
          ans["disclosure_status"].choice == "MISSING",
          str(ans["disclosure_status"].choice))
    check("battery_transmit_positive",
          (ans["transmits_offdevice"].noul or 0.0) > 0.5,
          str(ans["transmits_offdevice"].noul))
  except Exception as exc:  # pylint: disable=broad-exception-caught
    check("battery_types", False, repr(exc))

  print()
  if failures:
    print(f"{len(failures)} live check(s) FAILED: {', '.join(failures)}", file=sys.stderr)
    return 1
  print(f"Live smoke test passed against {model}.")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
