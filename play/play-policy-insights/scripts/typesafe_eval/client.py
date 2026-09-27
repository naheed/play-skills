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

"""Clients that answer typed questions against a state.

Two implementations share one interface (:class:`JevClient`):

- :class:`HttpJevClient` calls the real TypeSafe Jev HTTP API using only the
  standard library. This is the production path. It requires ``TYPESAFE_API_KEY``
  and network egress, and it sends the ``state`` (which includes app source
  snippets) to an external service.

- :class:`HeuristicJevClient` is an **offline, deterministic stand-in** used for
  development, CI smoke tests, and validating the end-to-end wiring without a key
  or network. It is NOT a source of real policy judgment: it approximates Jev's
  outputs from the static signals we place in the state. Every finding produced
  through it is tagged so it can never be mistaken for a Jev verdict.

The question wire format is a plain ``dict`` (no third-party SDK types) so the
package stays dependency-free:

    {"type": "noul"|"choice"|"score",
     "instructions": <str|dict>,
     "criteria": <dict|list|None>}

Answers are normalized into :class:`JevAnswer`, mirroring the fields the
documented HTTP API returns.
"""

from __future__ import annotations

import dataclasses
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any
from typing import Dict
from typing import Optional

from typesafe_eval import constants


@dataclasses.dataclass
class JevAnswer:
  """A single typed answer, normalized across clients and question types.

  Attributes:
    type: "noul", "choice", or "score".
    noul: For noul answers, the probability (0-1) that the statement is true.
    choice: For choice answers, the selected option key.
    score: For score answers, the (possibly fractional) level index.
    probabilities: For choice/score answers, option/level -> probability.
    confidence: For choice/score answers, calibrated certainty in [0, 1]. Noul
      answers do not carry a confidence (the probability itself is the signal).
    legend: For score answers, level index (as string) -> description.
  """

  type: str
  noul: Optional[float] = None
  choice: Optional[str] = None
  score: Optional[float] = None
  probabilities: Optional[Dict[str, float]] = None
  confidence: Optional[float] = None
  legend: Optional[Dict[str, str]] = None

  def to_dict(self) -> Dict[str, Any]:
    """Serializes the answer, dropping unset fields, for logging next to a finding."""
    return {k: v for k, v in dataclasses.asdict(self).items() if v is not None}

  @classmethod
  def from_dict(cls, data: Dict[str, Any]) -> "JevAnswer":
    """Rebuilds an answer from its serialized form (used by the result cache)."""
    return cls(
        type=data.get("type", ""),
        noul=data.get("noul"),
        choice=data.get("choice"),
        score=data.get("score"),
        probabilities=data.get("probabilities"),
        confidence=data.get("confidence"),
        legend=data.get("legend"),
    )


class JevClient:
  """Interface: evaluate a state against typed questions, return answers by id.

  Clients accumulate simple usage counters (requests and input tokens) so the
  batching benchmark can compare strategies. ``reset_usage`` zeroes them.
  """

  name = "base"

  def __init__(self) -> None:
    self.request_count = 0
    self.total_input_tokens = 0
    self.total_output_tokens = 0

  def reset_usage(self) -> None:
    self.request_count = 0
    self.total_input_tokens = 0
    self.total_output_tokens = 0

  def system_one(
      self,
      state: Any,
      questions: Dict[str, Dict[str, Any]],
      model: Optional[str] = None,
  ) -> Dict[str, JevAnswer]:
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Real HTTP client (standard library only)
# ---------------------------------------------------------------------------


class JevApiError(RuntimeError):
  """Raised when the TypeSafe API returns a non-retryable error."""


class HttpJevClient(JevClient):
  """Calls the documented TypeSafe Jev HTTP API with ``urllib``.

  Retries ``429`` (rate limit) and ``529`` (overloaded) with exponential
  backoff, honoring a ``retry-after`` header when present, matching the SDK's
  default behavior described in the API reference.
  """

  name = "http"

  def __init__(
      self,
      api_key: Optional[str] = None,
      endpoint: str = constants.DEFAULT_ENDPOINT,
      model: str = constants.DEFAULT_MODEL,
      timeout: float = 120.0,
      max_retries: int = 4,
      opener: Optional[Any] = None,
  ) -> None:
    super().__init__()
    self.api_key = api_key or os.environ.get(constants.API_KEY_ENV)
    if not self.api_key:
      raise JevApiError(
          f"No API key. Set {constants.API_KEY_ENV} or pass api_key=."
      )
    self.endpoint = endpoint
    self.model = model
    self.timeout = timeout
    self.max_retries = max_retries
    # Injectable for testing: a callable(request, timeout) -> file-like response.
    self._urlopen = opener or urllib.request.urlopen

  def build_payload(
      self,
      state: Any,
      questions: Dict[str, Dict[str, Any]],
      model: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Builds the JSON request body. Separated out so tests can assert on it."""
    return {
        "state": state,
        "model": model or self.model,
        "questions": questions,
    }

  @staticmethod
  def parse_response(body: Dict[str, Any]) -> Dict[str, JevAnswer]:
    """Normalizes the documented response body into :class:`JevAnswer` objects."""
    answers: Dict[str, JevAnswer] = {}
    for qid, raw in body.get("answers", {}).items():
      atype = raw.get("type")
      if atype == "noul":
        answers[qid] = JevAnswer(type="noul", noul=raw.get("noul"))
      elif atype == "choice":
        answers[qid] = JevAnswer(
            type="choice",
            choice=raw.get("choice"),
            probabilities=raw.get("probabilities"),
            confidence=raw.get("confidence"),
        )
      elif atype == "score":
        answers[qid] = JevAnswer(
            type="score",
            score=raw.get("score"),
            probabilities=raw.get("probabilities"),
            confidence=raw.get("confidence"),
            legend=raw.get("legend"),
        )
      else:
        # Unknown type: keep it visible rather than silently dropping.
        answers[qid] = JevAnswer(type=str(atype))
    return answers

  def system_one(
      self,
      state: Any,
      questions: Dict[str, Dict[str, Any]],
      model: Optional[str] = None,
  ) -> Dict[str, JevAnswer]:
    payload = json.dumps(self.build_payload(state, questions, model)).encode(
        "utf-8"
    )
    headers = {
        "Authorization": f"Bearer {self.api_key}",
        "Content-Type": "application/json",
    }

    last_error: Optional[Exception] = None
    for attempt in range(self.max_retries + 1):
      request = urllib.request.Request(
          self.endpoint, data=payload, headers=headers, method="POST"
      )
      try:
        with self._urlopen(request, timeout=self.timeout) as response:
          body = json.loads(response.read().decode("utf-8"))
          usage = body.get("usage", {}) or {}
          self.request_count += 1
          self.total_input_tokens += int(usage.get("input_tokens", 0) or 0)
          self.total_output_tokens += int(usage.get("output_tokens", 0) or 0)
          return self.parse_response(body)
      except urllib.error.HTTPError as exc:
        # 429/529 are transient; back off and retry. Everything else is fatal.
        if exc.code in (429, 529) and attempt < self.max_retries:
          retry_after = exc.headers.get("retry-after") if exc.headers else None
          delay = float(retry_after) if retry_after else 2.0 ** attempt
          time.sleep(delay)
          last_error = exc
          continue
        detail = ""
        try:
          detail = exc.read().decode("utf-8")
        except Exception:  # pylint: disable=broad-exception-caught
          pass
        raise JevApiError(f"HTTP {exc.code} from Jev: {detail}") from exc
      except urllib.error.URLError as exc:
        if attempt < self.max_retries:
          time.sleep(2.0 ** attempt)
          last_error = exc
          continue
        raise JevApiError(f"Connection error calling Jev: {exc}") from exc

    raise JevApiError(f"Exhausted retries calling Jev: {last_error}")


# ---------------------------------------------------------------------------
# Offline heuristic stand-in (development / CI only)
# ---------------------------------------------------------------------------


class HeuristicJevClient(JevClient):
  """Deterministic offline approximation of Jev, for wiring tests only.

  IMPORTANT: this is not a real judgment engine. It answers the specific question
  IDs defined in ``questions.py`` by reading the structured signal flags that the
  evaluator places in the ``state`` (co-located network/disclosure signals, the
  data type, the app's store category, etc.). It exists so the full pipeline runs
  offline and so tests are hermetic. Findings produced with this client are
  tagged ``client="heuristic"`` and must never be treated as Jev verdicts.

  The heuristics deliberately mirror the scanner's own signal logic, which makes
  it useful for validating integration but useless for discovering anything the
  static scanner did not already encode.
  """

  name = "heuristic"

  # Data types whose mere off-device transfer is high severity when undisclosed.
  _HIGH_SENSITIVITY = {
      "PRECISE_LOCATION",
      "APPROX_LOCATION",
      "CONTACTS",
      "SMS_CALL_LOG",
      "AUDIO",
      "HEALTH",
      "CREDIT_DEBIT_BANK_ACCOUNT_NUMBER",
  }

  # The scanner's "disclosure" signal list is deliberately broad and includes
  # generic verbs ("collect", "share", "privacy") that fire on things like a URL
  # containing "/collect". Treat a consent gate as present only when a real
  # UI-gate pattern is co-located, so the stand-in is not fooled by keyword
  # noise. (The real Jev path reads the snippet and does not need this filter.)
  _DISCLOSURE_GATES = {
      "AlertDialog",
      "Dialog",
      "MaterialAlertDialogBuilder",
      "Consent",
      "Disclosure",
      "Accept",
      "Agree",
  }

  # Store categories that plausibly make a data type "core" functionality.
  _CORE_BY_CATEGORY = {
      "PRECISE_LOCATION": {"maps & navigation", "travel & local", "weather"},
      "APPROX_LOCATION": {"maps & navigation", "travel & local", "weather"},
      "AUDIO": {"music & audio", "communication"},
      "CONTACTS": {"communication", "social", "dating"},
  }

  def system_one(
      self,
      state: Any,
      questions: Dict[str, Dict[str, Any]],
      model: Optional[str] = None,
  ) -> Dict[str, JevAnswer]:
    # Estimate input tokens (~4 chars/token) so the batching benchmark reports
    # meaningful numbers offline too; the live client uses the API's real count.
    self.request_count += 1
    approx_chars = len(json.dumps({"state": state, "questions": questions}))
    self.total_input_tokens += approx_chars // 4

    # Capability classification requests carry a ``symbols`` list; answer them
    # from generic behavioural keywords in the identifier (stand-in only).
    if isinstance(state, dict) and "symbols" in state and "capability_definitions" in state:
      return self._classify_symbols(state["symbols"], questions)

    signal = state.get("signal", {}) if isinstance(state, dict) else {}
    co = state.get("co_located_signals", {}) if isinstance(state, dict) else {}
    app = state.get("app", {}) if isinstance(state, dict) else {}
    snippet = state.get("code_snippet", "") if isinstance(state, dict) else ""

    data_type = signal.get("data_type", "")
    has_network = bool(co.get("network_transmission"))
    # Critic states carry the finding instead of a signal; treat labelled sinks
    # (or a snippet that mentions related data-flow lines) as network evidence.
    finding = state.get("finding", {}) if isinstance(state, dict) else {}
    if finding:
      has_network = has_network or bool(finding.get("sinks")) or (
          "Related data-flow lines" in str(finding.get("evidence_snippet", "")))
      snippet = snippet or str(finding.get("evidence_snippet", ""))
    has_disclosure = any(
        gate in (co.get("disclosure") or []) for gate in self._DISCLOSURE_GATES
    )
    destination = self._destination_prior(state) if isinstance(state, dict) else "unknown"
    category = str(app.get("store_category", "")).strip().lower()

    core_categories = self._CORE_BY_CATEGORY.get(data_type, set())
    is_core = category in core_categories if category else False

    # play_declaration coverage reads the declaration/detected fields of state.
    declared = (state.get("declaration") or {}).get("declared", []) if isinstance(state, dict) else []
    detected_name = (state.get("detected") or {}).get("name", "") if isinstance(state, dict) else ""

    answers: Dict[str, JevAnswer] = {}
    for qid, question in questions.items():
      # Batched requests namespace question ids as ``a<i>__<base>``; match on
      # the base id. (The real API keys off instructions, not ids, so this only
      # matters for the offline heuristic.)
      base_qid = qid.split("__")[-1]
      if base_qid == "declaration_covers":
        answers[qid] = JevAnswer(
            type="noul", noul=0.9 if detected_name in declared else 0.1)
        continue
      answers[qid] = self._answer(
          base_qid,
          question,
          data_type=data_type,
          has_network=has_network,
          has_disclosure=has_disclosure,
          is_core=is_core,
          snippet=snippet,
          signal=signal,
          destination=destination,
      )
    return answers

  @staticmethod
  def _destination_prior(state: Dict[str, Any]) -> str:
    """Offline stand-in for the ``destination_class`` Choice (WP7).

    Reads only what the state already carries: a ``USER_CHOSEN_DESTINATION``
    hint wins, then the strongest sink capability (telemetry/advertising ->
    third-party SDK, IPC only -> another app, network -> developer backend),
    else ``unknown``. This is a heuristic for hermetic runs, not a judgement.
    """
    hints = {h.get("hint") for h in state.get("destination_hints") or []}
    if "USER_CHOSEN_DESTINATION" in hints:
      return "user_chosen_destination"
    caps: set = set()
    for s in state.get("sinks") or []:
      caps.update(s.get("capabilities") or [])
    for c in state.get("callees") or []:
      for s in c.get("sinks") or []:
        caps.update(s.get("capabilities") or [])
    if caps & {"THIRD_PARTY_TELEMETRY", "ADVERTISING_SDK"}:
      return "third_party_sdk"
    if "NETWORK_EGRESS" in caps:
      return "developer_backend"
    if "IPC_SHARING" in caps:
      return "other_app_ipc"
    return "unknown"

  def _answer(
      self,
      qid: str,
      question: Dict[str, Any],
      *,
      data_type: str,
      has_network: bool,
      has_disclosure: bool,
      is_core: bool,
      snippet: str,
      signal: Dict[str, Any],
      destination: str = "unknown",
  ) -> JevAnswer:
    qtype = question.get("type")

    if qtype == "noul":
      return JevAnswer(
          type="noul",
          noul=self._noul_value(
              qid,
              has_network=has_network,
              has_disclosure=has_disclosure,
              is_core=is_core,
              snippet=snippet,
              signal=signal,
          ),
      )

    if qtype == "choice":
      options = list((question.get("criteria") or {}).keys())
      probs = self._choice_probs(
          qid, options, has_network=has_network, has_disclosure=has_disclosure,
          destination=destination,
      )
      choice = max(probs, key=probs.get) if probs else (options[0] if options else "")
      return JevAnswer(
          type="choice",
          choice=choice,
          probabilities=probs,
          confidence=_confidence_from_probs(probs),
      )

    if qtype == "score":
      levels = question.get("criteria") or []
      probs = self._severity_probs(
          len(levels),
          data_type=data_type,
          has_network=has_network,
          has_disclosure=has_disclosure,
          is_core=is_core,
      )
      score = sum(int(k) * v for k, v in probs.items())
      legend = {str(i): str(levels[i]) for i in range(len(levels))}
      return JevAnswer(
          type="score",
          score=score,
          probabilities=probs,
          confidence=_confidence_from_probs(probs),
          legend=legend,
      )

    return JevAnswer(type=str(qtype))

  # Generic *behavioural* keywords (not product names) that hint at a capability
  # in an identifier such as ``java.net.Socket`` or ``some.sdk.analytics.Tracker``.
  # This is the offline stand-in for the model's knowledge; it is deliberately
  # crude and exists only so the pipeline runs hermetically in tests.
  _CAPABILITY_HINTS = {
      "NETWORK_EGRESS": (".net", "net.", "http", "socket", "url", "request",
                         "websocket", "grpc", "dns", "client", "api."),
      "THIRD_PARTY_TELEMETRY": ("analytics", "crash", "telemetry", "metrics",
                                "tracking", "tracker", "report"),
      "ADVERTISING_SDK": ("ads", "advert", "adview", "admanager"),
      "IPC_SHARING": ("intent", "clipboard", "broadcast", "content", "provider",
                      "resolver", "share"),
      "LOCAL_PERSISTENCE": ("sqlite", "database", "prefs", "preferences", "persist",
                            "file", "storage", "datastore", "cache"),
      "LOGGING": ("log", "print"),
      "USER_DISCLOSURE_UI": ("dialog", "alert", "consent", "permission", "rationale"),
  }

  def _classify_symbols(
      self, symbols: list, questions: Dict[str, Dict[str, Any]]
  ) -> Dict[str, JevAnswer]:
    answers: Dict[str, JevAnswer] = {}
    by_id = {int(s["id"]): str(s.get("identifier", "")).lower() for s in symbols}
    for qid in questions:
      try:
        idx_str, cap = qid.split("__", 1)
        idx = int(idx_str.lstrip("s"))
      except ValueError:
        answers[qid] = JevAnswer(type="noul", noul=0.5)
        continue
      ident = by_id.get(idx, "")
      hints = self._CAPABILITY_HINTS.get(cap, ())
      answers[qid] = JevAnswer(
          type="noul", noul=0.85 if any(h in ident for h in hints) else 0.1)
    return answers

  @staticmethod
  def _noul_value(
      qid: str,
      *,
      has_network: bool,
      has_disclosure: bool,
      is_core: bool,
      snippet: str,
      signal: Dict[str, Any],
  ) -> float:
    if qid == "transmits_offdevice":
      return 0.9 if has_network else 0.1
    if qid == "signal_relevant":
      # The stand-in cannot judge semantics; lean relevant (recall-safe).
      return 0.8
    if qid == "evidence_shows_transfer":
      return 0.9 if has_network else 0.2
    if qid == "has_prominent_disclosure":
      return 0.85 if has_disclosure else 0.05
    if qid == "is_core_functionality":
      return 0.85 if is_core else 0.2
    if qid == "user_initiated":
      # The scanner cannot see intent; stay near "unknown" leaning no.
      return 0.4
    if qid == "is_third_party":
      # Retired in WP7 (``destination_class`` Choice); kept for older batteries.
      return 0.5
    if qid == "evidence_supports_claim":
      pattern = str(signal.get("matched_pattern", ""))
      return 0.9 if pattern and pattern in snippet else 0.3
    if qid == "is_account_deletion":
      # Real deletion verbs score high; generic "deactivate"/local delete low.
      pattern = str(signal.get("matched_pattern", "")).lower()
      strong = ("deleteaccount", "purgeuserdata", "closeaccount", "removeuser",
                "requestdelete", "destroy_account", "delete_profile")
      return 0.9 if any(s in pattern for s in strong) else 0.15
    if qid == "declaration_covers":
      return 0.5
    return 0.5

  @staticmethod
  def _choice_probs(
      qid: str,
      options: list,
      *,
      has_network: bool,
      has_disclosure: bool,
      destination: str = "unknown",
  ) -> Dict[str, float]:
    probs = {opt: 0.0 for opt in options}
    if qid == "destination_class" and probs:
      # WP7 stand-in: peak on the deterministic prior (see ``_destination_prior``).
      return _peak(probs, destination if destination in probs else "unknown")
    if qid == "disclosure_status" and probs:
      if has_disclosure:
        winner = "DISCLOSED"
      elif has_network:
        winner = "MISSING"
      else:
        winner = "EXEMPT"
      return _peak(probs, winner)
    if qid == "critic_verdict" and probs:
      # The heuristic critic is permissive: verify what the scanner surfaced.
      return _peak(probs, "VERIFIED")
    if qid == "declared_core_purpose" and probs:
      # Offline stand-in for the once-per-app purpose question (WP4): it has
      # no store listing to read, so it answers ``unknown`` with a peaked
      # distribution. Downstream reads ``unknown`` as "purpose not
      # established" (never as a justification), which is the recall-safe
      # default for hermetic runs. Tests that need a specific purpose use a
      # fixed client.
      return _peak(probs, "unknown" if "unknown" in probs else options[-1])
    # Uniform when we have no opinion.
    if options:
      even = 1.0 / len(options)
      return {opt: even for opt in options}
    return probs

  @staticmethod
  def _severity_probs(
      num_levels: int,
      *,
      data_type: str,
      has_network: bool,
      has_disclosure: bool,
      is_core: bool,
  ) -> Dict[str, float]:
    if num_levels <= 0:
      return {}
    sensitive = data_type in HeuristicJevClient._HIGH_SENSITIVITY
    if has_network and not has_disclosure and sensitive and not is_core:
      target = num_levels - 1  # CRITICAL
    elif has_network and not has_disclosure:
      target = min(1, num_levels - 1)  # IMPORTANT
    else:
      target = 0  # SUGGESTION
    return _peak_index({str(i): 0.0 for i in range(num_levels)}, str(target))


def _peak(probs: Dict[str, float], winner: str, mass: float = 0.9) -> Dict[str, float]:
  """Puts ``mass`` on ``winner`` and spreads the rest across the other options."""
  others = [k for k in probs if k != winner]
  result = {k: 0.0 for k in probs}
  if winner in result:
    result[winner] = mass
  if others:
    spread = (1.0 - result.get(winner, 0.0)) / len(others)
    for k in others:
      result[k] = spread
  return result


def _peak_index(probs: Dict[str, float], winner: str, mass: float = 0.85) -> Dict[str, float]:
  return _peak(probs, winner, mass)


def _confidence_from_probs(probs: Dict[str, float]) -> float:
  """Approximates TypeSafe's confidence: how peaked the distribution is.

  Uses ``(n * max - 1) / (n - 1)`` so an all-on-one distribution gives 1.0 and a
  uniform distribution gives 0.0, matching the shape described in the confidence
  docs. This is only used by the offline client; the real API returns its own
  calibrated confidence.
  """
  if not probs:
    return 0.0
  n = len(probs)
  if n == 1:
    return 1.0
  peak = max(probs.values())
  return max(0.0, min(1.0, (n * peak - 1.0) / (n - 1)))
