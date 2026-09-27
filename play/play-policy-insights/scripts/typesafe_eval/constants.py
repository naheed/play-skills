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

"""Single source of truth for tunable constants.

TypeSafe's guidance is to keep the questions and the thresholds in one reviewable
place so a human can audit the decision logic without spelunking. The question
*text* lives in ``questions.py``; every *number* a reviewer might want to tune
lives here.

None of these values are model weights. Jev is not fine-tuned per account; you
shape its behavior entirely through the request (state + criteria) and through
the thresholds below, which your own code applies to Jev's calibrated outputs.
"""

# ---------------------------------------------------------------------------
# Model / endpoint
# ---------------------------------------------------------------------------

# Pin a concrete version rather than the ``jev-latest`` alias so an audit report
# is reproducible: the alias can move under you when a new model ships.
DEFAULT_MODEL = "jev-1.13.0"

# ---------------------------------------------------------------------------
# Activation noise reduction (mirrors orchestrator.write_agent_prompts). The raw
# scan can surface hundreds of signals; we prioritize the Play build flavor and
# cap how many findings per data type reach the model. Caps bound cost but also
# cap recall — Jev is cheap and parallel, so these can be raised as a recall
# lever once a gold corpus justifies it.
# ---------------------------------------------------------------------------

PRIORITIZED_FLAVORS = ("main", "play")
MAX_PER_FILE_PER_TYPE = 2   # at most N findings of one data type from one file
MAX_FINDINGS_PER_TYPE = 4   # global cap per data type, after ranking (see below)

# Cascade (two-stage triage). Stage 1 is deterministic and cheap: every raw
# signal (up to MAX_CANDIDATES_PER_TYPE, a pure cost bound) is ranked by whether
# its file references a transfer-capable symbol and how close the nearest such
# reference is to the hit. Stage 2 sends only the top MAX_FINDINGS_PER_TYPE per
# data type to the full model battery. This replaces the previous "first N in
# scanner order" cap, which dropped real sinks in favour of log lines.
MAX_CANDIDATES_PER_TYPE = 40
SINK_SCOPE_BONUS_LINES = 0     # proximity 0 == sink reference inside the hit's own scope
MAX_ASKS_PER_REQUEST = 6       # batched mode: asks (data types) per file request

# ---------------------------------------------------------------------------
# Evaluator identity. Recorded on every finding's decision trace so a report can
# be traced back to the exact question wording, taxonomy, thresholds and model
# that produced it. Bump on any change to those inputs.
# ---------------------------------------------------------------------------

EVALUATOR_VERSION = "2.0.0-capability"

# Path fragments whose files are string catalogs / UI text, not behavior. A
# generic pattern like "deactivate" or "record" matching a localized
# ``res/values-tl/strings.xml`` translation is a false positive, so exclude these
# from signal activation. Layout XML (res/layout) and code are still scanned.
EXCLUDED_PATH_SUBSTRINGS = ("/res/values",)

# Documented System One evaluation endpoint.
DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"

# Environment variable holding the bearer token for the real HTTP client.
API_KEY_ENV = "TYPESAFE_API_KEY"

# Environment variable overriding the persistent capability-cache location.
CAPABILITY_CACHE_ENV = "PPI_CAPABILITY_CACHE"

# ---------------------------------------------------------------------------
# Capability classification (semantic layer, ``capabilities.py``).
# ---------------------------------------------------------------------------

# Capability names that imply data has left the device / the app sandbox, and
# the subset that additionally implies sharing with another party. IPC is in
# both by policy direction (handing data to another app is sharing). The
# definitions live in ``capabilities.CAPABILITIES``; the names are here so the
# policy layer can reference them without importing the semantic layer.
TRANSFER_CAPABILITY_NAMES = (
    "NETWORK_EGRESS", "THIRD_PARTY_TELEMETRY", "ADVERTISING_SDK", "IPC_SHARING",
)
SHARING_CAPABILITY_NAMES = ("THIRD_PARTY_TELEMETRY", "ADVERTISING_SDK", "IPC_SHARING")

T_CAPABILITY = 0.60             # label a capability when P(provides it) >= this
T_CAPABILITY_UNKNOWN_LOW = 0.35  # transfer capability in [low, T_CAPABILITY) -> UNKNOWN
CAPABILITY_BATCH_SIZE = 8       # identifiers per classification request
MAX_SINK_LINES_IN_STATE = 8     # sink-reference lines appended to a file's snippet

# ---------------------------------------------------------------------------
# Noul decision thresholds (probability that the yes-statement holds).
#
# Nouls return a bare probability in [0, 1]; the distance from 0.5 is the signal.
# These thresholds convert those probabilities into the booleans the existing
# worker schema expects. Start conservative and tune against a labeled set with
# the eval harness before trusting them on real traffic.
# ---------------------------------------------------------------------------

# Three-way transfer decision. Below T_TRANSMIT_LOW the data is treated as
# local; at/above T_TRANSMIT_HIGH it is treated as transmitted; in between the
# finding is emitted as IMPORTANT + MANUAL_REVIEW ("UNCERTAIN") instead of being
# silently downgraded to a local-only suggestion. The old single cliff at 0.55
# turned 0.52/0.54 answers on real transmissions into "Compliant".
T_TRANSMIT_LOW = 0.35
T_TRANSMIT_HIGH = 0.70
T_TRANSMIT = T_TRANSMIT_HIGH  # backwards-compatible alias used by the eval harness

T_RELEVANCE = 0.30         # drop a signal when P(snippet handles this data type) < this
T_DISCLOSURE = 0.50        # a prominent disclosure gate is present
T_CORE_FUNCTION = 0.60     # the access is core to the app's stated purpose
T_USER_INITIATED = 0.60    # the transfer is triggered by an explicit user action
T_THIRD_PARTY = 0.60       # the sink is outside the developer's control
T_EVIDENCE_SUPPORTS = 0.50  # critic: the snippet actually supports the claim
T_ACCOUNT_DELETION = 0.60   # deterministic gate: snippet really deletes an account
T_DECLARATION_COVERS = 0.50  # play_declaration: declaration covers a detected type

# ---------------------------------------------------------------------------
# Confidence gates (Choice/Score answers carry a calibrated confidence in [0, 1]).
#
# Mirrors the three-band pattern from the TypeSafe confidence docs: act, review,
# or refuse to act. The critic maps a low-confidence verdict to MANUAL_REVIEW.
# ---------------------------------------------------------------------------

CONF_ACT = 0.75            # at/above: act on the model's answer automatically
CONF_REVIEW_FLOOR = 0.50   # below: send to a human instead of guessing

# ---------------------------------------------------------------------------
# Threshold provenance. Thresholds are calibrated artifacts, not constants: this
# block records what data and model produced the values above, and
# ``calibrate.py`` regenerates it. A model upgrade or a taxonomy change requires
# re-running calibration and updating this block in the same change.
# ---------------------------------------------------------------------------

THRESHOLD_PROVENANCE = {
    "model": DEFAULT_MODEL,
    "calibrated_on": "dev set: 2 open-source apps, adjudicated against the legacy skill",
    "calibrated_at": "2026-09-27",
    "method": (
        "T_TRANSMIT_LOW = highest threshold with recall 1.0 on labelled "
        "transfers; T_TRANSMIT_HIGH = lowest threshold with precision >= 0.90 "
        "on labelled transfers; band in between abstains. See calibrate.py."
    ),
    "note": "Two-app dev set is a regression check, not a hold-out.",
}

# Minimum severity Score (0-indexed levels) required to treat a finding as an
# actual risk rather than an informational suggestion.
SEVERITY_LEVELS = ["SUGGESTION", "IMPORTANT", "CRITICAL"]

# Score >= this many levels is treated as "at least IMPORTANT" when routing.
SEVERITY_RISK_FLOOR = 1.0

# ---------------------------------------------------------------------------
# Severity is derived in code from Jev's atomic booleans, not asked as a broad
# Score (live testing showed the broad "rate the risk" question is context-poor:
# it cannot see that a disclosed, core-functionality use is compliant). Jev
# supplies transmits/disclosure/core; these tables turn them into a severity.
# ---------------------------------------------------------------------------

# Data types where an undisclosed off-device transfer is CRITICAL (vs IMPORTANT).
SENSITIVE_DATA_TYPES = frozenset({
    "PRECISE_LOCATION",
    "APPROX_LOCATION",
    "CONTACTS",
    "SMS_CALL_LOG",
    "AUDIO",
    "EMAILS",
    "HEALTH",
    "FITNESS",
    "PHOTOS",
    "VIDEOS",
    "CREDIT_DEBIT_BANK_ACCOUNT_NUMBER",
    "CREDIT_SCORE",
    "FINANCIAL_INFO_OTHER",
    "RACE_ETHNICITY",
    "POLITICAL_RELIGIOUS_BELIEFS",
    "SEXUAL_ORIENTATION",
})

# Restricted-permission policies where a non-core, undisclosed use is a real
# risk even without observed transmission (the permission itself is the concern).
HIGH_RISK_PERMISSION_POLICIES = frozenset({
    "location_access_policy",
    "contacts_access_policy",
    "audio_recording_policy",
    "sms_call_log_policy",
    "all_files_access_policy",
    "accessibility_api_policy",
    "package_visibility_policy",
})

# ---------------------------------------------------------------------------
# Eval harness acceptance bar (used by eval/run_eval.py). A policy domain should
# only be promoted from the offline heuristic to the live Jev path when a labeled
# run clears these. Recall is weighted highest: a missed violation (false
# negative) is worse than a false alarm a human can dismiss.
# ---------------------------------------------------------------------------

EVAL_MIN_AGREEMENT = 0.85   # fraction of labeled per-field decisions that match
EVAL_MIN_RECALL = 0.90      # fraction of true risks the tool flags
EVAL_MIN_PRECISION = 0.75   # fraction of flagged risks that are real


def severity_name(score: float) -> str:
  """Maps a Score answer (possibly fractional) onto a severity label.

  Jev Score answers can land between levels; we round to the nearest defined
  level. Numeric interpolation between levels is explicitly *not* relied upon
  (see the jaggedness notes on Score numeric calibration).
  """
  index = int(round(score))
  index = max(0, min(index, len(SEVERITY_LEVELS) - 1))
  return SEVERITY_LEVELS[index]
