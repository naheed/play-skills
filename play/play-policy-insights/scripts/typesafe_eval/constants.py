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
MAX_FINDINGS_PER_TYPE = 12  # global cap per data type, after ranking (see below)

# Cascade (two-stage triage). Stage 1 is deterministic and cheap: every raw
# signal (up to MAX_CANDIDATES_PER_TYPE, a pure cost bound) is ranked by the
# capability tier of the sinks inside the hit's own scope, then by how close the
# nearest sink reference is. Stage 2 sends only the top MAX_FINDINGS_PER_TYPE
# per data type to the full model battery. This replaces the previous "first N
# in scanner order" cap, which dropped real sinks in favour of log lines.
# MAX_FINDINGS_PER_TYPE was raised from 4 to 8 after live runs measured the
# whole battery stage at well under a minute per app: recall is the charter's
# first priority and the cost lever is cheap. Raised again to 12 in WP2: once
# anchors rank *every* occurrence, candidates whose transfer happens one callee
# hop away (a protocol class whose ``login`` writes through ``sendCommand``)
# rank below UI files with an IPC sink in scope; until WP6 resolves callees,
# the cap is the only thing standing between such a labelled transfer and a
# silent drop (``calibrate --rejoin`` caught two at cap 8).
# The per-type cap is a *cost* control and therefore only trims candidates
# whose own scope has no capability-labelled sink (tier 3). A candidate with a
# sink in its function (tier 0-2) is the exact situation the evaluator exists
# to check, so it is never dropped for cost; MAX_CANDIDATES_PER_TYPE and
# MAX_PER_FILE_PER_TYPE still bound the total. Rollback: set to False.
CAP_EXEMPTS_SINK_IN_SCOPE = True
MAX_CANDIDATES_PER_TYPE = 40
# ``symbol_references`` lists every line that uses an imported sink symbol
# (bounded only by this). The previous default of 12 lines per symbol silently
# hid every later call site, so an ``Intent`` used 14 times in an activity had
# its last two ``startActivity`` sites invisible to scope/proximity ranking
# (a labelled MIME-sharing transfer ranked tier 3 for exactly this reason).
# What the *model* sees is bounded separately (MAX_SINK_LINES_IN_STATE,
# MAX_SINK_REF_LINES_IN_STATE).
MAX_SYMBOL_REFERENCE_LINES = 400
MAX_SINK_REF_LINES_IN_STATE = 20   # per-sink ``lines`` listed in the state (nearest the anchors)
SINK_SCOPE_BONUS_LINES = 0     # proximity 0 == sink reference inside the hit's own scope
MAX_ASKS_PER_REQUEST = 6       # batched mode: asks (data types) per file request

# Ranking tier 0 (see context.Anchor.tier): explicit egress capabilities. IPC is
# still a transfer/sharing capability for *judgment*; it is only ranked below
# these because IPC-capable platform types appear in nearly every Android file.
RANK_STRONG_EGRESS_CAPABILITIES = ("NETWORK_EGRESS", "THIRD_PARTY_TELEMETRY", "ADVERTISING_SDK")

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
# Test source sets (unit and instrumentation) are excluded too: they are not
# compiled into the shipped artifact, so a transfer there is not app behaviour.
EXCLUDED_PATH_SUBSTRINGS = ("/res/values", "/src/test/", "/src/androidTest/", "/src/testDebug/")
# Localisation catalogs outside ``res/values*`` (gettext, Flutter ARB, Apple
# ``.strings``): pure UI text, same rationale as above (WP2).
EXCLUDED_PATH_SUFFIXES = (".po", ".pot", ".arb", ".strings", ".xliff", ".xlf")

# ---------------------------------------------------------------------------
# Lexical pre-gate (WP2, lesson L1). Scanner patterns are raw substrings, so
# ``record`` fires on ``LogRecord``, ``dob`` on a Croatian verb stem, ``race``
# on ``grace``. Before any model call the structure layer checks whether the
# pattern occurs as an identifier *word* (camelCase / snake_case / kebab / dot
# boundary; English affixes such as ``recorder`` / ``relogin`` still count).
# Candidates whose file contains only mid-word substring hits are dropped with
# a recorded reason. Rollback: set LEXICAL_PREGATE_ENABLED = False.
# ---------------------------------------------------------------------------
LEXICAL_PREGATE_ENABLED = True
# Hits that occur only in *type* positions (class header, generic argument,
# declared type) are a weaker signal than value uses, but a file that declares
# a field of the API type (``: AudioRecord``) and drives it through the field
# name is a real use. Dropping type-only candidates is therefore OFF by
# default; the verdict is still recorded on the anchor and in triage so the
# effect can be measured on a labelled set before enabling it.
LEXICAL_TYPE_ONLY_DROP = False
# Anchor selection ranks *every* occurrence (up to this bound) by sink tier and
# proximity; only MAX_HIT_LINES_IN_STATE of them are listed in the model state.
# Capping before ranking lost a labelled clipboard transfer whose only sink-
# adjacent occurrence was the sixth in file order (WP2 recall check).
MAX_OCCURRENCES_RANKED = 60
MAX_HIT_LINES_IN_STATE = 5

# ---------------------------------------------------------------------------
# One-hop first-party callee resolution (WP6, lesson L3). A data-type hit whose
# function hands the value to the app's *own* helper (``Uploader.send(loc)``)
# used to be judged from that function alone: the helper's network client was
# invisible, so the model abstained (UNCERTAIN) or the anchor ranked tier 3 and
# was capped away. The structure layer now indexes the app's own classes
# (simple name -> file) and, for every anchor whose enclosing scope references
# one, appends that file's capability-labelled sinks to the state as
# ``state["callees"]`` (``hop = 1``). Callee sinks count towards the anchor's
# rank tier, the cap exemption and the relevance soft gate exactly like a sink
# in the caller's own scope, because the call site *is* in scope. Rollback:
# set CALLEE_RESOLUTION_ENABLED = False (states, ranking and evidence revert to
# the same-file behaviour; the index is not built).
# ---------------------------------------------------------------------------
CALLEE_RESOLUTION_ENABLED = True
# Hops followed from the anchor's scope. Only 1 is implemented: the one-hop
# case covers the "thin wrapper around a network client" pattern the labelled
# set showed, and deeper chains need a real call graph, not a name index.
MAX_CALLEE_HOPS = 1
# Callees attached to one anchor, strongest reachable capability first, then
# nearest call site. Bounds the state size and the classification volume.
MAX_CALLEES_PER_ANCHOR = 3
# Callee files structurally indexed per *caller* file (their imports are then
# classified like the caller's own). Bounds the semantic-layer cost of a file
# that references many helpers inside its candidate scopes.
MAX_CALLEE_FILES_PER_CALLER = 8
# Rendered callee source lines appended to a caller's snippet, across all its
# callees. When the callee's sink scopes would exceed this, only the sink
# reference lines are rendered (the "sink lines only" fallback in the plan).
MAX_CALLEE_SNIPPET_LINES = 40
# Size of the file head read when indexing first-party classes (the ``package``
# declaration is always near the top; reading whole files for the index would
# make indexing a large app noticeably slower for no benefit).
CALLEE_INDEX_HEAD_BYTES = 4096

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
# WP2: below T_RELEVANCE the model may suppress a finding only when the anchor
# scope has no capability-labelled egress/IPC sink (rank tier 2-3). With a sink
# in scope the finding is kept, capped at IMPORTANT and routed to manual
# review (charter: never suppress by judgement alone). Rollback flag.
RELEVANCE_SOFT_GATE_ENABLED = True
# The soft gate exists for *uncertain* data-type matches. Below this floor the
# model is confidently negative (>= 90% "not this data type") and a sink in
# scope no longer justifies a review item: on the dev apps every keep under
# 0.10 was a lexical coincidence ("track" -> MUSIC, "record" -> AUDIO,
# "PowerManager" -> PERFORMANCE_DIAGNOSTICS) while the nearest genuine
# transfer sat at p=0.12 (MIME "video/*" -> VIDEOS). Applies only when the
# soft gate is enabled; below the floor the finding is dropped as before.
T_RELEVANCE_FLOOR = 0.10
# Second soft-gate condition (WP4 recall fix): an uncertain relevance answer
# (floor <= p < T_RELEVANCE) also keeps the finding when the *file* references
# a strong egress sink (NETWORK_EGRESS / THIRD_PARTY_TELEMETRY /
# ADVERTISING_SDK) anywhere, not only inside the anchor's own function. A file
# that both matches a sensitive-data token and talks to the network is exactly
# where a threshold-adjacent judgement must not suppress silently: on the dev
# apps a labelled credential transfer (relevance p=0.29 vs T_RELEVANCE=0.30,
# anchor tier 3, file-level network client) was lost to answer drift after the
# app-purpose fact entered the state. IPC-only or UNKNOWN file sinks do not
# qualify (too common: every Activity references Intent). Kept findings are
# capped at IMPORTANT, routed to review and traced as
# ``relevance="low_file_egress"``. Rollback flag.
RELEVANCE_SOFT_GATE_FILE_EGRESS = True
T_DISCLOSURE = 0.50        # a prominent disclosure gate is present
T_CORE_FUNCTION = 0.60     # the access is core to the app's stated purpose
T_USER_INITIATED = 0.60    # the transfer is triggered by an explicit user action
T_THIRD_PARTY = 0.60       # legacy ``is_third_party`` Noul threshold (eval harness compatibility)
T_EVIDENCE_SUPPORTS = 0.50  # critic: the snippet actually supports the claim

# ---------------------------------------------------------------------------
# WP7: ``destination_class`` replaces the ``is_third_party`` Noul.
#
# The data-safety battery asks *where* a transfer goes as a closed Choice
# (``questions.DESTINATION_CLASS_OPTIONS``): developer_backend,
# third_party_sdk, user_chosen_destination, platform_component,
# other_app_ipc, unknown. ``evaluate`` composes the policy consequence in code
# (plan §2 L2 table). Two classes -- ``user_chosen_destination`` (the user
# typed the server, or picked the app to share with) and
# ``platform_component`` (a system provider on the same device) -- mean the
# transfer is *not* collection by the developer, so the finding becomes a
# data-safety inventory SUGGESTION instead of a prominent-disclosure risk.
#
# That downgrade is the one place a model judgement lowers a severity, so it
# is gated twice (charter: a finding is never suppressed by judgement alone):
#   1. the Choice confidence must reach CONF_DESTINATION_ACT, and
#   2. an independent signal must agree: for ``user_chosen_destination`` the
#      deterministic USER_CHOSEN_DESTINATION hint in the anchor scope
#      (``structure.destination_hints``) or the battery's own
#      ``user_initiated`` >= T_USER_INITIATED; for ``platform_component`` the
#      absence of any strong-egress sink in the anchor scope and among the
#      callees the anchor reaches.
# An unconfirmed downgrade candidate keeps its transfer-based severity, is
# routed to manual review and traced as ``destination_confirmed=false``.
# ``unknown`` always routes to review. Rollback: DESTINATION_CLASS_ENABLED =
# False restores the pre-WP7 composition (sharing = IPC sink in scope only;
# the Choice is still asked and traced but never changes a severity).
# ---------------------------------------------------------------------------
DESTINATION_CLASS_ENABLED = True
CONF_DESTINATION_ACT = 0.75
# Destination classes that count as sharing with another party (plan §2 L2:
# ``third_party_sdk`` is collection + sharing; ``other_app_ipc`` is sharing).
SHARING_DESTINATION_CLASSES = ("third_party_sdk", "other_app_ipc")
# A transfer is composed as sharing (``is_third_party``) when the probability
# mass the Choice puts on the sharing classes together reaches this value --
# "more likely shared than not" -- or when a sharing-capable sink is in the
# anchor scope (static fact, no threshold). The argmax alone is not used: on
# the first WP7 live run a flat six-way distribution made ``third_party_sdk``
# the argmax at 0.38 on a developer-billing file and flipped the report's
# sharing flag. A sharing argmax below the mass is traced and review-flagged
# (``corroboration: low_sharing_mass``), never silently dropped. Lower than
# the downgrade gate on purpose: sharing raises, the downgrade lowers.
T_SHARING_MASS = 0.50
# Destination classes that, once confirmed, mean the transfer is not
# collection by the developer (no prominent-disclosure finding).
NON_COLLECTION_DESTINATION_CLASSES = ("user_chosen_destination", "platform_component")
# Deterministic destination hints (``structure.destination_hints``) are
# computed only when this is on; they ride in the state as
# ``destination_hints`` and in the trace, never as a decision.
DESTINATION_HINTS_ENABLED = True
T_ACCOUNT_DELETION = 0.60   # deterministic gate: snippet really deletes an account
T_DECLARATION_COVERS = 0.50  # play_declaration: declaration covers a detected type

# ---------------------------------------------------------------------------
# Confidence gates (Choice/Score answers carry a calibrated confidence in [0, 1]).
#
# Mirrors the three-band pattern from the TypeSafe confidence docs: act, review,
# or refuse to act. The critic maps a low-confidence verdict to MANUAL_REVIEW.
# ---------------------------------------------------------------------------

# WP4: the once-per-app ``declared_core_purpose`` Choice moderates severity in
# purpose-conditioned policies (all-files access, package visibility, exact
# alarms, ...). Below this confidence the purpose is treated as *not*
# established: ``evaluate.purpose_in`` returns False, which can only raise a
# severity, never lower one. Same bar as the critic's "act" threshold.
CONF_APP_PURPOSE = 0.75
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
    "calibrated_on": (
        "dev set: 48 hand-adjudicated transfer claims (23 true transfers) from "
        "the evaluator's own evidence traces on 2 open-source apps; test source "
        "sets and ambiguous anchors excluded. IPC hand-offs count as sharing."
    ),
    "calibrated_at": "2026-09-27",
    "method": (
        "T_TRANSMIT_LOW = highest threshold with recall 1.0 on labelled "
        "transfers; T_TRANSMIT_HIGH = lowest threshold with precision >= 0.90 "
        "on labelled transfers; band in between abstains. See calibrate.py."
    ),
    # Derived band on the dev set was [0.38, 0.60]. The shipped values are
    # deliberately wider: 0.35 keeps a 0.03 margin under the lowest-scoring true
    # transfer (recall first), and the derived upper bound rests on a 4-case
    # probability bin, too thin to move TRANSMITS (which drives Non-compliant
    # verdicts) from 0.70. Measured at the shipped values: recall 1.0 for
    # TRANSMITS+UNCERTAIN, precision 0.944 for TRANSMITS alone, abstention
    # 0.625, Brier 0.18, ECE 0.26 (the 0.5-0.6 bin is over-confident: 14 cases,
    # none a real transfer, which is why the band abstains there).
    "derived_band": {"T_TRANSMIT_LOW": 0.38, "T_TRANSMIT_HIGH": 0.60},
    "shipped_band": {"T_TRANSMIT_LOW": T_TRANSMIT_LOW, "T_TRANSMIT_HIGH": T_TRANSMIT_HIGH},
    "metrics_at_shipped": {
        "n": 48, "positives": 23, "false_negatives_local": 0,
        "precision_at_high": 0.944, "recall_at_high": 0.739,
        "abstention_rate": 0.625, "brier": 0.1785, "ece": 0.2552,
    },
    "note": (
        "Two-app dev set is a regression check, not a hold-out. Revisit "
        "T_TRANSMIT_HIGH once the labelled set exceeds ~100 cases."
    ),
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

# ---------------------------------------------------------------------------
# WP5: wave-1 manifest policies. Every table below is keyed by the closed
# ``declared_core_purpose`` option set (questions.APP_PURPOSE_OPTIONS) and read
# through ``evaluate.purpose_in``, so an unknown / low-confidence purpose can
# only *raise* a severity. Option labels are the evaluator's own; no vendor,
# library or app names appear here.
# ---------------------------------------------------------------------------

# Play target-API requirement. Source: "Target API level requirements for
# Google Play apps" (Play Console Help, answer 11926878), read 2026-09-27:
# from 2026-08-31 new apps and updates must target API 36; existing apps must
# target >= 35 to stay available to new users on newer devices. The evaluator
# audits phone/tablet apps; Wear OS / Automotive (35) and TV / XR (34) floors
# are not modelled. Update both values and the date together.
PLAY_REQUIRED_TARGET_SDK = 36          # new apps and updates
PLAY_EXISTING_APP_MIN_TARGET_SDK = 35  # published apps stay discoverable
PLAY_TARGET_SDK_PROVENANCE = {
    "source": "Play Console Help answer 11926878 (Target API level requirements)",
    "effective_from": "2026-08-31",
    "read_on": "2026-09-27",
}

# Purposes for which Play accepts MANAGE_EXTERNAL_STORAGE (All files access
# policy: file managers, backup / antivirus, document management).
ALL_FILES_ACCESS_PURPOSES = frozenset({"file_manager", "backup_or_antivirus"})
# Media permissions that are redundant next to MANAGE_EXTERNAL_STORAGE (the
# broad grant already covers every media file).
MEDIA_PERMISSION_SHORT_NAMES = frozenset({
    "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
    "READ_MEDIA_VISUAL_USER_SELECTED", "READ_EXTERNAL_STORAGE",
})

# Purposes for which Play accepts QUERY_ALL_PACKAGES (Package visibility policy:
# launchers, file managers, device search, antivirus / security, accessibility
# tools, app-management and per-app network-control utilities).
PACKAGE_VISIBILITY_PURPOSES = frozenset({
    "launcher", "file_manager", "backup_or_antivirus", "accessibility_tool",
    "per_app_network_control",
})

# Purposes for which Play accepts USE_EXACT_ALARM (Exact alarm policy: alarm
# clocks, timers, calendars).
EXACT_ALARM_PURPOSES = frozenset({"alarm_or_timer", "calendar"})

# Foreground-service type -> purposes that *clearly* fall outside the type's
# policy definition. A type absent from this table (dataSync, shortService,
# specialUse, systemExempted, mediaProcessing) is broadly usable and is never
# flagged as misaligned. ``other`` and ``unknown`` never appear: misalignment
# fires only for an *established* purpose (``evaluate.purpose_in``), so an
# unclassifiable app gets the Suggestion inventory, not an Important.
FGS_TYPE_MISALIGNED_PURPOSES = {
    # "Interactions with external devices over Bluetooth / NFC / IR / USB /
    # network": a VPN or firewall, alarm, calendar, launcher, messaging or
    # accessibility app does not drive external hardware.
    "connectedDevice": frozenset({
        "per_app_network_control", "alarm_or_timer", "calendar", "launcher",
        "messaging_default_handler", "accessibility_tool",
    }),
    "location": frozenset({
        "file_manager", "alarm_or_timer", "launcher", "accessibility_tool",
        "backup_or_antivirus", "per_app_network_control",
    }),
    "mediaPlayback": frozenset({
        "per_app_network_control", "calendar", "backup_or_antivirus", "accessibility_tool",
    }),
    "camera": frozenset({
        "file_manager", "alarm_or_timer", "calendar", "launcher",
        "per_app_network_control", "backup_or_antivirus",
    }),
    "microphone": frozenset({
        "file_manager", "alarm_or_timer", "calendar", "launcher",
        "per_app_network_control", "backup_or_antivirus",
    }),
    "health": frozenset({
        "file_manager", "backup_or_antivirus", "alarm_or_timer", "calendar",
        "messaging_default_handler", "accessibility_tool", "media_gallery_or_editor",
        "launcher", "per_app_network_control",
    }),
    "phoneCall": frozenset({
        "file_manager", "backup_or_antivirus", "alarm_or_timer", "calendar",
        "accessibility_tool", "media_gallery_or_editor", "launcher", "per_app_network_control",
    }),
    "mediaProjection": frozenset({
        "file_manager", "backup_or_antivirus", "alarm_or_timer", "calendar",
        "launcher", "per_app_network_control", "messaging_default_handler",
    }),
    "remoteMessaging": frozenset({
        "file_manager", "backup_or_antivirus", "alarm_or_timer", "calendar",
        "launcher", "per_app_network_control", "media_gallery_or_editor", "accessibility_tool",
    }),
}
# The manifest <property> a ``specialUse`` service must carry (Android 14+).
FGS_SPECIAL_USE_PROPERTY = "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
# The API level from which foregroundServiceType and per-type permissions are
# mandatory.
FGS_TYPE_REQUIRED_TARGET_SDK = 34

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
