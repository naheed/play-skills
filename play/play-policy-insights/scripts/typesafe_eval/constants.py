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

# 2.1.0 (M2): question wording changed (WP2 relevance MIME clause, WP6
# ``callees`` clause, WP7 ``destination_class`` Choice replacing the
# ``is_third_party`` Noul), ``T_TRANSMIT_HIGH`` 0.70 -> 0.72 from the rejoined
# dev set, label schema v2. Cached answers keyed on the old wording are simply
# re-asked; the version on a finding says which wording produced it.
EVALUATOR_VERSION = "2.1.0-capability"

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
T_TRANSMIT_HIGH = 0.72
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

# ---------------------------------------------------------------------------
# WP8: consent defaults, string resources, flavour attribution.
#
# The legacy skill's strongest Critical on App A was "crash reports upload by
# default"; the hybrid evaluator could see the upload but not the *default*,
# because the boolean that gates the call is declared in another file with
# its initialiser. WP8 adds three deterministic facts to the state and one
# Noul to the data-safety battery:
#
#   * ``guards`` -- the boolean flags guarding the anchor's scope (``if
#     (prefs.crashReportsEnabled)``), each with the declaration line and the
#     initialiser found in the same file or one hop away through the
#     first-party index (``structure.guard_flags`` / ``declaration_of``).
#     ``default_on`` is read from the initialiser (``= true``, ``getBoolean(k,
#     true)``, ``booleanPreference(false)``) and is None when no literal is
#     found. Priors, not decisions.
#   * ``strings`` -- ``R.string.<name>`` references in the anchor scope and
#     on disclosure lines resolved to the default-locale text
#     (``resources.ResourceIndex``), so disclosure questions are answered
#     against what the user actually reads instead of a resource id.
#   * ``consent_default_on`` Noul: "does the transfer happen unless the user
#     turns it off?".
#
# The composer acts on each guard's ``runs_by_default`` -- the declared
# literal folded with the flag's sense (``if (!enabled) return`` protects the
# code *after* it, so the transfer runs by default when ``enabled`` starts
# true) -- never on the raw literal.
# Composition (``evaluate.compose_consent``) is asymmetric like WP7's:
#   raise  IMPORTANT -> CRITICAL for an undisclosed TRANSMITS when the Noul is
#          at/above T_CONSENT_DEFAULT_ON *and* no guard keeps the transfer off
#          by default (such a guard vetoes the model's claim). An UNCERTAIN
#          decision is never raised: it is capped at IMPORTANT by design and
#          the default-on answer is only recorded (``capped_by:
#          uncertain_band``); likewise a TRANSMITS whose destination class is
#          unresolved (``capped_by: unresolved_destination``);
#   lower  to SUGGESTION + review for an undisclosed transfer only behind the
#          double gate: the Noul is confidently *negative* (<= 1 -
#          CONF_CONSENT_ACT) *and* a guard with ``runs_by_default == False``
#          was found in code (the user had to opt in). A toggle is not a
#          prominent disclosure, so the disclosure status stays MISSING and
#          the finding says "verify the toggle text".
# ``manifest_sources`` on a finding lists the source sets that declare the
# permission / component the finding rests on when they are a strict subset
# of the shipped build (a flavour-only permission), so a reviewer knows which
# build variant is affected. Rollback: CONSENT_DEFAULT_ENABLED = False keeps
# the question (traced) but never changes a severity; STRING_RESOLUTION_ENABLED
# / GUARDS_ENABLED / PERMISSION_ATTRIBUTION_ENABLED drop the corresponding
# state or finding field.
# ---------------------------------------------------------------------------
CONSENT_DEFAULT_ENABLED = True
GUARDS_ENABLED = True
STRING_RESOLUTION_ENABLED = True
PERMISSION_ATTRIBUTION_ENABLED = True
T_CONSENT_DEFAULT_ON = 0.60   # Noul mass for "enabled by default" (raise direction)
CONF_CONSENT_ACT = 0.75       # confident opt-in needed to lower (1 - this on the Noul)
MAX_GUARDS_IN_STATE = 6       # per anchor scope; nearest to the anchor first
MAX_STRINGS_IN_STATE = 8      # resolved string resources per state
# Lines read after a disclosure-symbol reference for ``R.string`` names: dialog
# builders put ``.setTitle(R.string.x).setMessage(R.string.y)`` on the lines
# that follow ``AlertDialog.Builder(ctx)``.
DISCLOSURE_STRING_WINDOW = 4
MAX_GUARD_DECLARATION_HOPS = 1  # same file, then one first-party hop via the receiver's type
# Android platform permissions each permission-goal policy rests on, used only
# to attribute a code finding to the source sets that declare the permission.
POLICY_PERMISSIONS = {
    "location_access_policy": (
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION"),
    "contacts_access_policy": (
        "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS"),
    "audio_recording_policy": ("android.permission.RECORD_AUDIO",),
    # WP9 wave-2 policies (code findings attributed to the storage permissions).
    "photo_video_access_policy": (
        "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
        "android.permission.READ_EXTERNAL_STORAGE"),
    "files_and_docs_policy": (
        "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"),
}
T_ACCOUNT_DELETION = 0.60   # deterministic gate: snippet really deletes an account

# ---------------------------------------------------------------------------
# WP9: wave-2 storage policies (photo_video_access_policy, files_and_docs_policy).
#
# Both policies are decided first from manifest facts (deterministic, no model
# call) and then refined per code site with one Noul each:
#
# photo_video_access_policy (manifest):
#   * targetSdk >= PHOTO_PICKER_TARGET_SDK (33) with READ_EXTERNAL_STORAGE not
#     capped at maxSdkVersion <= LEGACY_READ_STORAGE_MAX_SDK (32) -> IMPORTANT.
#     On 33+ the legacy permission grants no media access at all; keeping it
#     uncapped only produces a misleading permission prompt on older devices.
#   * a broad media permission (READ_MEDIA_IMAGES / READ_MEDIA_VIDEO, or the
#     legacy READ_EXTERNAL_STORAGE that grants media access up to API 32) with
#     an established purpose in PHOTO_VIDEO_PURPOSES -> SUGGESTION (Play Console
#     declaration reminder); any other purpose -> IMPORTANT "use the Photo
#     Picker" (review-marked when the purpose is not established).
#   * READ_MEDIA_IMAGES / READ_MEDIA_VIDEO on targetSdk >=
#     PARTIAL_MEDIA_ACCESS_TARGET_SDK (34) without
#     READ_MEDIA_VISUAL_USER_SELECTED -> SUGGESTION (declare it so a partial
#     "select photos" grant persists across sessions).
# photo_video_access_policy (code, Noul ``accesses_full_media_library`` on
#   MEDIA / PHOTOS / VIDEOS anchors, asked once per file and only when a broad
#   media permission ships): the answer splits "enumerates the library" from
#   "the user picks one item". p >= T_FULL_MEDIA_LIBRARY -> full_library;
#   p <= 1 - T_FULL_MEDIA_LIBRARY -> user_selected; between -> uncertain
#   (review). Deterministic ``media_access_hints`` (MediaStore collection
#   queries vs picker intents) corroborate or contradict the answer; a
#   contradiction is review-marked, never silently resolved. For a justified
#   purpose a user-selected site composes nothing (a gallery may also pick one
#   item) and a full-library site is a SUGGESTION; for any other purpose every
#   site is IMPORTANT (the matrix's "not a dedicated media manager" row; a
#   user-selected site is exactly the Photo Picker heuristic).
# files_and_docs_policy (manifest):
#   * WRITE_EXTERNAL_STORAGE not capped at maxSdkVersion <=
#     LEGACY_WRITE_STORAGE_MAX_SDK (29) with targetSdk >=
#     SCOPED_STORAGE_TARGET_SDK (30) -> IMPORTANT (the permission is inert under
#     scoped storage and misleads users at install / prompt time).
#   * requestLegacyExternalStorage="true" with targetSdk >= 30 -> SUGGESTION
#     (ignored by the platform when targeting 30+; preserveLegacyExternalStorage
#     is the upgrade-path flag).
# files_and_docs_policy (code, Noul ``creates_root_level_external_folder``,
#   asked only for files where ``structure.external_storage_paths`` finds a
#   path composed from the external-storage root that is written or created):
#   p >= T_ROOT_LEVEL_FOLDER confirms -> IMPORTANT unless the purpose is in
#   ALL_FILES_ACCESS_PURPOSES (a file manager or backup tool operates on the
#   shared tree by design -> SUGGESTION); the uncertain band -> SUGGESTION +
#   review; a confident "no" drops the finding only when no deterministic
#   *write* on a root-composed path exists (double gate) -- otherwise
#   SUGGESTION + review.
# Rollback: PHOTO_VIDEO_POLICY_ENABLED / FILES_AND_DOCS_POLICY_ENABLED remove
# the specs from the registry; STORAGE_HINTS_ENABLED / MEDIA_HINTS_ENABLED drop
# the deterministic state blocks (the questions are then answered on the code
# alone).
# ---------------------------------------------------------------------------
PHOTO_VIDEO_POLICY_ENABLED = True
FILES_AND_DOCS_POLICY_ENABLED = True
STORAGE_HINTS_ENABLED = True
MEDIA_HINTS_ENABLED = True
PHOTO_PICKER_TARGET_SDK = 33          # READ_MEDIA_* replace READ_EXTERNAL_STORAGE for media
LEGACY_READ_STORAGE_MAX_SDK = 32      # documented cap for READ_EXTERNAL_STORAGE
PARTIAL_MEDIA_ACCESS_TARGET_SDK = 34  # READ_MEDIA_VISUAL_USER_SELECTED introduced
SCOPED_STORAGE_TARGET_SDK = 30        # scoped storage enforced; WRITE_EXTERNAL_STORAGE inert
LEGACY_WRITE_STORAGE_MAX_SDK = 29     # documented cap for WRITE_EXTERNAL_STORAGE
T_FULL_MEDIA_LIBRARY = 0.60           # Noul mass for "enumerates the media library"
T_ROOT_LEVEL_FOLDER = 0.60            # Noul mass for "creates a root-level external folder"
MAX_STORAGE_HINTS_IN_STATE = 6        # external-storage path hints per state
MAX_MEDIA_HINTS_IN_STATE = 6          # media access hints per state
STORAGE_HINT_WINDOW = 6               # lines after a root reference searched for a write
# Purposes for which broad media permissions are accepted (Photo and Video
# Permissions policy: galleries / editors, backup tools, file managers).
PHOTO_VIDEO_PURPOSES = frozenset({"media_gallery_or_editor", "backup_or_antivirus", "file_manager"})
# Permissions that grant broad access to the user's photos and videos.
BROAD_MEDIA_PERMISSION_SHORT_NAMES = frozenset({"READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO"})
T_DECLARATION_COVERS = 0.50  # play_declaration: declaration covers a detected type

# ---------------------------------------------------------------------------
# WP10: ``data_type_confirmed`` (lesson L7).
#
# The scanner labels a signal with a taxonomy type from a lexical pattern, and
# the legacy agents corrected that label in a handful of recurring ways: a
# ``uid`` is an *app* UID (not a user account), a ``country_code`` derived
# from a remote peer's address is not the *user's* location, a server-assigned
# device id is a DEVICE_ID even when no hardware id is read. The transfer is
# real in every one of those cases -- only the type is wrong -- so this is a
# labelling refinement, not a recall lever, and the answer is read only for
# decisions at/above ``T_TRANSMIT_LOW`` (below the band the type is moot).
#
# One closed Choice per data-safety ask: ``as_labelled`` (default), one option
# per *sibling type* (the other types of the same taxonomy category plus the
# cross-category confusions in ``TYPE_CONFUSION_SIBLINGS``, capped at
# ``MAX_TYPE_SIBLING_OPTIONS``), ``NOT_PERSONAL`` and ``unknown``. The model
# picks the label; the consequences are composed in code
# (``evaluate.compose_type_confirmation``):
#   relabel   a sibling type at/above CONF_TYPE_CONFIRM replaces ``psl_constant``
#             / the summary and the severity is re-derived for the new type. A
#             relabel that would *lower* the severity is allowed one step at
#             most (CRITICAL -> IMPORTANT) and is review-flagged; a relabel that
#             raises it applies in full (raises are single-gated, as in WP7).
#   not personal  at/above CONF_TYPE_CONFIRM the finding is *kept* (a model
#             judgement never removes a finding), its severity is capped at
#             IMPORTANT, it is review-flagged and the summary says why. The
#             type stays as labelled so the report's inventory is unchanged.
#   unknown   at/above CONF_TYPE_CONFIRM on a transfer -> review flag only.
#   below the confidence bar every answer is traced only.
# Rollback: DATA_TYPE_CONFIRMED_ENABLED = False keeps the question in the
# battery (traced) but composes exactly as WP9 did.
# ---------------------------------------------------------------------------
DATA_TYPE_CONFIRMED_ENABLED = True
CONF_TYPE_CONFIRM = 0.75        # confidence at which a relabel / not-personal answer acts
MAX_TYPE_SIBLING_OPTIONS = 6    # sibling types offered per question (closed list)
NOT_PERSONAL = "NOT_PERSONAL"   # the "not personal or user data" option / label value
# Cross-category types the scanner's patterns confuse in practice (same-category
# siblings come from the taxonomy itself). Symmetric on purpose where both
# directions occur. Add a pair only with a fixture that exercises it.
TYPE_CONFUSION_SIBLINGS = {
    "USER_ACCOUNT": ("DEVICE_ID", "NAME"),
    "DEVICE_ID": ("USER_ACCOUNT",),
    "NAME": ("USER_ACCOUNT",),
    "EMAIL": ("EMAILS",),
    "EMAILS": ("EMAIL",),
    "PHONE": ("SMS_CALL_LOG",),
    "FILES_AND_DOCS": ("PHOTOS", "VIDEOS"),
    "PHOTOS": ("FILES_AND_DOCS",),
    "VIDEOS": ("FILES_AND_DOCS",),
    "AUDIO": ("OTHER_AUDIO",),
    "PRECISE_LOCATION": ("ADDRESS",),
    "APPROX_LOCATION": ("ADDRESS",),
    "CRASH_LOGS": ("DEVICE_ID",),
}

# ---------------------------------------------------------------------------
# WP11: wave-3 user-account policies (``account_deletion`` heuristics,
# ``login_credentials``).
#
# account_deletion -- "server-side identity provisioned without a deletion
# path". The scanner's per-token spec (``ACCOUNT_DELETION`` patterns + the
# ``is_account_deletion`` gate) can only confirm a deletion that is *named*
# like one; it cannot see the absence of a deletion path, which is the policy's
# actual failure mode. ``identity.scan_app`` walks every shipped first-party
# source file once (no model call) and records, at identifier boundaries and
# outside comments:
#   provisioning  a call that registers / creates an account, customer, device
#                 or installation on a server (``IDENTITY_PROVISION_RE``);
#   deletion      a call that deletes / removes / closes / unregisters one
#                 (``IDENTITY_DELETE_RE``) or an HTTP DELETE route;
#   identity      an account / customer / device / session identifier token
#                 (``IDENTITY_TOKEN_RE``);
#   network       an in-file HTTP shape (``NETWORK_SHAPE_RE``) or an import the
#                 capability layer already labelled NETWORK_EGRESS;
#   persistence   a write to preferences / a database / a key store
#                 (``PERSIST_SHAPE_RE``) or a LOCAL_PERSISTENCE import.
# A *provisioning site* is a file with provisioning + identity + network (in the
# file or one first-party hop away); it is *persisted* when the file or a hop
# also writes locally. A *deletion candidate* is a file with a deletion verb;
# it is *remote-shaped* when it also reaches the network. Composition
# (``engine._run_identity_lifecycle``):
#   provisioning, no deletion candidate      -> IMPORTANT (SUGGESTION + review
#                                               when persistence is not seen)
#   provisioning + candidate(s)              -> ask the two Nouls on each
#                                               candidate (at most
#                                               MAX_DELETION_CANDIDATES):
#     is_remote_delete >= T_REMOTE_DELETE           -> compliant path, traced
#     clears_local_state_only >= T_LOCAL_ONLY_DELETE -> IMPORTANT "clears local
#                                                       state only"
#     neither                                       -> IMPORTANT + review
#   no provisioning                          -> nothing (App B: the user's own
#                                               server credentials are stored
#                                               locally; nothing is provisioned)
# A client failure keeps the finding (recall-safe). The verb lists are closed
# and generic (no product names); add a verb only with a fixture.
#
# login_credentials -- one closed Choice per app, ``login_gate_type``, asked
# only when the deterministic scan finds login-shaped evidence (a login /
# sign-in / credential token in shipped source, or a semantic USER_ACCOUNT
# file), cached by digest like ``declared_core_purpose``:
#   app_account / third_party_sign_in_bridge >= CONF_LOGIN_GATE -> IMPORTANT
#     (Play Console reviewer credentials + account-deletion link)
#   user_remote_server_credentials >= CONF_LOGIN_GATE -> no finding; recorded
#   none >= CONF_LOGIN_GATE -> nothing
#   below the bar / unknown -> SUGGESTION + review (evidence was found)
# Rollback: IDENTITY_LIFECYCLE_ENABLED / LOGIN_GATE_ENABLED = False skip the
# stage; the per-token ``account_deletion`` spec is unchanged either way.
# ---------------------------------------------------------------------------
IDENTITY_LIFECYCLE_ENABLED = True
LOGIN_GATE_ENABLED = True
T_REMOTE_DELETE = 0.60          # Noul: the deletion candidate deletes the account on the server
T_LOCAL_ONLY_DELETE = 0.60      # Noul: the candidate only clears local state / signs out
CONF_LOGIN_GATE = 0.70          # Choice confidence at which login_gate_type acts
MAX_LIFECYCLE_FILES = 6000      # shipped source files scanned per app (cost bound, not evidence)
MAX_LIFECYCLE_HITS_PER_FILE = 12
MAX_DELETION_CANDIDATES = 3     # deletion candidates asked per app (strongest first)
MAX_PROVISIONING_IN_STATE = 6   # provisioning sites listed in the question state
LIFECYCLE_SNIPPET_LINES = 40    # lines of a deletion candidate shown to the model
MAX_LOGIN_FILES = 5             # login-evidence files listed in the login_gate_type state
LOGIN_SNIPPET_LINES = 30        # lines of the two densest login files shown to the model
# Verbs that provision a server-side identity. ``register`` alone is far too
# broad (``registerReceiver``), so every verb is bound to an identity noun.
IDENTITY_PROVISION_RE = (
    r"\b(?:register|create|provision|enrol|enroll|onboard)(?:Or[A-Z]\w*?)?"
    r"(?:Customer|Device|User|Account|Installation|Identity|Cid|Did)\b"
    r"|\bsign[_]?[Uu]p\b|\bcreate_account\b|\bregister_(?:user|device|account|customer)\b"
)
IDENTITY_DELETE_RE = (
    r"\b(?:delete|remove|close|deactivate|purge|destroy|erase|unregister|deregister|forget|revoke|wipe)"
    r"(?:My|Own|Or[A-Z]\w*?)?(?:Customer|Device|User|Account|Installation|Identity|Cid|Did)(?:Data)?\b"
    r"|\baccount[_]?[Dd]eletion\b|\brequest[_]?[Dd]elet(?:e|ion)\b|\bdelete_(?:profile|account|user)\b"
    r"|\bdestroy_account\b|\bpurge[_]?[Uu]ser[_]?[Dd]ata\b|@DELETE\s*\("
)
IDENTITY_TOKEN_RE = (
    r"\b(?:account|customer|device|user|client|install(?:ation)?|registration|session|subscriber|member)"
    r"[_]?(?:id|Id|ID|token|Token|key|Key)\b|\"(?:cid|did|uid|accountId|deviceId|userId)\""
)
NETWORK_SHAPE_RE = (
    r"@(?:GET|POST|PUT|DELETE|PATCH)\s*\(|\bHttpURLConnection\b|\bHttpsURLConnection\b|\bopenConnection\s*\("
    r"|\bURL\s*\(\s*\"https?://|\bWebSocket\b|\bHttpClient\b|\bhttps?://[\w.-]+/"
)
PERSIST_SHAPE_RE = (
    r"\bput(?:String|Long|Int|Boolean)\s*\(|\.edit\s*\(\s*\)|\bpersist\w*\b|\b(?:save|store|write)"
    r"(?:Identity|Account|Device|Cid|Did|Token|Credentials?|Id|Ids|Session)\w*\b|\binsert\w*\s*\(|\bupsert\w*\s*\("
    r"|\bDao\b|\bdataStore\b|\bDataStore\b|\bKeyStore\b|\bEncryptedFile\b|\bwriteText\s*\(|\bFileOutputStream\s*\("
)
# Login-shaped evidence for ``login_gate_type`` (identifier boundaries, code only).
LOGIN_SHAPE_RE = (
    r"\b(?:login|logIn|Login|signIn|sign_in|SignIn|signUp|sign_up|SignUp|authenticate|Authenticate"
    r"|loginWall|LoginActivity|LoginScreen|LoginFragment|LoginDialog|isLoggedIn|isAuthenticated"
    r"|credentials?|Credentials?|password|Password|oauth|OAuth|idToken|accessToken|refreshToken)\b"
)
# Remote-server shapes counted per login file (host / port / protocol fields
# point at the user's own server rather than a developer account system).
USER_SERVER_SHAPE_RE = (
    r"\b(?:host|hostname|Host|Hostname|port|Port|ftp|sftp|smb|ssh|webdav|imap|smtp|nfs"
    r"|FTP|SFTP|SMB|SSH|WebDAV|IMAP|SMTP|NFS)\b"
)

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
        "sets and ambiguous anchors excluded. Label schema v2: every true "
        "transfer carries a destination_class (8 developer_backend, 3 "
        "third_party_sdk, 11 user_chosen_destination, 1 platform_component). "
        "IPC hand-offs count as sharing unless the user chose the recipient."
    ),
    "calibrated_at": "2026-09-27",
    "calibrated_with": "typesafe_eval calibrate --rejoin at M2 (after WP6 + WP7)",
    "method": (
        "T_TRANSMIT_LOW = highest threshold with recall 1.0 on labelled "
        "transfers (platform_component labels are on-device hand-offs and "
        "exempt from the recall constraint: LOCAL composes the same inventory "
        "SUGGESTION); T_TRANSMIT_HIGH = lowest threshold with precision >= 0.90 "
        "on labelled transfers; band in between abstains. See calibrate.py."
    ),
    # Derived band at M2: [0.41, 0.72]. Shipped T_LOW 0.35 keeps a 0.06 margin
    # under the lowest-scoring off-device true transfer (a SAF tree hand-off
    # that has scored 0.38 / 0.40 / 0.41 across three runs); T_HIGH takes the
    # derived 0.72 because 0.70 leaves one labelled non-transfer at 0.71 in
    # TRANSMITS (precision 0.895 against the 0.90 target) and TRANSMITS drives
    # Non-Compliant verdicts. Three true transfers sit at exactly 0.71 and are
    # therefore UNCERTAIN (surfaced for review, still transferred) -- that is
    # why abstention (0.562) misses the M2 target of 0.50 on this set; the two
    # criteria cannot both hold on 48 cases and precision was preferred per the
    # charter ordering. Previous shipped band (2.0.0): [0.35, 0.70], derived
    # [0.38, 0.60] on the same labels before WP6/WP7.
    "derived_band": {"T_TRANSMIT_LOW": 0.41, "T_TRANSMIT_HIGH": 0.72},
    "shipped_band": {"T_TRANSMIT_LOW": T_TRANSMIT_LOW, "T_TRANSMIT_HIGH": T_TRANSMIT_HIGH},
    "metrics_at_shipped": {
        "n": 48, "positives": 23, "false_negatives_local": 0, "recall_exempt_local": 1,
        "precision_at_high": 0.933, "recall_at_high": 0.609,
        "abstention_rate": 0.562, "uncertain_true_transfers": 8,
        "brier": 0.1797, "ece": 0.2233,
        # Inside the abstention band only (27 cases): the number the M2 gate
        # compares with the pre-WP6/WP7 run at the same band (ECE 0.281).
        "in_band_brier": 0.2387, "in_band_ece": 0.2644,
    },
    "destination_at_shipped": {
        "accuracy": 0.826, "sharing_agreement": 0.783, "sharing_regressions": 0,
        "applied_downgrades": 7, "applied_downgrades_wrong": 0,
    },
    "note": (
        "Two-app dev set is a regression check, not a hold-out. Every band "
        "edge here is decided by a single case; revisit once the labelled set "
        "exceeds ~100 cases."
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
