# Request Batching — reusing app context across policies

Status: Draft / prototyped
Last updated: 2026-09-26

## The question

When one app is reviewed against many policies, can we avoid re-sending the same
code to Jev for every policy? Is there a context memory / cache we can reuse
across requests for the same app?

## What Jev actually offers

**There is no cross-request cache, session, or uploaded-document handle.** Per
the [State](https://docs.typesafe.ai/concepts/state.md) and
[API](https://docs.typesafe.ai/api.md) docs, the `state` is sent in the body of
every request and billed per input token; nothing on the server persists it
between calls.

What Jev *does* give us is the thing that makes re-sending unnecessary within a
request: **every question in one request is evaluated in parallel and in
isolation against one shared state.** So the lever is not caching — it is
**batching every question that shares a state into a single request** (the
[Speculative Fan-Out](https://docs.typesafe.ai/patterns/fan-out.md) pattern). The
[Parallel questions cookbook](https://docs.typesafe.ai/cookbooks/parallel_questions.md)
measures this directly: 13 questions in one call vs 13 single-question calls is
**12.2× cheaper and 10× faster with identical answers** — because the document
(the state) dominates each request and batching adds no cross-question noise.

Consequence for us: send each unit of code **once**, and fan out every policy
question about it in the same request.

## Where the redundancy is today

`orchestrator.py init` already produces the artifacts that make batching easy —
they just need to be re-pivoted:

| Artifact | Content | Role in a Jev state |
| --- | --- | --- |
| `data_safety_scan.json` | every signal, per file (`relpath (Pattern: X)`) | which files/lines to send |
| `manifest_details.json` | package, target SDK, permissions | app-level facts (shared by all files) |
| `play_store_info.json` | store category, declaration | app-level facts |
| `input_worker_<goal>.json` | per-**goal** `data_sources` | the findings, grouped by policy |

The prototype's per-finding evaluator sends **one request per finding**. Because
findings are grouped by policy, the same file is re-sent:

- once **per finding in that file** (AccountManager.kt has EMAIL, NAME,
  USER_ACCOUNT, ACCOUNT_DELETION → up to 4 requests re-sending the same code),
  and
- again **per policy goal** that touches it (LocationTracker.kt appears in both
  the permissions goal and the data-safety goal).

App facts are re-sent on every request. This is pure duplicated input token cost
and extra round trips.

## The optimization: batch by file

The shared "document" is the **source file**. Re-pivot the per-goal findings
from "by policy" to "by file", then send one request per file containing that
file's code once plus every policy/data-type battery, namespaced by finding:

```
input_worker_<goal>.json (by policy)         ──▶  invert to  by-file plan
                                                     │
   per file:  state = {app facts + file code once + co-located data-flow}
              questions = { a0__transmits, a0__disclosure, ...   (EMAIL)
                            a1__transmits, a1__is_core, ...       (LOCATION)
                            ... every data type / policy in this file }
                                                     │
                          ONE request per file  ─────┘
                                                     │
   demux answers by finding ──▶ compose ──▶ worker_<goal>.json (unchanged schema)
```

Implemented in `batch.py` (`plan_by_file`, `build_file_state`, `run_batched`);
run with `python -m typesafe_eval run <temp_dir> --batch`. The output is the same
`worker_<goal>.json` the rest of the pipeline consumes, so `aggregate` and
`generate_report.py` are untouched.

### Why the file is the right unit

Two constraints bound how much we batch:

- **Context budget.** Jev allows 64k tokens/request (32k for state + the longest
  question). The whole app will not fit; a file usually will.
- **Accuracy.** The [jaggedness notes](https://docs.typesafe.ai/model-jaggedness/jev-1.13.md)
  warn that a large state full of irrelevant detail costs accuracy. A file is the
  smallest state that still contains everything the file's questions need, so it
  maximizes reuse without diluting relevance.

## Measured results (demo app, live `jev-1.13.0`)

`python -m typesafe_eval benchmark <temp_dir> --client http`:

| strategy | requests | input tokens | latency | cost |
| --- | --- | --- | --- | --- |
| per-finding | 11 | 12,318 | ~1.7 s | $0.000517 |
| **batched (by file)** | **4** | **9,149** | **~0.6 s** | **$0.000384** |

**2.8× fewer requests, ~3× faster, 1.3× fewer input tokens**, with finding
agreement of **11–12 of 12** across runs.

Reading the numbers:

- **Requests and latency** scale with *findings per file*: the app has 4 source
  files with signals, so 11 requests collapse to 4, and fewer round trips give
  the ~3× latency win.
- **Token savings** scale with *file size*: here files are tiny, so the shared
  batteries are a large fraction of each request and the code-dedup saving is
  only 1.3×. On real apps where a file's code dominates the request, the saving
  approaches the request ratio (the cookbook's document-dominated 12× regime).
- **Accuracy must be checked, not assumed.** The benchmark compares findings
  between strategies. Most runs agree 12/12; the case that can move is the
  **audio-recording severity**, a genuine `is_core_functionality` boundary case
  that also carries run-to-run noise per-finding. Composing severity in code
  reduces this sensitivity, but the lesson stands: per the
  [evaluation charter](evaluation-charter.md), a batching change ships only if
  the benchmark shows precision/recall hold — borderline drift on a single
  suggestion-vs-important call is acceptable; a moved CRITICAL is not.

## Further levers (with trade-offs)

1. **Question dedup within a file.** Multiple data types in one file each ask
   `transmits_offdevice`/`has_prominent_disclosure`; ask shared ones once and
   fan the data-type-specific ones out. Cuts output tokens; keep per-data-type
   wording where it changes the judgment.
2. **App-level (manifest-only) policies** — `foreground_services_policy`,
   `target_api_level`, `package_visibility` — depend on `manifest_details.json`,
   not file code. Answer them in **one app-level request** (or in code), never
   per file.
3. **Multi-file batching** under the context budget cuts requests further, but a
   bigger, mixed state risks accuracy and can hit the 32k state limit. Only do it
   behind the benchmark's agreement check.
4. **Concurrency.** Independent per-file requests can be fired in parallel to cut
   wall-clock further, bounded by the rate limits (250k tokens/s, 1200 req/min).
5. **Batch the critic** by chunk: critic state is just the findings (small), so
   all findings in a chunk go in one request.

## What not to do

- Do not rely on a server-side cache — there is none.
- Do not send the whole app in one request — it breaks the context budget and
  dilutes relevance.
- Do not let a batching change ship without the benchmark's finding-agreement
  check; cost and latency are secondary to precision/recall.
