# Streaming Pipeline Optimization: Implementation Report

Implementation branch: `codex/streaming-pipeline-optimization`. The isolated branch was created from the preserved candidate-worktree state at `e3334a9d`. This report covers the branch's implementation and its explicitly measured synthetic verification; it does not claim a live Dify result.

Design: `docs/decisions/2026-10-01-streaming-pipeline-optimization-design.md`
Approved plan: `docs/plans/2026-10-01-streaming-pipeline-optimization.md`

## Baseline bottleneck and architecture change

The user-provided A-001 audit snapshot recorded 25,337,481 input tokens: Discovery 4,246,123, candidate hypothesis generation 11,968,550, and full-source `hypothesis_page` exploration 9,122,808. The latter two consumed about 83.25% combined. It recorded 1,044 selected candidates, 2,084 generated hypotheses, and no subsequent verification yet; a sample of serialized AST facts had about 62% repeated bytes. Those are **old-run audit values**, not measurements of this branch. We did not open or resume A-001 to remeasure them.

| Earlier candidate route | New candidate-v2 route |
| --- | --- |
| Static evidence → Discovery → candidate-by-candidate LLM calls → every Python source page → all hypotheses registered → global `HYPOTHESIS_DONE` barrier → Pro/Con and later stages | Static evidence → deterministic attack-surface index → Discovery → same-file candidate batches with shared context → persist each candidate result → immediately run its children through existing Pro/Con, verification, PoC and gates → explore only surfaces without enough review proof → final verified-primitive chaining → terminal coverage check and report |

The v2 route retains one pipeline and the existing Agent roles. There is no FAST/FULL/DEEP mode or separate LLM Cheap Gate. V1 is still available only to resume saved v1 runs; new candidate-enabled runs select v2. An empty Finding count is not treated as evidence of zero vulnerabilities.

## Mechanisms and evidence boundaries

### Candidate batching and qualified generation

- `candidate_batches.py` groups selected candidates by exact file path and stable ID, across the store's 32-row query pages. It caps one group at 16 candidates and a rendered prompt budget; v2 supplies 128 KiB. A large file or candidate is split or fails explicitly, never silently truncated. `file_context.py` makes a bounded, redacted, content-addressed shared context. The source and AST artifact remain separate from the prompt.
- `bootstrap_stages.py` requests an independent outcome per candidate ID. A hypothesis needs a plausible attacker-controlled source, concrete sensitive operation, reachability and trust-boundary evidence, existing controls, and exploit preconditions. A plainly trusted source or proven control can yield `NO_HYPOTHESIS`; grounded ambiguity is allowed to continue to verification. This is screening, not PoC-level confirmation.
- The batch result validates requested IDs and response schema. Missing IDs are retried within a bound; committed peers are not regenerated. Per-candidate result, provenance, shared-context hash, source hash, and static-bundle hash are persisted before child scheduling. The 33-candidate page-boundary test checks conservation of IDs.

### Streaming, backpressure, and chaining

- `application.py` routes each committed batch directly to the existing child runner. `HYPOTHESIS_DONE` now records that sources and their children finished; it is not the condition to *start* a child. Atomic claims, a per-turn attempted-ID set, and saved child checkpoints avoid double execution on resume.
- The configurable pending-child bound defaults to 128. The producer drains runnable children after a committed batch, context, or replay marker; before a new proposal, it checks the projected pending count. An exceeded bound becomes explicit `CANDIDATE_BACKPRESSURE_BLOCKED` rather than an unbounded queue or silent skip. This is not an autonomous wait for stuck children. The provider call-budget gate remains serial, so this change primarily removes the producer-to-first-child barrier; it does not assert parallel paid requests.
- Pro and Con keep separate roles and outputs while sharing bounded same-file context where IDs permit. A response is checked and stored per hypothesis; a missing ID does not inherit a peer's conclusion. Final Chaining reads only admitted verified primitives for the exact workspace/commit, checkpoints current pool fingerprints and bounded pair partitions, and validates persisted children before replay.

### Attack-surface coverage and targeted exploration

- `attack_surfaces.py` builds deterministic, extensible security-sensitive locations from AST/static evidence. Its coverage record binds surface ID, location, related candidates, source/index hashes, and review evidence. Candidate presence alone is not review proof. A candidate proposal with only a matching surface line cannot certify separate entry, sensitive-operation, and trust-boundary review parts, even if its child reaches a terminal state; it remains `INSUFFICIENT` for targeted exploration. A complete targeted review must record all required parts, a matching surface location, all context parts, and terminal evidence for every child it actually proposes. A fully reviewed `NO_HYPOTHESIS` result can cover a surface without creating a child. These are model-assisted review records, not independent dataflow proofs or measured vulnerability recall.
- `surface_contexts.py` constructs bounded source contexts around uncovered/insufficient surfaces, split into parts when needed. V2 no longer sends every Python file through arbitrary source pages; the old page route remains only for v1 resume. Each context decision is checkpointed and its hypotheses are sent to the child runner immediately. An unreviewed context part or oversized irreducible context remains a visible gap and prevents `COMPLETE`.
- Static parse failures, timed-out file×rule checks, unsupported product code, and out-of-scope languages remain separate from candidate/surface counts. A valid partial static result can feed analysis, but unverified product scope yields `PARTIAL`, not `COMPLETE`. Agent, evidence-integrity, checkout, and provider failures retain their stronger failure states.

### Attempt ownership, retry, and progress

- `attempt_owner.py`, `call_queue.py`, the provider adapters, and `store.py` connect each request to stage, candidate/hypothesis/surface, file, batch/context, retry predecessor, elapsed time, provider-reported usage, and request-byte classes. Byte classes are instrumentation for context duplication, not actual token counts. Unreported tokens or cost remain `NULL`.
- Codex subprocess invocations bind the logical call ID to captured child PID and process-start identity. Timeout/cancellation requests tree cleanup; unresolved in-flight or unconfirmed cleanup blocks duplicate work rather than inventing a successful termination. Retries stay bounded. API concurrency is not inferred from a config number without atomic budget/claim guarantees.
- Progress, CLI, and dashboard show static, triage, candidate/deep, PoC, and surface counts separately. V2 labels its dynamic fraction `known_checkpoint_fraction`, which can change as work is discovered; it is not an estimate of token spend, elapsed-time completion, repository-wide coverage, or Finding yield.

### Expected savings versus evidence

The design removes repeated same-file AST/source context across candidate calls, eliminates unconditional full-source LLM paging for new runs, starts verification before producer exhaustion, and prevents an unbounded pending tail. These are the expected token and time saving points; no numeric reduction is established yet. The small fake comparison below actually used more calls and serialized bytes in v2. Detection can regress if static surface detectors miss a primitive, if the qualified generator rejects a real but weakly evidenced path, or if bounded context omits a critical relation. The v2 route keeps grounded ambiguity, exact unreviewed-surface gaps, old-run compatibility, and non-`COMPLETE` terminal behavior to mitigate—not eliminate—those risks.

## Implemented path and current worktree

Candidate-enabled new analyses are assigned `candidate_pipeline_version=2`; a saved run's version controls resume. The v2 producer builds a scope-bound attack-surface index, completes Discovery, groups selected candidates by file under a serialized prompt-byte limit, registers each candidate's qualified proposal atomically, and drains runnable children after each committed batch. It then explores indexed surfaces that still lack review evidence using bounded context parts, drains their children, makes the final primitive-pool chaining pass, and evaluates a versioned terminal record. The existing child runner, Agent roles, independent Pro and Con evidence, PoC and gates, Finding, and report stages remain in the pipeline.

The branch also contains worktree edits for shared Pro/Con batching, final chaining, provider-safe concurrency bounds, and evidence-specific progress, dashboard, CLI, and documentation. These edits are included in the inventory below; their final verification is pending.

| Area | Files changed or added since the preserved `e3334a9d` baseline |
| --- | --- |
| Candidate producer and durable data | `src/sastsimi/simple_runtime/application.py`, `store.py`, `models.py`, `bootstrap_stages.py`, `candidates.py`, `candidate_batches.py`, `file_context.py`, `ast_facts.py` |
| Surface coverage and targeted exploration | `src/sastsimi/simple_runtime/attack_surfaces.py`, `surface_contexts.py` |
| Child evidence and chaining | `src/sastsimi/simple_runtime/stages.py`, `chaining.py` |
| Attempt ownership, retry, and provider process safety | `src/sastsimi/simple_runtime/attempt_owner.py`, `call_queue.py`, `provider.py`, `claude_provider.py`, `cursor_provider.py`, `src/sastsimi/providers/codex_subscription.py` |
| Composition and configuration | `src/sastsimi/composition/simple_runtime_composition.py`, `src/sastsimi/config/user_config.py`, `src/sastsimi/interfaces/cli/main.py`, `setup.py`, `public.py`, `src/sastsimi/setup/service.py` |
| Progress and dashboard | `src/sastsimi/progress/models.py`, `projector.py`, `src/sastsimi/dashboard/models.py`, `query.py`, `static/app.js` |
| User and architecture documentation | `README.md`, `docs/architecture/agents-and-providers.md`, `implementation-map.md`, `pipeline.md`, `runtime-and-recovery.md`, `docs/provider-setup.md`, `docs/usage.md`, the design and plan linked above, and this report |
| Candidate and surface unit tests | `tests/unit/simple_runtime/test_candidate_batches.py`, `test_candidate_batch_proposal.py`, `test_candidate_batch_checkpoint.py`, `test_candidate_pipeline.py`, `test_candidate_streaming.py`, `test_attack_surfaces.py`, `test_surface_contexts.py`, `test_surface_progress_store.py`, `test_surface_proposal.py` |
| Child, queue, provider, and chaining unit tests | `tests/unit/simple_runtime/test_call_queue.py`, `test_usage_record.py`, `test_claude_provider.py`, `test_cursor_provider.py`, `test_pro_con_batch.py`, `test_pro_con_batch_store.py`, `test_chain_pool_final.py`, `test_chain_registration_v2.py`, `test_chaining_pool_store.py`, `test_hypothesis_concurrency.py`, `test_parallel_hypotheses.py`, `test_rate_limit_retry.py` |
| Configuration, progress, UI, and boundary tests | `tests/unit/config/test_user_config.py`, `tests/unit/progress/test_progress_projector.py`, `tests/unit/dashboard/test_candidate_frontend.py`, `test_query.py`, `tests/unit/interfaces/test_public_candidate_status.py`, `tests/unit/simple_runtime/test_public_static_coverage_status.py`, `tests/security_negative/test_codex_subscription_boundary.py` |
| Windows CodeQL publication stability | `src/sastsimi/static_analysis/codeql_registry.py`, `tests/unit/static_analysis/test_codeql_registry.py`: narrow Windows-only rename retry after an intermittent registry publication failure reproduced during full tests; permanent denials and destination conflicts still fail. |
| Repository-wide CI formatting | Six pre-existing source/test files were mechanically formatted without changing behavior; see final scoped Git inventory. |

The new Task 12 fixture is `tests/integration/orchestration/test_streaming_candidate_pipeline.py`. Existing tests beyond this delta are not claimed as changed.

| Core file | Main responsibility changed |
| --- | --- |
| `simple_runtime/attempt_owner.py` | Immutable request owner and measured prompt-byte classes. |
| `simple_runtime/candidate_batches.py` | Stable file grouping, byte-bounded splitting, exact candidate-ID conservation. |
| `simple_runtime/file_context.py` | Bounded, redacted shared file context stored by content hash. |
| `simple_runtime/attack_surfaces.py` | Deterministic surface index and evidence-bound coverage evaluation. |
| `simple_runtime/surface_contexts.py` | Bounded context parts for still-unreviewed surfaces. |
| `simple_runtime/bootstrap_stages.py` | Qualified per-ID batch proposal and targeted surface proposal. |
| `simple_runtime/application.py` | V2 producer/child interleaving, backpressure, v1 routing, final chaining, and terminal proof. |
| `simple_runtime/stages.py` | Separate Pro/Con shared-context batching with per-ID results and retries. |
| `simple_runtime/chaining.py` | Exact-scope primitive-pool planning and bounded pair partitions. |
| `simple_runtime/store.py` | Additive owner, per-candidate, surface, Pro/Con, chaining, and atomic-claim checkpoints. |
| `simple_runtime/models.py` | Versioned run and terminal evidence fields. |
| `simple_runtime/call_queue.py` | Owned attempts, budget reservation, retry and safe concurrency bounds. |
| `simple_runtime/provider.py`, `claude_provider.py`, `cursor_provider.py` | Pass through logical owner/invocation metadata without inventing unavailable token counts. |
| `providers/codex_subscription.py` | Bind actual child-process identity to the invocation and checked cleanup. |
| `composition/simple_runtime_composition.py`, `config/user_config.py`, CLI setup modules | New-run v2 selection and validated configuration while retaining existing providers and v1 resume. |
| `progress/models.py`, `progress/projector.py` | Phase-specific counters and labeled dynamic checkpoint fraction. |
| `dashboard/models.py`, `dashboard/query.py`, `dashboard/static/app.js`, `interfaces/cli/public.py` | Display candidate, child, static-gap, and surface evidence without conflating counts. |
| `static_analysis/codeql_registry.py` | Limited Windows rename retry for a reproduced transient publish denial, separate from pipeline semantics. |

## Resume and data compatibility

| Saved run or data | Current handling |
| --- | --- |
| Pre-candidate run (`candidate_pipeline_version` absent) | Retains its existing non-candidate route and checkpoint contract. |
| Candidate v1 run | Resumes on the v1 route. Existing `HYPOTHESIS_DONE`, `__candidate_free_page_*` cursor records, `__candidate_free_done__`, proposal refs and hashes, and completed child checkpoints keep their prior meaning. V1 records are not reinterpreted as v2 batch or surface progress. |
| New candidate v2 run | Stores the version on run creation. Candidate outcomes and progress use additive, scope-bound tables and `simple_candidate_batch_progress_v2` artifacts. Resume checks candidate IDs, file context hash, source hash, static bundle hash, scope fingerprint, and already committed per-candidate results before requesting missing work. Surface progress is keyed by surface and context IDs and bound to the index, static bundle, and source. |
| Existing attempt rows | Additive ownership metadata leaves old attempts with nullable owner fields. Prompt-byte classes are bytes, not provider token counts. Unknown provider tokens and cost remain unknown rather than being converted to zero. |
| Codex call after timeout or cancellation | The call ID is tied to the invocation and captured child PID/start identity. An unresolved in-flight process blocks retry until its exact cleanup is confirmed; the configured Codex child concurrency remains one. |

For v2, the producer's terminal record binds the static bundle, scope, surface-index and coverage artifact hashes, surface counts, producer-finished marker, primitive-pool fingerprint, completed chaining batches, and zero pending children. `COMPLETE` additionally requires full static disposition and covered indexed surfaces with no recorded static gaps. Missing or insufficient review evidence remains visible as incomplete or `PARTIAL`, subject to the existing failure rules. A checkpoint percentage shown for v2 is labeled `known_checkpoint_fraction`; it is not code coverage or vulnerability recall.

## Limits and false-negative risks

- The product-code scan scope remains Python. Unsupported or out-of-scope product files, unavailable static engines, and unverified static file-by-rule combinations are recorded as gaps; they do not become proof of complete analysis.
- The surface index uses a finite set of deterministic AST and static-evidence detectors. A security operation the detectors do not recognize can be absent from targeted exploration. Even a `COMPLETE` result only certifies the indexed and recorded scope, not the absence of vulnerabilities or measured recall.
- The qualified proposal contract asks the model for attacker-controlled source, sensitive operation, reachability, trust boundary, controls, and preconditions. An incorrect `NO_HYPOTHESIS`, mistaken Discovery exclusion, or a missed candidate can discard a real path. Grounded but ambiguous paths are meant to continue into child verification; synthetic known-positive retention is a regression check, not a real-world recall estimate.
- File and surface contexts are bounded, redacted, and sometimes split. Evidence outside the supplied window can be missed by the model. Missing source, an oversized irreducible context, invalid IDs, incomplete surface parts, or missing review proof must remain an explicit incomplete/error state rather than a negative finding.
- Surface `COVERED` requires all labeled review parts, a matching surface location, complete context-part processing, and terminal evidence for each proposed child; a fully reviewed `NO_HYPOTHESIS` context has no child to verify. Raw candidate presence alone is insufficient. This reduces overstatement of coverage but cannot establish the completeness of the initial detector set or the correctness of a model's negative judgment.
- Codex, Claude, and Cursor child scheduling remains serial under the current provider safety bound. API child concurrency depends on explicit atomic budget and claim guarantees; the call budget gate still serializes billable requests for an analysis. No throughput gain from simultaneous provider calls is claimed.
- Prompt-byte classes, fake-provider elapsed times, and fixture call counts are useful for controlled comparison. They are not measured token consumption, provider charges, or evidence of production latency savings. No live provider or full Dify run is part of this report.
- A Windows report-export regression exposed `BUNDLE_PATH_UNSAFE` when pytest used an unusually long temporary root: the generated guard-file path failed to open with `FileNotFoundError`. The same test and full unit/legacy suite passed with a short external temporary root. This branch did not change the report-export path design; Windows deployments still need a sufficiently short writable data path until that independent limitation is addressed.

## Synthetic fixture measurement checklist

For a future production-representative benchmark, the comparison should only read immutable fixture source/static inputs and write generated DB, CAS, event log, and report outputs into separate temporary directories. It must not open, alter, or resume the original Dify A-001 DB, artifacts, or checkpoints. Use deterministic fake provider responses and a controlled clock or identical fake delays; do not issue live provider calls. The exploratory fixture below does **not** satisfy every item of this checklist.

1. Record the code commit, dirty-diff identity, fixture revision, Python version, configuration, and fake-delay schedule. Include a known-positive attack path, a grounded ambiguous path, an uncovered security sink, and more than 32 candidates in one file so batching crosses a DB page.
2. Run v1 and v2 from independent fresh temporary stores against the same immutable fixture and response policy. Capture each rendered request at the fake transport boundary and each producer/child event. If a cloned v1 resume check is used, clone only the synthetic store and artifacts; leave all pre-existing analyses untouched.
3. Report, by route and Agent stage: logical and physical LLM call counts; sum of actual serialized request bytes and the recorded raw/shared/candidate/fixed byte classes; elapsed time from producer start to first Pro/Con child start; maximum pending plus running child count; selected candidate IDs, hypothesis IDs, and terminal status for the known-positive case. Preserve missing provider token/cost fields as `NULL`.
4. Verify exact candidate-ID conservation across the page boundary, per-ID retry after a partial batch response, v1 marker replay, no duplicate child after resume, and the v2 uncovered-surface rule. If the same controlled timing run is repeated, report the individual runs or a stated summary statistic and the run count.
5. Put observed v1/v2 measurements in a separate results table only after execution. Explain any workload, prompt, or fake-delay difference. Do not turn byte ratios into token or money savings, and do not extrapolate synthetic known-positive retention to real-world recall.

### Observed partial synthetic comparison

The six orchestration tests passed after the conservative surface-proof change; a related unit-plus-integration run passed 57 tests. A separate 33-candidate single-file case crossed the 32-row DB page boundary: all 33 batch submissions were unique, and all 35 selected candidates in that case had terminal outcomes. The small v1/v2 comparison used three static candidates, two selected candidates, four indexed surfaces, four targeted contexts, deterministic fake responses, and no real LLM calls. It uses wall-clock `perf_counter_ns`, not a controlled clock, and does not capture per-Agent prompt classes or a fixed run/fixture revision. The producer prompts differ by design, so the numbers below are an exploratory contract comparison, not an equal-work cost benchmark.

| Small fixture measure | v1 | v2 |
| --- | ---: | ---: |
| Fake transport calls | 4 | 7 |
| Actual serialized request bytes sent to fake transport | 6,909 | 17,656 |
| Maximum pending child count | 1 | 1 |
| Known-positive child retained | Yes | Yes |
| First child starts after `analyze()` begins, sample 1 | 135.535 ms | 108.861 ms |
| First child starts after `analyze()` begins, sample 2 | 145.439 ms | 117.133 ms |

This tiny workload shows **more**, not fewer, calls and serialized request bytes in v2, partly because a candidate's single-location review no longer suppresses the fourth targeted surface. The two latency samples do not prove a throughput gain. Provider input tokens, output tokens, charges, production latency, and Dify findings were not measured; none are inferred from fake-transport bytes.

| Final verification item | Result |
| --- | --- |
| Formatter and Ruff | `ruff format --check .`: 878 files formatted; `ruff check .`: passed. Six pre-existing formatting discrepancies were mechanically formatted in this isolated branch to satisfy the repository-wide CI gate. |
| Source and test typing | `mypy --no-incremental src`: 471 source files, no issues. CI's `mypy --strict src tests`: **873 files, no issues** after test-only fixture typing corrections. |
| Unit, contract, provider and legacy runtime | Final unit + legacy simple runtime: **2,226 passed, 20 skipped** (42 existing Pydantic fixture warnings). Final contract + security-negative: **717 passed, 1 skipped**. The earlier provider integration subset passed 453 tests with 2 skipped; provider integration is also included in the full integration result below. |
| Synthetic orchestration fixture | Six tests passed, including the 32-row page boundary and the measured small v1/v2 comparison above. The focused candidate-pipeline plus orchestration suite passed 57 tests after the surface-proof correction. |
| Full integration and E2E | First integration run: 1,548 passed, 4 skipped, two failures with pytest's temporary repository under the main repository's ignored `build` directory. OpenGrep's saved JSON confirmed zero scanned files; the separate long-path Git failure was not traced to a specific subprocess error. With a temporary path outside the repository, the complete final rerun passed: **1,550 passed, 4 skipped**. Capability: 5 passed, 1 skipped. Non-Docker E2E: 1 passed. The real-Docker E2E, live provider calls, and full Dify scan were not run. |
| Documentation, patch scope, and original analysis | Documentation validator: 21 required files, 105 local links, 73 architecture source references, passed. `git diff --check`: passed. The 61 changed/untracked paths were reviewed against this branch's implementation, tests, documentation, narrow CodeQL stability fix, and CI-only formatting/type corrections. Work occurred in an isolated worktree; the original Dify A-001 database and artifacts were not opened, resumed, or changed by this implementation. |

No numeric savings, full Dify scan, live-provider outcome, pull request, or merge is asserted here.
