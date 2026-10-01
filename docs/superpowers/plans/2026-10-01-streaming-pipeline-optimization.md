# Streaming Pipeline Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the single SASTSIMI Python analysis pipeline evidence-complete while batching shared context, verifying hypotheses as they arrive, and exploring only uncovered security surfaces.

**Architecture:** New runs use candidate-pipeline v2 with versioned artifacts and streaming orchestration. Existing v1 runs retain their checkpoint meanings and resume path. The static scanner, Discovery, child runner, gates, chaining admission, Finding and report components remain the same; small modules own batching, context, and surface coverage.

**Tech Stack:** Python 3.12, SQLite, Pydantic, asyncio, pytest, Ruff, mypy.

**Spec:** docs/superpowers/specs/2026-10-01-streaming-pipeline-optimization-design.md

## Global Constraints

- No FAST/FULL/DEEP user modes; no separate LLM Cheap Gate.
- Do not open, alter, or resume original Dify A-001 DB/artifact/checkpoint. Do not run full Dify or live provider smoke tests.
- Keep Python product-code scope, static PARTIAL semantics, existing Agent roles, Pro/Con split, PoC/gates/report and chaining.
- Keep old v1 resume markers and child checkpoint refs valid; new v2 markers must be disjoint and scope-bound.
- Preserve the 27 existing dirty tracked files in the latest worktree and both untracked root files; never clean/reset them.
- Unknown provider usage remains NULL; prompt-byte classes are bytes, not measured tokens.
- Each task starts with a red test and ends with focused green verification and a scoped commit.

## Review Focus

1. A candidate file spans a 32-row DB page: batching still includes all IDs exactly once (Task 3).
2. A valid batch reply omits one ID while another has committed seeds: only the missing ID is retried, without duplicate child work (Tasks 4–5).
3. A blocked child remains in the queue while new batches arrive: no repeated attempt in the same turn or producer deadlock (Task 6).
4. A Codex timeout leaves a late child: resume blocks on the exact call/PID and does not count unknown usage as zero (Task 2).
5. A surface appears covered by a candidate but its important sink is unreviewed: targeted exploration still runs and COMPLETE remains unavailable (Tasks 7–8).

---

## File ownership map

- `simple_runtime/attempt_owner.py`: immutable logical-call owner and prompt-byte metrics only.
- `simple_runtime/candidate_batches.py`: stable file grouping, budgeted splitting, exact-ID result validation.
- `simple_runtime/file_context.py`: versioned, redacted, bounded file context artifact.
- `simple_runtime/attack_surfaces.py`: deterministic surface index, evidence-bound coverage, gap selection.
- `simple_runtime/application.py`: v2 streaming orchestration, backpressure, terminal check; v1 compatibility path remains.
- `simple_runtime/bootstrap_stages.py`: candidate batch proposal contract and qualified hypothesis schema.
- `simple_runtime/stages.py`: independent Pro and Con batch adapters and per-ID evidence fan-out.
- `simple_runtime/store.py`: additive schema, owner/attempt records, batch/surface checkpoint APIs and atomic child claim.
- `simple_runtime/call_queue.py`, `simple_runtime/provider.py`, `simple_runtime/claude_provider.py`, `simple_runtime/cursor_provider.py`, `providers/codex_subscription.py`: owner and exact child-process identity propagation.
- `simple_runtime/chaining.py`: final primitive-pool revision semantics.
- `progress/projector.py`, dashboard/query/models/static, CLI: separate work and coverage counts and relabeled percentage.
- Focused tests live under `tests/unit/simple_runtime`, `tests/unit/progress`, `tests/unit/dashboard`, `tests/integration/providers`, and `tests/simple_runtime`.

### Task 0: Isolate the exact baseline

**Files:** Worktree only; no product file edit.

**Interfaces:** Record source HEAD `41cfde01`, a hash of the 27-file tracked diff, and the new worktree path; later tasks use this copy. The two root untracked files remain in place.

- [ ] **Step 1:** Verify source worktree HEAD/status and root status; record the changed path list and diff hash without reading A-001.
- [ ] **Step 2:** Create an isolated `codex/` worktree under the writable root's ignored `build/` directory from source HEAD, then mechanically copy the exact 27 dirty tracked-file contents into it; do not alter the source worktree.
- [ ] **Step 3:** Compare each copied file hash with its source and compare status path sets; expected 27/27 matches and no unrelated changes. Bring the approved spec/plan commits into this branch without overwriting copied files.

### Task 1: Persist per-call ownership and usage safely

**Files:** Create `src/sastsimi/simple_runtime/attempt_owner.py`; modify `store.py`, `call_queue.py`, `provider.py`, Claude/Cursor provider modules and composition; test `tests/unit/simple_runtime/test_call_queue.py`, `test_usage_record.py`, provider tests.

**Interfaces:** `AttemptOwner(analysis_id, stage, candidate_ids=(), hypothesis_id=None, surface_id=None, file_path=None, batch_id=None, context_id=None, checkpoint_attempt_id=None)`; `SimpleLLMClient.call(..., owner: AttemptOwner | None = None, invocation_id: str | None = None)`; `record_llm_attempt(..., owner, retry_of, prompt_bytes)`. Legacy rows have NULL owner fields.

- [ ] **Step 1: Write red tests.** `test_attempt_owner_survives_retry_and_legacy_migration`: `assert row.stage == "DISCOVERY"`, `assert retry.retry_of == first.attempt_id`, `assert legacy.stage is None`; fake Claude/Cursor each yield exactly one owned row. Include byte-class fields and NULL token assertions.
- [ ] **Step 2: Run red tests.** Use the isolated worktree and `C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe -m pytest` on the named test files; expected assertion failures.
- [ ] **Step 3: Implement.** Add nullable columns or an owner side-table, explicit-column idempotency comparison instead of `SELECT *`, an immutable owner DTO, and owner propagation at each call site. Record raw/shared/candidate/fixed prompt byte counts separately; never manufacture provider tokens.
- [ ] **Step 4: Run focused tests and commit.** Expected all named tests pass; stage only this task's files.

### Task 2: Bind Codex call, invocation and actual process lifetime

**Files:** Modify `store.py`, `call_queue.py`, `provider.py`, `providers/codex_subscription.py`; tests `test_call_queue.py`, `tests/integration/providers/test_codex_subscription.py`, `tests/security_negative/test_codex_subscription_boundary.py`.

**Interfaces:** A single durable call ID is passed to `SimpleCodexClient.call` and `CodexProcessRequest.invocation_id`; child spawn records `(call_id, pid, start_identity)`; cleanup confirmation consumes only that captured identity.

- [ ] **Step 1: Write red fake-process tests.** `test_codex_timeout_keeps_exact_child_owned`: `assert call.invocation_id == request.invocation_id`, `assert call.child_pid == fake.pid`, `assert second_start_count == 0`, `assert attempt.input_tokens is None`; also assert a confirmed terminated tree permits one retry.
- [ ] **Step 2: Run these tests;** expected owner/PID assertions fail.
- [ ] **Step 3: Implement exact identity and bounded retry.** Preserve one-in-flight Codex safety; never infer cleanup from an arbitrary user-supplied PID or process-name match.
- [ ] **Step 4: Run provider, queue and negative tests; commit** only after all pass.

### Task 3: Build stable file batches and shared context

**Files:** Create `candidate_batches.py`, `file_context.py`; modify `store.py`, `ast_facts.py` only where necessary; tests `test_candidate_pipeline.py`, `test_ast_facts.py`.

**Interfaces:** `iter_candidate_batches(store, identity, scope, max_prompt_bytes) -> Iterator[CandidateBatch]`; `build_file_context(artifacts, ast_summary, workspace, path, candidates) -> StoredDataRef`. `CandidateBatch` carries `batch_id`, `path`, ordered `candidate_ids`, and `shared_context_ref`; its ID is a hash of scope, path, IDs and context hash.

- [ ] **Step 1: Write red tests.** `test_file_batch_spans_database_pages`: `assert set(flatten(batch.candidate_ids for batch in batches)) == expected_40_ids` and `assert len(flatten(...)) == 40`; `test_context_overflow_splits_without_loss`: assert every prompt is within budget and repeated builds have identical IDs/refs.
- [ ] **Step 2: Run red tests;** expected missing-module failures.
- [ ] **Step 3: Implement.** Use path-indexed query or bounded external grouping, canonical IDs, AST CAS reuse, bounded redacted source/function context, and a byte budget with model headroom; single oversized candidate remains explicit ERROR.
- [ ] **Step 4: Run candidate/AST tests; commit.**

### Task 4: Add candidate-ID-safe qualified batch proposal

**Files:** Modify `bootstrap_stages.py`; create focused `tests/unit/simple_runtime/test_candidate_batch_proposal.py`; update candidate tests.

**Interfaces:** `DirectHypothesisBootstrap.propose_batch(identity, static, batch: CandidateBatch) -> BatchProposalResult | StageFailure`; `BatchProposalResult.results` maps each candidate ID to seeds or NO_HYPOTHESIS/INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS, with `missing_ids` for bounded retry. Existing `propose` remains for legacy v1.

- [ ] **Step 1: Write red tests.** `test_batch_output_retries_only_missing_candidate`: `assert retry_ids == (missing_id,)`, `assert set(result.results) == requested_ids`; duplicate/unknown IDs fail. `test_qualified_generation_preserves_grounded_ambiguity`: assert no-source and proven-sanitized cases have no seeds, while a concrete ambiguous boundary and known-positive case retain seeds.
- [ ] **Step 2: Run red tests;** expected no `propose_batch` or schema failure.
- [ ] **Step 3: Implement.** Request source, sensitive operation, reachability, boundary, controls and preconditions in the existing Hypothesis Agent output; validate evidence before atomic candidate-specific registration. Keep Discovery verdict separate.
- [ ] **Step 4: Run batch and candidate tests; commit.**

### Task 5: Version new-run producer checkpoints

**Files:** Modify `models.py`, `store.py`, `application.py`, `composition/simple_runtime_composition.py`; tests `test_candidate_pipeline.py`, `test_proposal_registration.py`.

**Interfaces:** New runs persist `candidate_pipeline_version=2`; `save_candidate_batch_progress(identity, scope, batch_id, ref)` and `list_candidate_batch_progress(...)` bind complete candidate-ID sets and source hashes. V1 remains its old route.

- [ ] **Step 1: Write red tests.** `test_v2_batch_resume_is_idempotent`: `assert replay_call_count == 0`, `assert replay_hypothesis_ids == first_hypothesis_ids`; after partial commit, `assert retry_ids == uncommitted_ids`. `test_v1_marker_keeps_legacy_meaning`: assert the saved free-page cursor is reused unchanged.
- [ ] **Step 2: Run red tests;** expected v2 routing/checkpoint failures.
- [ ] **Step 3: Implement.** Add versioned durable batch artifacts and atomic per-candidate seed links; never reinterpret v1 free-page markers or change existing proposal input refs.
- [ ] **Step 4: Run registration/resume tests; commit.**

### Task 6: Stream child verification with bounded backpressure

**Files:** Modify `application.py`, `store.py`, optionally `runner.py`; tests `test_candidate_pipeline.py`, `test_parallel_hypotheses.py`.

**Interfaces:** `drain_candidate_children(..., attempted_in_turn: set[str], max_runnable: int) -> DrainOutcome`; `claim_hypothesis(...) -> bool` atomically prevents two workers from starting the same child. A bounded pending threshold is configurable with a safe default.

- [ ] **Step 1: Write red tests.** `test_streaming_starts_verification_before_next_batch`: `assert events.index("pro_con") < events.index("batch_2")`; `test_backpressure_bounds_pending`: `assert peak_pending <= threshold`; `test_blocked_child_once_per_turn`: `assert child_attempts == 1` despite later batches; resume reuses its successful peers.
- [ ] **Step 2: Run red tests;** expected old barrier/queue failures.
- [ ] **Step 3: Implement.** After each batch commit, drain runnable children; stop production at threshold; preserve stage outcomes and budget PAUSED behavior; complete HYPOTHESIS_DONE only after all sources finish.
- [ ] **Step 4: Run focused streaming, resume and runner tests; commit.**

### Task 7: Index security surfaces and evidence-bound coverage

**Files:** Create `attack_surfaces.py`; modify static-bundle assembly in `bootstrap_stages.py` and store for versioned surface refs; tests `test_attack_surfaces.py`, `test_static_coverage.py`.

**Interfaces:** `build_attack_surface_index(static_bundle, ast_manifest, candidates) -> SurfaceIndex`; `evaluate_surface_coverage(index, reviewed_evidence) -> SurfaceCoverage`. Each stable surface records file/symbol/lines/type/linked candidates/evidence and COVERED, UNCOVERED or INSUFFICIENT.

- [ ] **Step 1: Write red tests.** `test_surface_index_tracks_unreviewed_sink`: `assert {s.type for s in surfaces} >= {"AUTHORIZATION", "FILE_WRITE"}` and `assert sink.coverage_status == "UNCOVERED"`; a plain helper yields no surface, and an incomplete static file×rule remains a separate gap.
- [ ] **Step 2: Run red tests;** expected missing-module failures.
- [ ] **Step 3: Implement.** Deterministic extensible primitive detectors from AST/static evidence, exact scope and artifact hash, conservative coverage proof; never count raw candidate presence as review.
- [ ] **Step 4: Run surface/static tests; commit.**

### Task 8: Replace new-run full-source pages with targeted exploration

**Files:** Modify `hypothesis_pages.py`, `bootstrap_stages.py`, `application.py`, `store.py`; tests `test_hypothesis_pages.py`, `test_candidate_pipeline.py`.

**Interfaces:** `iter_uncovered_surface_contexts(index, coverage, budget_bytes) -> Iterator[SurfaceContext]`; `propose_surface(identity, static, context) -> tuple[HypothesisSeed, ...] | StageFailure`. V2 progress keys bind surface ID/context hash and are distinct from `__candidate_free_page_*`.

- [ ] **Step 1: Write red tests.** `test_targeted_exploration_skips_covered_surface`: `assert explored_ids == (uncovered_auth_id,)`, `assert full_source_page_calls == 0`; `test_surface_seed_streams_immediately`: `assert events.index("child") < events.index("next_surface")`; unresolved surface rejects COMPLETE.
- [ ] **Step 2: Run red tests;** expected full-source paging behavior.
- [ ] **Step 3: Implement.** Keep v1 source paging only for legacy resume. Persist each v2 surface decision and context artifact; split oversized context without byte slicing or silently marking covered.
- [ ] **Step 4: Run free-exploration and resume tests; commit.**

### Task 9: Share Pro/Con context and preserve chaining

**Files:** Modify `stages.py`, `application.py`, `chaining.py`, `store.py`; tests `test_pro_con_batch.py`, `test_simple_chaining.py`.

**Interfaces:** `run_pro_batch(hypothesis_ids, shared_ref)` and `run_con_batch(hypothesis_ids, shared_ref)` produce separate per-ID evidence refs; `finalize_chaining_for_pool(identity, pool_fingerprint)` runs when admitted primitive pool changes.

- [ ] **Step 1: Write red tests.** `test_pro_con_batch_has_exact_independent_ids`: `assert pro_call_count == con_call_count == 1` and `assert retry_ids == (missing_id,)`; `test_final_chain_uses_new_primitive_pool`: `assert chain_child_count == 1` after two admitted primitives, while speculative input contributes none. For >64 refs, assert considered + unconsidered == admitted.
- [ ] **Step 2: Run red tests;** expected batch/chaining failures.
- [ ] **Step 3: Implement.** Durable shared response + idempotent per-ID fan-out, exact current workspace/commit primitive filtering, pool-fingerprint final pass and bounded pair coverage.
- [ ] **Step 4: Run Pro/Con, chaining and child-stage tests; commit.**

### Task 10: Bound actual verification concurrency

**Files:** Modify `application.py`, `call_queue.py`, composition config; tests `test_parallel_hypotheses.py`, `test_call_queue.py`.

**Interfaces:** `effective_hypothesis_concurrency(provider, configured) -> int`; default 1 for Codex until exact process/ledger safety supports more; API providers may use a higher configured bound only with atomic budget reservations and exact child claims.

- [ ] **Step 1: Write red tests.** `test_atomic_claim_prevents_duplicate_child`: `assert sum(claim_results) == 1`; `test_provider_concurrency_respects_safety`: `assert codex_peak == 1`, `assert api_peak <= configured`, and cancellation leaves no unowned attempt or overspent reservation.
- [ ] **Step 2: Run red tests;** expected unsupported claim/budget failures.
- [ ] **Step 3: Implement.** Apply a bounded task group only after Task 6 and safety checks; do not raise Codex to 4 by changing a config constant.
- [ ] **Step 4: Run concurrency/usage tests; commit.**

### Task 11: Make progress and terminal status evidence-specific

**Files:** Modify `progress/projector.py`, `dashboard/query.py`, `dashboard/models.py`, `dashboard/static/app.js`, `interfaces/cli/public.py`, `application.py`; tests `test_progress_projector.py`, dashboard and public CLI tests.

**Interfaces:** V2 projection exposes static/triage/candidate/deep/PoC/surface counters and `percentage_kind='known_checkpoint_fraction'`; v2 terminal binds surface artifact hash, uncovered count, producer-finished marker and empty child queue.

- [ ] **Step 1: Write red tests.** `test_v2_progress_is_phase_counted`: `assert view.percentage_kind == "known_checkpoint_fraction"` and `assert replay_view == first_view`; `test_uncovered_surface_prevents_complete`: `assert outcome.status != "COMPLETE"`; existing v1 percent assertions stay unchanged.
- [ ] **Step 2: Run red tests;** expected UI/terminal contract failures.
- [ ] **Step 3: Implement.** Add phase counters and v2 proof validation; keep API compatibility where possible while labeling dynamic percent.
- [ ] **Step 4: Run progress/dashboard/CLI tests; commit.**

### Task 12: Regression, documentation and final proof

**Files:** Create `PIPELINE-OPTIMIZATION-IMPLEMENTATION.md`; update README and relevant runtime docs only where behavior changed; add `tests/integration/orchestration/test_streaming_candidate_pipeline.py` and synthetic fixture.

**Interfaces:** Fake benchmark emits old/new call count, serialized prompt bytes, first-child latency, pending peak, and known-positive retention; no live provider or Dify run.

- [ ] **Step 1: Write red end-to-end fixture tests.** `test_streaming_fixture_preserves_known_positive`: `assert selected_ids == terminal_ids`, `assert first_pro_con_at < producer_done_at`, `assert known_positive_id in hypothesis_ids`; `test_legacy_resume_clone_and_v2_gap`: assert a temporary cloned v1 run reuses checkpoints and a v2 uncovered surface is never COMPLETE.
- [ ] **Step 2: Run red integration tests;** expected pipeline contract failures before final wiring.
- [ ] **Step 3: Complete wiring and implementation report.** Document measured fixture results separately from expected savings, all changed files, resume compatibility, false-negative risks and limitations. Do not claim real-world recall or numeric savings not measured.
- [ ] **Step 4: Run formatter, Ruff, mypy, focused unit/integration, then feasible full tests; inspect `git diff --check`, scoped status and A-001 untouched evidence. Record pass/fail/not-run exactly and commit only intended files.

## Handoff

Implementation method: native execution in this chat, with an independent final code review, unless the user changes that preference. The plan requires a review before Task 0 or any code edit.
