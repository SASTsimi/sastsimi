# Route-bound Python Surface Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the existing A-001 replay and, only where source-bound proof warrants it, finish all 43 Python attack surfaces without changing historical v9 evidence.

**Architecture:** A deterministic v10 route/boundary proof is added after the pinned v9 run. It evaluates only the Python scope, preserves the v9 plan and reviews, and has its own content-addressed plan, coverage certificate, CAS pin, and independent read verifier. Existing resume finishes v9 before v10; consumers show the newest verified certificate.

**Tech Stack:** Python 3.12, `ast`, Pydantic contracts, SQLite checkpoint store, content-addressed artifact repository, pytest, PowerShell on Windows.

**Spec:** `docs/plans/2026-10-14-route-bound-surface-evidence-design.md`

## Global Constraints

- Keep A-001 ID `4ad946075a8a48d9a17b8ccd0926f57e`, commit `4163acacc4134bb7b70afe0435f8926e59d433c1`, and existing v4–v9 DB/artifacts unchanged.
- `100%` means all indexed Python product-code surfaces and other required pipeline stages are verified; it does not assert HTML/Jinja or external-library safety.
- Unresolved path, changed hash, pending child, PoC/environment failure, or unreadable evidence remains `INSUFFICIENT`/`PARTIAL`/actual blocked state.
- Do not create a new LLM review batch merely to relabel a legacy graph gap; reuse validated v9 parts.
- Tests and live resume must not expose tokens, sensitive source, or raw prompts in ordinary logs.

## Review Focus

- A same-file startup sink with no route reachability must not contaminate an unrelated route (Task 1 test).
- A route that can reach a sink through an alias, import, or dynamic call must not be marked unrelated (Task 1 test).
- A literal template call with request-derived context or a symlink/changed template must not certify the boundary (Task 1 test).
- A stale v9 parent or incomplete review part must not generate v10 coverage (Tasks 2–3 tests).
- Replacing the current terminal with v10 must not make its v9 predecessor unverifiable (Task 4 test).

---

### Task 1: Source-bound route and external-boundary proof

**Files:**
- Create: `src/sastsimi/simple_runtime/surface_route_boundary_v10.py`
- Test: `tests/unit/simple_runtime/test_surface_route_boundary_v10.py`

**Interfaces:**
- Produces `RouteBoundaryProofV10` with `surface_id`, `source_hashes`, `resolved_edges`, `discharged_gap_events`, `boundary_kind` (`PYTHON_RESPONSE`, `LITERAL_TEMPLATE`, or `NONE`), `external_scope_limit`, and `unresolved_reasons`; `to_json()` is canonicalizable.
- Produces `prove_route_boundaries_v10(index: SurfaceIndex, workspace: Path, graphs: Mapping[str, Mapping[str, object]], v9_paths: Mapping[str, PathCertificateV9]) -> dict[str, RouteBoundaryProofV10]`.

- [ ] **Step 1: Write failing tests.** Assert that the pinned-style fixture's module-level `init_db()` SQL is proven unrelated to each independently registered route, the direct `make_response` route is bound, and literal `render_template('index.html')` ends at an explicit `TEMPLATE_CONTENT_NOT_ANALYZED` boundary. Assert no discharge for a route-reachable SQL call, ambiguous app binding, alias/import/dynamic call, extra branch/return, request-derived template context, missing/symlinked/changed template, or changed Python hash.
- [ ] **Step 2: Run tests to verify RED.** From this worktree: `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_surface_route_boundary_v10.py -q`; expected import/test failure.
- [ ] **Step 3: Implement only the deterministic proof.** Read source with existing `_raw_source`; bind unique Flask app/decorator/function from AST; enumerate direct-call reachability and unresolved edges; attribute a legacy gap event only with a pinned unrelated call/closed route proof. Reuse the v9 HTML-response path but validate the entire route body and Flask/stdlib binding. For template handoff require one literal name, no additional context, a regular tracked resource under the checkout, and source/resource hashes; record the HTML/Jinja exclusion without claiming its safety.
- [ ] **Step 4: Run focused tests to verify GREEN.** Repeat Step 2's command; all tests pass.
- [ ] **Step 5: Commit only newly created proof/test files.** Use `git add -- <paths>` and `git commit --only -- <paths>`; do not stage existing dirty files.

### Task 2: Immutable successor plan and coverage evaluation

**Files:**
- Create: `src/sastsimi/simple_runtime/surface_enrichment_v10.py`, `src/sastsimi/simple_runtime/surface_coverage_v8.py`
- Test: `tests/unit/simple_runtime/test_surface_coverage_v8.py`

**Interfaces:**
- Consumes Task 1 `RouteBoundaryProofV10` and verified `SurfaceCoverageV7`/v9 part set.
- Produces `prepare_surface_enrichment_v10(identity: CheckpointIdentity, index: SurfaceIndex, v9_plan_ref: StoredDataRef, v9_coverage_ref: StoredDataRef, v9_terminal: CandidateTerminal, v9_progress_hash: str, proofs: Mapping[str, RouteBoundaryProofV10]) -> dict[str, object]`.
- Produces `evaluate_surface_coverage_v8(index: SurfaceIndex, parent: SurfaceCoverageV7, plan_ref: StoredDataRef, proofs: Mapping[str, RouteBoundaryProofV10], *, pending_candidate_count: int, pending_child_count: int) -> SurfaceCoverageV8`.

- [ ] **Step 1: Write failing tests.** Assert a complete closed Python route discharges only its attributed v9 path/graph reasons; an unrelated gap on another route remains; a literal template boundary counts only its Python route with `TEMPLATE_CONTENT_NOT_ANALYZED` preserved as scope limitation; static gap, missing v9 part, child HOLD/ERROR, pending candidate, and changed parent retain non-complete status. Assert `complete` requires all 43 indexed surface IDs and no unresolved work.
- [ ] **Step 2: Run RED.** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_surface_coverage_v8.py -q`; expected import/test failure.
- [ ] **Step 3: Implement plan and evaluator.** Bind new plan to analysis/workspace/commit/scope/index/AST hashes, v9 plan and coverage refs, saved v9 terminal snapshot, and v9 progress hash. Keep previous rows byte-for-byte. Recompute source proof and carry forward all nondischarged reasons/child status; do not manufacture v9 role citations or false vulnerability verdicts.
- [ ] **Step 4: Run GREEN and existing v9 coverage tests.** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_surface_coverage_v8.py tests/unit/simple_runtime/test_surface_enrichment_v9.py tests/unit/simple_runtime/test_surface_coverage_v7.py -q`; expected pass.
- [ ] **Step 5: Commit only this task's new files/tests.** Preserve unrelated dirty files.

### Task 3: Same-ID pinning and resume

**Files:**
- Modify: `src/sastsimi/simple_runtime/models.py`, `src/sastsimi/simple_runtime/store.py`, `src/sastsimi/simple_runtime/application.py`
- Test: `tests/unit/simple_runtime/test_surface_v10_store_pin.py`, `tests/simple_runtime/test_surface_v10_resume.py`

**Interfaces:**
- Adds `SimpleAnalysisRun.surface_enrichment_v10_plan_ref: StoredDataRef | None` and `CandidateTerminal.surface_proof_version == 8`.
- Adds `SimpleCheckpointStore.pin_surface_enrichment_v10_plan(...)` with the same CAS failure semantics as the v9 pin, comparing saved v9 terminal/root/index/progress snapshot.
- Existing `resume --enrich-saved-surface-evidence` first completes v9, then pins/runs v10; no new CLI flag or SQL progress table.

- [ ] **Step 1: Write failing tests.** Assert the current A-001-shaped run with v9 9/36 cannot pin v10, a replayable v9 36/36 PARTIAL parent can, a changed commit/source/root/terminal cannot, an interrupted v10 resume returns the same result, and a second resume makes no duplicate rows or artifacts.
- [ ] **Step 2: Run RED.** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_surface_v10_store_pin.py tests/simple_runtime/test_surface_v10_resume.py -q`.
- [ ] **Step 3: Implement model/store/application wiring.** Keep v9 pin/result unchanged; snapshot its terminal/root before successor pin; rebuild deterministic proof at resume; CAS-write new plan and coverage, then atomically update root/terminal only after verification. Preserve all hypothesis, PoC, Finding, report, and old surface progress records.
- [ ] **Step 4: Run GREEN and focused resume regressions.** Same command plus existing v9 store/resume tests.
- [ ] **Step 5: Commit reviewed hunks only.** Inspect each modified dirty file before staging; do not include unrelated user changes.

### Task 4: Independent read verifier and user-visible counts

**Files:**
- Create: `src/sastsimi/simple_runtime/surface_coverage_v8_read.py`
- Modify: `src/sastsimi/simple_runtime/surface_coverage_v7_read.py`, `src/sastsimi/simple_runtime/surface_proof_read.py`, `src/sastsimi/dashboard/query.py`, `src/sastsimi/composition/simple_runtime_composition.py`, `src/sastsimi/simple_runtime/stages.py`, `src/sastsimi/reporting/coverage_disclosure.py`, `src/sastsimi/reporting/bilingual_bundle.py`
- Test: `tests/unit/simple_runtime/test_surface_v10_read.py`, `tests/unit/dashboard/test_query.py`, `tests/unit/reporting/test_bilingual_bundle.py`.

**Interfaces:**
- Produces `verified_saved_coverage_v8(identity, index, coverage_ref, store, artifacts) -> SurfaceCoverageV8`.
- Extends `verified_surface_coverage_counts(...)` to proof version 8, returning only independently replayed counts; exposes `TEMPLATE_CONTENT_NOT_ANALYZED` as a separate scope limitation, not an unresolved Python surface count.

- [ ] **Step 1: Write failing tests.** Assert correct v10 counts render in CLI/dashboard/English/Korean report, template exclusion is visible, tampered v9 plan/progress/part/source or changed v10 result fails closed, and read verification still works after current root/terminal are v10.
- [ ] **Step 2: Run RED.** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_surface_v10_read.py -q`.
- [ ] **Step 3: Implement read replay.** Refactor v9 verifier to verify an explicitly saved predecessor terminal/root snapshot without requiring the current v9 terminal. Recompute v9, then v10 proof/coverage from pinned source, check CAS bytes and latest terminal claims. Update status/report consumers only through the verified reader, not by trusting saved counters.
- [ ] **Step 4: Run GREEN plus consumer regressions.** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_surface_v10_read.py tests/unit/dashboard/test_query.py tests/unit/reporting/test_bilingual_bundle.py tests/unit/simple_runtime/test_surface_v9_read.py -q`; expected pass.
- [ ] **Step 5: Commit reviewed hunks only.** Retain pre-existing edits.

### Task 5: Live A-001 verification and documentation

**Files:**
- Modify: `README.md` or existing surface-evidence documentation only for verified behavior.
- Test: full repository pytest, Ruff, mypy, architecture/import tests; existing A-001 DB read-only replay.

**Interfaces:** Uses the exact existing A-001 ID and existing CLI entry point; produces measured status/evidence, not a forced state.

- [ ] **Step 1: Check Docker engine, Codex auth, current lease, and source commit.** Do not resume while an old worker or unresolved child process may still be running. Start Docker Desktop only if available and verify `docker info` succeeds.
- [ ] **Step 2: Run focused tests, then all regression checks.** `& '..\..\.venv\Scripts\python.exe' -m pytest -q`, `& '..\..\.venv\Scripts\python.exe' -m ruff check src tests`, and `& '..\..\.venv\Scripts\python.exe' -m mypy src`; record exact pass/fail counts and fix only reproduced regressions.
- [ ] **Step 3: Resume A-001 with `--enrich-saved-surface-evidence`.** Reuse 9 completed v9 parts and all earlier work, finish remaining v9 parts/PoC, then run v10 on the same ID. Do not edit the DB directly.
- [ ] **Step 4: Independently read result, coverage, PoC, Scope Gate, and report artifacts.** Report covered/insufficient counts, verified percent, Docker/LLM failures, and HTML/Jinja exclusion. If any item remains unproved, leave `PARTIAL` or blocked; do not claim 100%.
- [ ] **Step 5: Update docs only with observed behavior and perform final review.** No success claim without fresh verification output.
