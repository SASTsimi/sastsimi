# Core-work Progress Separate from Verdict Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show 100% when verified base-analysis work is finished while preserving `PARTIAL` and all unresolved evidence whenever proof is insufficient.

**Architecture:** Keep `ProgressProjector` as the single source for CLI/dashboard progress. Credit a bound terminal surface outcome of `COVERED` or `INSUFFICIENT` as evaluated work, but retain the existing `covered` metric for security coverage. Use a new percentage-kind value so consumers clearly distinguish work progress from a completion verdict; do not alter terminal proof, finding, report-currentness, or resume rules.

**Tech Stack:** Python 3, Pydantic contracts, pytest, vanilla JavaScript dashboard.

**Spec:** `docs/superpowers/specs/2026-10-15-core-work-progress-separate-from-verdict-design.md`

## Global Constraints

- Preserve existing analysis IDs, checkpoints, artifacts, and resume behavior; do not write to the live A-001 database or replace its worker.
- Do not change `COMPLETE`/`PARTIAL`/`BLOCKED`, finding verdicts, report currentness, or validated surface `COVERED` counts.
- Keep original base hypothesis PoC/report stages in the denominator; exclude only separate, versioned successor work for historical `HOLD`.
- No database migration, new PoC generation, or V12 successor-chain implementation.
- Keep legacy non-v2 percentage behavior unchanged.

## Review Focus

- Bound terminal hash or scope mismatch must not earn evaluated-surface credit or 100% (Task 1 test).
- A terminal `UNCOVERED` surface must remain unfinished work and below 100% (Task 1 test).
- A terminal `INSUFFICIENT` surface may finish work but must remain unproven and `PARTIAL` (Task 1 test).
- Added or resumed V11 successor attempts must not change base numerator/denominator (Task 1 test).
- A dashboard/API view with missing surface proof must not imply full coverage merely from a high percentage (Task 2 test).

---

### Task 1: Project a versioned base-work percentage

**Files:**
- Modify: `src/sastsimi/progress/projector.py:441-575,643-674`
- Modify: `src/sastsimi/progress/models.py:18`
- Test: `tests/unit/progress/test_progress_projector.py`
- Test: `tests/unit/simple_runtime/test_surface_v11_interim_progress.py`

**Interfaces:**
- Consumes: existing `ProgressProjector.snapshot(...)`, verified `CandidateTerminal.surface_counts`, and `surface_counts` proof binding.
- Produces: `ProgressSnapshot.percentage_kind == "base_work_fraction"` for candidate pipeline v2; `phase_counts["surface"]["evaluated"]` as an integer only when a valid terminal surface proof exists. Existing `phase_counts["surface"]["completed"]` and `covered` continue to mean proven `COVERED`.

- [ ] **Step 1: Write failing projector tests.** Add `test_v2_partial_insufficient_surface_can_finish_base_work`, asserting a valid terminal with one `INSUFFICIENT` and zero `UNCOVERED` yields `status == "PARTIAL"`, `percent == 100`, `surface.evaluated == 1`, and `surface.covered == surface.completed == 0`. Extend the existing terminal test so `UNCOVERED == 1` stays below 100; add a bound-hash mismatch test that earns no `evaluated` credit. Assert the new percentage kind for v2 and unchanged kind/percent for legacy.
- [ ] **Step 2: Run the targeted tests red.** Run: `$env:PYTHONPATH='src'; & '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/progress/test_progress_projector.py -q` (expect the new assertions to fail before implementation).
- [ ] **Step 3: Implement the projector change.** In `ProgressProjector.snapshot`, after existing terminal proof validation, set `surface.evaluated = covered + insufficient`, credit that value instead of only `covered` to the aggregate numerator, and preserve `surface.completed = covered`. For v2, derive percentage from base credited/known units without a status-based 99% cap; allow 100 only with a valid candidate terminal and all known base units credited. For non-v2, retain the existing formula. Extend `ProgressSnapshot.percentage_kind` to include the exact literal `"base_work_fraction"` and emit it for v2.
- [ ] **Step 4: Pin successor isolation.** Add/extend a V11 interim-progress test that compares snapshots before and after a V11 child-attempt record is added or resumed: `completed_units`, `known_units`, and `percent` remain equal while separate child-attempt counters may change. Run: `$env:PYTHONPATH='src'; & '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/progress/test_progress_projector.py tests/unit/simple_runtime/test_surface_v11_interim_progress.py -q` (expect PASS).
- [ ] **Step 5: Commit this independently testable projection.** Stage only the four listed files and commit with `feat: separate base work progress from verdict`.

### Task 2: Explain the percentage consistently in CLI and dashboard

**Files:**
- Modify: `src/sastsimi/dashboard/models.py:54`
- Modify: `src/sastsimi/dashboard/static/app.js:156-188,289-375`
- Modify: `src/sastsimi/interfaces/cli/public.py:64-69,225-228`
- Modify: `docs/usage.md`
- Modify: `docs/dashboard-demo.md`
- Test: `tests/unit/interfaces/test_public_candidate_status.py`
- Test: `tests/unit/dashboard/test_candidate_frontend.py`
- Test: `tests/unit/dashboard/test_query.py`
- Test: `tests/integration/orchestration/test_streaming_candidate_pipeline.py`
- Test: `tests/unit/simple_runtime/test_public_static_coverage_status.py`
- Test: `tests/unit/simple_runtime/test_surface_v11_consumers.py`

**Interfaces:**
- Consumes: Task 1 `percentage_kind == "base_work_fraction"` and `surface.evaluated`.
- Produces: CLI/dashboard wording `기본 분석 작업 진행률` and a visible note that 100% can coexist with `PARTIAL` and does not certify coverage or submission readiness. The dashboard API model accepts the new literal without coercion.

- [ ] **Step 1: Write failing consumer tests.** In CLI and dashboard tests, assert the new kind renders `기본 분석 작업 진행률: 100%`, the surface line separately shows evaluated/proven/insufficient counts, and `PARTIAL` remains visible. Assert missing proof shows no evaluated count and does not state full coverage; preserve old-kind rendering for existing test fixtures.
- [ ] **Step 2: Run those tests red.** Run: `$env:PYTHONPATH='src'; & '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/interfaces/test_public_candidate_status.py tests/unit/dashboard/test_candidate_frontend.py tests/unit/dashboard/test_query.py -q` (expect new assertions to fail).
- [ ] **Step 3: Implement consumers and documentation.** Accept `"base_work_fraction"` in the dashboard model; update the UI donut label, list-card qualifier, overview/progress explanation, and CLI label/explanation for the new kind while keeping old-kind fallback. Show evaluated and proven coverage as different figures. Document a `100% / PARTIAL` example and the excluded successor work in both named docs; never call 100% a vulnerability confirmation.
- [ ] **Step 4: Update existing v2 contract assertions.** Change only former `"known_checkpoint_fraction"` expectations in the three listed integration/runtime tests to `"base_work_fraction"`; keep old-kind fixtures that intentionally check backward compatibility.
- [ ] **Step 5: Verify consumer and V9–V11 regression.** Run: `$env:PYTHONPATH='src'; & '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/interfaces/test_public_candidate_status.py tests/unit/dashboard/test_candidate_frontend.py tests/unit/dashboard/test_query.py tests/integration/orchestration/test_streaming_candidate_pipeline.py tests/unit/simple_runtime/test_public_static_coverage_status.py tests/unit/simple_runtime/test_surface_v11_consumers.py tests/simple_runtime/test_surface_v9_additive_resume.py tests/simple_runtime/test_surface_v10_resume.py tests/simple_runtime/test_surface_v11_resume.py tests/unit/simple_runtime/test_surface_coverage_v9.py tests/unit/simple_runtime/test_surface_child_revalidation_v11.py -q` (expect PASS).
- [ ] **Step 6: Commit consumer changes.** Stage only the listed Task 2 files and commit with `docs: clarify work progress and partial verdict`.

### Task 3: Whole-repository verification and safe handoff

**Files:** No product-file changes expected; add a focused regression only if the verification run finds a reproducible mismatch.

**Interfaces:** Consumes Tasks 1–2; produces verified test results and a concise handoff distinguishing percentage from terminal status.

- [ ] **Step 1: Inspect the exact diff and working tree.** Run `git diff --check` and `git status --short`; ensure no live runtime DB, logs, or unrelated user files are staged.
- [ ] **Step 2: Run repository checks.** Run `$env:PYTHONPATH='src'; & '..\..\.venv\Scripts\python.exe' -m pytest tests -q -n 4`, `& '..\..\.venv\Scripts\ruff.exe' check .`, and `& '..\..\.venv\Scripts\mypy.exe' --strict src tests` from this worktree. Report exact pass/fail/skip counts and any unavailable check rather than claiming success without output.
- [ ] **Step 3: Review edge-case invariants.** Confirm by test and code inspection that `PARTIAL`/HOLD proof and `COVERED` counts are unchanged; a new successor attempt does not alter base percent; and `UNCOVERED`/invalid proof cannot show 100%.
- [ ] **Step 4: Report the result without changing A-001.** State that an existing A-001 display will update only when its worker has completed and its persisted proof is read by the new code; do not promise that this design alone will make A-001 show 100%.
