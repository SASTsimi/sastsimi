# V9 Dashboard Projection Batching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild indexed dashboard detail tabs once per V9 context part without publishing stale `READY` data or changing analysis evidence.

**Architecture:** A task-local V9 context scope defers projection callbacks but never source transactions. Every relevant committed source write atomically marks the index dirty; a guarded publisher compares the source database version and index token before replacing rows, while readers use one SQLite snapshot.

**Tech Stack:** Python 3.12, SQLite, `ContextVar`, pytest, Ruff, mypy; existing vanilla-JS dashboard.

**Spec:** `docs/plans/2026-10-15-v9-dashboard-projection-batching-design.md`

## Global Constraints

- Keep the live A-001 process, data directory, original checkpoints, PoCs and findings unchanged while implementing in this isolated worktree.
- Source writes remain durable even if dashboard projection fails; no extra worker, trigger set, product dependency or source-data migration.
- Default scope is one V9 context iteration, not all 36 parts. The indexed tabs may return 409 updating, but progress/logs remain available.
- Never turn `PARTIAL`, `HOLD`, missing evidence or a stale index into `COMPLETE`/`READY`.
- An old worker keeps using its imported code until it naturally exits. Do not kill or restart it to deploy this change.
- In PowerShell from this worktree, set `$py='C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe'; $env:PYTHONPATH=(Resolve-Path src).Path; $bt=(Join-Path (Get-Location) '.pytest-projection-batch')` before the test commands below. If loopback tests hit sandbox `WinError 10013`, rerun the same tests with normal user network permission and report both outcomes.

## Review Focus

1. A stale projector finishes after another source commit: Task 1 must show `READY` is rejected, not briefly exposed.
2. A projector fails after another projector succeeds: Task 1 must show the failed publisher cannot clobber newer `READY`.
3. A reader overlaps an index replacement: Task 2 must return one coherent snapshot, never state from one generation with rows from another.
4. A V9 context is cancelled or the process exits after a committed source write: Tasks 3–4 must leave durable `INCOMPLETE` and support later rebuild without repeating a completed Agent call.
5. A copied async context writes after its parent scope exited: Task 3 must use immediate projection, not defer forever.

---

## File map

- Create `src/sastsimi/simple_runtime/dashboard_projection_batch.py`: shared task-local scope and transactional dirty-state helper. Place it below the runtime/dashboard import boundary.
- Modify `src/sastsimi/dashboard/read_model.py`: guarded conditional publication, CAS-safe failure state, coherent page reads.
- Modify `src/sastsimi/dashboard/projection.py`: guarded source snapshot and no stale failure overwrite.
- Modify `src/sastsimi/simple_runtime/store.py`: mark source writes dirty in their transaction and route post-commit callbacks through the shared scope.
- Modify `src/sastsimi/simple_runtime/application.py`: one projection scope around each V9 context iteration.
- Modify `src/sastsimi/dashboard/static/app.js`: generic updating/resume-required text.
- Update `docs/dashboard-read-model.md` and focused tests; do not change security verdict rules.

### Task 1: Guarded publication and stale-writer rejection

**Files:** Modify `src/sastsimi/dashboard/read_model.py`, `src/sastsimi/dashboard/projection.py`; test `tests/unit/dashboard/test_read_model.py` and `tests/simple_runtime/test_surface_hold_replay_v5_store.py`.

**Interfaces:** `DashboardReadModel.replace_if_current(analysis_id: str, marker: str, pages: dict[str, tuple[list[dict[str, object]], dict[str, object]]], *, guard: sqlite3.Connection, expected_data_version: int, expected_state_marker: str | None) -> dict[str, int] | None`; `DashboardReadModel.mark_incomplete_if_current(analysis_id: str, expected_state_marker: str | None, error: str) -> bool`. `None` means a newer source/index generation won, not an ordinary failure.

- [ ] Write failing tests for old snapshot after a new source commit, competing successful publisher, and failed older publisher after newer `READY`; assert no stale `READY` and no clobber. Replace the old HOLD test's temporary-stale-READY expectation with the guarded behavior.
- [ ] Run `& $py -m pytest tests/unit/dashboard/test_read_model.py tests/simple_runtime/test_surface_hold_replay_v5_store.py -q --basetemp $bt` and verify the new tests fail for the expected reason.
- [ ] Implement the guarded path: open a persistent guard connection before `collect_source_pages`, capture `PRAGMA data_version` and state marker, acquire `BEGIN IMMEDIATE` on that connection, compare both values, then replace rows and mark `READY` in the same transaction. Initialize schema before the scan. Keep existing `replace` only for test/explicit fixture setup; production `rebuild_analysis` must use the guarded method.
- [ ] Run the same command to green; add a focused test where `collect_source_pages` raises after another projector succeeded and verify the failure CAS leaves its `READY` untouched.
- [ ] Commit this independently testable publisher change.

### Task 2: Coherent indexed reads and explicit updating state

**Files:** Modify `src/sastsimi/dashboard/read_model.py`, `src/sastsimi/dashboard/static/app.js`; test `tests/unit/dashboard/test_read_model.py`, `tests/integration/dashboard/test_server.py`.

**Interfaces:** `DashboardReadModel.page(...)` remains public-compatible, but begins one read transaction before reading index state and ends it after summary/items. `DashboardIndexNotReady("DASHBOARD_INDEX_UPDATING")` and `...RESUME_REQUIRED` retain existing HTTP 409 codes.

- [ ] Add failing interleaving tests: commit a replacement between state and item SELECTs, and assert the page is wholly old or wholly new; add active/idle dirty-index HTTP 409 tests with generic browser message.
- [ ] Run `& $py -m pytest tests/unit/dashboard/test_read_model.py tests/integration/dashboard/test_server.py -q --basetemp $bt` to prove the new tests fail before changing code.
- [ ] Add explicit read snapshot and generic UI text; do not automatically rebuild or use source-mode fallback on every request. Run `node --check src/sastsimi/dashboard/static/app.js`.
- [ ] Re-run the same pytest command to green, including existing pagination and HOLD-generation regressions.
- [ ] Commit this reader/UI change.

### Task 3: Shared deferral and atomic dirty markers

**Files:** Create `src/sastsimi/simple_runtime/dashboard_projection_batch.py`; modify `src/sastsimi/simple_runtime/store.py`; test `tests/unit/simple_runtime/test_usage_record.py`, `tests/simple_runtime/test_surface_hold_replay_v5_store.py`, and new `tests/unit/dashboard/test_projection_batch.py`.

**Interfaces:** `defer_dashboard_projection(data_dir: Path, analysis_id: str, project: Callable[[Path, str], None]) -> Iterator[None]`; `projection_is_deferred(data_dir: Path, analysis_id: str) -> bool`; `mark_index_dirty_connection(connection: sqlite3.Connection, analysis_id: str) -> None`; `SimpleCheckpointStore.defer_dashboard_projection(analysis_id: str) -> Iterator[None]`. A fresh opaque dirty `source_marker` is written in the same source transaction; the published marker still carries the existing HOLD-generation suffix.

- [ ] Add RED tests for checkpoint, LLM-attempt and direct writes: all source rows commit, index becomes `INCOMPLETE` in that transaction, nested scopes flush once, distinct analyses remain independent, and a copied task writing after scope exit projects immediately. Test missing index schema does not fail a source commit.
- [ ] Run `& $py -m pytest tests/unit/simple_runtime/test_usage_record.py tests/simple_runtime/test_surface_hold_replay_v5_store.py tests/unit/dashboard/test_projection_batch.py -q --basetemp $bt` and verify expected failures.
- [ ] Implement the shared `ContextVar` scope and dirty helper. Audit each store method that currently calls `_project_after_direct_commit` and mark its source transaction dirty; route `_write`, `record_llm_attempt`, and direct post-commit callbacks through the shared deferral check. Preserve existing HOLD-only batching and immediate behavior outside the new scope.
- [ ] Re-run the same pytest command to green. Inject a projection failure after a committed source write; assert durable data and `INCOMPLETE`, then explicit rebuild success without a duplicate Agent attempt.
- [ ] Commit this source-writer change.

### Task 4: Batch exactly one V9 context and preserve resume

**Files:** Modify `src/sastsimi/simple_runtime/application.py`, `src/sastsimi/simple_runtime/store.py`; test `tests/unit/simple_runtime/test_surface_enrichment_v9.py`, `tests/simple_runtime/test_surface_v9_additive_resume.py`, `tests/simple_runtime/test_surface_v9_completed_call_replay.py`.

**Interfaces:** `_run_v9_surface_enrichment(...)` retains its signature. Its per-`context` loop enters `self._store.defer_dashboard_projection(identity.analysis_id)` around proposal, `commit_surface_exploration`, and child drain; a context-level `finally` performs exactly one guarded rebuild. `commit_surface_exploration(...)` atomically dirties the index when it commits progress/registrations.

- [ ] Add RED tests for one part that creates multiple children/LLM/checkpoint writes: exactly one rebuild at context exit and all progress/Agent records retained. Cover a saved part with no new Agent call, cancellation, an incomplete child, and resume after a dirty index; completed calls must not be repeated.
- [ ] Run `& $py -m pytest tests/unit/simple_runtime/test_surface_enrichment_v9.py tests/simple_runtime/test_surface_v9_additive_resume.py tests/simple_runtime/test_surface_v9_completed_call_replay.py -q --basetemp $bt` and confirm expected failures.
- [ ] Add the context scope and V9 progress dirtying without changing the candidate or hypothesis logic. On exception/cancellation, attempt the one exit flush; if it fails, leave a visible dirty index and retain the existing run status/error semantics.
- [ ] Re-run the same pytest command to green, then measure rebuild count and wall time before/after on a bounded mock-provider fixture. Report measured local values only.
- [ ] Commit this V9 integration change.

### Task 5: Verification and safe handoff

**Files:** Update `docs/dashboard-read-model.md`; test whole branch.

**Interfaces:** No new public CLI flag. `dashboard-index rebuild` remains the explicit repair path; progress/logs and all security evidence contracts stay unchanged.

- [ ] Update dashboard documentation for context-scoped indexing, 409 meanings and rebuild/resume repair; add a regression test proving unknown/dirty index is never a current report export.
- [ ] Run the focused dashboard/runtime suites, full non-Docker pytest, Docker E2E, Ruff check/format, mypy, docs validation and `git diff --check`. Report exact pass/skip counts and any environment-only failures separately.
- [ ] Obtain independent review of the final diff; fix only verified issues and re-run affected tests.
- [ ] Confirm the live A-001 process naturally ended or is safely idle before using the new code on that same ID. Do not modify live SQLite directly or replay an unresolved Codex call. Compare actual projection rebuild count/time on the later run before claiming A-001 speed improvement.
- [ ] Create a PR only after verified branch checks and attach it to this task; do not claim A-001 `COMPLETE` or confirmed vulnerabilities from dashboard performance work.
