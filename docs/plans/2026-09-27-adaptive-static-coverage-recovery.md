# Adaptive Static Coverage Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing OpenGrep-to-Semgrep fallback progress safely on large repositories while preserving exact file/rule coverage and A-007's prior data.

**Architecture:** Keep the current rule batches, coverage verifier, and fail-closed gate. Capture Semgrep JSON in an analysis-scoped file, deterministically plan larger bounded target chunks, reuse validated legacy/partial attempts, and isolate only remaining failures. Revalidate A-007's old partial OpenGrep artifact before any cross-fingerprint reuse.

**Tech Stack:** Python 3.12, pytest/pytest-asyncio, SQLite checkpoint store, Windows PowerShell, locally bound OpenGrep/Semgrep CE.

**Spec:** `docs/plans/2026-09-27-adaptive-static-coverage-recovery-design.md`

## Global Constraints

- No Dify-specific production paths, rule exceptions, generated-file exclusions, new parser, or changed rule semantics.
- A pair is verified only by `assess_scan`; parser errors, skips, process failures, and timeouts remain gaps and keep `STATIC_DONE` `BLOCKED`.
- Preserve the six OpenGrep batches and their fingerprint, and never blindly copy a count across coverage fingerprints.
- Semgrep chunks: at most 128 targets and 24,000 quoted Windows UTF-16 command-line units; no new concurrency.
- One isolated single-file timeout retry uses `--timeout 30`; all work shares `min(profile.max_elapsed_seconds, 3600)` and a finite split/retry budget.
- No automatic install, login, remote rules, persistent user-profile change, or increase to A-007's configured Codex usage limits; keep `gpt-6-sol`.
- Work in the existing `codex/bilingual-report-bundle` PR #202 worktree. Use its `src` on `PYTHONPATH` and the original checkout's `.venv` Python for tests. Give pytest a unique `--basetemp` path; do not reuse or delete an existing user path.
- Before each `Run` step in PowerShell, set `$env:PYTHONPATH=(Join-Path (Get-Location) 'src'); $py='C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe'; $uniqueTemp=Join-Path 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi' ('.pytest-codex-plan-'+[guid]::NewGuid().ToString('N'))`. Use a fresh `$uniqueTemp` for every pytest command. The sandbox may require approved execution to access Windows temporary files.

## Review Focus

1. A stale, symlinked, missing, or oversized Semgrep output file must never verify a pair (Task 1 tests).
2. Long/Unicode/space-containing Windows paths must not exceed the 24,000-unit command budget or reorder chunk keys on resume (Task 2 tests).
3. A mixed partial result must reuse proven pairs while leaving its parse-error pair blocked, without overwriting the prior raw artifact (Task 3 tests).
4. Deadline/cancellation during recursive splitting must stop children and return a bounded `BLOCKED` result (Task 3 tests).
5. Prior OpenGrep partial output from another analysis, commit, rule batch, or changed executable must not be imported into A-007 (Task 4 tests).

---

## File map

- `src/sastsimi/simple_runtime/semgrep_fallback.py`: local CLI arguments, bounded file output, result/error classification.
- `src/sastsimi/simple_runtime/semgrep_fallback_plan.py` (new): pure deterministic Windows-safe target chunking.
- `src/sastsimi/simple_runtime/bootstrap_stages.py`: legacy cache replay, adaptive fallback/split/resume, validated OpenGrep partial migration.
- `src/sastsimi/simple_runtime/store.py`: scoped lookup of an old OpenGrep attempt by exact run key across coverage fingerprints.
- `tests/unit/simple_runtime/test_semgrep_fallback.py`, `test_semgrep_fallback_plan.py` (new), `test_opengrep_batch_progress.py`, and `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`: behavior and regression tests.
- `README.md`, `docs/usage.md`, `docs/troubleshooting.md`, `docs/validation/2026-09-27-dify-static-coverage.md`: operator behavior and observed results, not promised outcomes.

### Task 1: Disk-backed, bounded Semgrep result adapter

**Files:** Modify `src/sastsimi/simple_runtime/semgrep_fallback.py:72-126`, `src/sastsimi/simple_runtime/bootstrap_stages.py:1187-1195`, `tests/unit/simple_runtime/test_semgrep_fallback.py`, and the `_CoverageProcess` fake in `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py:799-891`.

**Interfaces:** Keep `ScanProcess.run` unchanged. Extend `run_semgrep_fallback(process: ScanProcess, binding: SimpleToolBinding, workspace: Path, rules: Path, targets: Sequence[str], excluded_rule_ids: Sequence[str], timeout_seconds: int, *, output_dir: Path, per_file_timeout_seconds: int | None = None, max_output_bytes: int = 64 * 1024 * 1024) -> bytes`. Expose `build_semgrep_argv(binding: SimpleToolBinding, workspace: Path, rules: Path, targets: Sequence[str], excluded_rule_ids: Sequence[str], output_path: Path, per_file_timeout_seconds: int | None) -> tuple[str, ...]` for Task 2's exact command-length calculation.

- [ ] **Step 1: Write failing adapter tests.** Assert complete JSON is read from a fresh `--output` file even when stdout is empty; `--timeout 30` appears only on the isolated retry; missing/stale/symlinked/over-64-MiB/invalid JSON output is rejected; nonzero exit retains bounded raw evidence but grants no success; `EXTERNAL_TOOL_TIMEOUT` remains distinguishable; cancellation propagates. Update integration fake to write Semgrep JSON to its `--output` path, distinguishing its filename from OpenGrep output.
- [ ] **Step 2: Run the focused tests and confirm failure.** Run `& $py -m pytest -q tests/unit/simple_runtime/test_semgrep_fallback.py tests/integration/orchestration/test_simple_runtime_static_bootstrap.py --basetemp $uniqueTemp`; expected new output-file assertions FAIL, not pytest setup errors.
- [ ] **Step 3: Implement the adapter.** Generate a unique output name within the caller-provided analysis-scoped directory, reject preexisting/non-regular output, use `--json --output`, read at most 64 MiB after process exit, validate top-level JSON, and remove only that generated temporary file after retaining bytes or attaching them to `SemgrepFallbackError`. Preserve tool digest checks before/after execution and map process timeout separately from generic execution failure.
- [ ] **Step 4: Run focused tests; commit.** Same command as Step 2 must PASS; stage only Task 1 files and commit `fix: capture bounded semgrep file output`.

### Task 2: Deterministic Windows-safe target planner

**Files:** Create `src/sastsimi/simple_runtime/semgrep_fallback_plan.py` and `tests/unit/simple_runtime/test_semgrep_fallback_plan.py`.

**Interfaces:** `plan_semgrep_target_chunks(targets: Sequence[str], command_for: Callable[[tuple[str, ...]], Sequence[str]], *, max_targets: int = 128, max_command_utf16_units: int = 24_000) -> tuple[tuple[str, ...], ...]`. `command_for` receives a candidate chunk and returns the exact argv built via Task 1's `build_semgrep_argv` with a fixed-length output name.

- [ ] **Step 1: Write failing planner tests.** Assert 129 paths become 128+1 when short; a command over 24,000 quoted UTF-16 units splits deterministically; paths containing spaces, quotes, and non-BMP Unicode are counted after Windows quoting; input order/duplicates do not change output; a single unfit target raises `SEMGREP_COMMAND_TOO_LONG`.
- [ ] **Step 2: Run the new unit tests and confirm failure.** Run `& $py -m pytest -q tests/unit/simple_runtime/test_semgrep_fallback_plan.py --basetemp $uniqueTemp`; expected import/function failure.
- [ ] **Step 3: Implement the pure planner.** Sort/deduplicate normalized targets, use `subprocess.list2cmdline` and UTF-16 code-unit length on the exact `command_for` result, emit chunks under both caps, and fail rather than truncate an unfit single target.
- [ ] **Step 4: Run planner and adapter tests; commit.** Both unit files must PASS; commit `feat: plan bounded semgrep target chunks`.

### Task 3: Replay, split, and resume Semgrep gaps

**Files:** Modify `src/sastsimi/simple_runtime/bootstrap_stages.py:1089-1235` and `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py:1349-1600`.

**Interfaces:** Preserve `_collect_semgrep(...) -> tuple[list[CoverageSlice], list[StoredDataRef], list[str]]`; use Task 2's planner and Task 1's output adapter. Keep `assess_scan(..., targets=exact_targets)` authoritative.

- [ ] **Step 1: Write failing integration tests.** Pin these cases: 128-target first chunk and bounded argv; previously successful 32-target chunk is replayed; 128-target success survives resume with no second process; a partial 128-target result credits good pairs and splits only unverified paths; a cached partial raw artifact is revalidated without rerunning its parent or overwriting its ref; one-file parser error stays a gap on resume; one-file timeout is retried once with `--timeout 30`; cancellation and the shared deadline terminate the split queue; deduplicated findings do not multiply.
- [ ] **Step 2: Run focused integration tests and confirm failure.** Run `& $py -m pytest -q tests/integration/orchestration/test_simple_runtime_static_bootstrap.py --basetemp $uniqueTemp`; expected only the new behavior tests FAIL.
- [ ] **Step 3: Implement deterministic scheduling.** Reconstruct original OpenGrep-missing groups and legacy 32-target keys first; revalidate legacy success raw before subtracting pairs. Plan 128-target parents from that stable remainder *before* consulting new adaptive attempts. Revalidate cached complete/partial raw with the exact reconstructed targets, retain proven slices, and traverse a reproducible binary split tree only for unverified targets. Do not upsert over a partial raw ref before its proof is carried forward. Treat pinned one-file syntax errors as terminal gaps until the tool/input fingerprint changes; retry a one-file timeout once. Emit explicit reason slices for failed calls, respect the existing deadline, and never infer success from `paths.scanned` alone.
- [ ] **Step 4: Run focused integration, static coverage, and adapter tests; commit.** Run `& $py -m pytest -q tests/integration/orchestration/test_simple_runtime_static_bootstrap.py tests/unit/simple_runtime/test_static_coverage.py tests/unit/simple_runtime/test_semgrep_fallback.py tests/unit/simple_runtime/test_semgrep_fallback_plan.py --basetemp $uniqueTemp`; all must PASS. Commit `fix: resume adaptive semgrep coverage safely`.

### Task 4: Validate A-007 partial OpenGrep reuse across fallback opt-in

**Files:** Modify `src/sastsimi/simple_runtime/store.py:310-404`, `src/sastsimi/simple_runtime/bootstrap_stages.py:759-840`, `tests/unit/simple_runtime/test_opengrep_batch_progress.py`, and `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`.

**Interfaces:** Add `SimpleCheckpointStore.list_static_scan_attempts_for_run_key(identity: CheckpointIdentity, repository: str, tool: str, run_key: str) -> tuple[StaticScanAttempt, ...]`, ordered newest first and scoped to exact analysis/workspace/commit/repository/tool/key. The caller still validates raw via `parse_rule_batch` and `assess_scan` against the current plan.

- [ ] **Step 1: Write failing store/bootstrap tests.** The same A-007 identity with fallback newly enabled reuses its old partial batch's exact verified pairs without a scanner call; another analysis/commit/repository/batch key or changed OpenGrep executable is rejected; a corrupt old artifact is quarantined and rescanned; a clean tracked checkout is required. Assert a prior numeric count alone never advances coverage.
- [ ] **Step 2: Run the focused tests and confirm failure.** Run `& $py -m pytest -q tests/unit/simple_runtime/test_opengrep_batch_progress.py tests/integration/orchestration/test_simple_runtime_static_bootstrap.py --basetemp $uniqueTemp`; expected new cross-fingerprint tests FAIL.
- [ ] **Step 3: Implement scoped lookup and proof migration.** Query old attempts only for exact identity/tool/batch key; consider their raw refs only after the existing clean-workspace preflight and current tool digest validation. Re-run `parse_rule_batch` and `assess_scan` under the new coverage plan, preserve only verified pairs, and leave all other pairs as gaps. Do not share trial artifacts across analysis IDs.
- [ ] **Step 4: Run focused tests; commit.** Same command as Step 2 must PASS; commit `fix: revalidate prior opengrep partial coverage`.

### Task 5: Operator documentation and regression verification

**Files:** Modify `README.md`, `docs/usage.md`, `docs/troubleshooting.md`, `tests/contract/test_operator_docs.py`; after the field run, update `docs/validation/2026-09-27-dify-static-coverage.md` with measured results.

**Interfaces:** Keep `semgrep_fallback` opt-in and user profile unchanged. Document exact `BLOCKED` semantics, 128/24,000 limits, 30-second isolated timeout retry, and how to inspect unresolved relative paths/rules.

- [ ] **Step 1: Add failing doc-contract assertions.** `test_operator_docs.py` must assert the new bounded fallback and no-silent-skip language in README/usage/troubleshooting while retaining PowerShell one-line setup guidance.
- [ ] **Step 2: Run doc contract and confirm failure.** Run `& $py -m pytest -q tests/contract/test_operator_docs.py --basetemp $uniqueTemp`; expected new assertions FAIL.
- [ ] **Step 3: Update operator docs, then run quality checks.** Run the doc contract, `& $py -m ruff check src tests`, `& $py -m mypy src`, and `& $py -m pytest -q --basetemp $uniqueTemp`; report exact outputs and fix regressions without weakening tests. Commit documentation/test changes after they pass.
- [ ] **Step 4: Check PR branch diff.** Run `git diff --check` and compare changed files against this spec; review for Dify-specific production behavior, source leakage, and accidental profile writes.

### Task 6: Pinned Dify field trial and PR #202 update

**Files:** Update only the ignored local trial harness `.superpowers/sdd/2026-09-27-generic-static-coverage-fallback/dify-trial.py` as required by the new adapter; commit measured results in `docs/validation/2026-09-27-dify-static-coverage.md`.

**Interfaces:** Use `DirectStaticBootstrap.run` with analysis ID `statictrial20260927dify`, workspace `e1a07e64bfac4717b11cd5404a522576`, commit `8387590ace4a094de812b7847fc6a4c3a27cd52b`, in-memory Semgrep opt-in, and the existing one-hour limit. Do not write A-007 until the trial's exact coverage and other configured static tools succeed.

- [ ] **Step 1: Run the static-only trial.** Run `& $py .superpowers/sdd/2026-09-27-generic-static-coverage-fallback/dify-trial.py` after setting its one-hour test profile; confirm the pinned commit/tool digests and record expected/verified/gap counts, error reasons, and artifact refs. This may legitimately return `BLOCKED`.
- [ ] **Step 2: Decide from evidence, not status labels.** If every applicable pair and configured static tool passes, construct an ephemeral `PublicSimpleRuntimeApplication` profile with the verified Semgrep binding and resume A-007; track LLM/Docker/PoC/report through terminal state without raising usage caps. If the trial retains deterministic parser gaps, keep A-007 unchanged and report exact blockers before consuming its final retry.
- [ ] **Step 3: Sync validation docs and recheck.** Write only observed outcomes, run doc contract and `git diff --check`, commit the validation update, then push the existing PR branch and verify PR #202 CI. Attach any new PR only if one is created; this task updates the existing PR.

**Execution method:** Native/inline implementation, as the user previously requested direct implementation and speed; still wait for the user's review of this written plan before starting Task 1.
