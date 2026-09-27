# Generic Static Coverage Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep AST and CodeQL results when OpenGrep fails, rescan only unverified file/rule pairs with optional Semgrep CE, and never report unsupported or unverified coverage as complete.

**Architecture:** Derive a versioned coverage plan from one commit's tracked files and the existing rule catalog. Assess each OpenGrep batch and optional Semgrep fallback against that plan; persist engine-specific raw results and a compact coverage artifact, then gate static completion on verified applicable pairs. Dify is the only real-repository trial, never a special-case input.

**Tech Stack:** Python 3.12.x (`>=3.12,<3.13`), Pydantic, SQLite, pytest, OpenGrep 1.30.0, optional local Semgrep CE CLI, PowerShell on Windows.

**Spec:** `docs/superpowers/specs/2026-09-27-generic-static-coverage-fallback-design.md`

## Global Constraints

- Work on PR #202's `codex/bilingual-report-bundle` worktree; preserve user changes and current OpenGrep batch cache.
- No repository-specific paths, rule exclusions, source rewrites, automatic dependency installation, or network rule downloads during analysis.
- `COMPLETE` means all *configured, applicable* file/rule pairs are verified; unsupported source extensions remain visible and no engine is credited for another engine's rules.
- Semgrep is opt-in, its executable path/version/SHA-256 are bound at setup, and absence or failure produces an explicit `BLOCKED` gap.
- Keep `gpt-6-sol` as the user's existing Codex model setting; do not change LLM prompts, provider, or unrelated pipeline stages.
- Keep the current analysis time/cost limits for the Dify trial; request a separate decision before raising them.
- Use the original repository `.venv` Python while running tests from the PR worktree; pytest's `pythonpath = ["src", "."]` selects worktree code.

## Review Focus

1. `paths.scanned` contains a file with `PartialParsing`: Task 1's `test_scanned_file_with_parse_warning_remains_gap` must keep it unverified.
2. A scanner error has no usable in-root path: Task 1's `test_pathless_or_outside_error_invalidates_batch` must fail closed without reading outside the checkout.
3. A `.ts` file matches a catalog `javascript` rule: Task 1's `test_javascript_catalog_includes_typescript_targets` must include the pair rather than silently drop it.
4. Semgrep is missing, times out, or emits truncated/invalid JSON: Task 2's `test_fallback_failure_is_explicit` and Task 3's `test_codeql_survives_fallback_failure` must retain evidence and `BLOCKED`.
5. A resume uses changed rules, tracked files, commit, or scanner digest: Task 3's `test_changed_fingerprint_does_not_reuse_old_coverage` must invalidate only stale results.

---

### Task 1: Versioned file/rule coverage model

**Files:**
- Create: `src/sastsimi/simple_runtime/static_coverage.py` — expected pairs, verified slices, gap report, safe path normalization.
- Modify: `src/sastsimi/simple_runtime/opengrep_rule_batches.py` — retain each rule's languages and permit validated partial JSON without changing the current strict default.
- Test: `tests/unit/simple_runtime/test_static_coverage.py`; update `tests/unit/simple_runtime/test_opengrep_rule_batches.py`.

**Interfaces:**
- Extend `RuleBatchPlan` with immutable `rule_languages: tuple[tuple[str, ...], ...]` aligned with `rule_ids`.
- `parse_rule_batch(raw: bytes, batch: RuleBatch, *, allow_errors: bool = False) -> dict[str, object]` keeps the current strict behavior by default.
- `plan_static_coverage(workspace: Path, tracked: Sequence[str], commit_id: str, rules: RuleBatchPlan) -> StaticCoveragePlan` computes a fingerprint and applicable `(relative_path, rule_id)` pairs; classify other source extensions separately.
- `assess_scan(plan: StaticCoveragePlan, batch: RuleBatch, raw: bytes, *, engine: Literal["opengrep", "semgrep"], targets: Sequence[str] | None = None) -> CoverageSlice` accepts only validated in-root paths and subtracts errors/skips from `paths.scanned`.
- `finish_coverage(plan: StaticCoveragePlan, slices: Sequence[CoverageSlice]) -> StaticCoverageReport` returns counts and every remaining gap; its compact JSON form is an artifact, not one DB row per pair.

- [ ] **Step 1: Write failing tests** for zero-hit successful scans, Review Focus items 1–3, duplicate/unknown rule IDs, symlinks, skipped rules/files, and a verified fallback slice closing only its targeted gap.
- [ ] **Step 2: Run the coverage tests and confirm failure.** Run: `python -m pytest tests/unit/simple_runtime/test_static_coverage.py tests/unit/simple_runtime/test_opengrep_rule_batches.py -q`. Expected: new assertions fail before implementation.
- [ ] **Step 3: Implement the interfaces above** with a versioned `.py/.pyi` and JS/TS extension policy; a parser warning overrides `paths.scanned`, and an unlocatable error invalidates its entire batch.
- [ ] **Step 4: Re-run the same tests.** Expected: PASS, including existing strict-parser tests.
- [ ] **Step 5: Commit only Task 1 files.** Message: `feat: track static rule coverage per file`.

### Task 2: Opt-in local Semgrep fallback

**Files:**
- Create: `src/sastsimi/simple_runtime/semgrep_fallback.py` — bounded process invocation and tool-integrity check.
- Modify: `src/sastsimi/setup/service.py`, `src/sastsimi/config/user_config.py`, `src/sastsimi/interfaces/cli/main.py`, `src/sastsimi/interfaces/cli/setup.py` — optional `--semgrep-fallback`, binding and profile persistence; no default change.
- Test: `tests/unit/setup/test_system_tool_discovery.py`, `tests/unit/interfaces/test_setup_cli.py`, `tests/unit/config/test_user_config.py`, `tests/unit/simple_runtime/test_semgrep_fallback.py`.

**Interfaces:**
- Add `semgrep_fallback: bool = False` to `SetupChoices`, `UserConfig`, and `SimpleExecutionProfile`; when true, setup requires and binds a discovered `semgrep` executable, otherwise does not require it.
- `async def run_semgrep_fallback(process: ScanProcess, binding: SimpleToolBinding, workspace: Path, rules: Path, targets: Sequence[str], excluded_rule_ids: Sequence[str], timeout_seconds: int) -> bytes` scans only explicit in-root failed targets with local YAML, JSON output, version check disabled and metrics off; `ScanProcess` is a local structural protocol compatible with `LocalProcessExecutor`.
- Raise stable `SEMGREP_TOOL_UNAVAILABLE`, `SEMGREP_EXECUTION_FAILED`, or `SEMGREP_RESULT_INVALID` errors; Task 1's `assess_scan` decides coverage from returned JSON rather than a zero exit code alone.

- [ ] **Step 1: Write failing tests** named `test_semgrep_setup_opt_in_records_binding`, `test_fallback_only_receives_failed_paths_and_rules`, `test_fallback_failure_is_explicit` (missing binary, changed digest, timeout, invalid/truncated JSON), and `test_cancelled_fallback_stops_child`.
- [ ] **Step 2: Run those tests and confirm failure.** Run: `python -m pytest tests/unit/setup/test_system_tool_discovery.py tests/unit/interfaces/test_setup_cli.py tests/unit/config/test_user_config.py tests/unit/simple_runtime/test_semgrep_fallback.py -q`. Expected: FAIL for the new behavior.
- [ ] **Step 3: Implement discovery, config, CLI flag, and runner**; verify actual installed Semgrep CLI flags before using them. Do not add Semgrep as a mandatory `pyproject.toml` dependency.
- [ ] **Step 4: Re-run those tests.** Expected: PASS with a mocked executable and no Semgrep account.
- [ ] **Step 5: Commit only Task 2 files.** Message: `feat: add opt-in local semgrep fallback`.

### Task 3: Independent static execution, evidence, and resume

**Files:**
- Modify: `src/sastsimi/simple_runtime/bootstrap_stages.py` — run AST/OpenGrep/CodeQL independently, invoke fallback for uncovered pairs, merge candidate results with engine provenance, write coverage artifact.
- Modify: `src/sastsimi/simple_runtime/store.py` — `simple_static_scan_attempts` keyed by analysis/workspace/commit/repository/coverage fingerprint/tool/run key; retain status and artifact refs.
- Modify: `src/sastsimi/simple_runtime/application.py` — attach coverage evidence to a `BLOCKED` checkpoint and avoid immediate retries of identical deterministic parser gaps.
- Modify: `src/sastsimi/simple_runtime/opengrep_rule_batches.py` — keep fair per-rule candidate ordering while deduplicating fallback matches.
- Test: `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`, `tests/simple_runtime/test_simple_analysis_application.py`, `tests/unit/simple_runtime/test_opengrep_batch_progress.py`.

**Interfaces:**
- `SimpleCheckpointStore.save_static_scan_attempt(identity: CheckpointIdentity, repository: str, fingerprint: str, tool: str, run_key: str, status: Literal["SUCCEEDED", "BLOCKED"], raw_ref: StoredDataRef | None, coverage_ref: StoredDataRef | None, error_code: str | None) -> None` and `list_static_scan_attempts(identity: CheckpointIdentity, repository: str, fingerprint: str) -> tuple[StaticScanAttempt, ...]` reuse only artifact refs validated against the identity; missing-output failures still have a record.
- `StaticCoverageBlocked(RuntimeError)` carries a coverage artifact ref. The application stores it in `StageFailure.evidence_refs`, returns `BLOCKED`, and resumes failed work only when the bound tool/rule/source fingerprint changes; same-input parser warnings do not consume repeated automatic attempts.
- `simple_static_fact_bundle` gains `static_coverage_ref`; AST and CodeQL refs remain available even if OpenGrep's rules are incomplete. The coverage artifact also records AST parse-error count/truncation and CodeQL's configured Python-only scope without claiming either as OpenGrep coverage. OpenGrep and Semgrep raw outputs remain separate artifacts.
- `merge_static_candidates(plan: RuleBatchPlan, slices: Sequence[CoverageSlice]) -> bytes` preserves fair per-rule candidate ordering, deduplicates `(rule_id, relative_path, line)`, and records the contributing engine for each accepted match.

- [ ] **Step 1: Write failing integration tests** `test_codeql_runs_after_opengrep_partial_parse`, `test_semgrep_closes_only_failed_file_rule_pairs`, `test_codeql_survives_fallback_failure`, `test_codeql_failure_retains_ast_and_opengrep_evidence`, `test_ast_parse_errors_and_truncation_are_disclosed`, `test_resume_reuses_verified_batches_without_duplicate_findings`, and `test_changed_fingerprint_does_not_reuse_old_coverage`; update old fake OpenGrep JSON to include truthful `paths.scanned`.
- [ ] **Step 2: Run those tests and confirm failure.** Run: `python -m pytest tests/integration/orchestration/test_simple_runtime_static_bootstrap.py tests/simple_runtime/test_simple_analysis_application.py tests/unit/simple_runtime/test_opengrep_batch_progress.py -q`. Expected: FAIL for the new behavior.
- [ ] **Step 3: Implement durable partial results and orchestration** using Task 1/2 interfaces. Preserve valid existing batch refs; store failed attempts before raising and let CodeQL finish. Keep fallback output distinct and reuse only refs whose content, identity, and fingerprints verify.
- [ ] **Step 4: Re-run the same tests.** Expected: PASS, including existing timeout/batch-resume tests.
- [ ] **Step 5: Commit only Task 3 files.** Message: `feat: recover static coverage without losing tool results`.

### Task 4: Dashboard, operator docs, and Dify field trial

**Files:**
- Modify: `src/sastsimi/dashboard/models.py`, `src/sastsimi/dashboard/query.py`, `src/sastsimi/dashboard/static/app.js` — coverage counts, bounded gap preview with relative paths/reasons, engine provenance, explicit unsupported scope.
- Modify: `README.md`, `docs/troubleshooting.md`, `docs/usage.md` — Windows `.venv` setup, `--semgrep-fallback`, `BLOCKED` interpretation, and resume behavior.
- Test: `tests/unit/dashboard/test_query.py`, `tests/integration/dashboard/test_server.py`, `tests/contract/test_operator_docs.py`.

**Interfaces:**
- `AnalysisDetailView` gains `static_coverage_expected: int | None`, `static_coverage_verified: int | None`, `static_coverage_gap_count: int | None`, `static_coverage_gap_preview: tuple[dict[str, str], ...]`, `static_coverage_unsupported: tuple[tuple[str, int], ...]`, `static_ast_parse_error_count: int | None`, and `static_ast_truncated: bool | None`; the preview is capped at 100, while the full artifact remains retained.
- `DashboardQuery.get_analysis()` reads the scoped coverage ref from a successful static bundle or a blocked checkpoint; corrupt/missing refs show `unavailable`, never 100%.

- [ ] **Step 1: Write failing dashboard/docs tests** for blocked and completed summaries, relative-path-only gap previews, missing/corrupt coverage refs, and the documented PowerShell one-liners.
- [ ] **Step 2: Run those tests and confirm failure.** Run: `python -m pytest tests/unit/dashboard/test_query.py tests/integration/dashboard/test_server.py tests/contract/test_operator_docs.py -q`. Expected: FAIL for the new behavior.
- [ ] **Step 3: Implement the projection and docs** without changing finding report formats or current user setup files.
- [ ] **Step 4: Run targeted tests and the full suite.** Run: `python -m pytest -q`; then `python -m ruff check src tests`; then `python -m mypy src`. Expected: PASS for each; report and fix any environment-specific failure before claiming completion.
- [ ] **Step 5: Run one real Dify trial only** against `langgenius/dify@8387590ace4a094de812b7847fc6a4c3a27cd52b`. Use a temporary profile (do not overwrite the user's setup) with the existing data root so the checkout can be reused; install Semgrep CE in the current `.venv` for this trial. Check each fallback file/rule pair, AST/CodeQL artifacts, resume behavior, dashboard state, and final analysis outcome; if gaps remain, record them and keep `BLOCKED`.
- [ ] **Step 6: Commit docs and a sanitized field-trial summary, then update PR #202.** Never commit raw repository code, generated artifacts, credentials, or PoCs. Attach the PR to this task if not already attached; do not claim `COMPLETE` unless the actual run and coverage artifact prove it.
