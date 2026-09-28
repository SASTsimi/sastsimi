# Product-Code Static Scope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make deployable product source the default static-analysis scope, with auditable test exclusions and no false `COMPLETE` for unverified product code.

**Architecture:** A versioned `StaticFileScope` classifies one pinned tracked-file manifest. Both SimpleRuntime and production adapters consume its selected paths; all static cache identities and coverage proofs bind to its fingerprint. CodeQL applies an independently verified exact exclusion config during database creation.

**Tech Stack:** Python 3.12, Pydantic, SQLite, pytest, OpenGrep, Semgrep CE, CodeQL CLI 2.27.0, Windows PowerShell.

**Spec:** `docs/plans/2026-09-28-product-code-static-scope-design.md`

## Global Constraints

- Default `include_tests = false`; `true` analyzes tests using the existing rule/language mapping.
- Excluded paths are `EXCLUDED_TEST_FILE`, not verified pairs or unresolved product pairs.
- No Dify-specific path; exact path components and language-specific basenames only, with ambiguity included.
- Keep the complete tracked manifest for integrity; never reuse a differently scoped OpenGrep batch, CodeQL DB, or agent result.
- CodeQL remains at its currently supported languages; the cancelled language-expansion request is out of scope.
- Individual scan timeouts and finite resource limits remain; no unresolved product pair may produce `COMPLETE`.

## Review Focus

- A real product module named `contest.py` or `src/test_client.py` must not disappear merely due to a substring/prefix.
- A test-only file referenced as a package or executable entry point must remain in product scope.
- Path casing, backslashes, symlinks, Unicode, and NUL-delimited tracked paths must not cause silent omission.
- A scope change during resume must not validate old OpenGrep, CodeQL, or downstream results against a new denominator.
- CodeQL's configured filter may not exactly match the classifier; verification failure must stay `BLOCKED`.

---

### Task 1: Shared Scope Classifier and Configuration

**Files:**
- Create: `src/sastsimi/static_analysis/file_scope.py`
- Modify: `src/sastsimi/config/user_config.py`, `src/sastsimi/setup/service.py`, `src/sastsimi/interfaces/cli/main.py`, `src/sastsimi/interfaces/cli/setup.py`
- Test: `tests/unit/static_analysis/test_file_scope.py`, configuration/setup tests already adjacent to those modules

**Interfaces:**
- Produces: `StaticFileScope(all_tracked: tuple[str, ...], selected_paths: tuple[str, ...], excluded_test_files: tuple[TestExclusion, ...], fingerprint: str)` and `build_static_file_scope(workspace: Path, tracked: Sequence[str], *, include_tests: bool) -> StaticFileScope`.
- `TestExclusion(path: str, reason: str)` uses `EXCLUDED_TEST_FILE` as its status when persisted; reasons identify exact directory, anchored basename plus test marker, or other high-confidence proof.
- Config: `include_tests: bool = False` in `UserConfig`, `SimpleExecutionProfile`, setup choices, rendered TOML, and setup CLI flag.

- [ ] Add failing classifier tests for exact `tests`/`__tests__` path segments, `test_*.py`, `*_test.py`, `*.test.ts[x]`, `*.spec.js[x]`, non-test `contest.py`, ambiguous `src/test_client.py`, package entry-point protection, normalized paths, and include-tests mode.
- [ ] Run the new tests; confirm classification/config assertions fail before implementation.
- [ ] Implement the versioned classifier and config propagation. Treat file-name-only candidates as selected unless high-confidence content evidence exists; do not widen exclusion to `fixtures`, `mocks`, or `integration` directories.
- [ ] Re-run classifier and setup/config tests; expect pass, then commit only Task 1 files.

### Task 2: One Scope for SimpleRuntime AST, OpenGrep, Semgrep, and Coverage

**Files:**
- Modify: `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/simple_runtime/static_coverage.py`, `src/sastsimi/simple_runtime/semgrep_fallback_plan.py`, `src/sastsimi/simple_runtime/survey.py`, `src/sastsimi/simple_runtime/stages.py`
- Test: `tests/unit/simple_runtime/test_static_coverage.py`, `tests/unit/simple_runtime/test_semgrep_fallback_plan.py`, `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`

**Interfaces:**
- Consumes: Task 1 `StaticFileScope` and `include_tests` profile flag.
- Produces: coverage fingerprint and OpenGrep batch descriptors containing scope fingerprint; `expected_pairs` only for `selected_paths`, plus separate excluded-test metadata.

- [ ] Add failing tests proving AST and initial OpenGrep command receive exactly selected paths, fallback targets only unresolved selected pairs, excluded paths never enter expected/verified pairs, and scanner output mentioning an excluded path is rejected.
- [ ] Add failing replay tests proving all-tracked historical OpenGrep batches cannot satisfy product-only coverage and already verified product pairs remain reusable only with matching scope.
- [ ] Run targeted static bootstrap/coverage tests and observe the intended failures.
- [ ] Build the scope once after `_tracked_files`; pass selected paths to profiling, AST, explicit-file OpenGrep chunks, fallback, survey, and later requested-source retrieval. Keep full tracked paths solely for checkout integrity. Bind scope fingerprint to every plan/replay key.
- [ ] Re-run targeted tests and commit Task 2 files.

### Task 3: Production Static Adapters and CodeQL Input Parity

**Files:**
- Modify: `src/sastsimi/orchestration/static_work_handlers.py`, `src/sastsimi/static_analysis/codeql_provision_source.py`, `src/sastsimi/composition/production_static_adapters.py`, `src/sastsimi/simple_runtime/bootstrap_stages.py`, `docker/codeql/sastsimi-codeql`
- Create: `src/sastsimi/static_analysis/codeql_scope.py`
- Test: `tests/unit/static_analysis/test_codeql_scope.py`, production static adapter tests, `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`

**Interfaces:**
- Consumes: Task 1 scope manifest and its fingerprint.
- Produces: `write_codeql_scope_config(scope: StaticFileScope, destination: Path) -> Path` containing exact relative excluded paths; CodeQL DB identity incorporates scope fingerprint; production `selected_static_paths` accepts scoped paths.

- [ ] Add failing production adapter tests showing AST/OpenGrep actions and CodeQL provision DB key use the same selected manifest; empty selected language set is a scoped skip, not a scanner crash.
- [ ] Add failing CodeQL config tests for exact excluded paths, YAML escaping, scope cache separation, and rejected findings/extraction from excluded fixture paths.
- [ ] Run targeted tests and the pinned local `codeql database create --help` capability check; record whether `--codescanning-config` is supported on version 2.27.0.
- [ ] Pass the generated config to direct and Docker CodeQL database creation, verify an actual product/test fixture database excludes the test file, and bind provision identity to scope. If this cannot be verified, fail with a stable scope error instead of filtering SARIF after the fact.
- [ ] Re-run targeted production and CodeQL tests; commit Task 3 files.

### Task 4: Durable Exclusion Evidence, Reports, and Resume Guard

**Files:**
- Modify: `src/sastsimi/simple_runtime/store.py`, `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/simple_runtime/application.py`, `src/sastsimi/dashboard/query.py`, `src/sastsimi/dashboard/models.py`, `src/sastsimi/dashboard/static/app.js`, `src/sastsimi/reporting/bilingual_bundle.py`
- Test: `tests/unit/simple_runtime/test_static_coverage.py`, `tests/unit/dashboard/test_query.py`, `tests/unit/reporting/test_bilingual_bundle.py`, `tests/simple_runtime/test_static_to_report_resume.py`

**Interfaces:**
- Consumes: Task 1 exclusions and Task 2/3 scope fingerprints.
- Produces: `simple_static_file_exclusions` rows keyed by `(analysis_id, scope_fingerprint, path)` with `status='EXCLUDED_TEST_FILE'` and `reason`, selected/excluded counts, and a run-scope identity checked before resume or report generation. Both report languages include the full excluded-path/reason appendix.

- [ ] Add failing tests for path/count/reason in DB, artifact, dashboard, English/Korean reports; assert excluded files never increase successful scan counts.
- [ ] Add failing resume tests for same-scope reuse and changed-scope rejection or new-analysis requirement, including downstream agent result invalidation.
- [ ] Run those tests and confirm failures.
- [ ] Persist the scope manifest and exclusions once; surface them consistently in reports. Reject mismatched resume with a clear scope-change code and keep old artifacts intact. Preserve fail-closed product gap logic.
- [ ] Re-run report/resume tests; commit Task 4 files.

### Task 5: Generic Regression, Dify Retest, and Operator Documentation

**Files:**
- Modify: `README.md`, `docs/troubleshooting.md`, `docs/provider-setup.md`, `docs/validation/2026-09-28-dify-static-retest.md`
- Test: mixed-language fixture regression tests and the existing full suite

**Interfaces:**
- Consumes: Tasks 1–4 complete and a scope-qualified new Dify analysis identity.
- Produces: actual per-engine product coverage totals, excluded-test path manifest, remaining parser/time errors, and honest final status.

- [ ] Add/extend a mixed-language fixture proving the same selected/excluded file sets across engines and stable results when `include_tests=true`.
- [ ] Run targeted unit/integration/security tests, then the whole test suite, Ruff, mypy, `git diff --check`, and documentation link checks; fix any regression before proceeding.
- [ ] Audit Dify pinned commit's excluded candidates against backend/frontend entry points and representative product modules; revise only generic classifier rules if false exclusions appear.
- [ ] Start a new scope-qualified Dify trial, preserving old full-scope artifacts. Continue only after product pairs are verified; record exact remaining parser/timeouts and do not claim `COMPLETE` or `confirmed` without evidence.
- [ ] Sync README/operator docs with default scope, include-tests setup, exclusion semantics, resume behavior, actual Dify evidence, and limitations; commit only verified changes, then request whole-branch review and update the existing PR.

## Execution

Each task uses red-green-refactor tests and a scoped commit. Use the existing managed worktree and current PR branch; do not reset user changes or delete old Dify analysis data. The default execution method for speed is native, with one independent whole-branch review before publishing.
