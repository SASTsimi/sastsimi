# Product-Code Static Scope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make deployable product source the only static-analysis scope, dropping high-confidence test files from inputs and coverage with no false `COMPLETE` for unverified product code.

**Architecture:** A versioned `StaticFileScope` classifies one pinned tracked-file manifest. Both SimpleRuntime and production adapters consume its selected paths; all static cache identities and coverage proofs bind to its fingerprint. CodeQL stages only selected source where possible, or uses an independently verified exact input filter during database creation.

**Tech Stack:** Python 3.12, Pydantic, SQLite, pytest, OpenGrep, Semgrep CE, CodeQL CLI 2.27.0, Windows PowerShell.

**Spec:** `docs/plans/2026-09-28-product-code-static-scope-design.md`

## Global Constraints

- No public include-tests mode, exclusion status, per-file exclusion record, or exclusion report is created. `StaticFileScope` retains selected product paths only, not excluded test paths or reasons.
- Excluded paths are neither verified pairs nor unresolved product pairs.
- No Dify-specific path; classifier policy v3 uses exact test-directory components (including `e2e`, `spec`/`specs`, `testdata`, and named unit/integration/functional test directories) and language-specific basenames. Ambiguous names outside clear test directories stay included unless bounded head/tail content sampling finds test evidence; unreadable package manifests that might declare a test-like product entry point block instead of guessing.
- Keep the complete tracked manifest in the bootstrap integrity check, outside the product-only `StaticFileScope`; never reuse a differently scoped OpenGrep batch, CodeQL DB, or agent result.
- CodeQL remains at its currently supported languages; the cancelled language-expansion request is out of scope.
- Coverage policy v2 marks any selected file outside rule languages and the explicit non-source extension/basename allowlist as unsupported; unknown product-code extensions are not silently ignored.
- Individual scan timeouts and finite resource limits remain; no unresolved product pair may produce `COMPLETE`.

## Review Focus

- A real product module named `contest.py` or `src/test_client.py` must not disappear merely due to a substring/prefix.
- A test-only file referenced as a package or executable entry point must remain in product scope.
- Path casing, backslashes, symlinks, Unicode, and NUL-delimited tracked paths must not cause silent omission.
- A scope change during resume must not validate old OpenGrep, CodeQL, or downstream results against a new denominator.
- CodeQL's configured filter may not exactly match the classifier; verification failure must stay `BLOCKED`.

---

### Task 1: Shared Scope Classifier

**Files:**
- Create: `src/sastsimi/static_analysis/file_scope.py`
- Test: `tests/unit/static_analysis/test_file_scope.py`

**Interfaces:**
- Produces: `StaticFileScope(selected_paths: tuple[str, ...], fingerprint: str, policy_version: int)` and `build_static_file_scope(workspace: Path, tracked: Sequence[str]) -> StaticFileScope`. The classifier does not return excluded test paths or reasons.

- [ ] Add failing classifier tests for exact test-directory segments including `tests`, `__tests__`, `specs`, `e2e`, `testdata`, and the named test-suite directories; test `test_*.py`, `*_test.py`, `*.test.ts[x]`, `*.spec.js[x]`, non-test `contest.py`, ambiguous `src/test_client.py`, package entry-point protection, normalized paths, and absence of an include-tests option.
- [ ] Run the new tests; confirm classification/config assertions fail before implementation.
- [ ] Implement the versioned classifier. Treat file-name-only candidates as selected unless high-confidence content evidence exists; do not widen exclusion to `fixtures`, `mocks`, or `integration` directories. Remove the earlier uncommitted include-tests wiring.
- [ ] Re-run classifier and setup/config tests; expect pass, then commit only Task 1 files.

### Task 2: One Scope for SimpleRuntime AST, OpenGrep, Semgrep, and Coverage

**Files:**
- Modify: `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/simple_runtime/static_coverage.py`, `src/sastsimi/simple_runtime/semgrep_fallback_plan.py`, `src/sastsimi/simple_runtime/survey.py`, `src/sastsimi/simple_runtime/stages.py`
- Test: `tests/unit/simple_runtime/test_static_coverage.py`, `tests/unit/simple_runtime/test_semgrep_fallback_plan.py`, `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`

**Interfaces:**
- Consumes: Task 1 `StaticFileScope`.
- Produces: coverage fingerprint and OpenGrep batch descriptors containing scope fingerprint; `expected_pairs` only for `selected_paths`.

- [ ] Add failing tests proving AST and initial OpenGrep command receive exactly selected paths, fallback targets only unresolved selected pairs, excluded paths never enter expected/verified pairs, and scanner output mentioning an excluded path is rejected.
- [ ] Add failing replay tests proving all-tracked historical OpenGrep batches cannot satisfy product-only coverage and already verified product pairs remain reusable only with matching scope.
- [ ] Run targeted static bootstrap/coverage tests and observe the intended failures.
- [ ] Build the scope once after `_tracked_files`; pass selected paths to profiling, AST, explicit-file OpenGrep chunks, fallback, survey, and later requested-source retrieval. Keep full tracked paths solely for checkout integrity. Bind scope fingerprint to every plan/replay key. Remove the old full-root OpenGrep route and full-scope proof reuse.
- [ ] Re-run targeted tests and commit Task 2 files.

### Task 3: Production Static Adapters and CodeQL Input Parity

**Files:**
- Modify: `src/sastsimi/orchestration/static_work_handlers.py`, `src/sastsimi/static_analysis/codeql_provision_source.py`, `src/sastsimi/composition/production_static_adapters.py`, `src/sastsimi/simple_runtime/bootstrap_stages.py`, `docker/codeql/sastsimi-codeql`
- Create: `src/sastsimi/static_analysis/codeql_scope.py` if exact input filtering is needed for direct CodeQL execution
- Test: `tests/unit/static_analysis/test_codeql_scope.py`, production static adapter tests, `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`

**Interfaces:**
- Consumes: Task 1 scope manifest and its fingerprint.
- Produces: CodeQL database input limited to selected paths; CodeQL DB identity incorporates scope fingerprint; production `selected_static_paths` accepts scoped paths. Any scanner config is transient, not an exclusion artifact.

- [ ] Add failing production adapter tests showing AST/OpenGrep actions and CodeQL provision DB key use the same selected manifest; empty selected language set is a scoped skip, not a scanner crash.
- [ ] Add failing CodeQL input tests for exact selected paths, scope cache separation, and rejected findings/extraction from excluded fixture paths.
- [ ] Run targeted tests and the pinned local `codeql database create --help` capability check; record whether `--codescanning-config` is supported on version 2.27.0.
- [ ] Stage only selected files or pass a verified exact scanner filter to direct and Docker CodeQL database creation, verify an actual product/test fixture database excludes the test file, and bind provision identity to scope. If this cannot be verified, fail with a stable scope error instead of filtering SARIF after the fact.
- [ ] Re-run targeted production and CodeQL tests; commit Task 3 files.

### Task 4: Resume Guard Without Exclusion Records

**Files:**
- Modify: `src/sastsimi/simple_runtime/store.py`, `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/simple_runtime/application.py` as needed for scope identity
- Test: `tests/unit/simple_runtime/test_static_coverage.py`, `tests/simple_runtime/test_static_to_report_resume.py`

**Interfaces:**
- Consumes: Task 2/3 scope fingerprints.
- Produces: a run-scope identity checked before resume or downstream result reuse. No per-file exclusion records or excluded-path appendix.

- [ ] Add failing tests asserting excluded files never increase successful scan counts and no exclusion records are persisted.
- [ ] Add failing resume tests for same-scope reuse and changed-scope rejection or new-analysis requirement, including downstream agent result invalidation.
- [ ] Run those tests and confirm failures.
- [ ] Persist only the scope fingerprint necessary for safe replay. Reject mismatched resume with a clear scope-change code and keep old artifacts intact. Preserve fail-closed product gap logic.
- [ ] Re-run report/resume tests; commit Task 4 files.

### Task 5: Generic Regression, Dify Retest, and Operator Documentation

**Files:**
- Modify: `README.md`, `docs/troubleshooting.md`, `docs/provider-setup.md`, `docs/validation/2026-09-28-dify-static-retest.md`
- Test: mixed-language fixture regression tests and the existing full suite

**Interfaces:**
- Consumes: Tasks 1–4 complete and a scope-qualified new Dify analysis identity.
- Produces: actual per-engine product coverage totals, remaining parser/time errors, and honest final status.

- [ ] Add/extend a mixed-language fixture proving the same selected product file set across engines and that test files never count as verified.
- [ ] Run targeted unit/integration/security tests, then the whole test suite, Ruff, mypy, `git diff --check`, and documentation link checks; fix any regression before proceeding.
- [ ] Audit Dify pinned commit's excluded candidates against backend/frontend entry points and representative product modules; revise only generic classifier rules if false exclusions appear.
- [ ] Start a new scope-qualified Dify trial, preserving old full-scope artifacts. Continue only after product pairs are verified; record exact remaining parser/timeouts and do not claim `COMPLETE` or `confirmed` without evidence.
- [ ] Sync README/operator docs with product-only scope, resume behavior, actual Dify evidence, and limitations; do not publish exclusion paths/counts; commit only verified changes, then request whole-branch review and update the existing PR.

## Execution

Each task uses red-green-refactor tests and a scoped commit. Use the existing managed worktree and current PR branch; do not reset user changes or delete old Dify analysis data. The default execution method for speed is native, with one independent whole-branch review before publishing.
