# Reliable Unbounded Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the default cumulative analysis-time budget unlimited while preserving bounded calls and truthful, resumable file/rule-level static coverage; then exercise the existing Dify analysis end to end wherever evidence permits.

**Architecture:** Represent the cumulative limit as a positive integer or the explicit string `unlimited`, and centralize finite tool-call limits independently of it. Persist and revalidate coverage proof by exact repository commit, rule plan, tool fingerprint, and raw scan output; retry only unresolved file/rule pairs. The static gate stays fail-closed, and downstream checkpoints are resumed only after coverage succeeds.

**Tech Stack:** Python 3.12, Pydantic, SQLite, asyncio, pytest, Ruff, mypy, PowerShell, OpenGrep, Semgrep CE, CodeQL, Docker.

**Spec:** `docs/plans/2026-09-28-reliable-unbounded-analysis-design.md`

## Global Constraints

- All new analyses default to explicit `unlimited`; existing positive integer limits remain valid.
- Each external tool and LLM call retains a finite timeout, bounded retry count, cancellation, and output-size limit.
- Token ceilings stay finite and block later calls from measured totals; unknown usage blocks subsequent calls. Actual monetary cost cannot be enforced for Codex subscriptions or unpriced API responses, and must be disclosed rather than represented as zero.
- Test-only files are removed from the static input before coverage is calculated; they are never counted as verified product code. Generated and vendor product files are not silently excluded to manufacture coverage.
- A file/rule pair is verified only from a valid raw scan explicitly listing the scanned path with no error, skip, or skipped rule.
- AST and current Python-only CodeQL do not prove JavaScript OpenGrep rules.
- A static execution error remains `BLOCKED`; `COMPLETE` never implies a confirmed vulnerability.
- Do not mutate unrelated worktrees or overwrite the existing A-007 checkpoint.

## Review Focus

- A previously configured `3600` must remain finite after a round trip; Task 1 tests this.
- A new default must not bypass token/cost ceilings; Task 1 tests this.
- An already saved proof must be replayed even when prior chunk boundaries change; Task 3 tests this.
- A corrupt or mismatched raw artifact must not count as coverage; Task 3 tests this.
- An engine parser or singleton timeout must leave the exact pairs unverified; Task 4 tests this.

---

### Task 1: Explicit unlimited cumulative budget

**Files:**
- Modify: `src/sastsimi/config/user_config.py`, `src/sastsimi/setup/service.py`, `src/sastsimi/interfaces/cli/main.py`
- Modify: `src/sastsimi/simple_runtime/call_queue.py`, `src/sastsimi/simple_runtime/store.py`, `src/sastsimi/simple_runtime/application.py`
- Modify: `src/sastsimi/simple_runtime/portable_docker.py`, `src/sastsimi/simple_runtime/bootstrap_stages.py`
- Test: `tests/unit/config/test_user_config.py`, `tests/unit/simple_runtime/test_call_queue.py`, `tests/unit/interfaces/test_setup_cli.py`, `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`

**Interfaces:**
- Produces: `ElapsedLimit = int | Literal["unlimited"]`; `finite_call_timeout(limit: ElapsedLimit, cap: int) -> int` (positive integer); `RunUsageBudget.check() -> StageFailure | None` skips only the cumulative elapsed gate when unlimited.
- Consumes: existing positive integer configuration, persisted LLM attempt ledger, finite tool-call caps.

- [ ] **Step 1: Write failing tests** for default config/setup `unlimited`, TOML round-trip, legacy positive integer, no elapsed rejection under unlimited, and unchanged token/cost rejection.
- [ ] **Step 2: Run focused tests.** Run: `uv run pytest -q tests/unit/config/test_user_config.py tests/unit/simple_runtime/test_call_queue.py tests/unit/interfaces/test_setup_cli.py` Expected: new assertions fail on the current integer-only behavior.
- [ ] **Step 3: Implement minimal configuration, CLI, budget, resume, and bounded-call changes.** Make TOML serialize `unlimited` as a quoted string; keep integer values numeric. Resume should reopen only elapsed-budget failures when unlimited or when a raised finite limit has actual headroom. Preserve existing per-call caps.
- [ ] **Step 4: Run focused tests.** Run: `uv run pytest -q tests/unit/config/test_user_config.py tests/unit/simple_runtime/test_call_queue.py tests/unit/interfaces/test_setup_cli.py` Expected: PASS.
- [ ] **Step 5: Commit.** Run: `git add src tests && git commit -m "feat: default analyses to unlimited cumulative time"` Expected: one task commit, no unrelated files.

### Task 2: Remove aggregate static scan deadlines

**Files:**
- Modify: `src/sastsimi/simple_runtime/bootstrap_stages.py`
- Test: `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`

**Interfaces:**
- Consumes: Task 1 `ElapsedLimit` and finite call caps.
- Produces: `_collect_opengrep` and `_collect_semgrep` continue through all planned finite chunks without a shared one-hour wall-clock cutoff; each subprocess remains bounded.

- [ ] **Step 1: Change the existing shared-deadline integration test to assert every chunk is attempted after simulated elapsed time; add a test proving finite per-node timeouts remain.**
- [ ] **Step 2: Run focused tests.** Run: `uv run pytest -q tests/integration/orchestration/test_simple_runtime_static_bootstrap.py -k "deadline or timeout"` Expected: new no-aggregate-deadline assertion FAILS.
- [ ] **Step 3: Remove only shared static deadlines and use finite per-batch/node timeout constants.** Keep finite retries and interruption semantics; replay cached proof before deciding to execute a node.
- [ ] **Step 4: Run integration suite.** Run: `uv run pytest -q tests/integration/orchestration/test_simple_runtime_static_bootstrap.py` Expected: PASS.
- [ ] **Step 5: Commit.** Run: `git add src tests && git commit -m "fix: process static batches without global deadline"` Expected: one task commit.

### Task 3: Proof-preserving resume across changed chunk boundaries

**Files:**
- Modify: `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/simple_runtime/store.py`
- Test: `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`, `tests/unit/simple_runtime/test_static_coverage.py`

**Interfaces:**
- Consumes: `StaticCoveragePlan.fingerprint`, `CoverageSlice.verified_pairs`, persisted scan-attempt raw refs, and Task 2 finite node execution.
- Produces: reusable verified pairs re-assessed against current coverage plan independent of old chunk key; only missing pairs are scheduled for Semgrep.

- [ ] **Step 1: Add failing tests** for changed chunking with preserved prior proof, corrupted saved raw data, changed rule/tool fingerprint, and a partial retry that cannot erase already verified pairs.
- [ ] **Step 2: Run focused tests.** Run: `uv run pytest -q tests/integration/orchestration/test_simple_runtime_static_bootstrap.py -k "replay or fingerprint or corrupt"` Expected: new replay assertion FAILS and safety tests do not falsely pass.
- [ ] **Step 3: Implement a bounded replay path** over persisted Semgrep attempt refs for the exact analysis/repository/coverage fingerprint; reconstruct each attempt's selected rule IDs and targets from a durable descriptor (or an equivalent verified cache record), re-assess raw output, and retain only matching verified pairs. Keep unsafe/corrupt refs uncredited and preserve artifact quarantine behavior.
- [ ] **Step 4: Run static coverage tests.** Run: `uv run pytest -q tests/integration/orchestration/test_simple_runtime_static_bootstrap.py tests/unit/simple_runtime/test_static_coverage.py` Expected: PASS.
- [ ] **Step 5: Commit.** Run: `git add src tests && git commit -m "fix: reuse validated static proof across resume chunks"` Expected: one task commit.

### Task 4: Bounded isolated failure diagnosis and truthful coverage

**Files:**
- Modify: `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/simple_runtime/semgrep_fallback.py` only where actual repro warrants.
- Test: `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`, `tests/unit/simple_runtime/test_semgrep_fallback.py`
- Document: `docs/validation/2026-09-28-dify-static-retest.md`

**Interfaces:**
- Consumes: Tasks 2–3 unresolved pair set and raw scan attempts.
- Produces: finite singleton retry evidence, exact remaining path/rule/error report, and no false COMPLETE on parser or timeout failures.

- [ ] **Step 1: Reproduce representative Dify parser and PDF-worker timeout cases with bounded local scans; write failing tests for any generalizable defect observed.** Expected: exact raw tool error and pair are known, without modifying A-007.
- [ ] **Step 2: Run new focused tests.** Run: `uv run pytest -q tests/integration/orchestration/test_simple_runtime_static_bootstrap.py -k "parser or singleton or timeout"` Expected: defect-specific test FAILS before code changes, or record that engines genuinely cannot parse the input.
- [ ] **Step 3: Implement only evidence-safe, general fixes supported by the reproduction** (for example, retry scheduling, tool-result preservation, or a compatible engine path). Never interpret PartialParsing or a text search as successful rule coverage.
- [ ] **Step 4: Run static tests and write validation evidence.** Run: `uv run pytest -q tests/integration/orchestration/test_simple_runtime_static_bootstrap.py tests/unit/simple_runtime/test_semgrep_fallback.py` Expected: PASS; Dify test document states exact verified/unverified counts and remaining errors.
- [ ] **Step 5: Commit.** Run: `git add src tests docs/validation && git commit -m "fix: preserve evidence for isolated static failures"` Expected: one task commit when a code fix exists; documentation-only commit otherwise.

### Task 5: Dify resume, whole-pipeline validation, and documentation

**Files:**
- Modify: `README.md`, `docs/architecture/pipeline.md` and applicable setup/operations docs.
- Test: existing integration and end-to-end suites.
- Document: `docs/validation/2026-09-28-dify-end-to-end.md`

**Interfaces:**
- Consumes: Tasks 1–4, unchanged A-007 identity and checkpoint; existing Agent, PoC, gate, and report contracts.
- Produces: honest Dify run status, any verified report artifacts, generic setup/resume instructions, and regression evidence.

- [ ] **Step 1: Write/adjust regression tests for default unlimited setup and resume without duplicate completed checkpoints; run them RED where behavior changes.**
- [ ] **Step 2: Run the pinned Dify static path and resume A-007 only if all required pairs are verified.** Expected: the operation ends `COMPLETE` only if every required stage succeeds; otherwise exact `BLOCKED` status and raw evidence are recorded.
- [ ] **Step 3: Diagnose each downstream reproducible bug with a failing test, then minimally fix and rerun; do not synthesize a Finding or a confirmed report.** Expected: any report exists only after successful validation and gates.
- [ ] **Step 4: Sync README and architecture/operations docs; run `uv run pytest -q`, `uv run ruff check .`, `uv run mypy src`, and `pwsh -File scripts/validate-current-docs.ps1`.** Expected: all commands PASS or each remaining failure is named and traced.
- [ ] **Step 5: Commit.** Run: `git add README.md docs src tests && git commit -m "docs: document reliable analysis and Dify validation"` Expected: no sensitive artifacts or unrelated state committed.

## Final review and handoff

Request one independent whole-branch review, fix important findings with RED→GREEN tests, rerun the full checks, then report the actual Dify state and limitations. A `BLOCKED` status caused by an engine limitation is a truthful result, not permission to assert `COMPLETE`.
