# Terminal Gate Outcomes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish valid, non-reportable Technical Gate decisions without calling them execution failures, while making Gate revisions regenerate and rerun the PoC before a bounded terminal decision.

**Architecture:** Store the validated Gate decision separately from stage execution status. A `REVISE` replays from PoC candidate with exact feedback and source refs; `REJECT` or a third `REVISE` ends that hypothesis without Finding. One shared terminal-outcome rule drives runner, progress, dashboard, and CLI; operational failures keep their existing status.

**Tech Stack:** Python 3.12, Pydantic models, SQLite checkpoints/artifacts, asyncio, pytest, Ruff, mypy, PowerShell, Docker Linux.

**Spec:** `docs/superpowers/specs/2026-09-26-terminal-gate-outcomes-design.md`

## Global Constraints

- No execution/provider/Docker/authentication/database error becomes `FALSE`, `HOLD`, or a reportable Finding.
- Only an explicit Gate `ACCEPT` permits a TRUE Finding, TRUE Primitive, or report.
- Maximum three Gate decisions per hypothesis; count persists across resume and is independent of PoC script repair attempts.
- Preserve commit-pinned, bounded, redacted source retrieval and the current Docker/host security boundary.
- Do not rewrite historical A-004 checkpoints or hard-code changedetection.io behavior.
- Update PR #200, README/docs, and run a new pinned changedetection.io analysis with Codex `gpt-6-sol`.

## Review Focus

- `REVISE` with empty `revision_requests` must not become a successful terminal decision; Task 1 tests retryable `TECH_GATE_REVISION_REQUEST_EMPTY`.
- A checkpoint claiming Gate `ACCEPT` while its artifact says `REVISE` must never create a Finding or Primitive; Task 1 tests both guards.
- A crash after a Gate decision but before the rewind must not duplicate the PoC or exceed the revision budget; Task 2 tests resume.
- PoC generation may have used its own repair attempts before the first Gate review; Task 2 tests a separate Gate counter.
- A terminal rejected hypothesis alongside an operationally blocked sibling must keep the analysis `BLOCKED`; Task 3 tests mixed projection and CLI/dashboard agreement.

---

### Task 1: Persist valid Gate decisions and guard reportable outputs

**Files:** `src/sastsimi/simple_runtime/models.py`, `store.py`, `stages.py`, `chaining.py`; `tests/unit/simple_runtime/test_technical_gate_outcomes.py`, `tests/simple_runtime/test_simple_runtime.py`, relevant Finding/Primitive tests.

**Interfaces:** Add `gate_decision: Literal["ACCEPT", "REVISE", "REJECT"] | None` to `StageResult` and `StageCheckpoint`; `SimpleCheckpointStore.complete()` copies it. `TechnicalGateStage.__call__()` returns a `StageResult` for each valid decision with the exact artifact ref, or a retryable `TECH_GATE_REVISION_REQUEST_EMPTY` failure for an empty `REVISE` request. Finding, TRUE Primitive, and Reporter verify the checkpoint decision **and** artifact status are `ACCEPT`.

- [ ] Write failing tests for `ACCEPT`, `REVISE`, `REJECT`, empty revision request, and mismatched checkpoint/artifact guards. Assert valid non-accept decisions preserve exact refs and produce no reportable output.
- [ ] Run `./.venv/Scripts/python.exe -m pytest tests/unit/simple_runtime/test_technical_gate_outcomes.py -q` and confirm the new tests fail for the intended missing behavior.
- [ ] Implement the model, store, stage, and consumer changes without altering operational failure classification.
- [ ] Run the focused tests and existing `tests/integration/chaining/test_primitive_admission_runtime.py`; confirm green.
- [ ] Commit Task 1's code and tests.

### Task 2: Rewind to PoC with bounded, durable Gate feedback

**Files:** `src/sastsimi/simple_runtime/models.py`, `store.py`, `runner.py`, `stages.py`; `tests/simple_runtime/test_simple_runtime.py`, `tests/unit/simple_runtime/test_poc_candidate.py`.

**Interfaces:** Add `gate_revision_count: int = 0` to `StageCheckpoint`, inherited in `SimpleCheckpointStore.mark_running()`. Add `SimpleCheckpointStore.prepare_gate_revision(gate: StageCheckpoint) -> StageCheckpoint`, which atomically seeds a pending `POC_CANDIDATE_DONE` with incremented count and the Gate artifact as exact feedback while invalidating downstream stages. Add `terminal_gate_outcome(checkpoint: StageCheckpoint | None) -> Literal["REJECT", "INCONCLUSIVE"] | None` in `models.py`; it recognizes `REJECT` immediately and `REVISE` after two prior revisions. The runner uses this helper on both initial execution and resume.

- [ ] Replace the old final-Verification-only Gate tests with failing tests for first/second PoC replay, third `REVISE` terminal outcome, `REJECT`, `ACCEPT`, fresh candidate/execution attempt pairing, crash rollback, and idempotent resume. Include a Gate counter unaffected by earlier PoC repair attempts and a stale-stage-version reuse test.
- [ ] Run `./.venv/Scripts/python.exe -m pytest tests/simple_runtime/test_simple_runtime.py -q -k technical_gate` and confirm the new assertions fail as expected.
- [ ] Implement atomic rewind and runner decisions. Forward the requested-source artifact as a direct candidate output ref; prioritize Gate feedback and source in candidate, final Verification, and Gate prompts without changing size/redaction limits.
- [ ] Bump versions of changed stage outputs so old successful checkpoints cannot be mistaken for the new source/Gate contract; keep historical blocked A-004 unchanged.
- [ ] Run focused runner/candidate/source tests and verify terminal Gate decisions never execute Scope Gate, Finding, or Reporter.
- [ ] Commit Task 2's code and tests.

### Task 3: Project one truthful terminal status everywhere

**Files:** `src/sastsimi/progress/projector.py`, `src/sastsimi/dashboard/query.py`, `src/sastsimi/composition/simple_runtime_composition.py`, dashboard view/UI files only if required; `tests/unit/progress/test_progress_projector.py`, `tests/unit/dashboard/test_query.py`, `tests/simple_runtime/test_simple_analysis_application.py`, CLI result tests.

**Interfaces:** Consume `terminal_gate_outcome()` from Task 2. A terminal `REJECT` or exhausted `REVISE` credits skipped downstream work and exposes a non-reportable per-hypothesis disposition. The aggregate is `COMPLETE` only when every hypothesis is terminal and no operational checkpoint is `BLOCKED`/`FAILED`; the result exposes counts for inconclusive/rejected hypotheses without changing Finding count.

- [ ] Write failing tests for single terminal Gate 100%/`COMPLETE`, mixed terminal outcomes, an operationally blocked sibling, dashboard/CLI status agreement, zero Finding/report, and no `resume` hint on a terminal Gate.
- [ ] Run focused progress/dashboard/application/CLI tests and confirm the expected red tests.
- [ ] Implement shared projection, result counts, and minimal UI copy; keep historical blocked A-004 unchanged.
- [ ] Rerun focused tests; confirm `BLOCKED`/`FAILED` operational tests still pass.
- [ ] Commit Task 3's code and tests.

### Task 4: Verify, rerun the real target, and synchronize documentation

**Files:** `README.md`, `docs/architecture/pipeline.md`, `docs/architecture/gates-chaining-reporting.md`, `docs/architecture/runtime-and-recovery.md`, `docs/troubleshooting.md`, `docs/validation/2026-09-26-changedetection-trial.md`; PR #200 description.

**Interfaces:** No new runtime API. The trial uses `https://github.com/dgtlmoon/changedetection.io.git` at commit `d789fe3ea5809eef0134943917ef50f47259121b`, provider Codex model `gpt-6-sol`.

- [ ] Run full local tests (`./.venv/Scripts/python.exe -m pytest tests -q -n 4 -p no:cacheprovider`), Ruff format/check, mypy strict, documentation validator, and `git diff --check`; fix any failures before claiming success.
- [ ] Start a **new** pinned analysis, inspect result/checkpoints/artifacts, and require the real result command to report `COMPLETE` before saying the target passed. If an operational failure remains, diagnose it with a failing test and repeat; never relabel it as inconclusive.
- [ ] Update README, architecture, troubleshooting, and the trial log with exact observed counts and limits; run docs validation again.
- [ ] Commit documentation, push PR #200, wait for Linux/Windows CI and real-Docker E2E, and fix failures before handoff.
