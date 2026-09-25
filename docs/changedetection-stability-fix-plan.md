# changedetection.io Follow-up Stability Plan

**Goal:** Repair the two generic mismatches demonstrated by the pinned trial: a historical blocked checkpoint hides active analysis, and a fresh Codex setup still proposes the former default model. Align user-facing documentation with the measured run.

**Evidence:** `docs/validation/2026-09-26-changedetection-trial.md`. No target-name or commit-specific product branch is allowed.

**Execution:** Continuous inline TDD on `codex/changedetection-stability`. Keep existing analysis data and config. Do not repeat a full paid/usage-bearing analysis merely to validate a display-only change; use the existing `A-002` resume path after code checks because its four failed checkpoints are already recovery-exhausted and should not issue new model calls. Compare pre/post LLM-attempt counts to verify this assumption. If resume unexpectedly starts a new model call, stop it and report the unexpected behavior.

## Task 1 — Progress status priority

Files: `tests/unit/progress/test_progress_projector.py`, `src/sastsimi/progress/projector.py`.

1. Add a failing test with hypothesis A `BLOCKED` and later hypothesis B `RUNNING`; expect `RUNNING`, B's stage/ID, and no stale error code. Add a second case with A `BLOCKED` and B `FAILED`; expect `FAILED` and B's error. These fixtures must use generic IDs.
2. Run the focused test to observe RED.
3. In `_status`, prioritize active `RUNNING`, then terminal `FAILED`, then `BLOCKED`; otherwise preserve existing `COMPLETE` logic. Do not alter checkpoint data or verdict classification.
4. Run focused progress and dashboard tests, Ruff, mypy, and commit the change.

## Task 2 — Future Codex setup default

Files: `tests/unit/interfaces/test_setup_cli.py`, `src/sastsimi/interfaces/cli/setup.py`.

1. Add a failing noninteractive setup test omitting `--model` with `--provider codex`, expecting the persisted config/profile default to be `gpt-6-sol`. Check that an explicit `--model` still wins, and preserve the existing default for non-Codex providers. Mock tool/auth discovery; do not call a model.
2. Run the focused test to observe RED.
3. Change only the Codex branch of the setup model suggestion; do not hard-code the model in provider adapters or ignore explicit model input.
4. Run setup/provider tests, Ruff, mypy, and commit.

## Task 3 — Resume observation and documentation sync

Files: `README.md`, `docs/installation.md`, `docs/provider-setup.md`, `docs/usage.md`, `docs/changedetection-stability-design.md`, trial record if observed facts change.

1. Query `A-002` result and persisted LLM-attempt count. Run `resume A-002 --format json` once, then compare the count and final result. The existing exhausted checkpoints should be reused or returned without another LLM request. Do not call `resume` again if the assumption fails.
2. Simplify README quick start to PowerShell `.venv` commands, show an explicit Codex `gpt-6-sol` setup command and analyze/status/resume/result. Move diagnostic detail into the existing operational docs. Keep Cursor and Claude support discoverable and preserve their links.
3. State accurately that Codex token/cost usage is unavailable from this adapter, so the configured token/cost caps cannot enforce spending; elapsed time is only checked at LLM-call boundaries. Correct the earlier design wording. Explain that `BLOCKED` PoC errors are not `FALSE` and that historical blocked hypotheses do not hide currently running work after the fix.
4. Run docs validation, `git diff --check`, and commit.

## Final verification

Run targeted tests, complete pytest suite with `.venv\Scripts` on PATH, Ruff, mypy, and docs validation. Review the whole branch against its base, including regressions and sensitive output. Do not claim PoC repair or vulnerability findings: the four generated PoCs remained blocked in the observed run.
