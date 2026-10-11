# A-002 Safe Late PoC Replay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Diagnose Django migration-fixture candidate rejection safely and permit exactly one guarded same-ID retry of A-002's failed candidate without weakening PoC validation.

**Architecture:** Keep the existing recovery CLI and SQLite/CAS contracts. A pure closed-reason diagnostic feeds bounded candidate feedback; an append-only, compare-and-set late marker binds attempt 7 to the original fixture marker, and the candidate stage validates both. The historical attempt-6 subreason remains unknown because its rejected content was not saved.

**Tech Stack:** Python 3.12, Pydantic models, SQLite, content-addressed artifacts, pytest, Ruff, mypy, Windows PowerShell.

**Spec:** `docs/plans/2026-10-12-live-analysis-proof-recovery-design.md` (A-002 section).

## Global Constraints

- Preserve A-002's exact analysis ID, workspace/commit, all existing checkpoints/events/artifacts, and completed static/Agent work.
- Keep `django_migration_fixture_replay_forbidden` behavior and every current PoC sandbox/secret rule; do not infer a verdict from candidate repair.
- The attempt-6 rejected content is unavailable. Never state or backfill its specific internal rejection reason.
- One explicit late replay only: attempt 6 `RECOVERY_EXHAUSTED` may yield pending attempt number 6; `mark_running` advances to attempt 7. No automatic attempt 8.
- General logs receive only closed status/attempt/reason fields, never candidate bytes, full prompts, local paths, secrets, or raw exceptions.
- Run commands from the existing isolated `build/codex-a001-a002-recovery-final` worktree using `..\..\.venv\Scripts\python.exe`; stage/commit only named files, never `git add -A`.

## Review Focus

1. A forged recovery marker with a valid-looking parent ref must fail closed; Task 3 tests altered marker bytes and a different hypothesis identity.
2. A concurrent or repeated late recovery must not queue two attempts; Task 2 tests stale CAS and a second command.
3. A same-named but unpinned Django settings module must still be rejected; Task 1 tests module mismatch and Task 3 tests attempted bypass.
4. An unresolved Codex child process must block replay before DB mutation; Task 2 tests active/unconfirmed child status.
5. Legacy attempt-6 diagnostic without content must remain `UNKNOWN`, not a guessed category; Task 2 and Task 4 assert this in events and user output.

## File map

- `src/sastsimi/simple_runtime/django_migration_graph_omission.py`: pure closed-reason fixture validator; preserve Boolean wrapper.
- `src/sastsimi/contracts/poc_candidate.py`: optional closed reason on `PoCCandidateRejected`, compatible with existing callers.
- `src/sastsimi/simple_runtime/store.py`: transactional, one-shot late candidate replay and marker creation.
- `src/sastsimi/simple_runtime/recovery.py`: strict late-marker-to-original-fixture binding reader.
- `src/sastsimi/simple_runtime/stages.py`: apply the original fixture guard to attempt 7 and give bounded, safe retry feedback.
- `tests/unit/simple_runtime/test_django_migration_fixture_source_gap.py`, `tests/simple_runtime/test_poc_django_migration_fixture_replay.py`: unit and state-machine regressions.
- `tests/simple_runtime/test_poc_django_migration_public_wiring.py`, `docs/architecture/runtime-and-recovery.md`: command wiring and operator semantics.

---

### Task 1: Closed fixture-rejection reason without policy relaxation

**Files:** Modify `src/sastsimi/simple_runtime/django_migration_graph_omission.py:1229-1476`; test `tests/unit/simple_runtime/test_django_migration_fixture_source_gap.py`.

**Interfaces:** Produce `FixtureReplayReason = Literal["INVALID_PYTHON_OR_MIGRATION_BYPASS", "SYNTHETIC_SETTINGS_OR_MUTATION", "PINNED_PROJECT_BOOTSTRAP_MISSING", "SETUP_MIGRATE_ORDER_INVALID", "REQUEST_BEFORE_MIGRATION"]` and `django_migration_fixture_replay_rejection(content: bytes, *, flag: str | None = None, app_name: str | None = None, project_modules: tuple[str, ...] | None = None) -> FixtureReplayReason | None`. Keep `django_migration_fixture_replay_forbidden(...) -> bool` as `reason is not None` with its existing signature.

- [ ] **Step 1: Write failing parameterized tests** for `NATIVE_REPLAN` returning `None`, each current rejection class returning its closed code, and Boolean equivalence over the existing fixtures; test a lookalike unpinned project module.
- [ ] **Step 2: Run RED:** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_django_migration_fixture_source_gap.py -q -p no:cacheprovider`; expected new import/tests fail while old tests remain runnable.
- [ ] **Step 3: Implement the pure reason function** by splitting the existing Boolean branches, with no new acceptance path or source-value return; make the Boolean function delegate to it.
- [ ] **Step 4: Run GREEN** with the same command; expected all tests pass.
- [ ] **Step 5: Commit only the two named files** as `fix: classify fixture PoC rejection without relaxing guard`.

### Task 2: Compare-and-set single late replay

**Files:** Modify `src/sastsimi/simple_runtime/store.py:9229-9247,9296+`, `src/sastsimi/simple_runtime/recovery.py`; test `tests/simple_runtime/test_poc_django_migration_fixture_replay.py`.

**Interfaces:** Add `SimpleCheckpointStore._prepare_poc_django_migration_fixture_candidate_retry(self, stopped: StageCheckpoint, artifacts: SimpleArtifactRepository, *, fail_before_commit: bool = False) -> StageCheckpoint`. The existing public `prepare_poc_django_migration_settings_exhaustion_replay` dispatches to it only for `POC_CANDIDATE_DONE`, `BLOCKED/RECOVERY_EXHAUSTED`, attempt `MAX_RECOVERY_ATTEMPTS + 3`. Marker kind remains `simple_recovery_decision` with `late_fixture_replay_revision: 2`, parent fixture decision ref, saved attempt-6 checkpoint ref, original source projection ref/hash, and `historical_rejection_reason: "UNKNOWN"`. Produce `late_fixture_replay_binding(checkpoint: StageCheckpoint, artifacts: SimpleArtifactRepository) -> dict[str, object] | None` in `recovery.py` to validate the chain for Task 3.

- [ ] **Step 1: Write failing state-machine tests** that construct an attempt-6 fixture-guard rejection from the existing attempt-5 helper. Assert one pending attempt-6 checkpoint, unchanged static and prior artifacts, one decision event, one parent fixture ref, and `UNKNOWN` historical reason. Assert stale root/child, missing cleanup proof, active Codex child, corrupted source/ref, repeated call, and simulated pre-commit failure leave stored state unchanged.
- [ ] **Step 2: Run RED:** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/simple_runtime/test_poc_django_migration_fixture_replay.py -q -p no:cacheprovider`; expected new attempt-6 cases fail with the current attempt-4-only guard.
- [ ] **Step 3: Implement the new dispatch, strict preflight, marker reader, and one `BEGIN IMMEDIATE` CAS transaction.** Reuse the existing checkpoint snapshot/event helpers; do not add a CLI option, DB column, or unconditional retry path.
- [ ] **Step 4: Run GREEN** with the same command; expected prior attempt-5 and new attempt-7 setup tests pass.
- [ ] **Step 5: Commit only the three named source/test files** as `fix: bind one late Django fixture candidate replay`.

### Task 3: Preserve fixture guard and safe feedback on attempt 7

**Files:** Modify `src/sastsimi/contracts/poc_candidate.py:114+`, `src/sastsimi/simple_runtime/stages.py:232-352,2345-2460`; test `tests/simple_runtime/test_poc_django_migration_fixture_replay.py` and `tests/unit/simple_runtime/test_django_migration_fixture_source_gap.py`.

**Interfaces:** Extend `PoCCandidateRejected.__init__(code: str, *, reason_code: str | None = None)` while `str(error)` remains `code`. `_reject_migration_settings_replay_content(...)` must apply the unchanged candidate and Task-1 validator to a Task-2 late binding as well as the original attempt-6 binding. Only `FixtureReplayReason` or `UNCHANGED_CANDIDATE` may appear as `reason_code`; unbound marker errors have no repair detail.

- [ ] **Step 1: Write failing tests** that mark the pending checkpoint running as attempt 7 and reject the previous, synthetic-settings, migration-bypass, and order-invalid scripts; accept `NATIVE_REPLAN`. Assert forged parent marker or changed source fails `...UNBOUND`, not `...UNSUPPORTED`; assert retry prompt includes only closed reason and native ordering guidance, not candidate content or local paths.
- [ ] **Step 2: Run RED:** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/simple_runtime/test_poc_django_migration_fixture_replay.py tests/unit/simple_runtime/test_django_migration_fixture_source_gap.py -q -p no:cacheprovider`; expected attempt-7 cases fail because current guard only recognizes attempt 6.
- [ ] **Step 3: Implement the marker-chain guard and bounded in-attempt feedback.** Persist a safe diagnostic ref for a newly rejected candidate; never infer the attempt-6 subreason. Keep current `StageFailure` code, max retry count, candidate schema, and PoC execution checks.
- [ ] **Step 4: Run GREEN** with the same command, then run `& '..\..\.venv\Scripts\python.exe' -m pytest tests/simple_runtime/test_poc_django_migration_public_wiring.py -q -p no:cacheprovider`; expected all pass.
- [ ] **Step 5: Commit only the three named source/test files** as `fix: retain fixture safety on late candidate retry`.

### Task 4: Operator contract, full verification, and same-ID live check

**Files:** Modify `docs/architecture/runtime-and-recovery.md`; test `tests/simple_runtime/test_poc_django_migration_public_wiring.py`.

**Interfaces:** The existing `resume --repair-poc-django-migration-settings-exhaustion` command accepts the proven late candidate once; ordinary `resume` still does not reset an exhausted attempt. User-visible output identifies the bounded repair and an `UNKNOWN` historical subreason without leaking data.

- [ ] **Step 1: Add a failing public-wiring test** for the existing command on a saved attempt-6 fixture rejection and its second invocation; assert one pending retry followed by explicit refusal.
- [ ] **Step 2: Run RED:** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/simple_runtime/test_poc_django_migration_public_wiring.py -q -p no:cacheprovider`; expected new case fails.
- [ ] **Step 3: Wire only any missing public response text and document the one-shot command, unknown old cause, and safe terminal states.** Do not expose raw diagnostics.
- [ ] **Step 4: Run GREEN**, then `& '..\..\.venv\Scripts\python.exe' -m pytest tests -q -p no:cacheprovider`, `& '..\..\.venv\Scripts\python.exe' -m ruff check src tests`, and `& '..\..\.venv\Scripts\python.exe' -m mypy src`; expected exit 0 (record any pre-existing skip count).
- [ ] **Step 5: Commit only the test, docs, and any changed public-wiring file** as `docs: explain guarded late PoC recovery`.
- [ ] **Step 6: Before touching live data, record A-002 checkpoint/CAS hashes, process identity and command output.** Under its normal lease, invoke the existing repair command exactly once against analysis ID `f83c319e988b488d83d09dc1928d755b`, then ordinary same-ID resume. Compare static 1802/1802, prior artifacts, final candidate/PoC/verdict/status, LLM calls and attempt count. An unproven or newly rejected PoC stays `BLOCKED`; do not queue attempt 8 or report `confirmed` from a synthetic fixture.

## Implementation self-review

The closed rejection reasons, one-shot marker binding, and candidate guards
were implemented and tested. The approved live attempt 7 did not produce a
validated PoC; A-002 remains `BLOCKED / RECOVERY_EXHAUSTED`. The rejected
historical candidate bytes were not saved, so their exact internal subreason
must not be reconstructed from later diagnostics. No attempt 8 is planned or
authorized by this document. The wrapper parser now rejects shell statements
before the inspected Python heredoc, including an `exit 0` that would otherwise
look like a successful execution without running Django migration.
