# SimpleRuntime Local E2E Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a small sequential runtime that reuses completed SASTSIMI results and resumes only the failed hypothesis stage, then finish real PyGoat and ItsDangerous E2E runs.

**Architecture:** Keep the existing distributed Runtime frozen. Add one SQLite-backed checkpoint store, a sequential runner, a read-only importer for existing results, and direct sequential Codex/Docker stage adapters. Existing Agent semantics remain, but distributed lease, action-decision, budget-reservation, and dispatch-reconciliation contracts do not participate in this local path.

**Tech Stack:** Python 3.12, Pydantic 2, stdlib `sqlite3`, existing `CodexCliProcessRunner`, existing `DockerAdapter`, existing report Markdown renderer.

**Spec:** `docs/superpowers/specs/2026-09-21-simple-runtime-local-e2e-design.md`

## Global Constraints

- Reuse PyGoat analysis `fb712f30ec7447fea3acd638a393d9a2` and its existing data directory.
- Do not rerun clone, static analysis, hypothesis, Pro, or Con when their exact inputs are unchanged.
- Keep exact reference validation, sensitive-data inspection, PoC candidate/validated separation, and stale-result rejection.
- Provider, environment, and execution failures never become vulnerability `FALSE`.
- A final `TRUE` requires a same-attempt successful supporting execution and validated PoC.
- Use one subscription LLM call at a time; add concurrency only after both real E2E runs finish.
- Do not run the full suite or CI before both real E2E runs; run one normal and one failure-focused test during implementation.
- Do not perform unrelated refactors, documentation polish, or Medium/Low improvements.

## Review Focus

- A checkpoint with the same IDs but changed input reference must invalidate that stage and all downstream stages; Task 1 normal test covers this.
- A crash after stage output creation but before checkpoint commit must leave the stage resumable, not successful; Task 1 failure test covers transaction rollback.
- A Provider or Docker failure must stop before validated PoC, Gate, Finding, and Report; Task 2 failure test covers this.
- A PoC shell script requiring undeclared URL, cookie, secret, or environment values must be rejected before execution; Task 3 failure path covers this.
- A stale Gate or Report after Verification input changes must not be exported; Task 2 normal test covers downstream invalidation.

---

### Task 1: Checkpoint models and atomic store

**Files:**
- Create: `src/sastsimi/simple_runtime/__init__.py`
- Create: `src/sastsimi/simple_runtime/models.py`
- Create: `src/sastsimi/simple_runtime/store.py`
- Create: `tests/simple_runtime/test_simple_runtime.py`

**Interfaces:**
- Consumes: existing `StoredDataRef`, analysis/workspace/commit/hypothesis/attempt ID string values.
- Produces: `SimpleStage`, `StageStatus`, `StageCheckpoint`, `StageResult`, `StageFailure`, and `SimpleCheckpointStore`.

- [ ] **Step 1: Write the normal and failure tests first**

```python
def test_resume_reuses_exact_success_and_invalidates_changed_downstream(tmp_path):
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    first = checkpoint("POC_EXECUTION_DONE", inputs=(ref("candidate-a"),))
    store.save_success(first, outputs=(ref("execution-a"),))
    store.save_success(
        checkpoint("TECH_GATE_DONE", inputs=(ref("execution-a"),)),
        outputs=(ref("gate-a"),),
    )

    assert store.reusable(first.identity, first.stage, first.input_refs)
    store.invalidate_from(
        first.identity,
        SimpleStage.POC_EXECUTION_DONE,
        new_inputs=(ref("candidate-b"),),
    )

    assert not store.reusable(
        first.identity, SimpleStage.POC_EXECUTION_DONE, (ref("candidate-b"),)
    )
    assert store.get(first.identity, SimpleStage.TECH_GATE_DONE) is None


def test_failed_transaction_never_publishes_success_or_false(tmp_path):
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    current = checkpoint("POC_EXECUTION_DONE", inputs=(ref("candidate-a"),))

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.save_success(current, outputs=(ref("execution-a"),), fail_before_commit=True)

    restored = store.get(current.identity, current.stage)
    assert restored is None or restored.status != StageStatus.SUCCEEDED
    assert store.validated_poc(current.identity) is None
    assert store.verdict(current.identity) is None
```

- [ ] **Step 2: Run the two tests and confirm RED**

Run:

```powershell
$env:UV_CACHE_DIR = (Join-Path (Get-Location) '.review-tmp\uv-cache')
uv run pytest tests/simple_runtime/test_simple_runtime.py -q -p no:cacheprovider
```

Expected: collection or import failure because `sastsimi.simple_runtime` does not exist.

- [ ] **Step 3: Implement the minimal models**

```python
class SimpleStage(StrEnum):
    STATIC_DONE = "STATIC_DONE"
    HYPOTHESIS_DONE = "HYPOTHESIS_DONE"
    PRO_CON_DONE = "PRO_CON_DONE"
    VERIFICATION_INITIAL_DONE = "VERIFICATION_INITIAL_DONE"
    POC_CANDIDATE_DONE = "POC_CANDIDATE_DONE"
    POC_EXECUTION_DONE = "POC_EXECUTION_DONE"
    VERIFICATION_FINAL_DONE = "VERIFICATION_FINAL_DONE"
    CWE_DONE = "CWE_DONE"
    TECH_GATE_DONE = "TECH_GATE_DONE"
    SCOPE_GATE_DONE = "SCOPE_GATE_DONE"
    FINDING_DONE = "FINDING_DONE"
    REPORT_DONE = "REPORT_DONE"


class StageStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class CheckpointIdentity(BaseModel):
    analysis_id: str
    workspace_id: str
    commit_id: str
    hypothesis_id: str | None


class StageCheckpoint(BaseModel):
    identity: CheckpointIdentity
    stage: SimpleStage
    status: StageStatus
    input_refs: tuple[StoredDataRef, ...]
    input_hash: str
    output_refs: tuple[StoredDataRef, ...] = ()
    attempt_id: str | None = None
    attempt_number: int = 0
    error_code: str | None = None
    retryable: bool = False
    recipe_ref: StoredDataRef | None = None
    image_digest: str | None = None
    container_id: str | None = None
    markdown_path: str | None = None
```

`StageResult` contains only `output_refs`, optional validated PoC/report fields, and Docker cache fields. `StageFailure` contains `code`, `retryable`, and safe message; it contains no vulnerability verdict.

- [ ] **Step 4: Implement the SQLite store**

Create `simple_runtime_checkpoints` on first use with primary key `(analysis_id, hypothesis_key, stage)`. Store canonical JSON and `input_hash`. Use `BEGIN IMMEDIATE`, write the complete row, then commit. `fail_before_commit=True` exists only as a test seam and raises before commit. `invalidate_from()` deletes the named stage and later stages for the same identity. `reusable()` returns true only for `SUCCEEDED` with exactly matching ordered references and hash.

- [ ] **Step 5: Run the two focused tests and Ruff**

Run:

```powershell
uv run pytest tests/simple_runtime/test_simple_runtime.py -q -p no:cacheprovider
uv run ruff check src/sastsimi/simple_runtime tests/simple_runtime/test_simple_runtime.py
```

Expected: two tests pass and Ruff exits 0.

- [ ] **Step 6: Commit**

```powershell
git add src/sastsimi/simple_runtime tests/simple_runtime/test_simple_runtime.py
git commit -m "feat: add atomic simple runtime checkpoints"
```

### Task 2: Sequential runner and old-result importer

**Files:**
- Create: `src/sastsimi/simple_runtime/runner.py`
- Create: `src/sastsimi/simple_runtime/migration.py`
- Modify: `tests/simple_runtime/test_simple_runtime.py`

**Interfaces:**
- Consumes: Task 1 checkpoint store and the existing `records`, `artifacts`, `work_states`, and `work_attempts` SQLite tables.
- Produces: `SimpleStageHandler`, `SimpleRuntimeRunner.resume_analysis()`, and `import_existing_analysis()`.

- [ ] **Step 1: Extend the normal test to prove stage-only resume**

```python
@pytest.mark.asyncio
async def test_runner_starts_at_first_non_reusable_stage(tmp_path):
    calls: list[SimpleStage] = []
    handlers = handlers_recording(calls)
    store = seeded_through(store_at(tmp_path), SimpleStage.VERIFICATION_INITIAL_DONE)

    outcome = await SimpleRuntimeRunner(store, handlers).resume_analysis(identity())

    assert calls[0] is SimpleStage.POC_CANDIDATE_DONE
    assert SimpleStage.STATIC_DONE not in calls
    assert SimpleStage.HYPOTHESIS_DONE not in calls
    assert outcome.current_stage is SimpleStage.REPORT_DONE
```

- [ ] **Step 2: Extend the failure test to prove no downstream work**

```python
@pytest.mark.asyncio
async def test_runner_stops_on_provider_failure_without_false_or_downstream(tmp_path):
    handlers = handlers_with_failure(
        SimpleStage.POC_CANDIDATE_DONE,
        StageFailure("AUTH_REQUIRED", retryable=True, safe_message="login required"),
    )
    store = seeded_through(store_at(tmp_path), SimpleStage.VERIFICATION_INITIAL_DONE)

    outcome = await SimpleRuntimeRunner(store, handlers).resume_analysis(identity())

    assert outcome.status is StageStatus.BLOCKED
    assert store.verdict(identity()) is None
    assert store.validated_poc(identity()) is None
    assert store.get(identity(), SimpleStage.TECH_GATE_DONE) is None
    assert store.get(identity(), SimpleStage.REPORT_DONE) is None
```

- [ ] **Step 3: Run only the two focused tests and confirm the new assertions fail**

Run the same pytest command from Task 1. Expected: failures because runner/importer are absent.

- [ ] **Step 4: Implement the sequential runner**

```python
class SimpleStageHandler(Protocol):
    async def __call__(
        self,
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult: ...


class SimpleRuntimeRunner:
    async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
        for stage in HYPOTHESIS_STAGES:
            input_refs = self._inputs(stage, identity)
            if self.store.reusable(identity, stage, input_refs):
                continue
            self.store.mark_running(identity, stage, input_refs)
            try:
                handler = self.handlers.get(stage)
                if handler is None:
                    raise StageFailed("STAGE_HANDLER_MISSING")
                result = await handler(
                    self.store.require(identity, stage), self.store.prior(identity, stage)
                )
            except StageBlocked as error:
                self.store.mark_failure(identity, stage, error.failure, StageStatus.BLOCKED)
                return RunOutcome.blocked(stage, error.failure.code)
            except StageFailed as error:
                self.store.mark_failure(identity, stage, error.failure, StageStatus.FAILED)
                return RunOutcome.failed(stage, error.failure.code)
            self.store.complete(identity, stage, input_refs, result)
        return RunOutcome.complete(SimpleStage.REPORT_DONE)
```

`resume_analysis()` sorts hypotheses by ID and calls `resume_hypothesis()` one at a time. It never schedules another hypothesis concurrently in the first version.

- [ ] **Step 5: Implement read-only import**

`import_existing_analysis(data_dir, analysis_id, store)` reads exact records without updating them. It imports static/hypothesis/Pro/Con/initial Verification checkpoints. It imports `POC_CANDIDATE_DONE` only when a same-attempt `sandbox_command_record` and `POC_EXECUTION_FINISHED` with exit code 0 exist. It imports `POC_EXECUTION_DONE` only when the dynamic result is `SUCCEEDED + SUPPORTED` and has a validated PoC reference. It records reusable `environment_recipe` and image digest without marking failed PoC stages successful.

- [ ] **Step 6: Run the two tests and Ruff**

Run the Task 1 verification commands. Expected: two tests pass and Ruff exits 0.

- [ ] **Step 7: Commit**

```powershell
git add src/sastsimi/simple_runtime tests/simple_runtime/test_simple_runtime.py
git commit -m "feat: resume only incomplete simple runtime stages"
```

### Task 3: Direct sequential LLM and Docker stage adapters

**Files:**
- Create: `src/sastsimi/simple_runtime/provider.py`
- Create: `src/sastsimi/simple_runtime/poc.py`
- Create: `src/sastsimi/simple_runtime/stages.py`
- Modify: `src/sastsimi/prompts/templates/dynamic-reproduction/create-poc-candidate/1.0.2.md`
- Modify: `src/sastsimi/prompts/dynamic_reproduction.py`
- Modify: `src/sastsimi/prompts/production.py`
- Modify: `tests/simple_runtime/test_simple_runtime.py`

**Interfaces:**
- Consumes: `CodexCliProcessRunner.execute(CodexProcessRequest)`, `DockerAdapter.materialize_poc()`, `DockerAdapter.execute()`, Task 2 stage-handler protocol, existing record/artifact readers.
- Produces: `SimpleCodexClient.call()`, `PoCCandidateStage`, `PoCExecutionStage`, and downstream LLM stage handlers.

- [ ] **Step 1: Add rejection assertions to the failure test**

```python
with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
    validate_candidate(
        b'#!/bin/sh\n: "${POC_URL:?required}"\n',
        allowed_environment_names=frozenset(),
    )

assert validate_candidate(
    b"#!/bin/sh\nset -eu\npython - <<'PY'\nprint('supported')\nPY\n",
    allowed_environment_names=frozenset(),
)
```

- [ ] **Step 2: Run the two focused tests and confirm the candidate assertion fails**

Run the same pytest command. Expected: `validate_candidate` is missing.

- [ ] **Step 3: Implement the direct subscription client**

`SimpleCodexClient` owns one `asyncio.Lock`, creates a new `CodexProcessRequest` per call, and calls the existing exact executable/profile-bound `CodexCliProcessRunner`. It validates canonical JSON against the supplied small schema and returns `StageFailure` for `AUTH_REQUIRED`, `TIMED_OUT`, `RATE_LIMITED`, `INVALID_OUTPUT`, or `FAILED`. It stores prompt/output digests and never stores the login session or raw stderr.

- [ ] **Step 4: Implement PoC candidate validation and one repair**

`validate_candidate()` requires a POSIX shell shebang, rejects NUL/CR, host paths, Docker socket, secret-like values, external URLs, and undeclared `${NAME}`/`$NAME` inputs. The prompt requires a self-contained local harness using repository code, temporary harmless fixtures, or mocks inside the container. It forbids placeholder scripts that only print `INCONCLUSIVE` and exit 2.

On `INVALID_OUTPUT`, the client records the exact invalid field. If and only if the invalid field is `content`, it calls the same candidate stage once with the validation code and the original exact references. Reference or sensitive-data failures are not repaired.

- [ ] **Step 5: Implement PoC execution and image reuse**

The handler looks up the checkpointed recipe and image digest. If a recorded container is running and matches the image digest, reuse it; otherwise create one container from the existing image without rebuilding. Materialize verified bytes at `/tmp/sastsimi-poc-candidate`, execute `/bin/sh /tmp/sastsimi-poc-candidate` in `/workspace`, and store bounded stdout/stderr artifact references. Exit 0 alone is not validated PoC: the interpretation call must return `SUPPORTED` and cite the same execution references.

- [ ] **Step 6: Implement remaining stage handlers**

Implement small structured calls for final Verification, CWE, Technical Gate, Rule Scope Gate, Finding normalization, and Reporter. Each call receives only prior checkpoint exact references. Technical/Scope Gate rejection stops before Finding. Reporter accepts only an existing Finding plus supporting records and cannot add new facts. Markdown export uses the existing renderer after sensitive-data and stale-input checks.

- [ ] **Step 7: Run the two tests and Ruff**

Run the Task 1 verification commands. Expected: two tests pass and Ruff exits 0.

- [ ] **Step 8: Commit**

```powershell
git add src/sastsimi/simple_runtime src/sastsimi/prompts tests/simple_runtime/test_simple_runtime.py
git commit -m "feat: run sequential local llm and poc stages"
```

### Task 4: CLI, PyGoat migration, and real E2E completion

**Files:**
- Create: `src/sastsimi/interfaces/cli/simple_evaluation.py`
- Modify: `src/sastsimi/interfaces/cli/main.py`
- Modify: `src/sastsimi/composition/local_evaluation_entrypoint.py`
- Modify: `tests/simple_runtime/test_simple_runtime.py`
- Runtime-only outputs: existing PyGoat data directory and a new ItsDangerous data directory.

**Interfaces:**
- Consumes: Task 2 importer/runner, Task 3 handlers, existing local evaluation profile.
- Produces: CLI subcommands `evaluate simple-resume` and `evaluate simple-analyze`, dispatched respectively to `simple_evaluation.run_resume()` and `simple_evaluation.run_analyze()`.

- [ ] **Step 1: Add CLI parsing assertions to the normal test**

```python
assert main([
    "--data-dir", str(data_dir),
    "evaluate", "simple-resume", analysis_id,
    "--profile", str(profile), "--format", "json",
], simple_evaluation=entrypoint) == 0
```

- [ ] **Step 2: Run the two tests and confirm the CLI assertion fails**

Run the same pytest command. Expected: parser rejects `simple-resume`.

- [ ] **Step 3: Wire the explicit CLI commands**

`simple-resume` imports existing results once, then resumes only incomplete stages. `simple-analyze` uses the existing repository preparation/static/hypothesis path once, writes initial checkpoints, and switches to the sequential hypothesis runner. JSON output includes `analysis_id`, current stage, per-hypothesis status, finding IDs, report paths, and safe error codes.

- [ ] **Step 4: Run the focused tests and Ruff**

Run the Task 1 verification commands. Expected: two tests pass and Ruff exits 0.

- [ ] **Step 5: Import and resume the existing PyGoat analysis**

Run in WSL with the existing data directory and profile:

```bash
sastsimi --data-dir /home/taehyeon/.local/share/sastsimi/live-eval-pygoat-v37 \
  evaluate simple-resume fb712f30ec7447fea3acd638a393d9a2 \
  --profile /mnt/c/Users/taehy/Desktop/WHS/프로젝트/SAST시미/.worktrees/live-llm-e2e/runtime-data/local-evaluation.toml \
  --format json
```

Expected: no clone/static/hypothesis/Pro/Con calls; at least one hypothesis reaches `REPORT_DONE`, and the report path exists under the same data directory.

- [ ] **Step 6: Verify PyGoat evidence**

Run `status`, `results`, `reports`, and `report show/export` for the returned IDs. Confirm the final TRUE has same-attempt successful PoC execution and validated PoC reference. Confirm blocked hypotheses have no FALSE verdict or Finding.

- [ ] **Step 7: Run ItsDangerous after PyGoat**

Use tag `2.2.0` resolved to its full commit before execution. Run `simple-analyze` with a separate data directory. Confirm clone, AST/OpenGrep/CodeQL selection, LLM stages, and final result/report or an explicit non-FALSE blocked status. Do not claim a Finding when the evidence does not support one.

- [ ] **Step 8: Commit implementation changes**

```powershell
git add src/sastsimi tests/simple_runtime/test_simple_runtime.py
git commit -m "feat: expose resumable simple local evaluation"
```

### Task 5: One final verification and integration pass

**Files:**
- Modify only Blocker/High findings discovered by final verification.
- Do not add Medium/Low refinements.

**Interfaces:**
- Consumes: all prior tasks and the two real E2E records.
- Produces: one merge-ready branch and one final PR/CI run.

- [ ] **Step 1: Run the full local verification once**

```powershell
uv run pytest -q -p no:cacheprovider
uv run ruff check src tests
uv run mypy src
```

Expected: all commands exit 0. Fix only Blocker/High failures caused by this change.

- [ ] **Step 2: Recheck exact completion evidence**

Verify PyGoat Markdown output, ItsDangerous terminal/blocked result, no unresolved SimpleRuntime `RUNNING` checkpoint, no stored secret-like value, and no validated PoC without a supporting execution.

- [ ] **Step 3: Commit only necessary final fixes**

```powershell
git add src/sastsimi/simple_runtime src/sastsimi/interfaces/cli/simple_evaluation.py src/sastsimi/interfaces/cli/main.py src/sastsimi/composition/local_evaluation_entrypoint.py tests/simple_runtime/test_simple_runtime.py
git commit -m "fix: close simple runtime release blockers"
```

Skip this commit when no Blocker/High fix was required.

- [ ] **Step 4: Create one PR and run CI once**

Push the branch, create one PR summarizing SimpleRuntime, PyGoat evidence, ItsDangerous evidence, focused tests, and deferred Medium/Low items. Run CI once. Fix only Blocker/High CI failures, then merge after approval.
