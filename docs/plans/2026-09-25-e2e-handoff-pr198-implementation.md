# E2E handoff selective integration into PR #198 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the useful missing `impl/e2e-run` behaviors into PR #198 without changing the current default analysis or removing Codex, Cursor, Claude, or automatic recovery.

**Architecture:** Keep `SimpleExecutionProfile`, `SimpleAnalysisApplication`, `SimpleLLMClient`, checkpoint store, and stage handlers as the integration boundaries. Port isolated behavior from `origin/impl/e2e-run` into those current boundaries, one independently testable task at a time; never merge the branch wholesale. New hypothesis feeding is opt-in, and old profiles remain valid.

**Tech Stack:** Python 3.12, Pydantic v2, SQLite, asyncio, Docker CLI, pytest, Ruff, mypy; Windows PowerShell commands below run from the repository with `.venv` installed.

**Spec:** `docs/decisions/2026-09-25-e2e-handoff-selective-integration-design.md`

## Global Constraints

- Preserve current `cursor_provider.py`, `recovery.py`, all provider choices, Agent roles, default prompts, output schemas, and automatic recovery.
- `hypothesis_feed` defaults to the existing analysis path; `facts_survey` is explicit opt-in and processes eight suspicious points per turn.
- A retryable model call has at most three attempts including the first; auth, unsupported-model, boundary, policy, and confirmed counter-evidence failures are terminal.
- New configuration fields are optional; old `config.toml`, `profile.toml`, DB records, artifacts, and completed checkpoints remain readable and reusable.
- Only runtime-owned, provably dead Docker containers may be removed. An unknown owner or Windows liveness uncertainty fails safe.
- No secrets, full prompts, or repository code in ordinary logs. Live Claude inference requires the operator's own authenticated account and is not part of mock CI.
- The repo rejects `docs/superpowers`; keep this plan in `docs/plans` and run `scripts/validate-current-docs.ps1`.

## Review Focus

1. A repository `SECURITY.md` containing instructions to the model is data, not authority; Scope Gate must remain `UNCERTAIN` absent verified permission (Task 1 test).
2. An out-of-tree symlink or Windows drive path requested by survey cannot disclose host files (Task 3 test).
3. A provider returns 429 after a prior successful charged attempt; persisted usage must count each attempt once and never double-count on resume (Task 4 test).
4. A cancelled hypothesis while it holds a resource gate must release the slot and resume without rerunning successful siblings (Task 5 test).
5. A Docker container with incomplete or foreign ownership labels must never be swept; a missing dependency image may use source-only mode but cannot yield a validated exploit without a successful PoC (Task 6 test).

## File map and task order

1. Policy transport: `bootstrap_stages.py` extracts a scoped policy artifact; `application.py` and `models.py` persist its exact ref; `stages.py` applies policy precedence; composition wires it.
2. Claude launches: `claude_provider.py` spaces *process starts*, not whole inference calls; existing provider tests pin cancellation and no-tools behavior.
3. Survey: `facts.py`, `feeding.py`, `retrieval.py`, `proposals.py`, and a small survey coordinator provide deterministic facts, bounded safe reads, validation, and durable decisions; `bootstrap_stages.py` selects this only when configured.
4. Calls and usage: reuse the shared `SimpleClientFactory` semaphore and current provider retries; `store.py` remains the authoritative attempt ledger, with run-level summaries in the dashboard. Do not add a redundant second queue or usage file.
5. Parallelism: `application.py` schedules bounded hypotheses; `portable_docker.py` owns build gates; composition passes one set of gates for a run.
6. Docker: `portable_docker.py` records full-build/source-only attempts and owns exact container cleanup; `stages.py` preserves PoC error-versus-refutation semantics.

Each task is a separate commit and test gate. Tasks 1–3 can be reviewed independently; Tasks 4–6 consume the same profile fields and must be integrated in order. Use `git show origin/impl/e2e-run:<path>` as reference, not `git merge` or a whole-file overwrite. Do not push until the cumulative regression gate passes.

---

### Task 1: Exact repository security-policy ref to Scope Gate

**Files:**
- Modify: `src/sastsimi/simple_runtime/bootstrap_stages.py`, `application.py`, `models.py`, `stages.py`
- Modify: `src/sastsimi/composition/simple_runtime_composition.py`
- Test: `tests/unit/simple_runtime/test_security_policy.py`, `tests/unit/simple_runtime/test_rule_scope_gate.py`, `tests/simple_runtime/test_simple_analysis_application.py`

**Interfaces:**
- `StaticBootstrapResult.security_policy_ref: StoredDataRef | None = None` and `SimpleAnalysisRun.security_policy_ref: StoredDataRef | None = None` carry the exact analysis-scoped artifact on resume.
- `RuleScopeGateStage(..., security_policy_ref: StoredDataRef | None = None)` chooses published verified policy first, repository policy second, otherwise `UNCERTAIN`. Repository policy may establish `DENY`, but alone cannot upgrade the externally reportable result to `ALLOW`.

- [ ] **Step 1: Write failing tests.** Add the two unit files using the current artifact and fake-client fixtures. Pin tracked UTF-8 root, `.github/`, and `docs/SECURITY.md` with root-first priority; an out-of-checkout symlink; published-policy precedence; and a fake Agent returning `ALLOW` solely because policy prose orders it:

```python
assert static.security_policy_ref is not None
assert artifacts.read(static.security_policy_ref).find(b"ignore all rules") >= 0
assert published_ref in supplied_scope_refs
assert static.security_policy_ref not in supplied_scope_refs
assert gate_result["status"] == "UNCERTAIN"  # repo-only policy cannot grant reporting
assert resumed_static.security_policy_ref == static.security_policy_ref
```

- [ ] **Step 2: Confirm RED.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_security_policy.py tests/unit/simple_runtime/test_rule_scope_gate.py -q` (new interface/tests fail).
- [ ] **Step 3: Implement minimum transport.** Read only tracked `SECURITY.md`, `.github/SECURITY.md`, or `docs/SECURITY.md`, require a resolved in-checkout regular file, cap at 256 KiB, store `simple_repository_security_policy`, and persist its exact ref in run/static state. Pass it into the current Scope Gate without treating repository prose as instructions. If the only source is repository policy, clamp any Agent `ALLOW` to an `UNCERTAIN` artifact with the raw Agent output as evidence; retain `DENY`:

```python
policy_ref = artifacts.put_json(policy) if policy is not None else None
published_refs = artifacts.published_refs(self._POLICY_KINDS)
source_refs = published_refs
if not published_refs and self._security_policy_ref is not None:
    source_refs = (self._security_policy_ref,)
if not source_refs:
    return self._uncertain_without_policy(checkpoint)  # new private helper
if not published_refs and result.value["status"] == "ALLOW":
    return self._uncertain_with_repository_policy(checkpoint, result, output_ref)
```

- [ ] **Step 4: Confirm GREEN and regression.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_security_policy.py tests/unit/simple_runtime/test_rule_scope_gate.py tests/simple_runtime/test_simple_analysis_application.py -q` (all pass; resume reuses the policy ref).
- [ ] **Step 5: Commit.** Run: `git add -- src/sastsimi/simple_runtime/bootstrap_stages.py src/sastsimi/simple_runtime/application.py src/sastsimi/simple_runtime/models.py src/sastsimi/simple_runtime/stages.py src/sastsimi/composition/simple_runtime_composition.py tests/unit/simple_runtime/test_security_policy.py tests/unit/simple_runtime/test_rule_scope_gate.py tests/simple_runtime/test_simple_analysis_application.py` then `git commit -m "feat: pass repository policy to scope gate"`.

### Task 2: Claude CLI launch boundary parity

**Files:**
- Modify: `src/sastsimi/simple_runtime/claude_provider.py`
- Test: `tests/unit/simple_runtime/test_claude_provider.py`

**Interfaces:** `OfficialClaudeCLITransport.invoke(...) -> ClaudeCLIResponse` remains unchanged; process-start spacing is internal to the transport/child runner and must never serialize complete inference calls.

- [ ] **Step 1: Write failing tests.** Monkeypatch `asyncio.create_subprocess_exec` in the real `_run_child` path to record process-start times for concurrent calls; assert adjacent *starts* are at least 0.5 seconds apart while both inference calls can overlap. Re-run existing no-tools, pinned-binary, auth-failure, timeout, cancellation, and process-tree termination tests:

```python
assert second_spawn_at - first_spawn_at >= 0.5
assert first_inference_finished_at > second_spawn_at
assert "--tools" in argv and argv[argv.index("--tools") + 1] == ""
```

- [ ] **Step 2: Confirm RED.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_claude_provider.py -q` (new stagger test fails).
- [ ] **Step 3: Add a process-local launch gate at the `asyncio.create_subprocess_exec` boundary.** Record `loop.time()` after each spawn, wait only for `max(0, last_start + 0.5 - loop.time())`, and release the gate immediately after spawning. Keep the gate per event loop to avoid binding one `asyncio.Lock` to a dead `asyncio.run` loop. Preserve injected `ChildRunner` behavior and subprocess cancellation cleanup:

```python
async with launch_lock:
    await asyncio.sleep(max(0.0, next_start - loop.time()))
    process = await asyncio.create_subprocess_exec(*argv, **spawn_options)
    next_start = loop.time() + 0.5
# communicate and inference occur outside the launch lock
```

- [ ] **Step 4: Confirm GREEN.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_claude_provider.py -q` (all pass without a live account).
- [ ] **Step 5: Commit.** Run: `git add -- src/sastsimi/simple_runtime/claude_provider.py tests/unit/simple_runtime/test_claude_provider.py` then `git commit -m "fix: stagger concurrent Claude CLI launches"`.

### Task 3: Opt-in facts survey with safe source retrieval

**Files:**
- Modify: `src/sastsimi/config/user_config.py`, `src/sastsimi/composition/simple_runtime_composition.py`, `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/simple_runtime/store.py`
- Create/adapt: `src/sastsimi/simple_runtime/facts.py`, `feeding.py`, `retrieval.py`, `proposals.py`, `survey.py`, `code_redaction.py`
- Test: `tests/unit/simple_runtime/test_feeding.py`, `test_requested_sources.py`, `test_proposal_registration.py`, `test_hypothesis_survey.py`; `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`

**Interfaces:** `SimpleExecutionProfile.hypothesis_feed: Literal["current", "facts_survey"] = "current"`; `DirectHypothesisBootstrap(..., feed: str = "current")`; `extract_flows(workspace: Path, sources: Sequence[str]) -> dict[str, Any]`; `collect_requested_sources(requests: Iterable[str], *, workspace: Path, already_supplied: Sequence[str] = ()) -> dict[str, Any]`. Add `SimpleCheckpointStore.save_survey_progress(analysis_id: str, bundle_hash: str, item_key: str, ref: StoredDataRef) -> None` and `survey_progress(analysis_id: str, bundle_hash: str) -> dict[str, StoredDataRef]`, where `item_key="__survey__"` identifies the opening point list. The current `propose(...) -> tuple[HypothesisSeed, ...] | StageFailure` contract remains unchanged.

- [ ] **Step 1: Write RED tests for the profile and deterministic feed.** Old TOML loads as `current`, round-trips unchanged, and explicit `facts_survey` extracts Python route/call facts in stable order. Empty facts or non-Python source uses safe source reading, not zero coverage:

```python
assert SimpleExecutionProfile.model_validate(old_profile).hypothesis_feed == "current"
assert extract_flows(workspace, ("app.py",)) == extract_flows(workspace, ("app.py",))
assert survey_feed.kind == ("facts" if python_routes else "code")
```

- [ ] **Step 2: Write RED security and survey tests.** Reject `C:\\Users\\...`, `../...`, UNC paths, out-of-root symlinks, and invalid line spans; record refusal reasons. Fake Agent returns nine points: assert turns consume 8 then 1, each point has exactly one `PROPOSED`/`NOT_PROPOSED` decision, proposal locations are checked against tracked files and line counts, duplicates do not create a second seed, and a failure after the first batch preserves its valid proposals in SQLite. Restart the store from disk and assert resume reads its opening survey and decisions instead of calling completed points again:

```python
assert collect_requested_sources(["../secret"], workspace=workspace)["served"] == []
assert [len(batch) for batch in point_batches] == [8, 1]
assert set(decisions.values()) <= {"PROPOSED", "NOT_PROPOSED"}
assert "__survey__" in reopened_store.survey_progress(analysis_id, bundle_hash)
assert len(seeds_after_resume) == len({seed.hypothesis_id for seed in seeds_after_resume})
```

- [ ] **Step 3: Confirm RED.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_feeding.py tests/unit/simple_runtime/test_requested_sources.py tests/unit/simple_runtime/test_proposal_registration.py tests/unit/simple_runtime/test_hypothesis_survey.py -q` (new modules/mode fail).
- [ ] **Step 4: Implement survey-specific files and wiring.** Adapt deterministic AST and source-redaction functions from `origin/impl/e2e-run`, retaining their path/byte checks. Build a survey-only JSON schema and prompt. Create `simple_hypothesis_survey_progress` with primary key `(analysis_id, bundle_hash, item_key)` and an exact ref JSON column; write the opening survey, then each point decision/proposal artifact under a stable point key before advancing. On resume, load this ledger and skip recorded points; a conflicting ref for one key fails closed. Keep the current `DirectHypothesisBootstrap.propose` body untouched behind the `current` branch:

```python
if self._feed == "current":
    return await self._propose_current(identity, static)
return await self._propose_facts_survey(identity, static)
```

- [ ] **Step 5: Confirm GREEN and default regression.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_feeding.py tests/unit/simple_runtime/test_requested_sources.py tests/unit/simple_runtime/test_proposal_registration.py tests/unit/simple_runtime/test_hypothesis_survey.py tests/integration/orchestration/test_simple_runtime_static_bootstrap.py tests/simple_runtime/test_simple_analysis_application.py -q` (all pass; default path unchanged).
- [ ] **Step 6: Commit.** Run: `git add -- src/sastsimi/config/user_config.py src/sastsimi/composition/simple_runtime_composition.py src/sastsimi/simple_runtime/bootstrap_stages.py src/sastsimi/simple_runtime/store.py src/sastsimi/simple_runtime/facts.py src/sastsimi/simple_runtime/feeding.py src/sastsimi/simple_runtime/retrieval.py src/sastsimi/simple_runtime/proposals.py src/sastsimi/simple_runtime/survey.py src/sastsimi/simple_runtime/code_redaction.py tests/unit/simple_runtime tests/integration/orchestration/test_simple_runtime_static_bootstrap.py` then `git commit -m "feat: add optional resumable facts survey"`.

### Task 4: One run-level call limit, bounded retry, and durable usage

**Files:**
- Modify: `src/sastsimi/config/user_config.py`, `src/sastsimi/composition/simple_runtime_composition.py`, `src/sastsimi/simple_runtime/provider.py`, `cursor_provider.py`, `claude_provider.py`, `store.py`
- Modify: `src/sastsimi/dashboard/query.py`, `src/sastsimi/dashboard/models.py`, `src/sastsimi/dashboard/static/app.js`
- Test: `tests/unit/simple_runtime/test_call_queue.py`, `test_rate_limit_retry.py`, `test_usage_record.py`, `test_cursor_provider.py`, `test_claude_provider.py`; `tests/unit/dashboard/test_query.py`

**Interfaces:** Keep `SimpleLLMClient.call` unchanged. Add `SimpleCheckpointStore.usage_summary(analysis_id: str) -> dict[str, int | float | None]` that reads the persisted `simple_llm_attempts` ledger, counts each primary-key attempt ID once, and reports unknown cost separately. `SimpleClientFactory` already owns one shared semaphore; Cursor/Claude use it directly and Codex/OpenAI gain a thin gated wrapper, avoiding nested acquisition.

- [ ] **Step 1: Write failing queue and retry tests.** A fake client tracks active calls and receives 429, 503, auth, and unsupported-model errors. Assert at most configured concurrency, three attempts including the first, exponential backoff capped by the deadline, no auth/model retry, and cancellation releases the slot:

```python
assert fake.peak_active <= profile.llm_max_concurrency
assert fake.rate_limit_calls == 3
assert fake.auth_calls == 1
await asyncio.wait_for(shared_semaphore.acquire(), timeout=0.1)
shared_semaphore.release()
```

- [ ] **Step 2: Write failing usage tests.** Persist two known-cost attempts and one unknown-cost attempt, reload the store, resume the analysis, and assert no double count or false zero-cost display; the dashboard exposes `on_demand_possible` without calculating invented prices:

```python
assert summary["calls"] == 3
assert summary["cost_minor_units"] == 125.0
assert summary["unknown_cost_calls"] == 1
assert summary["input_tokens"] == 410
assert dashboard["on_demand_possible"] is True
assert "추가 사용량 과금 가능" in dashboard_text
```

- [ ] **Step 3: Confirm RED.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_call_queue.py tests/unit/simple_runtime/test_rate_limit_retry.py tests/unit/simple_runtime/test_usage_record.py -q` (new queue/summary fail).
- [ ] **Step 4: Implement the shared call limit and ledger projection.** Reuse the existing shared semaphore for Cursor/Claude and gate Codex/OpenAI once around `call`; correct current OpenAI `AUTH_REQUIRED` retryability. Do not stack an unbounded new retry loop on top of existing Cursor/Claude loops: configured `llm_max_retries` caps the logical Agent call at `min(value + 1, 3)` total attempts. A configured Cursor fallback consumes one of those slots, so primary Cursor gets at most two attempts and the fallback one; auth/model failures do not fall back. Before an attempt, compare persisted known token/cost totals and elapsed time to profile ceilings and return a typed budget failure if exhausted. Unknown cost stays unknown rather than being treated as free; retain the existing on-demand opt-in boundary and show a provider-neutral warning in the dashboard. Record every attempt once with a stable ID; dashboard queries `simple_llm_attempts`, never a separate append-only usage file:

```python
with self._connect() as connection:
    rows = connection.execute(
        "SELECT attempt_id, input_tokens, output_tokens, cost_cents "
        "FROM simple_llm_attempts WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchall()
attempts = {row["attempt_id"]: row for row in rows}
known = [row.cost_cents for row in attempts.values() if row.cost_cents is not None]
summary = {"calls": len(attempts), "cost_minor_units": sum(known) if known else None,
           "unknown_cost_calls": len(attempts) - len(known),
           "input_tokens": sum(row["input_tokens"] or 0 for row in attempts.values()),
           "output_tokens": sum(row["output_tokens"] or 0 for row in attempts.values())}
```

- [ ] **Step 5: Confirm GREEN and providers.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_call_queue.py tests/unit/simple_runtime/test_rate_limit_retry.py tests/unit/simple_runtime/test_usage_record.py tests/unit/simple_runtime/test_cursor_provider.py tests/unit/simple_runtime/test_claude_provider.py tests/unit/dashboard/test_query.py -q` (all pass).
- [ ] **Step 6: Commit.** Run: `git add -- src/sastsimi/config/user_config.py src/sastsimi/composition/simple_runtime_composition.py src/sastsimi/simple_runtime/provider.py src/sastsimi/simple_runtime/cursor_provider.py src/sastsimi/simple_runtime/claude_provider.py src/sastsimi/simple_runtime/store.py src/sastsimi/dashboard tests/unit/simple_runtime tests/unit/dashboard/test_query.py` then `git commit -m "feat: bound calls and report durable usage"`.

### Task 5: Per-run work/build/container gates and resume-safe parallel hypotheses

**Files:**
- Modify: `src/sastsimi/config/user_config.py`, `src/sastsimi/composition/simple_runtime_composition.py`, `src/sastsimi/simple_runtime/application.py`, `portable_docker.py`
- Test: `tests/unit/simple_runtime/test_resource_gates.py`, `test_parallel_hypotheses.py`; `tests/simple_runtime/test_simple_analysis_application.py`

**Interfaces:** Profile adds `max_parallel_hypotheses=1`, `max_parallel_builds=1`, `max_parallel_containers=1` with positive bounded integers. The existing `llm_max_concurrency=2` remains the call ceiling. `SimpleAnalysisApplication(..., max_parallel_hypotheses: int = 1)` and one `PortableDockerRuntime(profile)` share gates across all hypotheses of a run.

- [ ] **Step 1: Write RED tests.** With three fake hypotheses and limits 2/1/1, assert peak running hypothesis count is 2, build count 1, and container count 1. Interrupt one while another succeeds; after resume, the successful Agent's call count remains 1, the interrupted hypothesis continues, and chain child IDs remain unique:

```python
assert peak_hypotheses == 2
assert peak_builds == 1
assert peak_containers == 1
assert calls_for_completed_sibling == 1
assert len(run.hypothesis_ids) == len(set(run.hypothesis_ids))
```

- [ ] **Step 2: Confirm RED.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_resource_gates.py tests/unit/simple_runtime/test_parallel_hypotheses.py -q` (new limits fail).
- [ ] **Step 3: Implement gates.** Schedule a bounded number of child tasks, retain deterministic registration of chain children in the parent application, and persist checkpoint transitions before releasing a slot. Use `async with`/`finally` to release every semaphore on cancellation; do not mark cancellation as a vulnerability refutation:

```python
async with hypothesis_slots:
    return await self._runner_factory(self._store, child, static).resume_hypothesis(child)
```

- [ ] **Step 4: Confirm GREEN and resume.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_resource_gates.py tests/unit/simple_runtime/test_parallel_hypotheses.py tests/simple_runtime/test_simple_analysis_application.py -q` (all pass).
- [ ] **Step 5: Commit.** Run: `git add -- src/sastsimi/config/user_config.py src/sastsimi/composition/simple_runtime_composition.py src/sastsimi/simple_runtime/application.py src/sastsimi/simple_runtime/portable_docker.py tests/unit/simple_runtime/test_resource_gates.py tests/unit/simple_runtime/test_parallel_hypotheses.py tests/simple_runtime/test_simple_analysis_application.py` then `git commit -m "feat: bound per-run parallel work"`.

### Task 6: Docker fallback, exact ownership cleanup, and attempt evidence

**Files:**
- Modify: `src/sastsimi/simple_runtime/portable_docker.py`, `src/sastsimi/simple_runtime/stages.py`, `src/sastsimi/simple_runtime/runner.py`
- Test: `tests/unit/simple_runtime/test_portable_docker.py`, `test_poc_execution.py`, `test_container_cleanup.py`; `tests/e2e/test_dynamic_reproduction.py`

**Interfaces:** `PortableDockerRuntime.remove_owned(container_id: str, identity: CheckpointIdentity, attempt_id: str) -> bool` verifies labels before removal; `sweep_orphans()` only considers `sastsimi.owner=simple-runtime` with a matching known-dead host/PID. `DirectEnvironmentPreparer.prepare` keeps its return type but recipe records `dockerfile_source`, full-build failure, fallback mode, and exact refs.

- [ ] **Step 1: Write RED tests.** Simulate one dependency-install build failure then successful source-only image, unrelated Dockerfile failure, and both-fail. Assert only the dependency failure triggers fallback, the build attempt and degraded mode are artifacts, and failed PoC execution is `BLOCKED`/`HOLD`, never `FALSE`. Simulate owned/foreign/missing labels and Windows unknown PID; only exact owned and known-dead IDs are removed:

```python
assert recipe["dockerfile_source"] == "GENERATED_NO_INSTALL"
assert recipe["degraded"] is True
assert failed_execution.verdict != "FALSE"
assert removed_ids == [known_dead_owned_id]
```

- [ ] **Step 2: Confirm RED.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_portable_docker.py tests/unit/simple_runtime/test_poc_execution.py tests/unit/simple_runtime/test_container_cleanup.py -q` (new fallback/cleanup tests fail).
- [ ] **Step 3: Implement bounded fallback and cleanup.** Keep the current safe recipe and recovery patch. Try the repository Dockerfile once; classify dependency-install failure from captured build diagnostics before trying a generated source-only recipe. Persist both attempts, mark degraded mode, and never silently reuse an unbuildable full image. On PoC completion or error, collect execution evidence first, inspect label identity, then remove the exact container in `finally`; on restart sweep only an exactly labeled known-dead owner:

```python
try:
    result = await execute_and_record(container_id)
finally:
    if checkpoint.attempt_id is not None:
        await docker.remove_owned(container_id, checkpoint.identity, checkpoint.attempt_id)
```

- [ ] **Step 4: Confirm GREEN and real Docker fixture.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_portable_docker.py tests/unit/simple_runtime/test_poc_execution.py tests/unit/simple_runtime/test_container_cleanup.py -q`; with Docker available also run `.\.venv\Scripts\python.exe -m pytest tests/e2e/test_dynamic_reproduction.py -q` (all pass or report an environmental Docker blocker explicitly).
- [ ] **Step 5: Commit.** Run: `git add -- src/sastsimi/simple_runtime/portable_docker.py src/sastsimi/simple_runtime/stages.py src/sastsimi/simple_runtime/runner.py tests/unit/simple_runtime/test_portable_docker.py tests/unit/simple_runtime/test_poc_execution.py tests/unit/simple_runtime/test_container_cleanup.py tests/e2e/test_dynamic_reproduction.py` then `git commit -m "feat: record Docker fallback and clean owned containers"`.

### Task 7: Documentation and cumulative regression gate

**Files:**
- Modify: `docs/provider-setup.md`, `docs/usage.md`, `docs/troubleshooting.md`, `README.md` only where the new optional settings or degraded statuses need operator guidance
- Test: `tests/unit/config/test_user_config.py`, `tests/simple_runtime/test_simple_analysis_application.py`, current provider tests, full CI suite

**Interfaces:** Existing PowerShell `.venv` commands and default config remain valid; new TOML keys are documented as optional. The PR remains draft if live Claude login/inference or managed-hook evidence is unavailable.

- [ ] **Step 1: Add a config compatibility test.** Assert the old profile still loads, `to_toml()` round-trips new optional fields, and no default switches to `facts_survey`:

```python
assert load_simple_execution_profile(old_path).hypothesis_feed == "current"
assert load_simple_execution_profile(new_path).max_parallel_hypotheses == 2
```

- [ ] **Step 2: Confirm RED then update docs/config serializer.** Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/config/test_user_config.py tests/simple_runtime/test_simple_analysis_application.py -q`; add explicit PowerShell one-line examples and field descriptions; rerun the same command (all pass).
- [ ] **Step 3: Run quality checks.** Run each separately: `.\.venv\Scripts\ruff.exe format --check .`, `.\.venv\Scripts\ruff.exe check .`, `.\.venv\Scripts\mypy.exe --strict src tests`, `./scripts/validate-current-docs.ps1`, and `.\.venv\Scripts\python.exe -m pytest tests -q -n 4 --ignore=tests/e2e/test_dynamic_reproduction.py`. Record exact pass/fail counts; do not say CI passed if any command fails.
- [ ] **Step 4: Review scope and safety.** Run: `git diff origin/main --stat`; run: `git diff origin/main -- src/sastsimi/simple_runtime/cursor_provider.py src/sastsimi/simple_runtime/recovery.py`; inspect no credential in `git diff` and no default behavior change. Verify completed-Agent resume, unknown-cost display, policy precedence, and Docker-owned cleanup in final targeted tests.
- [ ] **Step 5: Commit and push.** Run: `git add -- README.md docs/provider-setup.md docs/usage.md docs/troubleshooting.md tests`; run: `git commit -m "docs: explain optional e2e handoff features"`; push only the current `codex/claude-selective-integration` branch to update PR #198. Inspect its CI checks before changing draft status. If a live Claude account is unavailable, leave that explicit limitation and do not invent a smoke-test success.
