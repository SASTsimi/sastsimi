from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import pytest

from sastsimi.composition.simple_runtime_composition import SimpleClientFactory
from sastsimi.config.user_config import SimpleExecutionProfile
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.base import CodexProcessRequest, CodexProcessResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attempt_owner import AttemptOwner, PromptByteCounts
from sastsimi.simple_runtime.call_queue import RunLimitedClient, RunUsageBudget
from sastsimi.simple_runtime.cursor_provider import CursorProvider
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import (
    SimpleCodexClient,
    SimpleLLMCallResult,
    SimpleLLMClient,
    SimpleOpenAIClient,
)
from sastsimi.simple_runtime.run_lease import analysis_run_lease
from sastsimi.simple_runtime.store import SimpleCheckpointStore


class _Client:
    def __init__(self, outcomes: list[SimpleLLMCallResult | StageFailure]) -> None:
        self.outcomes = outcomes
        self.calls = 0
        self.active = 0
        self.peak = 0

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
        owner: AttemptOwner | None = None,
        prompt_bytes: PromptByteCounts | None = None,
        invocation_id: str | None = None,
    ) -> SimpleLLMCallResult | StageFailure:
        del prompt, output_schema, timeout_ms, agent_name, owner, prompt_bytes
        del invocation_id
        self.calls += 1
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(0.02)
            return self.outcomes.pop(0)
        finally:
            self.active -= 1


class _CodexRunner:
    def __init__(self, outcomes: list[CodexProcessResult]) -> None:
        self.outcomes = outcomes
        self.calls = 0
        self.requests: list[CodexProcessRequest] = []

    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
        self.calls += 1
        self.requests.append(request)
        return self.outcomes.pop(0)


def _success() -> SimpleLLMCallResult:
    return SimpleLLMCallResult(
        value={"ok": True},
        prompt_digest="a" * 64,
        output_digest="b" * 64,
        input_tokens=5,
        output_tokens=2,
    )


@pytest.mark.asyncio
async def test_owned_retry_rows_link_logical_attempts(tmp_path: Path) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    inner = _Client(
        [
            StageFailure(
                code="RATE_LIMITED",
                retryable=True,
                safe_message="try again",
            ),
            _success(),
        ]
    )
    client = _wrapper(
        tmp_path,
        inner,
        asyncio.Semaphore(1),
        max_retries=1,
        max_tokens="unlimited",
        sleep=no_sleep,
    )
    owner = AttemptOwner(
        analysis_id="analysis-queue",
        stage="DISCOVERY",
        candidate_ids=("C-1", "C-2"),
        batch_id="batch-1",
        file_path="app/main.py",
    )
    result = await client.call(
        prompt=b"prompt",
        output_schema={"type": "object"},
        timeout_ms=10_000,
        agent_name="discovery",
        owner=owner,
        prompt_bytes=PromptByteCounts(fixed_prompt_bytes=6),
    )
    assert isinstance(result, SimpleLLMCallResult)
    with sqlite3.connect(client._store.database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT a.attempt_id, a.status, m.stage, m.candidate_ids_json, "
            "m.batch_id, m.file_path, m.retry_of, m.fixed_prompt_bytes "
            "FROM simple_llm_attempts AS a JOIN simple_llm_attempt_metadata AS m "
            "ON m.attempt_id = a.attempt_id ORDER BY a.attempt_number"
        ).fetchall()
    assert len(rows) == 2
    assert rows[0]["status"] == "RATE_LIMITED"
    assert rows[1]["status"] == "SUCCEEDED"
    assert rows[0]["stage"] == rows[1]["stage"] == "DISCOVERY"
    assert rows[0]["candidate_ids_json"] == '["C-1","C-2"]'
    assert rows[1]["retry_of"] == rows[0]["attempt_id"]
    assert rows[1]["batch_id"] == "batch-1"
    assert rows[1]["file_path"] == "app/main.py"
    assert rows[1]["fixed_prompt_bytes"] == 6


def _wrapper(
    tmp_path: Path,
    inner: SimpleLLMClient,
    semaphore: asyncio.Semaphore,
    *,
    max_retries: int = 2,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    max_tokens: int | Literal["unlimited"] = 1000,
    max_cost_minor_units: int = 1000,
) -> RunLimitedClient:
    identity = CheckpointIdentity(
        analysis_id="analysis-queue",
        workspace_id="workspace-queue",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    return RunLimitedClient(
        inner=inner,
        semaphore=semaphore,
        artifacts=artifacts,
        store=SimpleCheckpointStore(artifacts.paths.database),
        model="test-model",
        max_retries=max_retries,
        max_tokens=max_tokens,
        max_cost_minor_units=max_cost_minor_units,
        max_elapsed_seconds=3600,
        sleep=sleep,
    )


def _codex_client(
    tmp_path: Path, runner: _CodexRunner, *, max_retries: int = 0
) -> tuple[RunLimitedClient, SimpleCheckpointStore]:
    identity = CheckpointIdentity(
        analysis_id="analysis-queue",
        workspace_id="workspace-queue",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    inner = SimpleCodexClient(
        runner=runner,
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="test-model",
        artifacts=artifacts,
    )
    client = _wrapper(
        tmp_path,
        inner,
        asyncio.Semaphore(1),
        max_retries=max_retries,
        max_tokens="unlimited",
    )
    return client, SimpleCheckpointStore(artifacts.paths.database)


def _cleanup_confirmation(
    artifacts: SimpleArtifactRepository,
    checkpoint: StageCheckpoint,
    *,
    call_id: str | None = None,
) -> StoredDataRef:
    return artifacts.put_json(
        {
            "kind": "simple_codex_cleanup_confirmation",
            "analysis_id": checkpoint.identity.analysis_id,
            "stage": checkpoint.stage.value,
            "attempt_id": checkpoint.attempt_id,
            "checkpoint_sha256": hashlib.sha256(
                canonical_bytes(checkpoint)
            ).hexdigest(),
            "process_tree_stopped": True,
            "verification_method": "windows_process_inventory",
            "former_parent_pid": 12345,
            "observed_matching_process_count": 0,
            "observed_at": (checkpoint.updated_at + timedelta(seconds=1)).isoformat(),
            **({"call_id": call_id} if call_id is not None else {}),
        }
    )


def test_codex_cleanup_confirmation_rejects_active_analysis_lease(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-active-call",
        workspace_id="workspace-active-call",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            candidate_pipeline_version=1,
        )
    )
    checkpoint = store.mark_running(
        identity, SimpleStage.HYPOTHESIS_DONE, (), attempt_id="active-attempt"
    )
    call_id = "call-active"
    assert store.begin_codex_call(call_id, identity.analysis_id)
    confirmation = _cleanup_confirmation(artifacts, checkpoint, call_id=call_id)

    with analysis_run_lease(tmp_path, identity.analysis_id):
        with pytest.raises(ValueError, match="CODEX_CLEANUP_CONFIRMATION_ACTIVE_RUN"):
            store.confirm_codex_cleanup(checkpoint, confirmation, artifacts)
        assert store.unresolved_codex_call(identity.analysis_id) == call_id

    store.confirm_codex_cleanup(checkpoint, confirmation, artifacts)
    assert store.unresolved_codex_call(identity.analysis_id) is None


def test_v2_cleanup_confirmation_requires_captured_child_identity(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-exact-child",
        workspace_id="workspace-exact-child",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            candidate_pipeline_version=2,
        )
    )
    checkpoint = store.mark_running(
        identity, SimpleStage.HYPOTHESIS_DONE, (), attempt_id="exact-attempt"
    )
    call_id = "exact-call"
    assert store.begin_codex_call(call_id, identity.analysis_id)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "DELETE FROM simple_analysis_runs WHERE analysis_id = ?",
            (identity.analysis_id,),
        )
    store.begin_codex_child_spawn(
        call_id=call_id, analysis_id=identity.analysis_id, phase="EXEC"
    )
    arbitrary = _cleanup_confirmation(artifacts, checkpoint, call_id=call_id)
    with pytest.raises(ValueError, match="CODEX_CLEANUP_CONFIRMATION_INVALID"):
        store.confirm_codex_cleanup(checkpoint, arbitrary, artifacts)
    store.record_codex_child_spawn(
        call_id=call_id,
        analysis_id=identity.analysis_id,
        phase="EXEC",
        pid=4242,
        start_identity="started-4242",
    )
    store.begin_codex_child_spawn(
        call_id=call_id, analysis_id=identity.analysis_id, phase="LOGIN"
    )
    store.record_codex_child_spawn(
        call_id=call_id,
        analysis_id=identity.analysis_id,
        phase="LOGIN",
        pid=4141,
        start_identity="started-4141",
    )
    with pytest.raises(ValueError, match="CODEX_CLEANUP_CONFIRMATION_INVALID"):
        store.confirm_codex_cleanup(checkpoint, arbitrary, artifacts)
    assert store.unresolved_codex_call(identity.analysis_id) == call_id
    exact_marker = artifacts.put_json(
        json.loads(artifacts.read(arbitrary))
        | {
            "former_parent_pid": 4242,
            "observed_children": [
                {
                    "phase": "EXEC",
                    "pid": 4242,
                    "start_identity": "started-4242",
                },
                {
                    "phase": "LOGIN",
                    "pid": 4141,
                    "start_identity": "started-4141",
                },
            ],
        }
    )
    wrong_identity = artifacts.put_json(
        json.loads(artifacts.read(exact_marker))
        | {
            "observed_children": [
                {
                    "phase": "EXEC",
                    "pid": 4242,
                    "start_identity": "another-process",
                },
                {
                    "phase": "LOGIN",
                    "pid": 4141,
                    "start_identity": "started-4141",
                },
            ]
        }
    )
    with pytest.raises(ValueError, match="CODEX_CLEANUP_CONFIRMATION_INVALID"):
        store.confirm_codex_cleanup(checkpoint, wrong_identity, artifacts)
    store.confirm_codex_cleanup(checkpoint, exact_marker, artifacts)
    assert store.unresolved_codex_call(identity.analysis_id) is None


@pytest.mark.asyncio
async def test_codex_timeout_keeps_exact_child_owned(
    tmp_path: Path,
) -> None:
    runner = _CodexRunner(
        [
            CodexProcessResult("FAILED", None, None, cleanup_unconfirmed=True),
            CodexProcessResult("SUCCEEDED", b'{"ok":true}', None, 5, 2),
        ]
    )
    client, store = _codex_client(tmp_path, runner)

    first = await client.call(prompt=b"safe", output_schema={}, timeout_ms=5000)
    reopened = SimpleCheckpointStore(store.database_path)
    call_id = reopened.unresolved_codex_call("analysis-queue")
    second = await client.call(prompt=b"safe", output_schema={}, timeout_ms=5000)

    assert isinstance(first, StageFailure)
    assert first.code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert isinstance(call_id, str) and call_id
    assert isinstance(second, StageFailure)
    assert second.code == "CODEX_CALL_IN_FLIGHT_UNRESOLVED"
    assert not second.retryable
    assert runner.calls == 1
    assert runner.requests[0].invocation_id == call_id
    assert store.usage_summary("analysis-queue")["calls"] == 1
    with sqlite3.connect(store.database_path) as connection:
        attempt = connection.execute(
            "SELECT attempt_id, input_tokens FROM simple_llm_attempts "
            "WHERE analysis_id = ?",
            ("analysis-queue",),
        ).fetchone()
    assert attempt == (call_id, None)


@pytest.mark.asyncio
async def test_codex_confirmed_timeout_retries_with_new_owned_call(
    tmp_path: Path,
) -> None:
    runner = _CodexRunner(
        [
            CodexProcessResult("TIMED_OUT", None, None),
            CodexProcessResult("SUCCEEDED", b'{"ok":true}', None, 5, 2),
        ]
    )
    client, store = _codex_client(tmp_path, runner, max_retries=1)
    result = await client.call(prompt=b"safe", output_schema={}, timeout_ms=5000)
    assert isinstance(result, SimpleLLMCallResult)
    assert runner.calls == 2
    with sqlite3.connect(store.database_path) as connection:
        rows = connection.execute(
            "SELECT c.call_id, c.status, a.input_tokens, m.retry_of "
            "FROM simple_codex_calls AS c "
            "JOIN simple_llm_attempts AS a ON a.attempt_id = c.call_id "
            "LEFT JOIN simple_llm_attempt_metadata AS m "
            "ON m.attempt_id = c.call_id ORDER BY c.started_at"
        ).fetchall()
    assert len(rows) == 2
    assert [row[1] for row in rows] == ["SAFE", "SAFE"]
    assert rows[0][2] is None
    assert rows[1][2] == 5
    assert rows[1][3] == rows[0][0]
    assert [request.invocation_id for request in runner.requests] == [
        row[0] for row in rows
    ]


@pytest.mark.asyncio
async def test_codex_ledger_failure_leaves_durable_unresolved_call(
    tmp_path: Path,
) -> None:
    runner = _CodexRunner(
        [
            CodexProcessResult("SUCCEEDED", b'{"ok":true}', None, 5, 2),
            CodexProcessResult("SUCCEEDED", b'{"ok":true}', None, 5, 2),
        ]
    )
    client, store = _codex_client(tmp_path, runner)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_llm_attempt BEFORE INSERT ON simple_llm_attempts "
            "BEGIN SELECT RAISE(FAIL, 'ledger unavailable'); END"
        )

    with pytest.raises(sqlite3.IntegrityError, match="ledger unavailable"):
        await client.call(prompt=b"safe", output_schema={}, timeout_ms=5000)
    blocked = await client.call(prompt=b"safe", output_schema={}, timeout_ms=5000)

    assert isinstance(blocked, StageFailure)
    assert blocked.code == "CODEX_CALL_IN_FLIGHT_UNRESOLVED"
    assert runner.calls == 1
    assert SimpleCheckpointStore(store.database_path).unresolved_codex_call(
        "analysis-queue"
    )
    unresolved_usage = store.usage_summary("analysis-queue")
    assert unresolved_usage["calls"] == 1
    assert unresolved_usage["unknown_token_calls"] == 1
    assert unresolved_usage["unknown_cost_calls"] == 1
    assert unresolved_usage["unrecorded_in_flight_codex_calls"] == 1

    identity = CheckpointIdentity(
        analysis_id="analysis-queue",
        workspace_id="workspace-queue",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            candidate_pipeline_version=1,
        )
    )
    checkpoint = store.mark_running(
        identity, SimpleStage.HYPOTHESIS_DONE, (), attempt_id="stage-attempt"
    )
    call_id = store.unresolved_codex_call(identity.analysis_id)
    assert call_id is not None
    confirmation = _cleanup_confirmation(artifacts, checkpoint, call_id=call_id)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DROP TRIGGER reject_llm_attempt")

    store.confirm_codex_cleanup(checkpoint, confirmation, artifacts)

    with sqlite3.connect(store.database_path) as connection:
        reconciled = connection.execute(
            "SELECT status, input_tokens, output_tokens, cost_cents, "
            "artifact_ref_json FROM simple_llm_attempts WHERE attempt_id = ?",
            (call_id,),
        ).fetchone()
    assert reconciled == (
        "CODEX_USAGE_UNAVAILABLE",
        None,
        None,
        None,
        confirmation.model_dump_json(),
    )
    summary = store.usage_summary(identity.analysis_id)
    assert summary["calls"] == 1
    assert summary["unknown_token_calls"] == 1
    assert summary["unknown_cost_calls"] == 1
    assert store.has_codex_cleanup_confirmation(checkpoint, artifacts)
    finite = RunUsageBudget(
        store=store,
        analysis_id=identity.analysis_id,
        max_tokens=100,
        max_cost_minor_units=100,
        max_elapsed_seconds="unlimited",
    )
    assert (failure := finite.check()) is not None
    assert failure.code == "LLM_TOKEN_USAGE_UNAVAILABLE"
    unlimited = RunUsageBudget(
        store=store,
        analysis_id=identity.analysis_id,
        max_tokens="unlimited",
        max_cost_minor_units=100,
        max_elapsed_seconds="unlimited",
    )
    assert unlimited.check() is None


@pytest.mark.parametrize(
    ("stage", "status"),
    [
        (SimpleStage.PRO_CON_DONE, StageStatus.BLOCKED),
        (SimpleStage.POC_CANDIDATE_DONE, StageStatus.BLOCKED),
        (SimpleStage.REPORT_DONE, StageStatus.FAILED),
    ],
)
def test_legacy_child_cleanup_confirmation_accepts_exact_persisted_checkpoint(
    tmp_path: Path, stage: SimpleStage, status: StageStatus
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-legacy-child",
        workspace_id="workspace-legacy-child",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            candidate_pipeline_version=1,
        )
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=stage,
        status=status,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="legacy-child-attempt",
        attempt_number=1,
        error_code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
        retryable=False,
        updated_at=datetime.now(UTC) - timedelta(seconds=2),
    )
    store.save_checkpoint(checkpoint)
    confirmation = _cleanup_confirmation(artifacts, checkpoint)

    reopened = SimpleCheckpointStore(store.database_path)
    reopened.confirm_codex_cleanup(checkpoint, confirmation, artifacts)
    reopened.confirm_codex_cleanup(checkpoint, confirmation, artifacts)

    assert reopened.has_codex_cleanup_confirmation(checkpoint, artifacts)
    assert (
        len(reopened.stage_activity(identity, stage, checkpoint.attempt_id or "")) == 1
    )
    summary = reopened.usage_summary(identity.analysis_id)
    assert summary["calls"] == 1
    assert summary["unlinked_codex_usage_calls"] == 1
    assert summary["unknown_token_calls"] == 1
    assert summary["unknown_cost_calls"] == 1
    finite = RunUsageBudget(
        store=reopened,
        analysis_id=identity.analysis_id,
        max_tokens=100,
        max_cost_minor_units=100,
        max_elapsed_seconds="unlimited",
    )
    assert (failure := finite.check()) is not None
    assert failure.code == "LLM_TOKEN_USAGE_UNAVAILABLE"
    unlimited = RunUsageBudget(
        store=reopened,
        analysis_id=identity.analysis_id,
        max_tokens="unlimited",
        max_cost_minor_units=100,
        max_elapsed_seconds="unlimited",
    )
    assert unlimited.check() is None


def test_confirmed_codex_call_covers_only_its_recorded_interval(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-queue",
        workspace_id="workspace-queue",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    audit = artifacts.put_json({"kind": "simple_codex_cleanup_confirmation"})
    started = datetime.now(UTC) - timedelta(seconds=10)
    resolved = started + timedelta(seconds=5)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO simple_codex_calls "
            "(call_id, analysis_id, status, started_at, resolved_at, "
            "confirmation_ref_json) VALUES (?, ?, 'CONFIRMED', ?, ?, ?)",
            (
                "confirmed-call",
                identity.analysis_id,
                started.isoformat(),
                resolved.isoformat(),
                audit.model_dump_json(),
            ),
        )

    reopened = SimpleCheckpointStore(store.database_path)
    assert reopened.confirmed_codex_call_covering(identity.analysis_id, started)
    assert reopened.confirmed_codex_call_covering(
        identity.analysis_id, started + timedelta(seconds=3)
    )
    assert reopened.confirmed_codex_call_covering(identity.analysis_id, resolved)
    assert not reopened.confirmed_codex_call_covering(
        identity.analysis_id, started - timedelta(microseconds=1)
    )
    assert not reopened.confirmed_codex_call_covering(
        identity.analysis_id, resolved + timedelta(microseconds=1)
    )
    assert not reopened.confirmed_codex_call_covering(
        "another-analysis", started + timedelta(seconds=3)
    )
    store.begin_codex_call("new-unresolved-call", identity.analysis_id)
    assert not reopened.confirmed_codex_call_covering(
        identity.analysis_id, started + timedelta(seconds=3)
    )


@pytest.mark.asyncio
async def test_codex_process_crash_leaves_durable_unresolved_call(
    tmp_path: Path,
) -> None:
    class ProcessCrash(BaseException):
        pass

    class CrashingRunner(_CodexRunner):
        async def execute(self, _request: CodexProcessRequest) -> CodexProcessResult:
            self.calls += 1
            raise ProcessCrash

    runner = CrashingRunner([])
    client, store = _codex_client(tmp_path, runner)

    with pytest.raises(ProcessCrash):
        await client.call(prompt=b"safe", output_schema={}, timeout_ms=5000)

    assert runner.calls == 1
    assert SimpleCheckpointStore(store.database_path).unresolved_codex_call(
        "analysis-queue"
    )
    unresolved_usage = store.usage_summary("analysis-queue")
    assert unresolved_usage["calls"] == 1
    assert unresolved_usage["unknown_token_calls"] == 1
    assert unresolved_usage["unknown_cost_calls"] == 1
    assert unresolved_usage["unrecorded_in_flight_codex_calls"] == 1


@pytest.mark.asyncio
async def test_codex_invalid_output_retries_and_attempts_link_diagnostics(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-queue",
        workspace_id="workspace-queue",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    runner = _CodexRunner(
        [
            CodexProcessResult("SUCCEEDED", b'{"answer":"api_key=secret-one"', None),
            CodexProcessResult("INVALID_OUTPUT", None, None),
            CodexProcessResult("SUCCEEDED", b'{"ok":true}', None, 5, 2),
        ]
    )
    inner = SimpleCodexClient(
        runner=runner,
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="test-model",
        artifacts=artifacts,
    )

    async def no_wait(_delay: float) -> None:
        return None

    client = _wrapper(
        tmp_path,
        inner,
        asyncio.Semaphore(1),
        max_tokens="unlimited",
        sleep=no_wait,
    )
    with caplog.at_level(logging.INFO):
        result = await client.call(
            prompt=b"repo code and api_key=prompt-secret",
            output_schema={},
            timeout_ms=5000,
        )

    assert isinstance(result, SimpleLLMCallResult)
    assert runner.calls == 3
    with sqlite3.connect(artifacts.paths.database) as connection:
        attempts = connection.execute(
            "SELECT status, artifact_ref_json FROM simple_llm_attempts "
            "WHERE analysis_id = ? ORDER BY attempt_number",
            (identity.analysis_id,),
        ).fetchall()
    assert [status for status, _ in attempts] == [
        "INVALID_OUTPUT",
        "INVALID_OUTPUT",
        "SUCCEEDED",
    ]
    for index, (_status, ref_json) in enumerate(attempts[:2]):
        metadata = json.loads(
            artifacts.read(StoredDataRef.model_validate_json(ref_json))
        )
        assert len(metadata["evidence_refs"]) == 2
        diagnostic_ref = StoredDataRef.model_validate(metadata["evidence_refs"][-1])
        diagnostic = json.loads(artifacts.read(diagnostic_ref))
        assert diagnostic["kind"] == "simple_llm_invalid_output"
        assert diagnostic["category"] == (
            "json_malformed" if index == 0 else "process_invalid_output"
        )
    assert "secret-one" not in caplog.text
    assert "prompt-secret" not in caplog.text
    assert "repo code" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("max_retries", [0, 2, 5])
async def test_codex_invalid_output_exhausts_configured_retry_limit(
    tmp_path: Path,
    max_retries: int,
) -> None:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-queue",
            workspace_id="workspace-queue",
            commit_id="a" * 40,
            hypothesis_id=None,
        ),
    )
    runner = _CodexRunner(
        [
            CodexProcessResult("SUCCEEDED", b"{", None)
            for _ in range(min(max_retries, 2) + 1)
        ]
    )
    inner = SimpleCodexClient(
        runner=runner,
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="test-model",
        artifacts=artifacts,
    )

    async def no_wait(_delay: float) -> None:
        return None

    result = await _wrapper(
        tmp_path,
        inner,
        asyncio.Semaphore(1),
        sleep=no_wait,
        max_tokens="unlimited",
        max_retries=max_retries,
    ).call(prompt=b"safe", output_schema={}, timeout_ms=5000)

    assert isinstance(result, StageFailure)
    assert result.code == "INVALID_OUTPUT"
    assert not result.retryable
    assert runner.calls == min(max_retries, 2) + 1


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout_ms,oversleep", [(300, False), (600, True)])
async def test_invalid_output_is_terminal_when_deadline_prevents_retry(
    tmp_path: Path,
    timeout_ms: int,
    oversleep: bool,
) -> None:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-queue",
            workspace_id="workspace-queue",
            commit_id="a" * 40,
            hypothesis_id=None,
        ),
    )
    diagnostic_ref = artifacts.put_json({"kind": "invalid_output_diagnostic"})
    inner = _Client(
        [
            StageFailure(
                code="INVALID_OUTPUT",
                retryable=True,
                safe_message="Invalid model output",
                evidence_refs=(diagnostic_ref,),
            )
        ]
    )

    async def controlled_sleep(_delay: float) -> None:
        if oversleep:
            await asyncio.sleep(0.7)
        else:
            raise AssertionError("No backoff should fit before the deadline")

    result = await _wrapper(
        tmp_path,
        inner,
        asyncio.Semaphore(1),
        sleep=controlled_sleep,
        max_tokens="unlimited",
    ).call(prompt=b"safe", output_schema={}, timeout_ms=timeout_ms)

    assert isinstance(result, StageFailure)
    assert result.code == "INVALID_OUTPUT"
    assert result.retryable is False
    assert result.evidence_refs == (diagnostic_ref,)
    assert inner.calls == 1
    with sqlite3.connect(artifacts.paths.database) as connection:
        attempt = connection.execute(
            "SELECT status, artifact_ref_json FROM simple_llm_attempts "
            "WHERE analysis_id = ?",
            (artifacts.identity.analysis_id,),
        ).fetchone()
    assert attempt is not None
    status, ref_json = attempt
    assert status == "INVALID_OUTPUT"
    metadata = json.loads(artifacts.read(StoredDataRef.model_validate_json(ref_json)))
    assert metadata["evidence_refs"] == [diagnostic_ref.model_dump(mode="json")]


@pytest.mark.asyncio
async def test_numeric_token_cap_stops_retry_when_invalid_usage_is_unknown(
    tmp_path: Path,
) -> None:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-queue",
            workspace_id="workspace-queue",
            commit_id="a" * 40,
            hypothesis_id=None,
        ),
    )
    runner = _CodexRunner(
        [
            CodexProcessResult("SUCCEEDED", b"{", None),
            CodexProcessResult("SUCCEEDED", b'{"ok":true}', None),
        ]
    )
    inner = SimpleCodexClient(
        runner=runner,
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="test-model",
        artifacts=artifacts,
    )

    async def no_wait(_delay: float) -> None:
        return None

    result = await _wrapper(
        tmp_path, inner, asyncio.Semaphore(1), sleep=no_wait, max_tokens=1000
    ).call(prompt=b"safe", output_schema={}, timeout_ms=5000)

    assert isinstance(result, StageFailure)
    assert result.code == "LLM_TOKEN_USAGE_UNAVAILABLE"
    assert runner.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["AUTH_REQUIRED", "CANCELLED"])
async def test_codex_terminal_failure_is_not_retried(
    tmp_path: Path, status: Literal["AUTH_REQUIRED", "CANCELLED"]
) -> None:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-queue",
            workspace_id="workspace-queue",
            commit_id="a" * 40,
            hypothesis_id=None,
        ),
    )
    runner = _CodexRunner([CodexProcessResult(status, None, None)])
    inner = SimpleCodexClient(
        runner=runner,
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="test-model",
        artifacts=artifacts,
    )

    result = await _wrapper(
        tmp_path, inner, asyncio.Semaphore(1), max_tokens="unlimited"
    ).call(prompt=b"safe", output_schema={}, timeout_ms=5000)

    assert isinstance(result, StageFailure)
    assert not result.retryable
    assert runner.calls == 1


@pytest.mark.asyncio
async def test_unconfirmed_codex_process_cleanup_is_not_retried(
    tmp_path: Path,
) -> None:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-queue",
            workspace_id="workspace-queue",
            commit_id="a" * 40,
            hypothesis_id=None,
        ),
    )
    runner = _CodexRunner(
        [CodexProcessResult("FAILED", None, None, cleanup_unconfirmed=True)]
    )
    inner = SimpleCodexClient(
        runner=runner,
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="test-model",
        artifacts=artifacts,
    )

    result = await _wrapper(
        tmp_path, inner, asyncio.Semaphore(1), max_tokens="unlimited"
    ).call(prompt=b"safe", output_schema={}, timeout_ms=5000)

    assert isinstance(result, StageFailure)
    assert result.code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert not result.retryable
    assert runner.calls == 1


@pytest.mark.asyncio
async def test_codex_runner_reports_unconfirmed_cleanup_after_its_own_timeout(
    tmp_path: Path,
) -> None:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-queue",
            workspace_id="workspace-queue",
            commit_id="a" * 40,
            hypothesis_id=None,
        ),
    )

    class CleanupAfterTimeoutRunner:
        calls = 0
        requested_timeout_ms = 0
        cancelled_during_cleanup = False

        async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
            self.calls += 1
            self.requested_timeout_ms = request.timeout_ms
            try:
                async with asyncio.timeout(request.timeout_ms / 1000):
                    await asyncio.Event().wait()
            except TimeoutError:
                pass
            try:
                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                self.cancelled_during_cleanup = True
                raise
            return CodexProcessResult("FAILED", None, None, cleanup_unconfirmed=True)

    runner = CleanupAfterTimeoutRunner()
    inner = SimpleCodexClient(
        runner=runner,
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="test-model",
        artifacts=artifacts,
    )

    result = await asyncio.wait_for(
        _wrapper(tmp_path, inner, asyncio.Semaphore(1), max_tokens="unlimited").call(
            prompt=b"safe", output_schema={}, timeout_ms=100
        ),
        timeout=1,
    )

    assert isinstance(result, StageFailure)
    assert result.code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert not result.retryable
    assert runner.calls == 1
    assert 1 <= runner.requested_timeout_ms <= 100
    assert not runner.cancelled_during_cleanup


@pytest.mark.asyncio
async def test_non_codex_short_deadline_still_cancels_slow_inner(
    tmp_path: Path,
) -> None:
    class SlowClient:
        requested_timeout_ms = 0
        cancelled = False

        async def call(
            self,
            *,
            prompt: bytes,
            output_schema: Mapping[str, Any],
            timeout_ms: int,
            agent_name: str = "agent",
            owner: AttemptOwner | None = None,
            prompt_bytes: PromptByteCounts | None = None,
            invocation_id: str | None = None,
        ) -> SimpleLLMCallResult | StageFailure:
            del prompt, output_schema, agent_name, owner, prompt_bytes
            del invocation_id
            self.requested_timeout_ms = timeout_ms
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise
            raise AssertionError("deadline should cancel the inner call")

    inner = SlowClient()
    result = await asyncio.wait_for(
        _wrapper(tmp_path, inner, asyncio.Semaphore(1), max_retries=0).call(
            prompt=b"safe", output_schema={}, timeout_ms=500
        ),
        timeout=3,
    )

    assert isinstance(result, StageFailure)
    assert result.code == "TIMED_OUT"
    assert 1 <= inner.requested_timeout_ms <= 500
    assert inner.cancelled


@pytest.mark.asyncio
async def test_shared_queue_limits_concurrent_agents(tmp_path: Path) -> None:
    inner = _Client([_success() for _ in range(4)])
    gate = asyncio.Semaphore(2)
    clients = [_wrapper(tmp_path, inner, gate, max_retries=0) for _ in range(4)]

    results = await asyncio.gather(
        *[
            client.call(prompt=b"safe", output_schema={}, timeout_ms=5000)
            for client in clients
        ]
    )

    assert all(isinstance(result, SimpleLLMCallResult) for result in results), results
    assert inner.peak <= 2


@pytest.mark.asyncio
async def test_cancellation_releases_queue_slot(tmp_path: Path) -> None:
    entered = asyncio.Event()

    class HangingClient(_Client):
        async def call(self, **kwargs: Any) -> SimpleLLMCallResult | StageFailure:
            del kwargs
            entered.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    gate = asyncio.Semaphore(1)
    client = _wrapper(tmp_path, HangingClient([]), gate)
    task = asyncio.create_task(
        client.call(prompt=b"safe", output_schema={}, timeout_ms=5_000)
    )
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(gate.acquire(), timeout=0.2)
    gate.release()


@pytest.mark.asyncio
async def test_queued_call_rechecks_budget_after_prior_call_is_recorded(
    tmp_path: Path,
) -> None:
    inner = _Client([_success(), _success()])
    gate = asyncio.Semaphore(1)
    clients = [
        _wrapper(tmp_path, inner, gate, max_retries=0, max_tokens=7) for _ in range(2)
    ]
    results = await asyncio.gather(
        *[
            client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)
            for client in clients
        ]
    )
    assert inner.calls == 1
    assert sum(isinstance(result, SimpleLLMCallResult) for result in results) == 1
    assert any(
        isinstance(result, StageFailure) and result.code == "LLM_TOKEN_BUDGET_EXHAUSTED"
        for result in results
    )


@pytest.mark.asyncio
async def test_missing_tokens_in_persisted_attempt_block_resumed_call(
    tmp_path: Path,
) -> None:
    unmeasured = SimpleLLMCallResult(
        value={"ok": True}, prompt_digest="a" * 64, output_digest="b" * 64
    )
    inner = _Client([unmeasured, _success()])
    gate = asyncio.Semaphore(1)
    first = await _wrapper(tmp_path, inner, gate, max_retries=0).call(
        prompt=b"safe", output_schema={}, timeout_ms=1000
    )
    resumed = await _wrapper(tmp_path, inner, gate, max_retries=0).call(
        prompt=b"safe", output_schema={}, timeout_ms=1000
    )

    assert isinstance(first, SimpleLLMCallResult)
    assert isinstance(resumed, StageFailure)
    assert resumed.code == "LLM_TOKEN_USAGE_UNAVAILABLE"
    assert inner.calls == 1


@pytest.mark.asyncio
async def test_unlimited_tokens_allows_resumed_call_after_unmeasured_attempt(
    tmp_path: Path,
) -> None:
    unmeasured = SimpleLLMCallResult(
        value={"ok": True}, prompt_digest="a" * 64, output_digest="b" * 64
    )
    inner = _Client([unmeasured, _success()])
    gate = asyncio.Semaphore(1)
    first = await _wrapper(
        tmp_path, inner, gate, max_retries=0, max_tokens="unlimited"
    ).call(prompt=b"safe", output_schema={}, timeout_ms=1000)
    resumed = await _wrapper(
        tmp_path, inner, gate, max_retries=0, max_tokens="unlimited"
    ).call(prompt=b"safe", output_schema={}, timeout_ms=1000)

    assert isinstance(first, SimpleLLMCallResult)
    assert isinstance(resumed, SimpleLLMCallResult)
    assert inner.calls == 2


@pytest.mark.asyncio
async def test_reported_tokens_allow_more_subscription_calls_when_cost_is_unknown(
    tmp_path: Path,
) -> None:
    inner = _Client([_success(), _success()])
    client = _wrapper(tmp_path, inner, asyncio.Semaphore(1), max_retries=0)

    first = await client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)
    second = await client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)

    assert isinstance(first, SimpleLLMCallResult)
    assert isinstance(second, SimpleLLMCallResult)
    assert inner.calls == 2


@pytest.mark.asyncio
async def test_unmeasured_api_cost_blocks_next_billable_call(tmp_path: Path) -> None:
    class FakeAPIClient(SimpleOpenAIClient):
        def __init__(self) -> None:
            super().__init__(credential_ref="env:NOT_USED", model="test-model")
            self.calls = 0

        async def call(
            self,
            *,
            prompt: bytes,
            output_schema: Mapping[str, Any],
            timeout_ms: int,
            agent_name: str = "agent",
            owner: AttemptOwner | None = None,
            prompt_bytes: PromptByteCounts | None = None,
            invocation_id: str | None = None,
        ) -> SimpleLLMCallResult:
            del prompt, output_schema, timeout_ms, agent_name, owner, prompt_bytes
            del invocation_id
            self.calls += 1
            return _success()

    inner = FakeAPIClient()
    client = _wrapper(tmp_path, inner, asyncio.Semaphore(1), max_retries=0)

    first = await client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)
    second = await client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)

    assert isinstance(first, SimpleLLMCallResult)
    assert isinstance(second, StageFailure)
    assert second.code == "LLM_COST_USAGE_UNAVAILABLE"
    assert inner.calls == 1


@pytest.mark.asyncio
async def test_api_cost_guard_survives_resume_without_blocking_first_fallback(
    tmp_path: Path,
) -> None:
    subscription_result = _success().model_copy(update={"provider": "codex-cli"})
    subscription = _wrapper(
        tmp_path, _Client([subscription_result]), asyncio.Semaphore(1), max_retries=0
    )
    assert isinstance(
        await subscription.call(prompt=b"safe", output_schema={}, timeout_ms=1000),
        SimpleLLMCallResult,
    )

    class FakeAPIClient(SimpleOpenAIClient):
        def __init__(self) -> None:
            super().__init__(credential_ref="env:NOT_USED", model="test-model")
            self.calls = 0

        async def call(
            self,
            *,
            prompt: bytes,
            output_schema: Mapping[str, Any],
            timeout_ms: int,
            agent_name: str = "agent",
            owner: AttemptOwner | None = None,
            prompt_bytes: PromptByteCounts | None = None,
            invocation_id: str | None = None,
        ) -> SimpleLLMCallResult:
            del prompt, output_schema, timeout_ms, agent_name, owner, prompt_bytes
            del invocation_id
            self.calls += 1
            return _success()

    inner = FakeAPIClient()
    first_fallback = await _wrapper(
        tmp_path, inner, asyncio.Semaphore(1), max_retries=0
    ).call(prompt=b"safe", output_schema={}, timeout_ms=1000)
    resumed_fallback = await _wrapper(
        tmp_path, inner, asyncio.Semaphore(1), max_retries=0
    ).call(prompt=b"safe", output_schema={}, timeout_ms=1000)

    assert isinstance(first_fallback, SimpleLLMCallResult)
    assert isinstance(resumed_fallback, StageFailure)
    assert resumed_fallback.code == "LLM_COST_USAGE_UNAVAILABLE"
    assert inner.calls == 1


def test_legacy_attempt_with_unknown_provider_blocks_api_even_if_model_changed(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-queue",
        workspace_id="workspace-queue",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    ref = artifacts.put_json({"kind": "simple_llm_attempt"})
    store.record_llm_attempt(
        attempt_id="legacy-attempt",
        analysis_id=identity.analysis_id,
        agent="agent",
        model="legacy-other-model",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=1,
        input_tokens=5,
        output_tokens=2,
        cost_cents=None,
        artifact_ref=ref,
    )
    api = SimpleOpenAIClient(credential_ref="env:NOT_USED", model="test-model")
    failure = _wrapper(tmp_path, api, asyncio.Semaphore(1)).budget_failure()

    assert isinstance(failure, StageFailure)
    assert failure.code == "LLM_COST_USAGE_UNAVAILABLE"


def test_openai_factory_uses_the_run_limited_adapter(tmp_path: Path) -> None:
    profile = SimpleExecutionProfile(
        provider_profile_ref="local-openai",
        provider="openai",
        model="test-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=tmp_path,
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        tools={},
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-factory",
        workspace_id="workspace-factory",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    client = SimpleClientFactory(profile)(
        identity, SimpleArtifactRepository(tmp_path, identity)
    )
    assert isinstance(client, RunLimitedClient)


def test_cursor_fallback_reserves_one_of_three_attempts(tmp_path: Path) -> None:
    profile = SimpleExecutionProfile(
        provider_profile_ref="local-cursor",
        provider="cursor",
        model="account-model",
        auth_mode="API_KEY",
        credential_ref="env:CURSOR_API_KEY",
        data_dir=tmp_path,
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        tools={},
        cursor_allow_on_demand=True,
        fallback_provider="openai",
        fallback_model="fallback-model",
        llm_max_retries=5,
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-fallback",
        workspace_id="workspace-fallback",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    client = SimpleClientFactory(profile)(
        identity, SimpleArtifactRepository(tmp_path, identity)
    )
    assert isinstance(client, CursorProvider)
    assert client._max_retries == 1
    assert isinstance(client._fallback, RunLimitedClient)
    assert client._fallback._max_retries == 0


@pytest.mark.asyncio
async def test_operational_log_has_metadata_but_no_prompt(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sastsimi.simple_runtime.call_queue")
    client = _wrapper(tmp_path, _Client([_success()]), asyncio.Semaphore(1))
    await client.call(
        prompt=b"sensitive repository source",
        output_schema={},
        timeout_ms=1000,
        agent_name="hypothesis",
    )
    assert "analysis-queue" in caplog.text
    assert "hypothesis" in caplog.text
    assert "SUCCEEDED" in caplog.text
    assert "sensitive repository source" not in caplog.text


@pytest.mark.asyncio
async def test_fractional_provider_cost_is_recorded_without_invalid_artifact(
    tmp_path: Path,
) -> None:
    priced = _success().model_copy(update={"cost_minor_units": 1.5})
    result = await _wrapper(tmp_path, _Client([priced]), asyncio.Semaphore(1)).call(
        prompt=b"safe", output_schema={}, timeout_ms=1000
    )

    assert isinstance(result, SimpleLLMCallResult)
    with sqlite3.connect(tmp_path / "db" / "sastsimi.sqlite3") as connection:
        stored = connection.execute(
            "SELECT cost_cents FROM simple_llm_attempts WHERE analysis_id = ?",
            ("analysis-queue",),
        ).fetchone()
    assert stored == (1.5,)


@pytest.mark.asyncio
async def test_negative_wrapped_usage_cannot_reduce_run_budget(tmp_path: Path) -> None:
    invalid = _success().model_copy(
        update={"input_tokens": -100, "cost_minor_units": -4}
    )
    wrapper = _wrapper(tmp_path, _Client([invalid]), asyncio.Semaphore(1))

    result = await wrapper.call(prompt=b"safe", output_schema={}, timeout_ms=1000)

    assert isinstance(result, SimpleLLMCallResult)
    failure = wrapper.budget_failure()
    assert isinstance(failure, StageFailure)
    assert failure.code == "LLM_TOKEN_USAGE_UNAVAILABLE"


@pytest.mark.asyncio
async def test_context_limit_rejection_allows_smaller_resumed_api_call(
    tmp_path: Path,
) -> None:
    class FakeAPIClient(SimpleOpenAIClient):
        def __init__(self) -> None:
            super().__init__(credential_ref="env:NOT_USED", model="test-model")
            self.calls = 0

        async def call(
            self,
            *,
            prompt: bytes,
            output_schema: Mapping[str, Any],
            timeout_ms: int,
            agent_name: str = "agent",
            owner: AttemptOwner | None = None,
            prompt_bytes: PromptByteCounts | None = None,
            invocation_id: str | None = None,
        ) -> SimpleLLMCallResult | StageFailure:
            del prompt, output_schema, timeout_ms, agent_name, owner, prompt_bytes
            del invocation_id
            self.calls += 1
            if self.calls == 1:
                return StageFailure(
                    code="CONTEXT_LIMIT_EXCEEDED",
                    retryable=False,
                    safe_message="Split the batch",
                )
            return _success().model_copy(update={"cost_minor_units": 1})

    inner = FakeAPIClient()
    client = _wrapper(tmp_path, inner, asyncio.Semaphore(1), max_retries=0)

    oversized = await client.call(prompt=b"large", output_schema={}, timeout_ms=1000)
    smaller = await client.call(prompt=b"small", output_schema={}, timeout_ms=1000)

    assert isinstance(oversized, StageFailure)
    assert oversized.code == "CONTEXT_LIMIT_EXCEEDED"
    assert isinstance(smaller, SimpleLLMCallResult)
    assert inner.calls == 2


@pytest.mark.asyncio
async def test_same_cost_limit_resume_stops_before_llm_request(tmp_path: Path) -> None:
    priced = _success().model_copy(update={"cost_minor_units": 7})
    inner = _Client([priced, _success()])
    gate = asyncio.Semaphore(1)
    first = await _wrapper(
        tmp_path,
        inner,
        gate,
        max_retries=0,
        max_cost_minor_units=7,
    ).call(prompt=b"safe", output_schema={}, timeout_ms=1000)
    resumed = await _wrapper(
        tmp_path,
        inner,
        gate,
        max_retries=0,
        max_cost_minor_units=7,
    ).call(prompt=b"safe", output_schema={}, timeout_ms=1000)

    assert isinstance(first, SimpleLLMCallResult)
    assert isinstance(resumed, StageFailure)
    assert resumed.code == "LLM_COST_BUDGET_EXHAUSTED"
    assert inner.calls == 1


@pytest.mark.asyncio
async def test_context_rejection_does_not_trap_raised_cost_budget_resume(
    tmp_path: Path,
) -> None:
    context_failure = StageFailure(
        code="CONTEXT_LIMIT_EXCEEDED",
        retryable=False,
        safe_message="Split the batch",
    )
    priced = _success().model_copy(update={"cost_minor_units": 7})
    inner = _Client([context_failure, priced, priced])
    gate = asyncio.Semaphore(1)
    client = _wrapper(tmp_path, inner, gate, max_retries=0, max_cost_minor_units=7)

    oversized = await client.call(prompt=b"large", output_schema={}, timeout_ms=1000)
    smaller = await client.call(prompt=b"small", output_schema={}, timeout_ms=1000)
    paused = await client.call(prompt=b"next", output_schema={}, timeout_ms=1000)

    assert isinstance(oversized, StageFailure)
    assert oversized.code == "CONTEXT_LIMIT_EXCEEDED"
    assert isinstance(smaller, SimpleLLMCallResult)
    assert isinstance(paused, StageFailure)
    assert paused.code == "LLM_COST_BUDGET_EXHAUSTED"
    assert inner.calls == 2

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-queue",
        workspace_id="workspace-queue",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.FAILED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        error_code=paused.code,
        retryable=False,
    )
    store.save_checkpoint(checkpoint)

    reopened = store.reopen_budget_failures(
        identity.analysis_id,
        max_tokens=1000,
        max_cost_minor_units=8,
        max_elapsed_seconds=3600,
    )

    assert reopened == 1
    assert (
        store.require(identity, SimpleStage.PRO_CON_DONE).status is StageStatus.PENDING
    )
    resumed = await _wrapper(
        tmp_path, inner, gate, max_retries=0, max_cost_minor_units=8
    ).call(prompt=b"resume", output_schema={}, timeout_ms=1000)
    assert isinstance(resumed, SimpleLLMCallResult)
    assert inner.calls == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("limit_kind", ["tokens", "cost"])
async def test_concurrent_calls_cannot_both_spend_same_remaining_budget(
    tmp_path: Path, limit_kind: str
) -> None:
    priced = _success().model_copy(update={"cost_minor_units": 7})
    inner = _Client([priced, priced])
    gate = asyncio.Semaphore(2)
    clients = [
        _wrapper(
            tmp_path,
            inner,
            gate,
            max_retries=0,
            max_tokens=7 if limit_kind == "tokens" else "unlimited",
            max_cost_minor_units=7 if limit_kind == "cost" else 1000,
        )
        for _ in range(2)
    ]

    results = await asyncio.gather(
        *[
            client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)
            for client in clients
        ]
    )

    expected = (
        "LLM_TOKEN_BUDGET_EXHAUSTED"
        if limit_kind == "tokens"
        else "LLM_COST_BUDGET_EXHAUSTED"
    )
    assert inner.calls == 1
    assert sum(isinstance(result, SimpleLLMCallResult) for result in results) == 1
    assert (
        sum(
            isinstance(result, StageFailure) and result.code == expected
            for result in results
        )
        == 1
    )
