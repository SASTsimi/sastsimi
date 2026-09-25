from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.composition.simple_runtime_composition import SimpleClientFactory
from sastsimi.config.user_config import SimpleExecutionProfile
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.call_queue import RunLimitedClient
from sastsimi.simple_runtime.cursor_provider import CursorProvider
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
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
    ) -> SimpleLLMCallResult | StageFailure:
        del prompt, output_schema, timeout_ms, agent_name
        self.calls += 1
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(0.02)
            return self.outcomes.pop(0)
        finally:
            self.active -= 1


def _success() -> SimpleLLMCallResult:
    return SimpleLLMCallResult(
        value={"ok": True},
        prompt_digest="a" * 64,
        output_digest="b" * 64,
        input_tokens=5,
        output_tokens=2,
    )


def _wrapper(
    tmp_path: Path,
    inner: _Client,
    semaphore: asyncio.Semaphore,
    *,
    max_retries: int = 2,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    max_tokens: int = 1000,
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
        max_cost_minor_units=1000,
        max_elapsed_seconds=3600,
        sleep=sleep,
    )


@pytest.mark.asyncio
async def test_shared_queue_limits_concurrent_agents(tmp_path: Path) -> None:
    inner = _Client([_success() for _ in range(4)])
    gate = asyncio.Semaphore(2)
    clients = [_wrapper(tmp_path, inner, gate, max_retries=0) for _ in range(4)]

    results = await asyncio.gather(
        *[
            client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)
            for client in clients
        ]
    )

    assert all(isinstance(result, SimpleLLMCallResult) for result in results)
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
