from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.composition.simple_runtime_composition import SimpleClientFactory
from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding
from sastsimi.providers.base import CodexProcessRequest, CodexProcessResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attempt_owner import AttemptOwner, PromptByteCounts
from sastsimi.simple_runtime.call_queue import RunLimitedClient
from sastsimi.simple_runtime.claude_provider import ClaudeProvider
from sastsimi.simple_runtime.cursor_provider import CursorProvider
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import (
    SimpleCodexClient,
    SimpleLLMCallResult,
    SimpleOpenAIClient,
)


def _profile(
    tmp_path: Path, provider: str = "openai", **changes: Any
) -> SimpleExecutionProfile:
    tools = {}
    if provider == "claude":
        tools = {
            "claude": SimpleToolBinding(
                executable_path=tmp_path / "claude.exe",
                version="2.1.280 (Claude Code)",
                executable_sha256="a" * 64,
            )
        }
    return SimpleExecutionProfile(
        provider_profile_ref=f"local-{provider}",
        provider=provider,
        model="primary",
        light_model="light",
        agent_models={"technical_gate": "explicit"},
        auth_mode="SUBSCRIPTION_LOGIN" if provider == "claude" else "API_KEY",
        credential_ref=(
            "CLAUDE_CLI_LOGIN"
            if provider == "claude"
            else "env:CURSOR_API_KEY"
            if provider == "cursor"
            else "env:OPENAI_API_KEY"
        ),
        data_dir=tmp_path,
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=1000,
        max_tokens="unlimited",
        docker_network="NONE",
        tools=tools,
        llm_max_retries=0,
        **changes,
    )


def _context(tmp_path: Path) -> tuple[CheckpointIdentity, SimpleArtifactRepository]:
    identity = CheckpointIdentity(
        analysis_id="analysis-routing",
        workspace_id="workspace-routing",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    return identity, SimpleArtifactRepository(tmp_path, identity)


@pytest.mark.asyncio
async def test_routed_client_forwards_every_call_argument_and_caches_models() -> None:
    from sastsimi.simple_runtime.model_routing import ModelRoutedClient

    made: list[str] = []
    seen: list[tuple[str, dict[str, Any]]] = []

    class RecordingClient:
        def __init__(self, model: str) -> None:
            self.model = model

        async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
            seen.append((self.model, kwargs))
            return SimpleLLMCallResult(
                value={"ok": True},
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    def make(model: str) -> RecordingClient:
        made.append(model)
        return RecordingClient(model)

    routed = ModelRoutedClient(
        primary_model="primary",
        agent_models={"cwe_label": "light", "technical_gate": "explicit"},
        client_factory=make,
    )
    owner = AttemptOwner(analysis_id="analysis-routing", stage="DISCOVERY")
    byte_counts = PromptByteCounts(fixed_prompt_bytes=7)
    schema: Mapping[str, Any] = {"type": "object"}
    for agent in ("cwe_label", "technical_gate", "hypothesis", "cwe_label"):
        await routed.call(
            prompt=b"source",
            output_schema=schema,
            timeout_ms=3000,
            agent_name=agent,
            owner=owner,
            prompt_bytes=byte_counts,
            invocation_id="internal-id",
        )

    assert made == ["light", "explicit", "primary"]
    assert [model for model, _ in seen] == ["light", "explicit", "primary", "light"]
    for (_, arguments), agent in zip(
        seen, ("cwe_label", "technical_gate", "hypothesis", "cwe_label"), strict=True
    ):
        assert arguments == {
            "prompt": b"source",
            "output_schema": schema,
            "timeout_ms": 3000,
            "agent_name": agent,
            "owner": owner,
            "prompt_bytes": byte_counts,
            "invocation_id": "internal-id",
        }


@pytest.mark.asyncio
async def test_routed_client_propagates_cancellation_and_terminal_failure() -> None:
    from sastsimi.simple_runtime.model_routing import ModelRoutedClient

    entered = asyncio.Event()
    cancelled = asyncio.Event()

    class SlowClient:
        async def call(self, **kwargs: Any) -> SimpleLLMCallResult | StageFailure:
            del kwargs
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise
            raise AssertionError("unreachable")

    routed = ModelRoutedClient(
        primary_model="primary",
        agent_models={"cwe_label": "light"},
        client_factory=lambda model: SlowClient(),
    )
    task = asyncio.create_task(
        routed.call(
            prompt=b"safe", output_schema={}, timeout_ms=3000, agent_name="cwe_label"
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set()

    failure = StageFailure(
        code="MODEL_OR_REQUEST_UNSUPPORTED",
        retryable=False,
        safe_message="Configured model is unavailable",
    )

    class FailedClient:
        async def call(self, **kwargs: Any) -> StageFailure:
            del kwargs
            return failure

    routed = ModelRoutedClient(
        primary_model="primary",
        agent_models={"cwe_label": "light"},
        client_factory=lambda model: FailedClient(),
    )
    assert (
        await routed.call(
            prompt=b"safe", output_schema={}, timeout_ms=3000, agent_name="cwe_label"
        )
        == failure
    )


@pytest.mark.parametrize("provider", ["openai", "codex"])
def test_factory_routes_codex_and_openai_per_model(
    tmp_path: Path, provider: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.simple_runtime.model_routing import ModelRoutedClient

    profile = _profile(tmp_path, provider)
    factory = SimpleClientFactory(profile)
    if provider == "codex":
        monkeypatch.setattr(
            factory, "_codex", lambda identity, artifacts, model: object()
        )
    identity, artifacts = _context(tmp_path)
    routed = factory(identity, artifacts)

    assert isinstance(routed, ModelRoutedClient)
    cwe_client = routed.client_for_agent("cwe_label")
    technical_gate_client = routed.client_for_agent("technical_gate")
    hypothesis_client = routed.client_for_agent("hypothesis")
    assert isinstance(cwe_client, RunLimitedClient)
    assert isinstance(technical_gate_client, RunLimitedClient)
    assert isinstance(hypothesis_client, RunLimitedClient)
    assert cwe_client._model == "light"
    assert technical_gate_client._model == "explicit"
    assert hypothesis_client._model == "primary"
    assert cwe_client is routed.client_for_agent("report_draft")
    assert cwe_client._semaphore is factory._semaphore
    assert hypothesis_client._semaphore is factory._semaphore


@pytest.mark.parametrize("provider", ["claude", "cursor"])
def test_factory_passes_effective_map_to_existing_providers(
    tmp_path: Path, provider: str
) -> None:
    profile = _profile(tmp_path, provider)
    identity, artifacts = _context(tmp_path)
    client = SimpleClientFactory(profile)(identity, artifacts)

    assert isinstance(
        client, ClaudeProvider if provider == "claude" else CursorProvider
    )
    assert client._default_model == "primary"
    assert client._agent_models["cwe_label"] == "light"
    assert client._agent_models["technical_gate"] == "explicit"
    assert client._agent_models["hypothesis"] == "primary"


@pytest.mark.asyncio
async def test_mixed_models_share_budget_and_persist_actual_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _profile(tmp_path, "openai").model_copy(update={"max_tokens": 7})
    factory = SimpleClientFactory(profile)
    identity, artifacts = _context(tmp_path)
    seen: list[str] = []

    async def fake_call(self: SimpleOpenAIClient, **kwargs: Any) -> SimpleLLMCallResult:
        del kwargs
        seen.append(self._model)
        await asyncio.sleep(0.01)
        return SimpleLLMCallResult(
            value={"ok": True},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
            provider="openai-api",
            model=self._model,
            input_tokens=5,
            output_tokens=2,
            cost_minor_units=1,
        )

    monkeypatch.setattr(SimpleOpenAIClient, "call", fake_call)
    routed = factory(identity, artifacts)
    first = await routed.call(
        prompt=b"safe", output_schema={}, timeout_ms=3000, agent_name="cwe_label"
    )
    second = await routed.call(
        prompt=b"safe", output_schema={}, timeout_ms=3000, agent_name="hypothesis"
    )

    assert isinstance(first, SimpleLLMCallResult)
    assert isinstance(second, StageFailure)
    assert second.code == "LLM_TOKEN_BUDGET_EXHAUSTED"
    assert seen == ["light"]
    with sqlite3.connect(factory._store.database_path) as connection:
        models = [
            row[0]
            for row in connection.execute(
                "SELECT model FROM simple_llm_attempts WHERE analysis_id = ?",
                (identity.analysis_id,),
            )
        ]
    assert models == ["light"]


def test_single_model_factory_preserves_original_adapter(tmp_path: Path) -> None:
    profile = _profile(tmp_path, "openai").model_copy(
        update={"light_model": None, "agent_models": {}}
    )
    identity, artifacts = _context(tmp_path)
    assert isinstance(
        SimpleClientFactory(profile)(identity, artifacts), RunLimitedClient
    )


@pytest.mark.asyncio
async def test_mixed_openai_models_share_concurrency_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _profile(tmp_path, "openai").model_copy(update={"llm_max_concurrency": 1})
    factory = SimpleClientFactory(profile)
    identity, artifacts = _context(tmp_path)
    active = 0
    peak = 0

    async def fake_call(self: SimpleOpenAIClient, **kwargs: Any) -> SimpleLLMCallResult:
        nonlocal active, peak
        del kwargs
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.02)
            return SimpleLLMCallResult(
                value={"ok": True},
                prompt_digest="a" * 64,
                output_digest="b" * 64,
                provider="openai-api",
                model=self._model,
                input_tokens=5,
                output_tokens=2,
                cost_minor_units=1,
            )
        finally:
            active -= 1

    monkeypatch.setattr(SimpleOpenAIClient, "call", fake_call)
    routed = factory(identity, artifacts)
    results = await asyncio.gather(
        routed.call(
            prompt=b"safe", output_schema={}, timeout_ms=3000, agent_name="cwe_label"
        ),
        routed.call(
            prompt=b"safe", output_schema={}, timeout_ms=3000, agent_name="hypothesis"
        ),
    )

    assert all(isinstance(result, SimpleLLMCallResult) for result in results)
    assert peak == 1
    with sqlite3.connect(factory._store.database_path) as connection:
        rows = connection.execute(
            "SELECT model FROM simple_llm_attempts WHERE analysis_id = ?",
            (identity.analysis_id,),
        ).fetchall()
    assert sorted(row[0] for row in rows) == ["light", "primary"]


@pytest.mark.asyncio
async def test_codex_model_route_keeps_codex_run_guard_and_actual_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.simple_runtime.model_routing import ModelRoutedClient

    profile = _profile(tmp_path, "codex")
    factory = SimpleClientFactory(profile)
    identity, artifacts = _context(tmp_path)
    seen: list[str] = []

    class Runner:
        async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
            seen.append(request.model)
            return CodexProcessResult("SUCCEEDED", b'{"ok":true}', None, 5, 2)

    monkeypatch.setattr(
        factory,
        "_codex",
        lambda _identity, _artifacts, model: SimpleCodexClient(
            runner=Runner(),
            provider_profile_ref=artifacts.put_json({"kind": "test_profile"}),
            model=model,
            artifacts=artifacts,
        ),
    )
    routed = factory(identity, artifacts)
    results = [
        await routed.call(
            prompt=b"safe", output_schema={}, timeout_ms=3000, agent_name=agent
        )
        for agent in ("cwe_label", "hypothesis")
    ]

    assert all(isinstance(result, SimpleLLMCallResult) for result in results)
    assert seen == ["light", "primary"]
    assert isinstance(routed, ModelRoutedClient)
    cwe_client = routed.client_for_agent("cwe_label")
    hypothesis_client = routed.client_for_agent("hypothesis")
    assert isinstance(cwe_client, RunLimitedClient)
    assert isinstance(hypothesis_client, RunLimitedClient)
    assert cwe_client._provider == "codex-cli"
    assert hypothesis_client._provider == "codex-cli"
    assert factory._store.unresolved_codex_call(identity.analysis_id) is None
    with sqlite3.connect(factory._store.database_path) as connection:
        rows = connection.execute(
            "SELECT model FROM simple_llm_attempts WHERE analysis_id = ? "
            "ORDER BY rowid",
            (identity.analysis_id,),
        ).fetchall()
    assert [row[0] for row in rows] == ["light", "primary"]
