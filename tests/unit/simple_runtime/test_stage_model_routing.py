"""The stronger model must reach the hypothesis agent and nothing else."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import pytest

from sastsimi.sandbox.docker_adapter import DockerAdapter
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.stages import SimpleContainerFactory, build_stage_handlers


class _NamedClient:
    def __init__(self, name: str) -> None:
        self.name = name

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
    ) -> SimpleLLMCallResult | StageFailure:
        raise AssertionError("not invoked")


class _Containers:
    async def acquire(self, checkpoint: StageCheckpoint) -> str:
        raise AssertionError("not invoked")


def _clients(handlers: dict[SimpleStage, object]) -> dict[SimpleStage, set[str]]:
    found: dict[SimpleStage, set[str]] = {}
    for stage, handler in handlers.items():
        names: set[str] = set()
        _collect(handler, names, depth=0)
        if names:
            found[stage] = names
    return found


def _collect(value: object, names: set[str], *, depth: int) -> None:
    if depth > 4:
        return
    if isinstance(value, _NamedClient):
        names.add(value.name)
        return
    for attribute in vars(value).values() if hasattr(value, "__dict__") else ():
        _collect(attribute, names, depth=depth + 1)


def _build(base: _NamedClient) -> dict[SimpleStage, object]:
    artifacts = SimpleArtifactRepository.__new__(SimpleArtifactRepository)
    return cast(
        dict[SimpleStage, object],
        build_stage_handlers(
            client=base,
            artifacts=artifacts,
            docker=cast(DockerAdapter, object()),
            containers=cast(SimpleContainerFactory, _Containers()),
        ),
    )


def test_every_stage_runs_on_the_one_stage_client() -> None:
    """Only the hypothesis agent may differ; the stages share one client."""

    clients = _clients(_build(_NamedClient("base")))

    assert clients, "no stage exposed an LLM client"
    assert all(names == {"base"} for names in clients.values()), clients


@pytest.mark.asyncio
async def test_the_hypothesis_agent_asks_for_the_deep_client(tmp_path: Any) -> None:
    """The proposals decide everything downstream, so that call may cost more."""

    asked: list[bool] = []

    class _Probe(Exception):
        pass

    def factory(
        identity: object, artifacts: object, *, deep: bool = False
    ) -> _NamedClient:
        asked.append(deep)
        raise _Probe

    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path, client_factory=cast(Any, factory)
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    with pytest.raises(_Probe):
        await bootstrap.propose(identity, cast(Any, object()))

    assert asked == [True]


def _timeouts(handlers: dict[SimpleStage, object]) -> dict[SimpleStage, set[int]]:
    found: dict[SimpleStage, set[int]] = {}
    for stage, handler in handlers.items():
        values: set[int] = set()
        _collect_timeouts(handler, values, depth=0)
        if values:
            found[stage] = values
    return found


def _collect_timeouts(value: object, values: set[int], *, depth: int) -> None:
    if depth > 4 or not hasattr(value, "__dict__"):
        return
    for name, attribute in vars(value).items():
        if name == "_call_timeout_ms" and isinstance(attribute, int):
            values.add(attribute)
        else:
            _collect_timeouts(attribute, values, depth=depth + 1)


def test_every_llm_stage_honours_the_configured_call_timeout() -> None:
    """No stage may keep a fixed ceiling the operator's budget cannot raise."""

    base = _NamedClient("base")
    artifacts = SimpleArtifactRepository.__new__(SimpleArtifactRepository)
    handlers = cast(
        dict[SimpleStage, object],
        build_stage_handlers(
            client=base,
            artifacts=artifacts,
            docker=cast(DockerAdapter, object()),
            containers=cast(SimpleContainerFactory, _Containers()),
            store=cast(Any, object()),
            call_timeout_ms=999_000,
            poc_timeout_ms=888_000,
        ),
    )

    timeouts = _timeouts(handlers)
    assert SimpleStage.CHAINING_DONE in timeouts, "chaining exposed no call timeout"
    for stage, values in timeouts.items():
        assert values == {999_000}, (stage, values)


def test_hypothesis_bootstrap_honours_the_configured_call_timeout(
    tmp_path: Any,
) -> None:
    from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap

    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path,
        client_factory=cast(Any, lambda *a, **k: _NamedClient("base")),
        call_timeout_ms=777_000,
    )

    assert bootstrap._call_timeout_ms == 777_000
