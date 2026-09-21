"""The stronger model must reach the reasoning roles and only those."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from sastsimi.sandbox.docker_adapter import DockerAdapter
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import SimpleStage, StageCheckpoint, StageFailure
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


_DEEP_STAGES = {
    SimpleStage.PRO_CON_DONE,
    SimpleStage.VERIFICATION_INITIAL_DONE,
    SimpleStage.VERIFICATION_FINAL_DONE,
}


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


def _build(
    tmp_path: Any, base: _NamedClient, deep: _NamedClient | None
) -> dict[SimpleStage, object]:
    artifacts = SimpleArtifactRepository.__new__(SimpleArtifactRepository)
    return cast(
        dict[SimpleStage, object],
        build_stage_handlers(
            client=base,
            deep_client=deep,
            artifacts=artifacts,
            docker=cast(DockerAdapter, object()),
            containers=cast(SimpleContainerFactory, _Containers()),
        ),
    )


def test_reasoning_roles_use_the_deep_client(tmp_path: Any) -> None:
    base = _NamedClient("base")
    deep = _NamedClient("deep")

    clients = _clients(_build(tmp_path, base, deep))

    assert clients, "no stage exposed an LLM client"
    for stage in _DEEP_STAGES:
        assert clients[stage] == {"deep"}, stage
    for stage, names in clients.items():
        if stage not in _DEEP_STAGES:
            assert names == {"base"}, stage


def test_without_a_deep_client_every_stage_uses_the_one_client(tmp_path: Any) -> None:
    base = _NamedClient("base")

    clients = _clients(_build(tmp_path, base, None))

    assert clients
    assert all(names == {"base"} for names in clients.values())


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


def test_every_llm_stage_honours_the_configured_call_timeout(tmp_path: Any) -> None:
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
