"""Each resource has its own ceiling, because they cost very different things."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding
from sastsimi.simple_runtime.portable_docker import PortableDockerRuntime


def _profile(tmp_path: Path, **overrides: object) -> SimpleExecutionProfile:
    fields: dict[str, object] = {
        "provider_profile_ref": "local-claude",
        "provider": "claude",
        "model": "claude-sonnet-5",
        "auth_mode": "SUBSCRIPTION_LOGIN",
        "credential_ref": "OFFICIAL_CLIENT_SESSION",
        "data_dir": tmp_path / "data",
        "workspace_root": tmp_path / "workspaces",
        "max_cost_minor_units": 10_000,
        "max_tokens": 500_000,
        "max_elapsed_seconds": 3_600,
        "docker_network": "NONE",
        "tools": {
            "docker": SimpleToolBinding(
                executable_path=tmp_path / "docker",
                version="28.2.2",
                executable_sha256="a" * 64,
            )
        },
    }
    fields.update(overrides)
    return SimpleExecutionProfile(**fields)  # type: ignore[arg-type]


def test_the_ceilings_default_to_a_strictly_sequential_run(tmp_path: Path) -> None:
    profile = _profile(tmp_path)

    assert profile.max_parallel_hypotheses == 1
    assert profile.max_parallel_calls == 1
    assert profile.max_parallel_builds == 1
    assert profile.max_parallel_containers == 1


def test_the_ceilings_round_trip_through_toml(tmp_path: Path) -> None:
    rendered = _profile(
        tmp_path,
        max_parallel_hypotheses=6,
        max_parallel_calls=4,
        max_parallel_builds=1,
        max_parallel_containers=3,
    ).to_toml()

    assert "max_parallel_hypotheses = 6" in rendered
    assert "max_parallel_calls = 4" in rendered
    assert "max_parallel_builds = 1" in rendered
    assert "max_parallel_containers = 3" in rendered


class _CountingRuntime(PortableDockerRuntime):
    """Counts how many builds the gate lets run at the same time."""

    live = 0
    peak = 0

    async def _build_or_reuse(
        self,
        tag: str,
        workspace: Path,
        dockerfile: bytes,
        labels: Any,
    ) -> str:
        type(self).live += 1
        type(self).peak = max(type(self).peak, type(self).live)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        type(self).live -= 1
        return "sha256:" + "b" * 64


@pytest.mark.asyncio
async def test_the_build_gate_bounds_concurrent_builds(tmp_path: Path) -> None:
    # A build was measured above two gigabytes, so two at once is what the
    # ceiling exists to prevent.
    _CountingRuntime.live = 0
    _CountingRuntime.peak = 0
    runtime = _CountingRuntime(_profile(tmp_path, max_parallel_builds=2))

    await asyncio.gather(
        *(
            runtime.build_or_reuse(
                workspace=tmp_path,
                dockerfile=f"FROM python:3.12-slim  # {index}".encode(),
                cache_key=f"key-{index}",
                labels={},
            )
            for index in range(6)
        )
    )

    assert _CountingRuntime.peak == 2


@pytest.mark.asyncio
async def test_one_build_at_a_time_is_the_default(tmp_path: Path) -> None:
    _CountingRuntime.live = 0
    _CountingRuntime.peak = 0
    runtime = _CountingRuntime(_profile(tmp_path))

    await asyncio.gather(
        *(
            runtime.build_or_reuse(
                workspace=tmp_path,
                dockerfile=f"FROM scratch  # {index}".encode(),
                cache_key=f"key-{index}",
                labels={},
            )
            for index in range(4)
        )
    )

    assert _CountingRuntime.peak == 1


class _TimedClient:
    """Records when each call starts and ends, to see what overlapped."""

    def __init__(self) -> None:
        self.live = 0
        self.peak = 0

    async def call(self, **kwargs: object) -> Any:
        from sastsimi.simple_runtime.provider import SimpleLLMCallResult

        self.live += 1
        self.peak = max(self.peak, self.live)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.live -= 1
        return SimpleLLMCallResult(
            value={
                "claims": [],
                "evidence_refs": [],
                "limitations": [],
                "requested_paths": [],
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


@pytest.mark.asyncio
async def test_pro_and_con_review_at_the_same_time(tmp_path: Path) -> None:
    # Con is a new independent review of the same inputs, so making it wait for
    # Pro doubles the wall clock of the stage for no reason.
    from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
    from sastsimi.simple_runtime.models import (
        CheckpointIdentity,
        SimpleStage,
        StageCheckpoint,
        StageStatus,
        input_reference_hash,
    )
    from sastsimi.simple_runtime.stages import ProConStage

    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    client = _TimedClient()
    stage = ProConStage(
        cast(Any, client), SimpleArtifactRepository(tmp_path / "data", identity)
    )

    await stage(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.RUNNING,
            input_refs=(),
            input_hash=input_reference_hash(()),
            attempt_id="attempt-1",
        ),
        {},
    )

    assert client.peak == 2


@pytest.mark.asyncio
async def test_the_container_ceiling_is_shared_by_every_hypothesis() -> None:
    """Handlers are built per hypothesis, so a gate made inside one is one each.

    Measured on a live run: five containers were alive against a configured
    limit of four, because six hypotheses each held their own semaphore.
    """

    import asyncio as _asyncio

    from sastsimi.simple_runtime.stages import PoCExecutionStage

    shared = _asyncio.Semaphore(2)
    stages = [
        PoCExecutionStage(
            client=cast(Any, object()),
            artifacts=cast(Any, object()),
            docker=cast(Any, object()),
            containers=cast(Any, object()),
            max_parallel_containers=2,
            container_slots=shared,
        )
        for _ in range(6)
    ]

    live = 0
    peak = 0

    async def hold(stage: Any) -> None:
        nonlocal live, peak
        async with stage._container_slots:
            live += 1
            peak = max(peak, live)
            await _asyncio.sleep(0)
            await _asyncio.sleep(0)
            live -= 1

    await _asyncio.wait_for(
        _asyncio.gather(*(hold(stage) for stage in stages)), timeout=2
    )

    assert peak == 2


@pytest.mark.asyncio
async def test_without_a_shared_gate_each_stage_keeps_its_own() -> None:
    """The fallback still bounds one stage, for a caller that builds only one."""

    from sastsimi.simple_runtime.stages import PoCExecutionStage

    stage = PoCExecutionStage(
        client=cast(Any, object()),
        artifacts=cast(Any, object()),
        docker=cast(Any, object()),
        containers=cast(Any, object()),
        max_parallel_containers=3,
    )

    assert stage._container_slots._value == 3
