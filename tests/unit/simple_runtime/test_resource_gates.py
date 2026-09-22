"""Each resource has its own ceiling, because they cost very different things."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

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
