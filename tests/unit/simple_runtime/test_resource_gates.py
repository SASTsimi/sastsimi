from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding
from sastsimi.sandbox.docker_adapter import DockerCommandOutcome
from sastsimi.simple_runtime.portable_docker import PortableDockerRuntime


def _profile(tmp_path: Path) -> SimpleExecutionProfile:
    executable = tmp_path / "docker.exe"
    executable.write_bytes(b"fake")
    return SimpleExecutionProfile(
        provider_profile_ref="local-openai",
        provider="openai",
        model="model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=tmp_path,
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        tools={
            "docker": SimpleToolBinding(
                executable_path=executable,
                version="1",
                executable_sha256=hashlib.sha256(b"fake").hexdigest(),
            )
        },
        max_parallel_builds=1,
        max_parallel_containers=1,
    )


@pytest.mark.asyncio
async def test_build_and_container_creation_have_shared_run_gates(
    tmp_path: Path,
) -> None:
    class ProbeRuntime(PortableDockerRuntime):
        def __init__(self, profile: SimpleExecutionProfile) -> None:
            super().__init__(profile)
            self.active_builds = 0
            self.peak_builds = 0
            self.active_creates = 0
            self.peak_creates = 0
            self.created = 0
            self.built_tags: set[str] = set()

        async def _run(self, args, *, timeout_seconds, input_bytes=None):  # type: ignore[no-untyped-def]
            del timeout_seconds, input_bytes
            if args[:2] == ("image", "inspect"):
                if args[-1] not in self.built_tags:
                    return DockerCommandOutcome(1, b"", b"missing", False)
                return DockerCommandOutcome(0, b"sha256:" + b"a" * 64, b"", False)
            if args[0] == "create":
                self.active_creates += 1
                self.peak_creates = max(self.peak_creates, self.active_creates)
                try:
                    await asyncio.sleep(0.02)
                    self.created += 1
                    return DockerCommandOutcome(
                        0, f"container-{self.created}".encode(), b"", False
                    )
                finally:
                    self.active_creates -= 1
            if args[0] == "build":
                self.active_builds += 1
                self.peak_builds = max(self.peak_builds, self.active_builds)
                try:
                    await asyncio.sleep(0.02)
                    self.built_tags.add(args[args.index("--tag") + 1])
                finally:
                    self.active_builds -= 1
            return DockerCommandOutcome(0, b"", b"", False)

    runtime = ProbeRuntime(_profile(tmp_path))
    digest = "sha256:" + "a" * 64
    await asyncio.gather(
        *[
            runtime.build_or_reuse(
                workspace=tmp_path,
                dockerfile=b"FROM scratch\n",
                cache_key=f"build-{index}",
                labels={},
            )
            for index in range(3)
        ]
    )
    await asyncio.gather(*[runtime.create_container(digest, {}) for _ in range(3)])
    assert runtime.peak_builds == 1
    assert runtime.peak_creates == 1
    assert runtime.created == 3


@pytest.mark.asyncio
async def test_cancelled_build_releases_the_shared_slot(tmp_path: Path) -> None:
    entered = asyncio.Event()

    class BlockingBuild(PortableDockerRuntime):
        async def _run(self, args, *, timeout_seconds, input_bytes=None):  # type: ignore[no-untyped-def]
            del timeout_seconds, input_bytes
            if args[:2] == ("image", "inspect"):
                return DockerCommandOutcome(1, b"", b"missing", False)
            if args[0] == "build":
                entered.set()
                await asyncio.Event().wait()
            return DockerCommandOutcome(0, b"", b"", False)

    runtime = BlockingBuild(_profile(tmp_path))
    task = asyncio.create_task(
        runtime.build_or_reuse(
            workspace=tmp_path,
            dockerfile=b"FROM scratch\n",
            cache_key="one",
            labels={},
        )
    )
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(runtime._build_slots.acquire(), timeout=0.2)
    runtime._build_slots.release()
