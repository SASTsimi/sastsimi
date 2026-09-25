from __future__ import annotations

import asyncio
import os
import socket
from collections.abc import Mapping, Sequence

import pytest

from sastsimi.ports.docker_state import DockerContainerState
from sastsimi.sandbox.docker_adapter import DockerCommandOutcome, DockerOperationError
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.portable_docker import PortableDockerRuntime


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-owned",
        workspace_id="workspace-owned",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-owned",
    )


def _labels(identity: CheckpointIdentity) -> dict[str, str]:
    return {
        "sastsimi.owner": "simple-runtime",
        "sastsimi.analysis-id": identity.analysis_id,
        "sastsimi.workspace-id": identity.workspace_id,
        "sastsimi.commit-id": identity.commit_id,
        "sastsimi.hypothesis-id": identity.hypothesis_id or "analysis",
        "sastsimi.attempt-id": "attempt-owned",
        "sastsimi.host": socket.gethostname(),
        "sastsimi.pid": str(os.getpid()),
    }


class _CleanupDocker(PortableDockerRuntime):
    def __init__(self, states: Mapping[str, DockerContainerState]) -> None:
        self.states = states
        self.commands: list[tuple[str, ...]] = []

    async def inspect(self, container_id: str) -> DockerContainerState:
        return self.states[container_id]

    async def _run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: int,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        del timeout_seconds, input_bytes
        self.commands.append(tuple(args))
        if args[0] == "ps":
            return DockerCommandOutcome(0, b"owned\nforeign\n", b"", False)
        return DockerCommandOutcome(0, b"", b"", False)


class _DeadOwnerDocker(_CleanupDocker):
    @staticmethod
    def _pid_known_dead(pid: int, *, platform_name: str | None = None) -> bool:
        del pid, platform_name
        return True


def _state(container_id: str, labels: Mapping[str, str]) -> DockerContainerState:
    return DockerContainerState(
        container_id=container_id,
        image_digest="sha256:" + "a" * 64,
        user="10001:10001",
        network_mode="none",
        privileged=False,
        read_only_rootfs=False,
        running=True,
        exit_code=0,
        health_status=None,
        labels=labels,
    )


@pytest.mark.asyncio
async def test_remove_owned_requires_exact_identity_and_attempt() -> None:
    identity = _identity()
    runtime = _CleanupDocker(
        {
            "owned": _state("owned", _labels(identity)),
            "foreign": _state(
                "foreign", {**_labels(identity), "sastsimi.attempt-id": "other"}
            ),
            "missing": _state(
                "missing",
                {
                    key: value
                    for key, value in _labels(identity).items()
                    if key != "sastsimi.owner"
                },
            ),
        }
    )

    assert await runtime.remove_owned("owned", identity, "attempt-owned") is True
    assert await runtime.remove_owned("foreign", identity, "attempt-owned") is False
    assert await runtime.remove_owned("missing", identity, "attempt-owned") is False
    assert runtime.commands == [("rm", "--force", "owned")]


@pytest.mark.asyncio
async def test_sweep_skips_foreign_and_unknown_owner() -> None:
    identity = _identity()
    dead = {**_labels(identity), "sastsimi.pid": "99999999"}
    runtime = _DeadOwnerDocker(
        {
            "owned": _state("owned", dead),
            "foreign": _state("foreign", {**dead, "sastsimi.host": "other-host"}),
        }
    )

    removed = await runtime.sweep_orphans()

    assert removed == ("owned",)
    assert ("rm", "--force", "owned") in runtime.commands
    assert ("rm", "--force", "foreign") not in runtime.commands


def test_unknown_windows_pid_cannot_be_swept() -> None:
    assert PortableDockerRuntime._pid_known_dead(99999999, platform_name="nt") is False


@pytest.mark.asyncio
async def test_container_limit_covers_running_lifetime() -> None:
    identity = _identity()

    class _LifetimeDocker(_CleanupDocker):
        def __init__(self) -> None:
            super().__init__({})
            self._container_slots = asyncio.Semaphore(1)
            self._container_limit = 1
            self.running = False

        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            del timeout_seconds, input_bytes
            self.commands.append(tuple(args))
            if args[0] == "ps":
                return DockerCommandOutcome(
                    0, b"owned\n" if self.running else b"", b"", False
                )
            if args[0] == "create":
                return DockerCommandOutcome(0, b"owned\n", b"", False)
            if args[0] == "start":
                self.running = True
            if args[0] == "rm":
                self.running = False
            return DockerCommandOutcome(0, b"", b"", False)

        async def inspect(self, container_id: str) -> DockerContainerState:
            return _state(container_id, _labels(identity))

    runtime = _LifetimeDocker()
    labels = _labels(identity)
    digest = "sha256:" + "a" * 64

    assert await runtime.create_container(digest, labels) == "owned"
    with pytest.raises(DockerOperationError, match="DOCKER_CONTAINER_LIMIT_REACHED"):
        await runtime.create_container(digest, labels)
    assert await runtime.remove_owned("owned", identity, "attempt-owned") is True
    assert await runtime.create_container(digest, labels) == "owned"
