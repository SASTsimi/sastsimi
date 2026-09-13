from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from sastsimi.capabilities.docker_build_boundary import (
    DockerDataRootBoundary,
    ProductionDockerBuildBoundaryProbe,
)
from sastsimi.capabilities.probes import CommandObservation


class _Commands:
    def __init__(self, info: dict[str, object], *, legacy_help: str) -> None:
        self._info = info
        self._legacy_help = legacy_help
        self.calls: list[tuple[tuple[str, ...], Mapping[str, str] | None]] = []

    def run(
        self,
        executable: Path,
        arguments: tuple[str, ...],
        *,
        timeout_ms: int,
        environment_overrides: Mapping[str, str] | None = None,
    ) -> CommandObservation:
        del executable, timeout_ms
        self.calls.append((arguments, environment_overrides))
        effective = arguments[2:]
        if effective == ("info", "--format", "{{json .}}"):
            return CommandObservation(True, json.dumps(self._info))
        if effective == ("image", "build", "--help"):
            return CommandObservation(True, self._legacy_help)
        raise AssertionError(effective)


def _docker_info() -> dict[str, object]:
    return {
        "ID": "daemon-a",
        "OSType": "linux",
        "Architecture": "x86_64",
        "Driver": "overlay2",
        "DockerRootDir": "/srv/sastsimi-docker",
        "MemoryLimit": True,
        "CpuCfsPeriod": True,
        "CpuCfsQuota": True,
        "PidsLimit": True,
        "Labels": ["sastsimi.dedicated=true"],
        "DriverStatus": [["Backing Filesystem", "xfs"]],
    }


_LEGACY_HELP = """
--cpu-period int
--cpu-quota int
--memory bytes
--network string
--ulimit ulimit
"""


def test_dedicated_bounded_linux_engine_can_produce_build_capability() -> None:
    commands = _Commands(_docker_info(), legacy_help=_LEGACY_HELP)
    boundary = DockerDataRootBoundary(
        total_bytes=8 * 1024 * 1024 * 1024,
        identity_hash="a" * 64,
        dedicated_mount=True,
    )
    probe = ProductionDockerBuildBoundaryProbe(
        operating_system="linux",
        docker_executable=Path("/usr/bin/docker"),
        docker_host="unix:///run/user/1000/docker.sock",
        command_runner=commands,
        data_root_inspector=lambda _path: boundary,
        effective_user_id=1000,
    )

    result = probe()

    assert result.code == "DOCKER_BUILD_BOUNDARY_PRECHECK_PASSED"
    assert result.capability is not None
    assert result.capability.build_backend == "LEGACY_LIMITED"
    assert result.capability.enforced_build_limits == (
        "CPU",
        "MEMORY",
        "PID",
        "DISK",
    )
    assert result.capability.external_build_disk_limit_bytes == 8 * 1024**3
    assert result.storage_identity_hash == "a" * 64
    assert commands.calls[-1][1] == {"DOCKER_BUILDKIT": "0"}


def test_desktop_or_unbounded_engine_stays_blocked() -> None:
    commands = _Commands(_docker_info(), legacy_help=_LEGACY_HELP)
    probe = ProductionDockerBuildBoundaryProbe(
        operating_system="windows",
        docker_executable=Path("C:/Program Files/Docker/docker.exe"),
        docker_host="npipe:////./pipe/docker_engine",
        command_runner=commands,
        data_root_inspector=lambda _path: DockerDataRootBoundary(
            total_bytes=8 * 1024**3,
            identity_hash="b" * 64,
            dedicated_mount=True,
        ),
    )

    result = probe()

    assert result.capability is None
    assert result.code == "DOCKER_BUILD_HOST_OS_UNSUPPORTED"
    assert commands.calls == []


def test_containerd_or_non_dedicated_data_root_stays_blocked() -> None:
    containerd_info = _docker_info()
    containerd_info["DriverStatus"] = [["driver-type", "io.containerd.snapshotter.v1"]]
    containerd = ProductionDockerBuildBoundaryProbe(
        operating_system="linux",
        docker_executable=Path("/usr/bin/docker"),
        docker_host="unix:///run/user/1000/docker.sock",
        command_runner=_Commands(containerd_info, legacy_help=_LEGACY_HELP),
        data_root_inspector=lambda _path: DockerDataRootBoundary(
            total_bytes=8 * 1024**3,
            identity_hash="c" * 64,
            dedicated_mount=True,
        ),
        effective_user_id=1000,
    )
    shared_root = ProductionDockerBuildBoundaryProbe(
        operating_system="linux",
        docker_executable=Path("/usr/bin/docker"),
        docker_host="unix:///run/user/1000/docker.sock",
        command_runner=_Commands(_docker_info(), legacy_help=_LEGACY_HELP),
        data_root_inspector=lambda _path: DockerDataRootBoundary(
            total_bytes=8 * 1024**3,
            identity_hash="d" * 64,
            dedicated_mount=False,
        ),
        effective_user_id=1000,
    )

    assert containerd().code == "DOCKER_BUILD_IMAGE_STORE_UNSUPPORTED"
    assert shared_root().code == "DOCKER_BUILD_DISK_BOUNDARY_UNPROVEN"


def test_other_users_rootless_daemon_is_not_a_local_trusted_target() -> None:
    probe = ProductionDockerBuildBoundaryProbe(
        operating_system="linux",
        docker_executable=Path("/usr/bin/docker"),
        docker_host="unix:///run/user/2000/docker.sock",
        command_runner=_Commands(_docker_info(), legacy_help=_LEGACY_HELP),
        data_root_inspector=lambda _path: None,
        effective_user_id=1000,
    )

    result = probe()

    assert result.capability is None
    assert result.code == "DOCKER_BUILD_DAEMON_TARGET_UNTRUSTED"
