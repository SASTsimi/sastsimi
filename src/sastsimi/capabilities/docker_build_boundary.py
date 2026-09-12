"""Fail-closed production proof for Docker build resource boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol, cast

from sastsimi.contracts.capabilities import (
    CapabilityOperatingSystem,
    DockerBuildCapability,
)

from .probes import CommandObservation

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ROOTLESS_DOCKER_HOST = re.compile(
    r"^unix:///run/user/(?P<uid>[1-9][0-9]*)/docker\.sock$"
)
_CLASSIC_STORAGE_DRIVERS = frozenset({"overlay2", "btrfs", "zfs", "vfs"})
_REQUIRED_LEGACY_OPTIONS = (
    "--cpu-period",
    "--cpu-quota",
    "--memory",
    "--network",
    "--ulimit",
)

type DockerBuildBoundaryCode = Literal[
    "DOCKER_BUILD_BOUNDARY_PRECHECK_PASSED",
    "DOCKER_BUILD_HOST_OS_UNSUPPORTED",
    "DOCKER_BUILD_DAEMON_TARGET_UNTRUSTED",
    "DOCKER_BUILD_DAEMON_INFO_UNAVAILABLE",
    "DOCKER_BUILD_DAEMON_LIMITS_UNSUPPORTED",
    "DOCKER_BUILD_DAEMON_NOT_DEDICATED",
    "DOCKER_BUILD_IMAGE_STORE_UNSUPPORTED",
    "DOCKER_BUILD_DISK_BOUNDARY_UNPROVEN",
    "DOCKER_BUILD_LEGACY_BACKEND_UNSUPPORTED",
]


class DockerBoundaryCommandRunner(Protocol):
    def run(
        self,
        executable: Path,
        arguments: tuple[str, ...],
        *,
        timeout_ms: int,
        environment_overrides: Mapping[str, str] | None = None,
    ) -> CommandObservation: ...


class _StatVfsResult(Protocol):
    f_frsize: int
    f_blocks: int


@dataclass(frozen=True, slots=True)
class DockerDataRootBoundary:
    """Host-observed hard capacity of the daemon's whole classic data root."""

    total_bytes: int
    identity_hash: str
    dedicated_mount: bool

    def __post_init__(self) -> None:
        if self.total_bytes <= 0 or _DIGEST.fullmatch(self.identity_hash) is None:
            raise ValueError("DOCKER_DATA_ROOT_BOUNDARY_INVALID")


@dataclass(frozen=True, slots=True)
class DockerBuildBoundaryProbeResult:
    """Sanitized precheck result; actual controlled build is a separate gate."""

    code: DockerBuildBoundaryCode
    capability: DockerBuildCapability | None = None
    storage_identity_hash: str | None = None

    @property
    def safe_summary(self) -> str:
        return {
            "DOCKER_BUILD_BOUNDARY_PRECHECK_PASSED": (
                "Docker build boundary precheck passed; controlled build is required"
            ),
            "DOCKER_BUILD_HOST_OS_UNSUPPORTED": (
                "Docker build hard-limit proof requires a supported Linux host"
            ),
            "DOCKER_BUILD_DAEMON_TARGET_UNTRUSTED": (
                "Docker daemon target is not the approved local system "
                "or current-user socket"
            ),
            "DOCKER_BUILD_DAEMON_INFO_UNAVAILABLE": (
                "Docker daemon boundary information is unavailable"
            ),
            "DOCKER_BUILD_DAEMON_LIMITS_UNSUPPORTED": (
                "Docker daemon cannot enforce all CPU, memory, and process limits"
            ),
            "DOCKER_BUILD_DAEMON_NOT_DEDICATED": (
                "Docker daemon is not marked as dedicated to SASTSIMI"
            ),
            "DOCKER_BUILD_IMAGE_STORE_UNSUPPORTED": (
                "Docker image store cannot be proven to stay under "
                "one bounded data root"
            ),
            "DOCKER_BUILD_DISK_BOUNDARY_UNPROVEN": (
                "Docker build cache and image output have no proven hard disk boundary"
            ),
            "DOCKER_BUILD_LEGACY_BACKEND_UNSUPPORTED": (
                "Docker legacy builder cannot enforce the required build-step limits"
            ),
        }[self.code]


class ProductionDockerBuildBoundaryProbe:
    """Prove an already provisioned local Docker boundary without changing the host."""

    def __init__(
        self,
        *,
        operating_system: CapabilityOperatingSystem,
        docker_executable: Path | None,
        docker_host: str | None,
        command_runner: DockerBoundaryCommandRunner,
        data_root_inspector: Callable[[Path], DockerDataRootBoundary | None],
        effective_user_id: int | None = None,
    ) -> None:
        self._operating_system = operating_system
        self._docker_executable = docker_executable
        self._docker_host = docker_host
        self._commands = command_runner
        self._inspect_data_root = data_root_inspector
        self._effective_user_id = effective_user_id

    def __call__(self) -> DockerBuildBoundaryProbeResult:
        if self._operating_system != "linux":
            return self._blocked("DOCKER_BUILD_HOST_OS_UNSUPPORTED")
        if self._docker_executable is None or not self._trusted_local_host():
            return self._blocked("DOCKER_BUILD_DAEMON_TARGET_UNTRUSTED")
        info = self._docker_info()
        if info is None:
            return self._blocked("DOCKER_BUILD_DAEMON_INFO_UNAVAILABLE")
        if not all(
            info.get(field) is True
            for field in ("MemoryLimit", "CpuCfsPeriod", "CpuCfsQuota", "PidsLimit")
        ):
            return self._blocked("DOCKER_BUILD_DAEMON_LIMITS_UNSUPPORTED")
        labels = info.get("Labels")
        if not isinstance(labels, list) or "sastsimi.dedicated=true" not in labels:
            return self._blocked("DOCKER_BUILD_DAEMON_NOT_DEDICATED")
        if not self._classic_image_store(info):
            return self._blocked("DOCKER_BUILD_IMAGE_STORE_UNSUPPORTED")
        root_text = info.get("DockerRootDir")
        if not isinstance(root_text, str) or not self._safe_absolute_path(root_text):
            return self._blocked("DOCKER_BUILD_DISK_BOUNDARY_UNPROVEN")
        boundary = self._inspect_data_root(Path(root_text))
        if boundary is None or not boundary.dedicated_mount:
            return self._blocked("DOCKER_BUILD_DISK_BOUNDARY_UNPROVEN")
        if not self._legacy_builder_supports_limits():
            return self._blocked("DOCKER_BUILD_LEGACY_BACKEND_UNSUPPORTED")
        capability = DockerBuildCapability(
            build_backend="LEGACY_LIMITED",
            enforced_build_limits=("CPU", "MEMORY", "PID", "DISK"),
            external_build_disk_limit_bytes=boundary.total_bytes,
            external_build_storage_identity_hash=boundary.identity_hash,
        )
        return DockerBuildBoundaryProbeResult(
            code="DOCKER_BUILD_BOUNDARY_PRECHECK_PASSED",
            capability=capability,
            storage_identity_hash=boundary.identity_hash,
        )

    def _trusted_local_host(self) -> bool:
        host = self._docker_host
        if host in {"unix:///var/run/docker.sock", "unix:///run/docker.sock"}:
            return True
        if host is None or self._effective_user_id is None:
            return False
        match = _ROOTLESS_DOCKER_HOST.fullmatch(host)
        return match is not None and int(match.group("uid")) == self._effective_user_id

    def _docker_info(self) -> dict[str, object] | None:
        assert self._docker_executable is not None
        assert self._docker_host is not None
        observed = self._commands.run(
            self._docker_executable,
            ("--host", self._docker_host, "info", "--format", "{{json .}}"),
            timeout_ms=15_000,
        )
        if not observed.succeeded or observed.safe_stdout is None:
            return None
        try:
            parsed = json.loads(observed.safe_stdout)
        except (TypeError, ValueError):
            return None
        if not isinstance(parsed, dict):
            return None
        if (
            not isinstance(parsed.get("ID"), str)
            or not parsed["ID"]
            or parsed.get("OSType") != "linux"
        ):
            return None
        return cast(dict[str, object], parsed)

    @staticmethod
    def _classic_image_store(info: dict[str, object]) -> bool:
        if info.get("Driver") not in _CLASSIC_STORAGE_DRIVERS:
            return False
        status = info.get("DriverStatus")
        if not isinstance(status, list):
            return False
        flattened = " ".join(
            str(value) for row in status if isinstance(row, list) for value in row
        ).lower()
        return "containerd.snapshotter" not in flattened

    def _legacy_builder_supports_limits(self) -> bool:
        assert self._docker_executable is not None
        assert self._docker_host is not None
        observed = self._commands.run(
            self._docker_executable,
            ("--host", self._docker_host, "image", "build", "--help"),
            timeout_ms=15_000,
            environment_overrides={"DOCKER_BUILDKIT": "0"},
        )
        return bool(
            observed.succeeded
            and observed.safe_stdout is not None
            and all(
                option in observed.safe_stdout for option in _REQUIRED_LEGACY_OPTIONS
            )
        )

    @staticmethod
    def _safe_absolute_path(value: str) -> bool:
        parsed = PurePosixPath(value)
        return bool(
            value
            and len(value) <= 1024
            and not any(ord(character) < 32 for character in value)
            and parsed.is_absolute()
            and ".." not in parsed.parts
        )

    @staticmethod
    def _blocked(code: DockerBuildBoundaryCode) -> DockerBuildBoundaryProbeResult:
        return DockerBuildBoundaryProbeResult(code=code)


def inspect_local_docker_data_root(path: Path) -> DockerDataRootBoundary | None:
    """Read only filesystem identity/capacity; never mount or configure a quota."""

    if os.name != "posix" or not path.is_absolute() or path == Path("/"):
        return None
    try:
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            if stat.S_ISLNK(current.lstat().st_mode):
                return None
        resolved = path.resolve(strict=True)
        if resolved != path or not resolved.is_dir() or not os.path.ismount(resolved):
            return None
        root_stat = resolved.stat()
        if root_stat.st_dev == resolved.parent.stat().st_dev:
            return None
        statvfs = cast(Callable[[Path], _StatVfsResult], os.__dict__["statvfs"])
        filesystem = statvfs(resolved)
        total_bytes = filesystem.f_frsize * filesystem.f_blocks
        if total_bytes <= 0:
            return None
        identity = hashlib.sha256(
            f"{root_stat.st_dev}:{root_stat.st_ino}:{filesystem.f_frsize}:"
            f"{filesystem.f_blocks}".encode()
        ).hexdigest()
    except (OSError, ValueError):
        return None
    return DockerDataRootBoundary(
        total_bytes=total_bytes,
        identity_hash=identity,
        dedicated_mount=True,
    )


__all__ = [
    "DockerBuildBoundaryProbeResult",
    "DockerDataRootBoundary",
    "ProductionDockerBuildBoundaryProbe",
    "inspect_local_docker_data_root",
]
