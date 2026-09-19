"""Closed Docker boundary for creating one Python CodeQL database.

The repository is read-only and the database is created on a size-bounded
tmpfs. The database is streamed out through a bounded fixed command while the
container is alive, after its exact Docker inspect record has been validated.
Publication into the immutable registry is owned by the operator service.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, replace
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Protocol

_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BOUND_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_NON_ROOT_USER = re.compile(r"^(?P<uid>[0-9]+):(?P<gid>[0-9]+)$")
_CONTAINER_NAME = re.compile(r"^sastsimi-codeql-provision-[0-9a-f]{24}$")
_REPARSE_POINT = 0x400
_SOURCE_TARGET = "/input/repository"
_DATABASE_TARGET = "/work/database"


class CodeQLProvisionBoundaryError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> CodeQLProvisionBoundaryError:
    return CodeQLProvisionBoundaryError(code)


def _link_like(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _trusted(path: Path, *, directory: bool) -> Path:
    try:
        if not path.is_absolute() or _link_like(path):
            raise ValueError
        info = path.lstat()
        exact = path.resolve(strict=True)
        if (
            exact != path.absolute()
            or int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and not stat.S_ISREG(info.st_mode))
        ):
            raise ValueError
    except (OSError, ValueError):
        raise _fail("CODEQL_PROVISION_PATH_INVALID") from None
    return exact


def _mount_text(path: Path) -> str:
    value = str(path)
    if any(character in value for character in ",\r\n\0"):
        raise _fail("CODEQL_PROVISION_MOUNT_FORBIDDEN")
    return value


@dataclass(frozen=True, slots=True)
class ContainerCodeQLProvisionSpec:
    docker_executable: Path
    image_digest: str
    repository_source: Path
    database_destination: Path
    action_id: str
    attempt_id: str
    user: str
    pids_limit: int
    memory_limit_bytes: int
    cpu_limit_millicores: int
    database_limit_bytes: int

    def __post_init__(self) -> None:
        identity = _NON_ROOT_USER.fullmatch(self.user)
        if _IMAGE_DIGEST.fullmatch(self.image_digest) is None:
            raise _fail("CODEQL_PROVISION_IMAGE_NOT_PINNED")
        if identity is None or 0 in {
            int(identity.group("uid")),
            int(identity.group("gid")),
        }:
            raise _fail("CODEQL_PROVISION_NON_ROOT_REQUIRED")
        if any(
            _BOUND_ID.fullmatch(value) is None
            for value in (self.action_id, self.attempt_id)
        ):
            raise _fail("CODEQL_PROVISION_ID_INVALID")
        if any(
            type(value) is not int or value <= 0
            for value in (
                self.pids_limit,
                self.memory_limit_bytes,
                self.cpu_limit_millicores,
                self.database_limit_bytes,
            )
        ):
            raise _fail("CODEQL_PROVISION_LIMIT_INVALID")
        docker = _trusted(self.docker_executable, directory=False)
        repository = _trusted(self.repository_source, directory=True)
        destination = _trusted(self.database_destination, directory=True)
        if (
            repository == destination
            or repository in destination.parents
            or destination in repository.parents
            or any(destination.iterdir())
        ):
            raise _fail("CODEQL_PROVISION_DESTINATION_INVALID")
        _mount_text(repository)
        object.__setattr__(self, "docker_executable", docker)
        object.__setattr__(self, "repository_source", repository)
        object.__setattr__(self, "database_destination", destination)


def _cpu_text(millicores: int) -> str:
    value = format(Decimal(millicores) / Decimal(1000), "f")
    return value.rstrip("0").rstrip(".") if "." in value else value


def _tmpfs(spec: ContainerCodeQLProvisionSpec) -> str:
    identity = _NON_ROOT_USER.fullmatch(spec.user)
    if identity is None:
        raise _fail("CODEQL_PROVISION_NON_ROOT_REQUIRED")
    return (
        f"{_DATABASE_TARGET}:rw,noexec,nosuid,nodev,"
        f"size={spec.database_limit_bytes},mode=0700,"
        f"uid={identity.group('uid')},gid={identity.group('gid')}"
    )


def _name(spec: ContainerCodeQLProvisionSpec) -> str:
    digest = hashlib.sha256(
        f"{spec.action_id}|{spec.attempt_id}".encode()
    ).hexdigest()[:24]
    return "sastsimi-codeql-provision-" + digest


def build_codeql_provision_create_argv(
    spec: ContainerCodeQLProvisionSpec,
) -> tuple[str, ...]:
    """Build the only admitted container command; no repository command enters it."""

    return (
        str(spec.docker_executable),
        "create",
        "--name",
        _name(spec),
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        spec.user,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(spec.pids_limit),
        "--cpus",
        _cpu_text(spec.cpu_limit_millicores),
        "--memory",
        str(spec.memory_limit_bytes),
        "--tmpfs",
        _tmpfs(spec),
        "--mount",
        (
            f"type=bind,src={_mount_text(spec.repository_source)},"
            f"dst={_SOURCE_TARGET},readonly"
        ),
        "--label",
        f"sastsimi.action-id={spec.action_id}",
        "--label",
        f"sastsimi.attempt-id={spec.attempt_id}",
        spec.image_digest,
        "provision-python",
    )


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError
    return value


def _empty(value: object) -> bool:
    return value is None or value == [] or value == ""


def validate_codeql_provision_inspect(
    record: Mapping[str, object], spec: ContainerCodeQLProvisionSpec
) -> None:
    try:
        config = _mapping(record.get("Config"))
        host = _mapping(record.get("HostConfig"))
        labels = _mapping(config.get("Labels"))
        tmpfs = _mapping(host.get("Tmpfs"))
        mounts = record.get("Mounts")
        security = host.get("SecurityOpt")
        if not isinstance(mounts, list) or not isinstance(security, list):
            raise ValueError
        if (
            config.get("Image") != spec.image_digest
            or config.get("User") != spec.user
            or config.get("Cmd") != ["provision-python"]
            or labels.get("sastsimi.action-id") != spec.action_id
            or labels.get("sastsimi.attempt-id") != spec.attempt_id
            or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or host.get("CapDrop") != ["ALL"]
            or not _empty(host.get("CapAdd"))
            or tuple(str(item) for item in security)
            not in (("no-new-privileges",), ("no-new-privileges:true",))
            or host.get("PidsLimit") != spec.pids_limit
            or host.get("Memory") != spec.memory_limit_bytes
            or host.get("NanoCpus") != spec.cpu_limit_millicores * 1_000_000
            or not _empty(host.get("Binds"))
            or not _empty(host.get("PidMode"))
            or host.get("IpcMode") not in (None, "", "private")
            or not _empty(host.get("Devices"))
            or not _empty(host.get("DeviceRequests"))
            or not _empty(host.get("VolumesFrom"))
            or set(tmpfs) != {_DATABASE_TARGET}
            or frozenset(str(tmpfs[_DATABASE_TARGET]).split(","))
            != frozenset(_tmpfs(spec).split(":", 1)[1].split(","))
        ):
            raise ValueError
        by_destination: dict[str, Mapping[str, object]] = {}
        for raw in mounts:
            mount = _mapping(raw)
            destination = mount.get("Destination")
            if not isinstance(destination, str) or destination in by_destination:
                raise ValueError
            by_destination[destination] = mount
        destinations = set(by_destination)
        if destinations not in (
            {_SOURCE_TARGET},
            {_SOURCE_TARGET, _DATABASE_TARGET},
        ):
            raise ValueError
        source = by_destination[_SOURCE_TARGET]
        if (
            source.get("Type") != "bind"
            or source.get("Source") != str(spec.repository_source)
            or source.get("RW") is not False
        ):
            raise ValueError
        if _DATABASE_TARGET in by_destination:
            database = by_destination[_DATABASE_TARGET]
            if database.get("Type") != "tmpfs" or database.get("RW") is not True:
                raise ValueError
    except (KeyError, TypeError, ValueError):
        raise _fail("CODEQL_PROVISION_INSPECT_MISMATCH") from None


class CodeQLProvisionStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class CodeQLProvisionResult:
    status: CodeQLProvisionStatus
    reason: str | None
    database_root: Path | None


class CodeQLProvisionDockerPort(Protocol):
    async def create(self, argv: tuple[str, ...]) -> None: ...

    async def inspect(self, container_name: str) -> Mapping[str, object]: ...

    async def start(self, container_name: str) -> None: ...

    async def wait_provision_ready(self, container_name: str) -> bool: ...

    async def copy_database(
        self, container_name: str, destination: Path, *, max_bytes: int
    ) -> None: ...

    async def remove(self, container_name: str) -> None: ...


def _valid_database(root: Path) -> bool:
    try:
        marker = root / "codeql-database.yml"
        info = marker.lstat()
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not _link_like(marker)
            and 0 < info.st_size <= 1024 * 1024
        )
    except OSError:
        return False


async def run_codeql_python_provision(
    *,
    port: CodeQLProvisionDockerPort,
    spec: ContainerCodeQLProvisionSpec,
    timeout_seconds: float,
    cleanup_timeout_seconds: float = 5.0,
) -> CodeQLProvisionResult:
    if timeout_seconds <= 0 or cleanup_timeout_seconds <= 0:
        raise ValueError("CODEQL_PROVISION_RUNTIME_LIMIT_INVALID")
    argv = build_codeql_provision_create_argv(spec)
    name = _name(spec)
    create_attempted = False
    result = CodeQLProvisionResult(
        CodeQLProvisionStatus.FAILED, "CODEQL_PROVISION_RUNTIME_ERROR", None
    )
    try:
        async with asyncio.timeout(timeout_seconds):
            create_attempted = True
            await port.create(argv)
            inspect = await port.inspect(name)
            validate_codeql_provision_inspect(inspect, spec)
            await port.start(name)
            if not await port.wait_provision_ready(name):
                result = replace(result, reason="CODEQL_PROVISION_EXIT_NONZERO")
            else:
                await port.copy_database(
                    name,
                    spec.database_destination,
                    max_bytes=spec.database_limit_bytes,
                )
                if not _valid_database(spec.database_destination):
                    result = replace(result, reason="CODEQL_PROVISION_DATABASE_INVALID")
                else:
                    result = CodeQLProvisionResult(
                        CodeQLProvisionStatus.SUCCEEDED,
                        None,
                        spec.database_destination,
                    )
    except TimeoutError:
        result = replace(
            result,
            status=CodeQLProvisionStatus.TIMED_OUT,
            reason="CODEQL_PROVISION_TIMEOUT",
        )
    except asyncio.CancelledError:
        result = replace(
            result,
            status=CodeQLProvisionStatus.CANCELLED,
            reason="CODEQL_PROVISION_CANCELLED",
        )
    except CodeQLProvisionBoundaryError as error:
        result = replace(result, reason=error.code)
    except Exception:
        result = replace(result, reason="CODEQL_PROVISION_RUNTIME_ERROR")
    if create_attempted:
        try:
            async with asyncio.timeout(cleanup_timeout_seconds):
                await port.remove(name)
        except Exception:
            result = CodeQLProvisionResult(
                CodeQLProvisionStatus.FAILED,
                "CODEQL_PROVISION_REMOVE_FAILED",
                None,
            )
    if result.status is not CodeQLProvisionStatus.SUCCEEDED:
        for candidate in tuple(spec.database_destination.iterdir()):
            if candidate.is_dir() and not _link_like(candidate):
                import shutil

                shutil.rmtree(candidate, ignore_errors=True)
            else:
                try:
                    candidate.unlink()
                except OSError:
                    pass
    return result


__all__ = [
    "CodeQLProvisionBoundaryError",
    "CodeQLProvisionDockerPort",
    "CodeQLProvisionResult",
    "CodeQLProvisionStatus",
    "ContainerCodeQLProvisionSpec",
    "build_codeql_provision_create_argv",
    "run_codeql_python_provision",
    "validate_codeql_provision_inspect",
]
