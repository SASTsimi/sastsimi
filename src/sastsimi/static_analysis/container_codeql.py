"""Pure Docker command and evidence boundary for a pinned CodeQL image.

This module does not invoke Docker and does not resolve a CodeQL provider.  It
constructs one closed command shape and validates the corresponding inspect
record so a later production adapter cannot silently weaken the boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BOUND_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_NON_ROOT_USER = re.compile(r"^(?P<uid>[0-9]+):(?P<gid>[0-9]+)$")
_REPARSE_POINT = 0x400
_DATABASE_TARGET = "/input/database"
_QUERY_TARGET = "/input/query-pack"
_DATABASE_WORK = "/work/database"
_OUTPUT_WORK = "/work/output"


class ContainerCodeQLBoundaryError(ValueError):
    """A safe, stable error that contains no submitted host path or payload."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> ContainerCodeQLBoundaryError:
    return ContainerCodeQLBoundaryError(code)


def _link_like(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _trusted_path(path: Path, *, directory: bool) -> Path:
    try:
        if not path.is_absolute() or _link_like(path):
            raise ValueError
        info = path.lstat()
        resolved = path.resolve(strict=True)
        if (
            resolved != path.absolute()
            or int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and not stat.S_ISREG(info.st_mode))
        ):
            raise ValueError
    except (OSError, ValueError):
        raise _fail("CODEQL_CONTAINER_PATH_INVALID") from None
    return resolved


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _mount_text(path: Path) -> str:
    value = str(path)
    if any(character in value for character in ",\r\n\0"):
        raise _fail("CODEQL_CONTAINER_MOUNT_FORBIDDEN")
    return value


@dataclass(frozen=True, slots=True)
class ContainerCodeQLSpec:
    """Exact, immutable inputs for one isolated CodeQL container attempt."""

    docker_executable: Path
    image_digest: str
    database_source: Path
    query_pack_source: Path
    workspace_root: Path
    action_id: str
    attempt_id: str
    user: str
    pids_limit: int
    memory_limit_bytes: int
    cpu_limit_millicores: int
    database_limit_bytes: int
    output_limit_bytes: int

    def __post_init__(self) -> None:
        if _IMAGE_DIGEST.fullmatch(self.image_digest) is None:
            raise _fail("CODEQL_CONTAINER_IMAGE_NOT_PINNED")
        identity = _NON_ROOT_USER.fullmatch(self.user)
        if identity is None or 0 in {
            int(identity.group("uid")),
            int(identity.group("gid")),
        }:
            raise _fail("CODEQL_CONTAINER_NON_ROOT_REQUIRED")
        if any(
            _BOUND_ID.fullmatch(value) is None
            for value in (self.action_id, self.attempt_id)
        ):
            raise _fail("CODEQL_CONTAINER_ID_INVALID")
        limits = (
            self.pids_limit,
            self.memory_limit_bytes,
            self.cpu_limit_millicores,
            self.database_limit_bytes,
            self.output_limit_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in limits):
            raise _fail("CODEQL_CONTAINER_LIMIT_INVALID")

        docker = _trusted_path(self.docker_executable, directory=False)
        database = _trusted_path(self.database_source, directory=True)
        query_pack = _trusted_path(self.query_pack_source, directory=True)
        workspace = _trusted_path(self.workspace_root, directory=True)
        if (
            _overlap(database, query_pack)
            or _overlap(database, workspace)
            or _overlap(query_pack, workspace)
        ):
            raise _fail("CODEQL_CONTAINER_MOUNT_FORBIDDEN")
        _mount_text(database)
        _mount_text(query_pack)
        object.__setattr__(self, "docker_executable", docker)
        object.__setattr__(self, "database_source", database)
        object.__setattr__(self, "query_pack_source", query_pack)
        object.__setattr__(self, "workspace_root", workspace)


def _cpu_text(millicores: int) -> str:
    value = format(Decimal(millicores) / Decimal(1000), "f")
    return value.rstrip("0").rstrip(".") if "." in value else value


def _tmpfs_argument(target: str, limit_bytes: int) -> str:
    return f"{target}:rw,noexec,nosuid,nodev,size={limit_bytes},mode=0700"


def _container_name(spec: ContainerCodeQLSpec) -> str:
    identity = f"{spec.action_id}|{spec.attempt_id}".encode()
    return "sastsimi-codeql-" + hashlib.sha256(identity).hexdigest()[:24]


def build_container_codeql_run_argv(spec: ContainerCodeQLSpec) -> tuple[str, ...]:
    """Return the only admitted Docker command for one CodeQL analysis.

    The pinned image owns the trusted fixed entrypoint.  Repository code,
    command text, environment values, host output directories, Docker sockets,
    and secrets are deliberately absent from this command.
    """

    return (
        str(spec.docker_executable),
        "run",
        "--name",
        _container_name(spec),
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
        _tmpfs_argument(_DATABASE_WORK, spec.database_limit_bytes),
        "--tmpfs",
        _tmpfs_argument(_OUTPUT_WORK, spec.output_limit_bytes),
        "--mount",
        f"type=bind,src={_mount_text(spec.database_source)},dst={_DATABASE_TARGET},readonly",
        "--mount",
        f"type=bind,src={_mount_text(spec.query_pack_source)},dst={_QUERY_TARGET},readonly",
        "--label",
        f"sastsimi.action-id={spec.action_id}",
        "--label",
        f"sastsimi.attempt-id={spec.attempt_id}",
        spec.image_digest,
    )


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _fail("CODEQL_CONTAINER_INSPECT_MISMATCH")
    return value


def _empty(value: object) -> bool:
    return value is None or value == [] or value == ""


def _tmpfs_options(target: str, limit_bytes: int) -> frozenset[str]:
    return frozenset(
        {"rw", "noexec", "nosuid", "nodev", f"size={limit_bytes}", "mode=0700"}
    )


def validate_container_inspect(
    record: Mapping[str, object], spec: ContainerCodeQLSpec
) -> None:
    """Validate Docker's post-create state against the issued exact request."""

    try:
        config = _mapping(record.get("Config"))
        host = _mapping(record.get("HostConfig"))
        labels = _mapping(config.get("Labels"))
        security_options = host.get("SecurityOpt")
        tmpfs = _mapping(host.get("Tmpfs"))
        mounts = record.get("Mounts")
        if not isinstance(security_options, list) or not isinstance(mounts, list):
            raise ValueError
        normalized_security = tuple(str(item) for item in security_options)
        if normalized_security not in (
            ("no-new-privileges",),
            ("no-new-privileges:true",),
        ):
            raise ValueError
        if (
            config.get("Image") != spec.image_digest
            or config.get("User") != spec.user
            or labels.get("sastsimi.action-id") != spec.action_id
            or labels.get("sastsimi.attempt-id") != spec.attempt_id
            or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or host.get("CapDrop") != ["ALL"]
            or not _empty(host.get("CapAdd"))
            or host.get("PidsLimit") != spec.pids_limit
            or host.get("Memory") != spec.memory_limit_bytes
            or host.get("NanoCpus") != spec.cpu_limit_millicores * 1_000_000
            or not _empty(host.get("Binds"))
            or not _empty(host.get("PidMode"))
            or host.get("IpcMode") not in (None, "", "private")
            or not _empty(host.get("Devices"))
            or not _empty(host.get("DeviceRequests"))
            or not _empty(host.get("VolumesFrom"))
            or set(tmpfs) != {_DATABASE_WORK, _OUTPUT_WORK}
            or frozenset(str(tmpfs[_DATABASE_WORK]).split(","))
            != _tmpfs_options(_DATABASE_WORK, spec.database_limit_bytes)
            or frozenset(str(tmpfs[_OUTPUT_WORK]).split(","))
            != _tmpfs_options(_OUTPUT_WORK, spec.output_limit_bytes)
        ):
            raise ValueError

        by_destination: dict[str, Mapping[str, object]] = {}
        for item in mounts:
            mount = _mapping(item)
            destination = mount.get("Destination")
            if not isinstance(destination, str) or destination in by_destination:
                raise ValueError
            by_destination[destination] = mount
        if set(by_destination) != {
            _DATABASE_TARGET,
            _QUERY_TARGET,
            _DATABASE_WORK,
            _OUTPUT_WORK,
        }:
            raise ValueError
        expected_binds = {
            _DATABASE_TARGET: spec.database_source,
            _QUERY_TARGET: spec.query_pack_source,
        }
        for destination, source in expected_binds.items():
            mount = by_destination[destination]
            if (
                mount.get("Type") != "bind"
                or mount.get("RW") is not False
                or mount.get("Source") != str(source)
            ):
                raise ValueError
        for destination in (_DATABASE_WORK, _OUTPUT_WORK):
            mount = by_destination[destination]
            if mount.get("Type") != "tmpfs" or mount.get("RW") is not True:
                raise ValueError
    except (ContainerCodeQLBoundaryError, KeyError, TypeError, ValueError):
        raise _fail("CODEQL_CONTAINER_INSPECT_MISMATCH") from None


def collect_bounded_stdout(chunks: Iterable[bytes], *, max_bytes: int) -> bytes:
    """Collect a byte stream without ever accepting more than ``max_bytes``."""

    if type(max_bytes) is not int or max_bytes <= 0:
        raise _fail("CODEQL_CONTAINER_STDOUT_LIMIT")
    result = bytearray()
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise _fail("CODEQL_CONTAINER_STDOUT_MALFORMED")
        if len(result) + len(chunk) > max_bytes:
            raise _fail("CODEQL_CONTAINER_STDOUT_LIMIT")
        result.extend(chunk)
    return bytes(result)


def validate_sarif_payload(payload: bytes, *, max_bytes: int) -> bytes:
    """Validate a bounded SARIF 2.1.0 envelope and preserve its exact bytes."""

    if (
        not isinstance(payload, bytes)
        or type(max_bytes) is not int
        or max_bytes <= 0
        or len(payload) > max_bytes
    ):
        raise _fail("CODEQL_CONTAINER_SARIF_LIMIT")
    try:
        decoded = json.loads(payload.decode("utf-8", errors="strict"))
        if (
            not isinstance(decoded, dict)
            or decoded.get("version") != "2.1.0"
            or not isinstance(decoded.get("runs"), list)
        ):
            raise ValueError
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _fail("CODEQL_CONTAINER_SARIF_MALFORMED") from None
    return payload


__all__ = [
    "ContainerCodeQLBoundaryError",
    "ContainerCodeQLSpec",
    "build_container_codeql_run_argv",
    "collect_bounded_stdout",
    "validate_container_inspect",
    "validate_sarif_payload",
]
