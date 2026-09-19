from __future__ import annotations

import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from sastsimi.static_analysis.container_codeql import (
    ContainerCodeQLBoundaryError,
    ContainerCodeQLSpec,
    build_container_codeql_run_argv,
    collect_bounded_stdout,
    validate_container_inspect,
    validate_sarif_payload,
)


def _spec() -> ContainerCodeQLSpec:
    root = Path(__file__).resolve().parents[3]
    return ContainerCodeQLSpec(
        docker_executable=Path(sys.executable).resolve(),
        image_digest="sha256:" + "a" * 64,
        database_source=root / "src",
        query_pack_source=root / "tests",
        workspace_root=root / "docs",
        action_id="action-123",
        attempt_id="attempt-456",
        user="65532:65532",
        pids_limit=64,
        memory_limit_bytes=536_870_912,
        cpu_limit_millicores=500,
        database_limit_bytes=268_435_456,
        output_limit_bytes=16_777_216,
    )


def _inspect(spec: ContainerCodeQLSpec) -> dict[str, object]:
    return {
        "Config": {
            "Image": spec.image_digest,
            "User": spec.user,
            "Labels": {
                "sastsimi.action-id": spec.action_id,
                "sastsimi.attempt-id": spec.attempt_id,
            },
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": spec.pids_limit,
            "Memory": spec.memory_limit_bytes,
            "NanoCpus": spec.cpu_limit_millicores * 1_000_000,
            "Binds": None,
            "PidMode": "",
            "IpcMode": "private",
            "Devices": [],
            "DeviceRequests": None,
            "VolumesFrom": None,
            "Tmpfs": {
                "/work/database": ("rw,noexec,nosuid,nodev,size=268435456,mode=0700"),
                "/work/output": "rw,noexec,nosuid,nodev,size=16777216,mode=0700",
            },
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(spec.database_source.resolve()),
                "Destination": "/input/database",
                "RW": False,
            },
            {
                "Type": "bind",
                "Source": str(spec.query_pack_source.resolve()),
                "Destination": "/input/query-pack",
                "RW": False,
            },
            {
                "Type": "tmpfs",
                "Destination": "/work/database",
                "RW": True,
            },
            {
                "Type": "tmpfs",
                "Destination": "/work/output",
                "RW": True,
            },
        ],
    }


def test_run_argv_has_only_the_fixed_codeql_container_boundary() -> None:
    """Removing any required boundary argument must change this literal command."""

    spec = _spec()

    argv = build_container_codeql_run_argv(spec)

    assert argv == (
        str(spec.docker_executable.resolve()),
        "run",
        "--name",
        "sastsimi-codeql-68aa90a6f9fb88217375de7f",
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--cpus",
        "0.5",
        "--memory",
        "536870912",
        "--tmpfs",
        "/work/database:rw,noexec,nosuid,nodev,size=268435456,mode=0700",
        "--tmpfs",
        "/work/output:rw,noexec,nosuid,nodev,size=16777216,mode=0700",
        "--mount",
        f"type=bind,src={spec.database_source.resolve()},dst=/input/database,readonly",
        "--mount",
        f"type=bind,src={spec.query_pack_source.resolve()},dst=/input/query-pack,readonly",
        "--label",
        "sastsimi.action-id=action-123",
        "--label",
        "sastsimi.attempt-id=attempt-456",
        "sha256:" + "a" * 64,
    )
    assert "--privileged" not in argv
    assert "/var/run/docker.sock" not in " ".join(argv)
    assert str(spec.workspace_root.resolve()) not in argv


@pytest.mark.parametrize(
    ("replace", "code"),
    [
        ({"image_digest": "latest"}, "CODEQL_CONTAINER_IMAGE_NOT_PINNED"),
        ({"user": "0:0"}, "CODEQL_CONTAINER_NON_ROOT_REQUIRED"),
        ({"user": "00:65532"}, "CODEQL_CONTAINER_NON_ROOT_REQUIRED"),
        ({"action_id": "unsafe\nlabel"}, "CODEQL_CONTAINER_ID_INVALID"),
        ({"attempt_id": ""}, "CODEQL_CONTAINER_ID_INVALID"),
        ({"pids_limit": 0}, "CODEQL_CONTAINER_LIMIT_INVALID"),
        ({"memory_limit_bytes": 0}, "CODEQL_CONTAINER_LIMIT_INVALID"),
        ({"cpu_limit_millicores": 0}, "CODEQL_CONTAINER_LIMIT_INVALID"),
        ({"database_limit_bytes": 0}, "CODEQL_CONTAINER_LIMIT_INVALID"),
        ({"output_limit_bytes": 0}, "CODEQL_CONTAINER_LIMIT_INVALID"),
    ],
)
def test_spec_rejects_substitutable_identity_and_unbounded_resources(
    replace: dict[str, object], code: str
) -> None:
    """Relaxing an identity or resource field must fail before Docker is invoked."""

    original = _spec()
    fields = {
        name: getattr(original, name)
        for name in ContainerCodeQLSpec.__dataclass_fields__
    }
    fields.update(replace)

    with pytest.raises(ContainerCodeQLBoundaryError, match=f"^{code}$"):
        ContainerCodeQLSpec(**fields)


def test_spec_rejects_database_or_query_mount_overlapping_workspace() -> None:
    """A disguised workspace mount must never become a database/query input."""

    spec = _spec()
    inside_workspace = spec.workspace_root / "architecture-v5"
    fields = {
        name: getattr(spec, name) for name in ContainerCodeQLSpec.__dataclass_fields__
    }
    fields["database_source"] = inside_workspace

    with pytest.raises(
        ContainerCodeQLBoundaryError, match="^CODEQL_CONTAINER_MOUNT_FORBIDDEN$"
    ):
        ContainerCodeQLSpec(**fields)


def test_inspect_accepts_only_the_exact_requested_boundary() -> None:
    """A complete inspect record for the issued request must validate."""

    spec = _spec()

    validate_container_inspect(_inspect(spec), spec)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["Config"].__setitem__("Image", "sha256:" + "b" * 64),
        lambda value: value["Config"].__setitem__("User", "0:0"),
        lambda value: value["Config"]["Labels"].__setitem__(
            "sastsimi.attempt-id", "other-attempt"
        ),
        lambda value: value["HostConfig"].__setitem__("NetworkMode", "bridge"),
        lambda value: value["HostConfig"].__setitem__("ReadonlyRootfs", False),
        lambda value: value["HostConfig"].__setitem__("Privileged", True),
        lambda value: value["HostConfig"].__setitem__("CapDrop", []),
        lambda value: value["HostConfig"].__setitem__("CapAdd", ["SYS_ADMIN"]),
        lambda value: value["HostConfig"].__setitem__("SecurityOpt", []),
        lambda value: value["HostConfig"].__setitem__("PidsLimit", 128),
        lambda value: value["HostConfig"].__setitem__("Memory", 1_073_741_824),
        lambda value: value["HostConfig"].__setitem__("NanoCpus", 1_000_000_000),
        lambda value: value["HostConfig"].__setitem__("Binds", ["/:/host:rw"]),
        lambda value: value["HostConfig"]["Tmpfs"].__setitem__(
            "/work/output", "rw,size=16777216"
        ),
        lambda value: value["Mounts"].append(
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            }
        ),
        lambda value: value["Mounts"][0].__setitem__("RW", True),
    ],
)
def test_inspect_rejects_security_or_mount_substitution(
    mutate: Callable[[dict[str, object]], object],
) -> None:
    """Any weaker runtime boundary must invalidate the completed attempt."""

    spec = _spec()
    actual = copy.deepcopy(_inspect(spec))
    mutate(actual)

    with pytest.raises(
        ContainerCodeQLBoundaryError, match="^CODEQL_CONTAINER_INSPECT_MISMATCH$"
    ):
        validate_container_inspect(actual, spec)


def test_stdout_collection_is_incremental_and_bounded() -> None:
    """A child cannot make the parent retain stdout beyond the approved cap."""

    assert collect_bounded_stdout((b"ab", b"cd"), max_bytes=4) == b"abcd"

    with pytest.raises(
        ContainerCodeQLBoundaryError, match="^CODEQL_CONTAINER_STDOUT_LIMIT$"
    ):
        collect_bounded_stdout((b"ab", b"cde"), max_bytes=4)


@pytest.mark.parametrize(
    ("payload", "max_bytes", "code"),
    [
        (b"", 100, "CODEQL_CONTAINER_SARIF_MALFORMED"),
        (b"not-json", 100, "CODEQL_CONTAINER_SARIF_MALFORMED"),
        (b"\xff", 100, "CODEQL_CONTAINER_SARIF_MALFORMED"),
        (b"[]", 100, "CODEQL_CONTAINER_SARIF_MALFORMED"),
        (b'{"version":"2.0.0","runs":[]}', 100, "CODEQL_CONTAINER_SARIF_MALFORMED"),
        (b'{"version":"2.1.0","runs":{}}', 100, "CODEQL_CONTAINER_SARIF_MALFORMED"),
        (
            b'{"version":"2.1.0","runs":[]}',
            8,
            "CODEQL_CONTAINER_SARIF_LIMIT",
        ),
    ],
)
def test_sarif_validation_fails_closed_for_malformed_or_oversized_payload(
    payload: bytes, max_bytes: int, code: str
) -> None:
    """Malformed or over-limit data must never be decoded as CodeQL evidence."""

    with pytest.raises(ContainerCodeQLBoundaryError, match=f"^{code}$"):
        validate_sarif_payload(payload, max_bytes=max_bytes)


def test_sarif_validation_preserves_the_exact_valid_payload() -> None:
    """Validation must not rewrite the bytes whose digest is later recorded."""

    payload = json.dumps(
        {"version": "2.1.0", "runs": []}, separators=(",", ":")
    ).encode()

    assert validate_sarif_payload(payload, max_bytes=len(payload)) is payload
