from __future__ import annotations

import copy
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from sastsimi.static_analysis.container_codeql_provision import (
    CodeQLProvisionStatus,
    ContainerCodeQLProvisionSpec,
    build_codeql_provision_create_argv,
    run_codeql_python_provision,
)


def _spec(tmp_path: Path) -> ContainerCodeQLProvisionSpec:
    repository = tmp_path / "repository"
    repository.mkdir()
    destination = tmp_path / "database"
    destination.mkdir()
    return ContainerCodeQLProvisionSpec(
        docker_executable=Path(sys.executable).resolve(),
        image_digest="sha256:" + "a" * 64,
        repository_source=repository,
        database_destination=destination,
        action_id="action-provision",
        attempt_id="attempt-provision",
        user="65532:65532",
        pids_limit=64,
        memory_limit_bytes=536_870_912,
        cpu_limit_millicores=500,
        database_limit_bytes=268_435_456,
    )


def _inspect(spec: ContainerCodeQLProvisionSpec) -> dict[str, object]:
    return {
        "Config": {
            "Image": spec.image_digest,
            "User": spec.user,
            "Cmd": ["provision-python"],
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
                "/work/database": (
                    "rw,noexec,nosuid,nodev,size=268435456,mode=0700,"
                    "uid=65532,gid=65532"
                )
            },
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(spec.repository_source),
                "Destination": "/input/repository",
                "RW": False,
            },
            {"Type": "tmpfs", "Destination": "/work/database", "RW": True},
        ],
    }


def test_provision_command_is_fixed_offline_non_root_and_resource_bounded(
    tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)

    argv = build_codeql_provision_create_argv(spec)

    assert argv == (
        str(spec.docker_executable),
        "create",
        "--name",
        "sastsimi-codeql-provision-796cce1f1eafe4a9f441d9a4",
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
        (
            "/work/database:rw,noexec,nosuid,nodev,size=268435456,mode=0700,"
            "uid=65532,gid=65532"
        ),
        "--mount",
        f"type=bind,src={spec.repository_source},dst=/input/repository,readonly",
        "--label",
        "sastsimi.action-id=action-provision",
        "--label",
        "sastsimi.attempt-id=attempt-provision",
        spec.image_digest,
        "provision-python",
    )
    wire = " ".join(argv)
    assert "/var/run/docker.sock" not in wire
    assert "--env" not in argv
    assert "--privileged" not in argv
    assert str(spec.database_destination) not in wire


class _Port:
    def __init__(self, spec: ContainerCodeQLProvisionSpec) -> None:
        self.spec = spec
        self.inspect_record: Mapping[str, object] = _inspect(spec)
        self.ready = True
        self.operations: list[str] = []

    async def create(self, argv: tuple[str, ...]) -> None:
        self.operations.append("create")
        image_position = argv.index(self.spec.image_digest)
        record = copy.deepcopy(dict(self.inspect_record))
        cast(dict[str, object], record["Config"])["Cmd"] = list(
            argv[image_position + 1 :]
        )
        self.inspect_record = record

    async def inspect(self, container_name: str) -> Mapping[str, object]:
        del container_name
        self.operations.append("inspect")
        return self.inspect_record

    async def start(self, container_name: str) -> None:
        del container_name
        self.operations.append("start")

    async def wait_provision_ready(self, container_name: str) -> bool:
        del container_name
        self.operations.append("ready")
        return self.ready

    async def copy_database(
        self, container_name: str, destination: Path, *, max_bytes: int
    ) -> None:
        del container_name
        assert max_bytes == self.spec.database_limit_bytes
        self.operations.append("copy")
        (destination / "codeql-database.yml").write_text(
            "primaryLanguage: python\n", encoding="utf-8"
        )

    async def remove(self, container_name: str) -> None:
        del container_name
        self.operations.append("remove")


@pytest.mark.asyncio
async def test_provision_validates_before_start_and_copies_only_after_success(
    tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    port = _Port(spec)

    result = await run_codeql_python_provision(
        port=port,
        spec=spec,
        timeout_seconds=1,
    )

    assert result.status is CodeQLProvisionStatus.SUCCEEDED
    assert result.reason is None
    assert result.database_root == spec.database_destination
    assert port.operations == [
        "create",
        "inspect",
        "start",
        "ready",
        "copy",
        "remove",
    ]


@pytest.mark.asyncio
async def test_provision_accepts_tmpfs_reported_only_in_host_config(
    tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    port = _Port(spec)
    record = copy.deepcopy(_inspect(spec))
    record["Mounts"] = [
        item
        for item in cast(list[dict[str, object]], record["Mounts"])
        if item["Type"] != "tmpfs"
    ]
    port.inspect_record = record

    result = await run_codeql_python_provision(
        port=port,
        spec=spec,
        timeout_seconds=1,
    )

    assert result.status is CodeQLProvisionStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_provision_boundary_mismatch_never_copies_or_accepts_a_database(
    tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    port = _Port(spec)
    record = copy.deepcopy(_inspect(spec))
    cast(dict[str, object], record["HostConfig"])["NetworkMode"] = "bridge"
    port.inspect_record = record

    result = await run_codeql_python_provision(
        port=port,
        spec=spec,
        timeout_seconds=1,
    )

    assert result.status is CodeQLProvisionStatus.FAILED
    assert result.reason == "CODEQL_PROVISION_INSPECT_MISMATCH"
    assert result.database_root is None
    assert port.operations == ["create", "inspect", "remove"]
    assert tuple(spec.database_destination.iterdir()) == ()


@pytest.mark.asyncio
async def test_provision_nonzero_exit_is_not_a_published_empty_database(
    tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    port = _Port(spec)
    port.ready = False

    result = await run_codeql_python_provision(
        port=port,
        spec=spec,
        timeout_seconds=1,
    )

    assert result.status is CodeQLProvisionStatus.FAILED
    assert result.reason == "CODEQL_PROVISION_EXIT_NONZERO"
    assert result.database_root is None
    assert "copy" not in port.operations
    assert tuple(spec.database_destination.iterdir()) == ()
