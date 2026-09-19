from __future__ import annotations

import asyncio
import copy
import json
import sys
from collections.abc import AsyncIterator, Mapping
from pathlib import Path

import pytest

from sastsimi.static_analysis.container_codeql import ContainerCodeQLSpec
from sastsimi.static_analysis.container_codeql_runtime import (
    CodeQLArtifactIdentity,
    CodeQLContainerRunStatus,
    ContainerCodeQLProbeObservation,
    ContainerCodeQLProbeRequest,
    TmpfsCapDenialEvidence,
    probe_container_codeql_boundary,
    run_container_codeql,
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


def _identity() -> CodeQLArtifactIdentity:
    return CodeQLArtifactIdentity(
        database_digest="sha256:" + "b" * 64,
        tracked_manifest_digest="sha256:" + "c" * 64,
        query_digest="sha256:" + "d" * 64,
    )


def _inspect(spec: ContainerCodeQLSpec) -> dict[str, object]:
    return {
        "Config": {
            "Image": spec.image_digest,
            "User": spec.user,
            "Cmd": ["analyze"],
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
                ),
                "/work/output": (
                    "rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=65532,gid=65532"
                ),
            },
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(spec.database_source),
                "Destination": "/input/database",
                "RW": False,
            },
            {
                "Type": "bind",
                "Source": str(spec.query_pack_source),
                "Destination": "/input/query-pack",
                "RW": False,
            },
            {"Type": "tmpfs", "Destination": "/work/database", "RW": True},
            {"Type": "tmpfs", "Destination": "/work/output", "RW": True},
        ],
    }


def _sarif() -> bytes:
    return json.dumps({"version": "2.1.0", "runs": []}, separators=(",", ":")).encode()


class FakeDockerPort:
    def __init__(self, spec: ContainerCodeQLSpec) -> None:
        self.spec = spec
        self.operations: list[tuple[str, object]] = []
        self.inspect_record: Mapping[str, object] = _inspect(spec)
        self.exit_code = 0
        self.stdout_chunks: tuple[bytes, ...] = (_sarif(),)
        self.failure_operation: str | None = None
        self.wait_forever = False
        self.remove_failure = False
        self.probe_observation = ContainerCodeQLProbeObservation(
            image_digest=spec.image_digest,
            codeql_version="2.23.1",
            database=TmpfsCapDenialEvidence(
                target="/work/database",
                limit_bytes=spec.database_limit_bytes,
                attempted_bytes=spec.database_limit_bytes + 1,
                bytes_written=spec.database_limit_bytes,
                denial_code="ENOSPC",
            ),
            output=TmpfsCapDenialEvidence(
                target="/work/output",
                limit_bytes=spec.output_limit_bytes,
                attempted_bytes=spec.output_limit_bytes + 1,
                bytes_written=spec.output_limit_bytes,
                denial_code="ENOSPC",
            ),
        )

    def _fail(self, operation: str) -> None:
        if self.failure_operation == operation:
            raise RuntimeError("host path and secret must not escape")

    async def create(self, argv: tuple[str, ...]) -> None:
        self.operations.append(("create", argv))
        self._fail("create")
        image_position = argv.index(self.spec.image_digest)
        mutable = copy.deepcopy(self.inspect_record)
        mutable["Config"]["Cmd"] = list(argv[image_position + 1 :])
        self.inspect_record = mutable

    async def start(self, container_name: str) -> None:
        self.operations.append(("start", container_name))
        self._fail("start")

    async def inspect(self, container_name: str) -> Mapping[str, object]:
        self.operations.append(("inspect", container_name))
        self._fail("inspect")
        return self.inspect_record

    async def wait(self, container_name: str) -> int:
        self.operations.append(("wait", container_name))
        self._fail("wait")
        if self.failure_operation == "cancel":
            raise asyncio.CancelledError
        if self.wait_forever:
            await asyncio.Event().wait()
        return self.exit_code

    def logs(self, container_name: str) -> AsyncIterator[bytes]:
        self.operations.append(("logs", container_name))

        async def stream() -> AsyncIterator[bytes]:
            self._fail("logs")
            for chunk in self.stdout_chunks:
                yield chunk

        return stream()

    async def probe(
        self, container_name: str, request: ContainerCodeQLProbeRequest
    ) -> ContainerCodeQLProbeObservation:
        self.operations.append(("probe", (container_name, request)))
        self._fail("probe")
        return self.probe_observation

    async def remove(self, container_name: str) -> None:
        self.operations.append(("remove", container_name))
        if self.remove_failure:
            raise RuntimeError("unsafe daemon detail")


@pytest.mark.asyncio
async def test_run_uses_exact_lifecycle_and_returns_bound_artifact_identity() -> None:
    spec = _spec()
    port = FakeDockerPort(spec)

    result = await run_container_codeql(
        port=port,
        spec=spec,
        artifact_identity=_identity(),
        timeout_seconds=1,
        stdout_limit_bytes=1024,
    )

    expected_name = "sastsimi-codeql-68aa90a6f9fb88217375de7f"
    assert [operation for operation, _value in port.operations] == [
        "create",
        "inspect",
        "start",
        "wait",
        "logs",
        "remove",
    ]
    create_argv = port.operations[0][1]
    assert isinstance(create_argv, tuple)
    assert create_argv[create_argv.index("--name") + 1] == expected_name
    assert create_argv[-1] == "analyze"
    assert all(value == expected_name for _operation, value in port.operations[1:])
    assert result.status is CodeQLContainerRunStatus.SUCCEEDED
    assert result.raw_sarif == _sarif()
    assert result.reason is None
    assert result.image_digest == spec.image_digest
    assert result.database_digest == _identity().database_digest
    assert result.tracked_manifest_digest == _identity().tracked_manifest_digest
    assert result.query_digest == _identity().query_digest


@pytest.mark.asyncio
async def test_create_failure_is_not_masked_by_cleanup_failure() -> None:
    spec = _spec()
    port = FakeDockerPort(spec)
    port.failure_operation = "create"
    port.remove_failure = True

    result = await run_container_codeql(
        port=port,
        spec=spec,
        artifact_identity=_identity(),
        timeout_seconds=1,
        stdout_limit_bytes=1024,
    )

    assert result.status is CodeQLContainerRunStatus.FAILED
    assert result.reason == "CODEQL_CONTAINER_RUNTIME_ERROR"
    assert [operation for operation, _value in port.operations] == [
        "create",
        "remove",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "expected_reason"),
    [
        ("inspect", "CODEQL_CONTAINER_INSPECT_MISMATCH"),
        ("exit", "CODEQL_CONTAINER_EXIT_NONZERO"),
        ("malformed", "CODEQL_CONTAINER_SARIF_MALFORMED"),
        ("over-limit", "CODEQL_CONTAINER_STDOUT_LIMIT"),
        ("crash", "CODEQL_CONTAINER_RUNTIME_ERROR"),
    ],
)
async def test_run_fails_closed_and_removes_only_the_exact_container(
    case: str, expected_reason: str
) -> None:
    spec = _spec()
    port = FakeDockerPort(spec)
    if case == "inspect":
        weakened = copy.deepcopy(_inspect(spec))
        weakened["HostConfig"]["NetworkMode"] = "bridge"
        port.inspect_record = weakened
    elif case == "exit":
        port.exit_code = 9
    elif case == "malformed":
        port.stdout_chunks = (b"not-sarif",)
    elif case == "over-limit":
        port.stdout_chunks = (b"x" * 17,)
    else:
        port.failure_operation = "wait"

    result = await run_container_codeql(
        port=port,
        spec=spec,
        artifact_identity=_identity(),
        timeout_seconds=1,
        stdout_limit_bytes=16 if case == "over-limit" else 1024,
    )

    assert result.status is CodeQLContainerRunStatus.FAILED
    assert result.raw_sarif is None
    assert result.reason == expected_reason
    assert port.operations[-1] == (
        "remove",
        "sastsimi-codeql-68aa90a6f9fb88217375de7f",
    )
    assert "host path" not in result.reason


@pytest.mark.asyncio
async def test_run_timeout_is_stable_and_still_removes_the_container() -> None:
    spec = _spec()
    port = FakeDockerPort(spec)
    port.wait_forever = True

    result = await run_container_codeql(
        port=port,
        spec=spec,
        artifact_identity=_identity(),
        timeout_seconds=0.01,
        stdout_limit_bytes=1024,
    )

    assert result.status is CodeQLContainerRunStatus.TIMED_OUT
    assert result.reason == "CODEQL_CONTAINER_TIMEOUT"
    assert port.operations[-1][0] == "remove"


@pytest.mark.asyncio
async def test_run_cancel_is_a_stable_result_and_still_removes_the_container() -> None:
    spec = _spec()
    port = FakeDockerPort(spec)
    port.failure_operation = "cancel"

    result = await run_container_codeql(
        port=port,
        spec=spec,
        artifact_identity=_identity(),
        timeout_seconds=1,
        stdout_limit_bytes=1024,
    )

    assert result.status is CodeQLContainerRunStatus.CANCELLED
    assert result.reason == "CODEQL_CONTAINER_CANCELLED"
    assert port.operations[-1][0] == "remove"


@pytest.mark.asyncio
async def test_cleanup_failure_invalidates_an_otherwise_successful_result() -> None:
    spec = _spec()
    port = FakeDockerPort(spec)
    port.remove_failure = True

    result = await run_container_codeql(
        port=port,
        spec=spec,
        artifact_identity=_identity(),
        timeout_seconds=1,
        stdout_limit_bytes=1024,
    )

    assert result.status is CodeQLContainerRunStatus.FAILED
    assert result.raw_sarif is None
    assert result.reason == "CODEQL_CONTAINER_REMOVE_FAILED"


@pytest.mark.asyncio
async def test_probe_requires_exact_image_version_and_real_cap_plus_one_denials() -> (
    None
):
    spec = _spec()
    port = FakeDockerPort(spec)
    request = ContainerCodeQLProbeRequest(expected_codeql_version="2.23.1")

    result = await probe_container_codeql_boundary(
        port=port,
        spec=spec,
        request=request,
        timeout_seconds=1,
    )

    assert result.status is CodeQLContainerRunStatus.SUCCEEDED
    assert result.reason is None
    assert result.image_digest == spec.image_digest
    assert result.codeql_version == "2.23.1"
    assert [operation for operation, _value in port.operations] == [
        "create",
        "inspect",
        "start",
        "probe",
        "remove",
    ]
    sent_request = port.operations[3][1][1]
    assert sent_request.database_attempted_bytes == spec.database_limit_bytes + 1
    assert sent_request.output_attempted_bytes == spec.output_limit_bytes + 1
    create_argv = port.operations[0][1]
    assert create_argv[-3:] == (
        "probe",
        str(spec.database_limit_bytes + 1),
        str(spec.output_limit_bytes + 1),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mismatch", ["image", "version", "database", "output"])
async def test_probe_fails_closed_for_substitution_or_missing_denial(
    mismatch: str,
) -> None:
    spec = _spec()
    port = FakeDockerPort(spec)
    observation = port.probe_observation
    if mismatch == "image":
        port.probe_observation = ContainerCodeQLProbeObservation(
            image_digest="sha256:" + "f" * 64,
            codeql_version=observation.codeql_version,
            database=observation.database,
            output=observation.output,
        )
    elif mismatch == "version":
        port.probe_observation = ContainerCodeQLProbeObservation(
            image_digest=observation.image_digest,
            codeql_version="2.24.0",
            database=observation.database,
            output=observation.output,
        )
    elif mismatch == "database":
        port.probe_observation = ContainerCodeQLProbeObservation(
            image_digest=observation.image_digest,
            codeql_version=observation.codeql_version,
            database=TmpfsCapDenialEvidence(
                target="/work/database",
                limit_bytes=spec.database_limit_bytes,
                attempted_bytes=spec.database_limit_bytes,
                bytes_written=spec.database_limit_bytes,
                denial_code="ENOSPC",
            ),
            output=observation.output,
        )
    else:
        port.probe_observation = ContainerCodeQLProbeObservation(
            image_digest=observation.image_digest,
            codeql_version=observation.codeql_version,
            database=observation.database,
            output=TmpfsCapDenialEvidence(
                target="/work/output",
                limit_bytes=spec.output_limit_bytes,
                attempted_bytes=spec.output_limit_bytes + 1,
                bytes_written=spec.output_limit_bytes + 1,
                denial_code="",
            ),
        )

    result = await probe_container_codeql_boundary(
        port=port,
        spec=spec,
        request=ContainerCodeQLProbeRequest(expected_codeql_version="2.23.1"),
        timeout_seconds=1,
    )

    assert result.status is CodeQLContainerRunStatus.FAILED
    assert result.reason == "CODEQL_CONTAINER_PROBE_MISMATCH"
    assert port.operations[-1][0] == "remove"
