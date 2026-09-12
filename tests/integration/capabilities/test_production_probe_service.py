from __future__ import annotations

import inspect
import json
import sqlite3
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest

import sastsimi.capabilities as capability_api
from sastsimi.bootstrap import build_runtime
from sastsimi.capabilities import (
    ProductionCapabilityProbeService,
    build_production_capability_probe_service,
)
from sastsimi.capabilities.probes import CommandObservation
from sastsimi.capabilities.service import _CapabilityProbeEngine
from sastsimi.capabilities.store import (
    _CapabilityProbeEvidenceAuthority,
    _SQLiteCapabilityProbeStore,
)
from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.capabilities import DockerBuildCapability
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.runtime.services import RuntimeServices
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade
from tests.integration.runtime_support import TestClock, TestIds


class FakeCommands:
    def __init__(
        self,
        *,
        docker_daemon: bool = True,
        fail_operation: str | None = None,
        mutate_after_version: Path | None = None,
        opengrep_check_ids: tuple[str, ...] = (
            "sastsimi.probe.python",
            "sastsimi.probe.javascript",
        ),
        docker_boundary_safe: bool = True,
        docker_tmpfs: str = "rw,noexec,nosuid,nodev,size=16m",
    ) -> None:
        self.docker_daemon = docker_daemon
        self.fail_operation = fail_operation
        self.mutate_after_version = mutate_after_version
        self.opengrep_check_ids = opengrep_check_ids
        self.docker_boundary_safe = docker_boundary_safe
        self.docker_tmpfs = docker_tmpfs
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.environment_overrides: list[Mapping[str, str] | None] = []
        self.docker_target = "daemon-a|linux|x86_64"

    def run(
        self,
        executable: Path,
        arguments: tuple[str, ...],
        *,
        timeout_ms: int,
        environment_overrides: Mapping[str, str] | None = None,
    ) -> CommandObservation:
        del timeout_ms
        command = executable.stem.lower()
        self.calls.append((command, arguments))
        self.environment_overrides.append(environment_overrides)
        effective_arguments = (
            arguments[2:]
            if arguments[:2] == ("--host", "npipe:////./pipe/docker_engine")
            else arguments
        )
        operation = next(
            (
                item
                for item in (
                    "clone",
                    "checkout",
                    "scan",
                    "build",
                    "run",
                    "inspect",
                    "rm",
                )
                if item in effective_arguments
            ),
            None,
        )
        if self.fail_operation is not None and operation == self.fail_operation:
            return CommandObservation(False, None)
        if command == "git":
            if effective_arguments == ("--version",):
                result = CommandObservation(True, "git version 2.51.0")
                if self.mutate_after_version is not None:
                    self.mutate_after_version.write_bytes(b"changed-during-probe")
                return result
            if "rev-parse" in effective_arguments:
                return CommandObservation(True, "a" * 40)
            return CommandObservation(True, "ok")
        if command == "opengrep":
            if effective_arguments == ("--version",):
                return CommandObservation(True, "1.10.0")
            return CommandObservation(
                True,
                json.dumps(
                    {
                        "results": [
                            {"check_id": check_id}
                            for check_id in self.opengrep_check_ids
                        ]
                    }
                ),
            )
        if command == "codeql":
            return CommandObservation(True, "2.23.1")
        if command == "docker":
            if effective_arguments[0] == "version":
                if self.docker_daemon:
                    return CommandObservation(True, "28.3.3|28.3.3")
                return CommandObservation(False, None)
            if effective_arguments[0] == "info":
                return CommandObservation(True, self.docker_target)
            if effective_arguments[:2] == ("image", "inspect"):
                return CommandObservation(True, "sha256:" + "c" * 64)
            if effective_arguments[:2] == ("image", "build"):
                return CommandObservation(True, "sha256:" + "b" * 64)
            if effective_arguments[0] == "run":
                return CommandObservation(True, "probe-container")
            if effective_arguments[0] == "inspect":
                user = "65532:65532" if self.docker_boundary_safe else "root"
                return CommandObservation(
                    True,
                    json.dumps(
                        [
                            {
                                "Config": {"User": user},
                                "HostConfig": {
                                    "NetworkMode": "none",
                                    "ReadonlyRootfs": True,
                                    "Privileged": False,
                                    "CapDrop": ["ALL"],
                                    "SecurityOpt": ["no-new-privileges"],
                                    "PidsLimit": 64,
                                    "Memory": 67_108_864,
                                    "NanoCpus": 500_000_000,
                                    "Binds": None,
                                    "PidMode": "",
                                    "IpcMode": "private",
                                    "Tmpfs": {"/tmp": self.docker_tmpfs},
                                },
                                "State": {"Health": {"Status": "healthy"}},
                                "Mounts": [{"Type": "tmpfs", "Destination": "/tmp"}],
                            }
                        ]
                    ),
                )
            if effective_arguments[:2] in {
                ("rm", "--force"),
                ("image", "rm"),
            }:
                return CommandObservation(True, "removed")
        raise AssertionError((command, effective_arguments))


class FakeOpenAI:
    def __init__(self, *, passed: bool) -> None:
        self.passed = passed

    def probe(self, *, model: str, secret: str) -> bool:
        assert model == "gpt-test"
        assert secret == "top-secret-value"
        return self.passed


class FakeSecrets:
    def resolve(self, reference: SecretReference) -> str:
        assert reference.reference == "env:OPENAI_API_KEY"
        return "top-secret-value"


_VERIFIED_DOCKER_BUILD_CAPABILITY = DockerBuildCapability(
    build_backend="LEGACY_LIMITED",
    enforced_build_limits=("CPU", "MEMORY", "PID", "DISK"),
    external_build_disk_limit_bytes=64 * 1024 * 1024,
    external_build_storage_identity_hash="a" * 64,
)


def _service(
    tmp_path: Path,
    *,
    available: set[str],
    docker_daemon: bool = True,
    openai_passed: bool = True,
    host_id: str = "host-a",
    docker_build_capability: DockerBuildCapability | None = (
        _VERIFIED_DOCKER_BUILD_CAPABILITY
    ),
) -> tuple[_CapabilityProbeEngine, RuntimeServices, _SQLiteCapabilityProbeStore]:
    binaries = tmp_path / "bin"
    binaries.mkdir(parents=True, exist_ok=True)
    located: dict[str, Path] = {}
    located["python"] = Path(sys.executable)
    for name in available:
        path = binaries / f"{name}.exe"
        path.write_bytes((name + "-binary").encode())
        located[name] = path

    store = _SQLiteCapabilityProbeStore(
        tmp_path / "capability-probes.sqlite3", host_id=host_id
    )
    authority = _CapabilityProbeEvidenceAuthority(store)
    upgrade(Database(tmp_path / "db" / "sastsimi.sqlite3"))
    runtime = build_runtime(
        tmp_path,
        WorkspaceId("host-configuration"),
        CommitId("host-configuration-v1"),
        TestClock(),
        TestIds(),
        evidence=authority,
        capability_host_id=host_id,
    )
    commands = FakeCommands(docker_daemon=docker_daemon)
    service = _CapabilityProbeEngine(
        registry=runtime.configuration,
        artifacts=runtime.unit_of_work.artifacts,
        store=store,
        host_id=host_id,
        operating_system="windows",
        architecture="x86_64",
        clock=lambda: datetime(2026, 9, 13, tzinfo=UTC),
        executable_locator=lambda name: located.get(name),
        command_runner=commands,
        docker_host="npipe:////./pipe/docker_engine",
        secret_resolver=FakeSecrets(),
        openai_probe=FakeOpenAI(passed=openai_passed),
        approval_identity=lambda: "taehyeon-git",
        scratch_root=tmp_path / "scratch",
        docker_build_capability_probe=lambda: docker_build_capability,
    )
    return service, runtime, store


def test_real_probe_receipts_require_exact_human_approval_before_active(
    tmp_path: Path,
) -> None:
    service, runtime, store = _service(
        tmp_path, available={"git", "opengrep", "docker", "codeql"}
    )

    git = service.probe("GIT")
    python_ast = service.probe("PYTHON_AST")
    opengrep = service.probe("OPENGREP")
    docker = service.probe("DOCKER")
    openai = service.probe(
        "OPENAI_API",
        model="gpt-test",
        credential_ref=SecretReference(reference="env:OPENAI_API_KEY"),
    )
    codeql = service.probe("CODEQL")

    assert [item.status for item in service.list()] == [
        "PASSED",
        "PASSED",
        "PASSED",
        "PASSED",
        "PASSED",
        "BLOCKED",
    ]
    assert openai.activation_supported is False
    assert codeql.safe_summary == "CodeQL quota control probe is unavailable"
    with pytest.raises(LookupError, match="CAPABILITY_ROUTE_NOT_ACTIVE"):
        runtime.configuration.resolve_active_capability(
            capability_kind="GIT",
            language="ANY",
            operation="CLONE",
            operating_system="windows",
            architecture="x86_64",
        )
    with pytest.raises(ValueError, match="APPROVAL_TARGET_MISMATCH"):
        service.approve(
            git.probe_id,
            expected_target_hash="f" * 64,
        )

    exact_ref = service.approve(
        git.probe_id,
        expected_target_hash=git.approval_target_hash or "",
    )
    selection = runtime.configuration.resolve_active_capability(
        capability_kind="GIT",
        language="ANY",
        operation="CHECKOUT",
        operating_system="windows",
        architecture="x86_64",
    )
    assert selection.profile_ref == exact_ref
    assert runtime.configuration.resolve_pinned_active_profile(exact_ref).status == (
        "ACTIVE"
    )
    git_executable = service.resolve_executable(exact_ref)
    assert git_executable.name == "git.exe"
    assert store.approved_profile_ref(git.probe_id) == exact_ref
    python_ref = service.approve(
        python_ast.probe_id,
        expected_target_hash=python_ast.approval_target_hash or "",
    )
    opengrep_ref = service.approve(
        opengrep.probe_id,
        expected_target_hash=opengrep.approval_target_hash or "",
    )
    docker_ref = service.approve(
        docker.probe_id,
        expected_target_hash=docker.approval_target_hash or "",
    )
    assert (
        runtime.configuration.resolve_active_static_tool(
            adapter_key="PYTHON_AST",
            language="PYTHON",
            operating_system="windows",
            architecture="x86_64",
        ).profile_ref
        == python_ref
    )
    assert (
        runtime.configuration.resolve_active_static_tool(
            adapter_key="OPENGREP",
            language="JAVASCRIPT",
            operating_system="windows",
            architecture="x86_64",
        ).profile_ref
        == opengrep_ref
    )
    assert (
        runtime.configuration.resolve_active_capability(
            capability_kind="DOCKER",
            language="ANY",
            operation="CONTAINER_RUN",
            operating_system="windows",
            architecture="x86_64",
        ).profile_ref
        == docker_ref
    )
    assert service.resolve_executable(python_ref).is_file()
    assert service.resolve_executable(opengrep_ref).name == "opengrep.exe"
    assert service.resolve_executable(docker_ref).name == "docker.exe"
    docker_path, docker_host = service.resolve_docker_command(docker_ref)
    assert docker_path.name == "docker.exe"
    assert docker_host == "npipe:////./pipe/docker_engine"
    target = service.resolve_current(docker_ref)
    assert target.profile_ref == docker_ref
    assert target.executable == docker_path
    assert target.daemon_target == docker_host
    assert target.build_backend == "LEGACY_LIMITED"
    assert target.enforced_build_limits == frozenset({"CPU", "MEMORY", "PID", "DISK"})
    assert target.external_build_disk_limit_bytes == 64 * 1024 * 1024
    service.require_current(target)
    git_executable.write_bytes(b"changed-after-approval")
    with pytest.raises(ValueError, match="CAPABILITY_EXECUTABLE_CHANGED"):
        service.resolve_executable(exact_ref)

    with sqlite3.connect(store.path) as connection:
        payloads = "".join(
            str(row[0])
            for row in connection.execute("SELECT payload FROM probe_receipts")
        )
    assert str(tmp_path) not in payloads
    assert "top-secret-value" not in payloads
    assert "stderr" not in payloads.lower()


@pytest.mark.parametrize(
    ("kind", "available", "docker_daemon", "openai_passed"),
    [
        ("GIT", set(), True, True),
        ("DOCKER", {"docker"}, False, True),
        ("OPENAI_API", set(), True, False),
        ("CODEQL", {"codeql"}, True, True),
    ],
)
def test_blocked_or_incomplete_probe_cannot_be_forged_active(
    tmp_path: Path,
    kind: str,
    available: set[str],
    docker_daemon: bool,
    openai_passed: bool,
) -> None:
    service, _runtime, _store = _service(
        tmp_path,
        available=available,
        docker_daemon=docker_daemon,
        openai_passed=openai_passed,
    )
    if kind == "OPENAI_API":
        receipt = service.probe(
            "OPENAI_API",
            model="gpt-test",
            credential_ref=SecretReference(reference="env:OPENAI_API_KEY"),
        )
    else:
        receipt = service.probe(kind)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="PROBE_NOT_ACTIVATABLE"):
        service.approve(
            receipt.probe_id,
            expected_target_hash=receipt.approval_target_hash or "0" * 64,
        )

    other_host, _runtime, _store = _service(
        tmp_path / "other", available=available, host_id="host-b"
    )
    with pytest.raises((LookupError, ValueError)):
        other_host.approve(
            receipt.probe_id,
            expected_target_hash=receipt.approval_target_hash or "0" * 64,
        )


def test_public_production_facade_has_no_dependency_injection_or_caller_identity() -> (
    None
):
    build_parameters = inspect.signature(
        build_production_capability_probe_service
    ).parameters
    assert set(build_parameters) == {
        "data_dir",
        "host_id",
        "executable_paths",
        "docker_host",
    }

    assert "command_runner" not in build_parameters
    assert "store" not in build_parameters
    constructor = inspect.signature(ProductionCapabilityProbeService).parameters
    assert set(constructor) == {
        "data_dir",
        "host_id",
        "executable_paths",
        "docker_host",
    }
    assert (
        "approved_by"
        not in inspect.signature(ProductionCapabilityProbeService.approve).parameters
    )
    assert not hasattr(capability_api, "CapabilityProbeService")
    assert not hasattr(capability_api, "SQLiteCapabilityProbeStore")


def test_activation_requires_actual_operations_not_only_version(
    tmp_path: Path,
) -> None:
    service, _runtime, _store = _service(
        tmp_path, available={"git", "opengrep", "docker"}
    )
    commands = service._commands
    assert isinstance(commands, FakeCommands)

    for kind in ("GIT", "OPENGREP", "DOCKER"):
        receipt = service.probe(kind)
        assert receipt.activation_supported is True

    flattened = [
        (command, " ".join(arguments)) for command, arguments in commands.calls
    ]
    assert any(
        command == "git" and "clone" in arguments for command, arguments in flattened
    )
    assert any(
        command == "git" and "checkout" in arguments for command, arguments in flattened
    )
    assert any(
        command == "opengrep" and "scan" in arguments
        for command, arguments in flattened
    )
    assert any(
        command == "docker" and "build" in arguments for command, arguments in flattened
    )
    docker_build_index = next(
        index
        for index, (_command, arguments) in enumerate(commands.calls)
        if "build" in arguments
    )
    docker_build_arguments = commands.calls[docker_build_index][1]
    assert "--cpu-period" in docker_build_arguments
    assert "--cpu-quota" in docker_build_arguments
    assert "--memory" in docker_build_arguments
    assert "--ulimit" in docker_build_arguments
    assert commands.environment_overrides[docker_build_index] == {
        "DOCKER_BUILDKIT": "0"
    }
    assert any(
        command == "docker" and "run" in arguments for command, arguments in flattened
    )
    assert any(
        command == "docker" and "inspect" in arguments
        for command, arguments in flattened
    )
    assert any(
        command == "docker" and "rm" in arguments for command, arguments in flattened
    )


def test_opengrep_cannot_activate_unprobed_javascript_scope(tmp_path: Path) -> None:
    service, _runtime, _store = _service(tmp_path, available={"opengrep"})
    service._commands = FakeCommands(opengrep_check_ids=("sastsimi.probe",))

    receipt = service.probe("OPENGREP")

    assert receipt.status == "BLOCKED"
    assert receipt.activation_supported is False


def test_executable_digest_change_during_probe_or_before_approval_fails_closed(
    tmp_path: Path,
) -> None:
    service, _runtime, _store = _service(tmp_path, available={"git"})
    executable = tmp_path / "bin" / "git.exe"
    commands = FakeCommands(mutate_after_version=executable)
    service._commands = commands

    changed_during_probe = service.probe("GIT")
    assert changed_during_probe.activation_supported is False

    executable.write_bytes(b"git-binary")
    service._commands = FakeCommands()
    receipt = service.probe("GIT")
    executable.write_bytes(b"changed-before-approval")
    with pytest.raises(ValueError, match="CAPABILITY_EXECUTABLE_CHANGED"):
        service.approve(
            receipt.probe_id,
            expected_target_hash=receipt.approval_target_hash or "",
        )


def test_docker_approval_rechecks_exact_daemon_target(tmp_path: Path) -> None:
    service, _runtime, _store = _service(tmp_path, available={"docker"})
    commands = service._commands
    assert isinstance(commands, FakeCommands)
    receipt = service.probe("DOCKER")
    commands.docker_target = "other|npipe://different-engine"

    with pytest.raises(ValueError, match="CAPABILITY_EXECUTION_TARGET_CHANGED"):
        service.approve(
            receipt.probe_id,
            expected_target_hash=receipt.approval_target_hash or "",
        )


def test_docker_execution_rechecks_exact_daemon_target(tmp_path: Path) -> None:
    service, _runtime, _store = _service(tmp_path, available={"docker"})
    commands = service._commands
    assert isinstance(commands, FakeCommands)
    receipt = service.probe("DOCKER")
    profile_ref = service.approve(
        receipt.probe_id,
        expected_target_hash=receipt.approval_target_hash or "",
    )
    commands.docker_target = "daemon-b|linux|x86_64"

    with pytest.raises(ValueError, match="CAPABILITY_EXECUTION_TARGET_CHANGED"):
        service.resolve_executable(profile_ref)


def test_docker_probe_pins_every_command_to_exact_host(tmp_path: Path) -> None:
    service, _runtime, _store = _service(tmp_path, available={"docker"})
    commands = service._commands
    assert isinstance(commands, FakeCommands)

    receipt = service.probe("DOCKER")

    assert receipt.activation_supported is True
    docker_calls = [
        arguments for command, arguments in commands.calls if command == "docker"
    ]
    assert docker_calls
    assert all(
        arguments[:2] == ("--host", "npipe:////./pipe/docker_engine")
        for arguments in docker_calls
    )


def test_docker_probe_cannot_claim_boundary_from_unsafe_container(
    tmp_path: Path,
) -> None:
    service, _runtime, _store = _service(tmp_path, available={"docker"})
    service._commands = FakeCommands(docker_boundary_safe=False)

    receipt = service.probe("DOCKER")

    assert receipt.status == "BLOCKED"
    assert receipt.activation_supported is False


def test_docker_probe_without_verified_build_boundary_stays_blocked(
    tmp_path: Path,
) -> None:
    """An executable and daemon alone cannot claim a T11-safe ACTIVE profile."""

    service, _runtime, _store = _service(
        tmp_path,
        available={"docker"},
        docker_build_capability=None,
    )

    receipt = service.probe("DOCKER")

    assert receipt.status == "BLOCKED"
    assert receipt.activation_supported is False
    assert receipt.docker_build_capability is None
    assert receipt.approval_target_hash is None
    assert receipt.safe_summary == (
        "Docker build cache and image output have no proven hard disk boundary"
    )


def test_docker_target_revalidation_rejects_changed_daemon(
    tmp_path: Path,
) -> None:
    service, _runtime, _store = _service(tmp_path, available={"docker"})
    commands = service._commands
    assert isinstance(commands, FakeCommands)
    receipt = service.probe("DOCKER")
    profile_ref = service.approve(
        receipt.probe_id,
        expected_target_hash=receipt.approval_target_hash or "",
    )
    target = service.resolve_current(profile_ref)
    commands.docker_target = "changed-daemon|linux|x86_64"

    with pytest.raises(ValueError, match="CAPABILITY_EXECUTION_TARGET_CHANGED"):
        service.require_current(target)


def test_docker_target_revalidation_rejects_changed_storage_boundary(
    tmp_path: Path,
) -> None:
    service, _runtime, _store = _service(tmp_path, available={"docker"})
    receipt = service.probe("DOCKER")
    profile_ref = service.approve(
        receipt.probe_id,
        expected_target_hash=receipt.approval_target_hash or "",
    )
    target = service.resolve_current(profile_ref)
    changed = _VERIFIED_DOCKER_BUILD_CAPABILITY.model_copy(
        update={"external_build_storage_identity_hash": "b" * 64}
    )
    service._docker_build_capability_probe = lambda: changed

    with pytest.raises(ValueError, match="CAPABILITY_DOCKER_BOUNDARY_CHANGED"):
        service.require_current(target)


def test_docker_probe_rejects_incomplete_tmpfs_boundary(tmp_path: Path) -> None:
    service, _runtime, _store = _service(tmp_path, available={"docker"})
    service._commands = FakeCommands(docker_tmpfs="rw")

    receipt = service.probe("DOCKER")

    assert receipt.status == "BLOCKED"
    assert receipt.activation_supported is False


@pytest.mark.parametrize(
    ("mounts", "expected"),
    (
        ([], False),
        ([{"Type": "tmpfs", "Destination": "/tmp"}], True),
        (
            [
                {"Type": "tmpfs", "Destination": "/tmp"},
                {"Type": "tmpfs", "Destination": "/tmp"},
            ],
            False,
        ),
    ),
)
def test_docker_boundary_requires_exactly_one_tmpfs_mount(
    mounts: list[dict[str, str]],
    expected: bool,
) -> None:
    state: dict[str, object] = {
        "Config": {"User": "65532:65532"},
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidsLimit": 64,
            "Memory": 67_108_864,
            "NanoCpus": 500_000_000,
            "Binds": None,
            "PidMode": "",
            "IpcMode": "private",
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16m"},
        },
        "State": {"Health": {"Status": "healthy"}},
        "Mounts": mounts,
    }

    assert _CapabilityProbeEngine._docker_boundary_passed(state) is expected


@pytest.mark.parametrize(
    ("kind", "failure"),
    (("GIT", "checkout"), ("OPENGREP", "scan"), ("DOCKER", "rm")),
)
def test_incomplete_real_operation_set_cannot_activate(
    tmp_path: Path, kind: str, failure: str
) -> None:
    service, _runtime, _store = _service(
        tmp_path, available={kind.lower() if kind != "OPENGREP" else "opengrep"}
    )
    service._commands = FakeCommands(fail_operation=failure)

    receipt = service.probe(kind)  # type: ignore[arg-type]

    assert receipt.status == "BLOCKED"
    assert receipt.activation_supported is False
    assert receipt.approval_target_hash is None


def test_registry_publish_precedes_idempotent_probe_marker_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, runtime, store = _service(tmp_path, available={"git"})
    receipt = service.probe("GIT")
    real_publish = store.publish
    publish_calls = 0

    def crash_before_marker(probe_id: str, profile_ref: object) -> None:
        nonlocal publish_calls
        publish_calls += 1
        if publish_calls == 1:
            raise RuntimeError("simulated marker crash")
        real_publish(probe_id, profile_ref)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "publish", crash_before_marker)
    with pytest.raises(RuntimeError, match="simulated marker crash"):
        service.approve(
            receipt.probe_id,
            expected_target_hash=receipt.approval_target_hash or "",
        )
    assert store.approved_profile_ref(receipt.probe_id) is None

    recovered = service.approve(
        receipt.probe_id,
        expected_target_hash=receipt.approval_target_hash or "",
    )
    assert store.approved_profile_ref(receipt.probe_id) == recovered
    assert runtime.configuration.resolve_pinned_active_profile(recovered).status == (
        "ACTIVE"
    )
