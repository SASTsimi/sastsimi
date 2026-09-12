from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.capabilities.probes import CommandObservation
from sastsimi.capabilities.service import CapabilityProbeService
from sastsimi.capabilities.store import (
    CapabilityProbeEvidenceAuthority,
    SQLiteCapabilityProbeStore,
)
from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.runtime.services import RuntimeServices
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade
from tests.integration.runtime_support import TestClock, TestIds


class FakeCommands:
    def __init__(self, *, docker_daemon: bool = True) -> None:
        self.docker_daemon = docker_daemon

    def run(
        self, executable: Path, arguments: tuple[str, ...], *, timeout_ms: int
    ) -> CommandObservation:
        del timeout_ms
        command = executable.stem.lower()
        if command == "git":
            return CommandObservation(True, "git version 2.51.0")
        if command == "opengrep":
            return CommandObservation(True, "1.10.0")
        if command == "codeql":
            return CommandObservation(True, "2.23.1")
        if command == "docker" and arguments[0] == "version":
            if self.docker_daemon:
                return CommandObservation(True, "28.3.3|28.3.3")
            return CommandObservation(False, None)
        raise AssertionError((command, arguments))


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


def _service(
    tmp_path: Path,
    *,
    available: set[str],
    docker_daemon: bool = True,
    openai_passed: bool = True,
    host_id: str = "host-a",
) -> tuple[CapabilityProbeService, RuntimeServices, SQLiteCapabilityProbeStore]:
    binaries = tmp_path / "bin"
    binaries.mkdir(parents=True, exist_ok=True)
    located: dict[str, Path] = {}
    for name in available:
        path = binaries / f"{name}.exe"
        path.write_bytes((name + "-binary").encode())
        located[name] = path

    store = SQLiteCapabilityProbeStore(
        tmp_path / "capability-probes.sqlite3", host_id=host_id
    )
    authority = CapabilityProbeEvidenceAuthority(store)
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
    service = CapabilityProbeService(
        registry=runtime.configuration,
        artifacts=runtime.unit_of_work.artifacts,
        store=store,
        host_id=host_id,
        operating_system="windows",
        architecture="x86_64",
        clock=lambda: datetime(2026, 9, 13, tzinfo=UTC),
        executable_locator=lambda name: located.get(name),
        command_runner=FakeCommands(docker_daemon=docker_daemon),
        secret_resolver=FakeSecrets(),
        openai_probe=FakeOpenAI(passed=openai_passed),
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
            approved_by="taehyeon-git",
        )

    exact_ref = service.approve(
        git.probe_id,
        expected_target_hash=git.approval_target_hash or "",
        approved_by="taehyeon-git",
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
        approved_by="taehyeon-git",
    )
    opengrep_ref = service.approve(
        opengrep.probe_id,
        expected_target_hash=opengrep.approval_target_hash or "",
        approved_by="taehyeon-git",
    )
    docker_ref = service.approve(
        docker.probe_id,
        expected_target_hash=docker.approval_target_hash or "",
        approved_by="taehyeon-git",
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
            approved_by="taehyeon-git",
        )

    other_host, _runtime, _store = _service(
        tmp_path / "other", available=available, host_id="host-b"
    )
    with pytest.raises((LookupError, ValueError)):
        other_host.approve(
            receipt.probe_id,
            expected_target_hash=receipt.approval_target_hash or "0" * 64,
            approved_by="taehyeon-git",
        )
