"""CodeQL operator functions publish only prebuilt database artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.config.codeql_container import CodeQLContainerRuntimeConfig
from sastsimi.interfaces.cli.codeql import run_inspect, run_provision, run_register
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.static_analysis.codeql_provision_source import PreparedCodeQLSource
from sastsimi.static_analysis.container_codeql_provision import (
    CodeQLProvisionResult,
    CodeQLProvisionStatus,
    ContainerCodeQLProvisionSpec,
)

COMMIT_ID = "a" * 40
TRACKED_MANIFEST_SHA256 = "b" * 64


def _config(tmp_path: Path, **changes: object) -> CodeQLContainerRuntimeConfig:
    registry = tmp_path / "PRIVATE_REGISTRY_PATH"
    query_pack = tmp_path / "query-pack"
    registry.mkdir(exist_ok=True)
    query_pack.mkdir(exist_ok=True)
    values: dict[str, object] = {
        "schema_version": 1,
        "image": "registry.example/sastsimi/codeql@sha256:" + "c" * 64,
        "expected_codeql_version": "2.27.0",
        "database_registry_root": registry,
        "query_pack_root": query_pack,
        "query_pack_sha256": "d" * 64,
        "database_provider_key": "controlled-codeql-db",
        "database_provider_revision": "2026-09-19.1",
        "database_provider_evidence_sha256": "e" * 64,
        "database_limit_bytes": 32 * 1024 * 1024,
        "output_limit_bytes": 8 * 1024 * 1024,
        "pids_limit": 128,
        "memory_limit_bytes": 1024 * 1024 * 1024,
        "nano_cpus": 1_000_000_000,
        "container_uid": 10001,
        "container_gid": 10001,
    }
    values.update(changes)
    return CodeQLContainerRuntimeConfig.model_validate(values)


def _database(tmp_path: Path) -> Path:
    database = tmp_path / "PRIVATE_CREATED_DATABASE"
    database.mkdir()
    (database / "codeql-database.yml").write_text(
        "primaryLanguage: python\n", encoding="utf-8"
    )
    return database


def test_register_and_inspect_return_only_safe_exact_identifiers(
    tmp_path: Path,
) -> None:
    """Catches absolute-path disclosure or publication/lookup identity drift."""

    config = _config(tmp_path)
    registered = run_register(
        config=config,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id=COMMIT_ID,
        language="python",
        tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
        database_root=_database(tmp_path),
    )
    inspected = run_inspect(
        config=config,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id=COMMIT_ID,
        language="python",
        tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
    )

    assert registered.code == ExitCode.OK
    assert set(registered.data) == {"artifact_key", "database_digest", "status"}
    assert registered.data["status"] == "REGISTERED"
    assert inspected.code == ExitCode.OK
    assert inspected.data == registered.data | {"status": "AVAILABLE"}
    wire = json.dumps((registered.data, inspected.data))
    assert "PRIVATE_REGISTRY_PATH" not in wire
    assert "PRIVATE_CREATED_DATABASE" not in wire
    assert str(tmp_path) not in wire


def test_register_rejects_non_exact_identity_before_writing(tmp_path: Path) -> None:
    """Catches a branch name or unsafe value entering the immutable registry."""

    config = _config(tmp_path)
    result = run_register(
        config=config,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id="main",
        language="python",
        tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
        database_root=_database(tmp_path),
    )

    assert result.code == ExitCode.INPUT_ERROR
    assert result.data == {
        "reason_code": "CODEQL_DATABASE_IDENTITY_INVALID",
        "status": "BLOCKED",
    }
    assert tuple(config.database_registry_root.iterdir()) == ()


def test_register_never_overwrites_an_existing_exact_key(tmp_path: Path) -> None:
    """Catches accidental replacement of an approved immutable DB artifact."""

    config = _config(tmp_path)
    database = _database(tmp_path)
    assert (
        run_register(
            config=config,
            repository_url="https://example.invalid/owner/repository.git",
            commit_id=COMMIT_ID,
            language="python",
            tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
            database_root=database,
        ).code
        == ExitCode.OK
    )

    duplicate = run_register(
        config=config,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id=COMMIT_ID,
        language="python",
        tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
        database_root=database,
    )

    assert duplicate.code == ExitCode.CONFIG_ERROR
    assert duplicate.data == {
        "reason_code": "CODEQL_DATABASE_ALREADY_PUBLISHED",
        "status": "BLOCKED",
    }


def test_inspect_requires_the_configured_provider_identity(tmp_path: Path) -> None:
    """Catches a registry entry reused under a substituted Provider revision."""

    config = _config(tmp_path)
    assert (
        run_register(
            config=config,
            repository_url="https://example.invalid/owner/repository.git",
            commit_id=COMMIT_ID,
            language="python",
            tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
            database_root=_database(tmp_path),
        ).code
        == ExitCode.OK
    )
    substituted = _config(
        tmp_path,
        database_provider_revision="2026-09-19.substituted",
    )

    result = run_inspect(
        config=substituted,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id=COMMIT_ID,
        language="python",
        tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
    )

    assert result.code == ExitCode.INTEGRITY_ERROR
    assert result.data == {
        "reason_code": "CODEQL_DATABASE_INTEGRITY_CHECK_FAILED",
        "status": "BLOCKED",
    }


def test_inspect_reports_an_absent_exact_key_without_inventing_a_path(
    tmp_path: Path,
) -> None:
    """Catches missing registry entries being reported as available."""

    config = _config(tmp_path)
    result = run_inspect(
        config=config,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id=COMMIT_ID,
        language="python",
        tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
    )

    assert result.code == ExitCode.CAPABILITY_UNSUPPORTED
    assert result.data == {
        "reason_code": "CODEQL_DATABASE_NOT_FOUND",
        "status": "BLOCKED",
    }
    assert str(tmp_path) not in json.dumps(result.data)


def test_cancelled_register_cleans_partial_state_and_returns_no_path(
    tmp_path: Path,
) -> None:
    """Catches cancellation leaking a temporary path or partial artifact."""

    config = _config(tmp_path)
    result = run_register(
        config=config,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id=COMMIT_ID,
        language="python",
        tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
        database_root=_database(tmp_path),
        cancellation_requested=lambda: True,
    )

    assert result.code == ExitCode.BLOCKED
    assert result.data == {
        "reason_code": "CODEQL_DATABASE_PROVISION_CANCELLED",
        "status": "BLOCKED",
    }
    assert tuple(config.database_registry_root.iterdir()) == ()
    assert str(tmp_path) not in json.dumps(result.data)


def test_register_rejects_database_larger_than_configured_limit(
    tmp_path: Path,
) -> None:
    """Catches a prebuilt database exhausting the host registry during copy."""

    config = _config(tmp_path, database_limit_bytes=4)
    result = run_register(
        config=config,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id=COMMIT_ID,
        language="python",
        tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
        database_root=_database(tmp_path),
    )

    assert result.code == ExitCode.INTEGRITY_ERROR
    assert result.data == {
        "reason_code": "CODEQL_DATABASE_REGISTRATION_FAILED",
        "status": "BLOCKED",
    }
    assert tuple(config.database_registry_root.iterdir()) == ()


def test_provision_builds_and_publishes_one_exact_python_database(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    repository = tmp_path / "repository"
    repository.mkdir()
    executable = Path(__file__).resolve()
    observed: dict[str, object] = {}

    def prepare(**kwargs: object) -> PreparedCodeQLSource:
        observed["prepare"] = kwargs
        destination = kwargs["destination"]
        assert isinstance(destination, Path)
        (destination / "app.py").write_text("print('safe')\n", encoding="utf-8")
        return PreparedCodeQLSource(
            root=destination.resolve(),
            tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
        )

    async def provision(**kwargs: object) -> CodeQLProvisionResult:
        spec = kwargs["spec"]
        observed["spec"] = spec
        spec.database_destination.joinpath("codeql-database.yml").write_text(
            "primaryLanguage: python\n", encoding="utf-8"
        )
        return CodeQLProvisionResult(
            CodeQLProvisionStatus.SUCCEEDED,
            None,
            spec.database_destination,
        )

    result = run_provision(
        config=config,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id=COMMIT_ID,
        language="python",
        repository_root=repository,
        git_executable=executable,
        docker_executable=executable,
        source_preparer=prepare,
        docker_port_factory=lambda _path: object(),
        provision_runner=provision,
    )

    assert result.code == ExitCode.OK
    prepare_call = observed["prepare"]
    assert isinstance(prepare_call, dict)
    source_destination = prepare_call["destination"]
    provision_spec = observed["spec"]
    assert isinstance(source_destination, Path)
    assert source_destination.parent == config.database_registry_root.parent
    assert (
        provision_spec.database_destination.parent
        == config.database_registry_root.parent
    )
    assert result.data["status"] == "REGISTERED"
    assert result.data["tracked_manifest_sha256"] == TRACKED_MANIFEST_SHA256
    assert set(result.data) == {
        "artifact_key",
        "database_digest",
        "tracked_manifest_sha256",
        "status",
    }
    assert tuple(config.database_registry_root.iterdir())


def test_provision_resolves_relative_repository_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    repository = tmp_path / "repository"
    repository.mkdir()
    executable = Path(__file__).resolve()
    observed: dict[str, Path] = {}

    def prepare(**kwargs: object) -> PreparedCodeQLSource:
        repository_root = kwargs["repository_root"]
        destination = kwargs["destination"]
        assert isinstance(repository_root, Path)
        assert isinstance(destination, Path)
        observed["repository_root"] = repository_root
        return PreparedCodeQLSource(
            root=destination.resolve(),
            tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
        )

    async def provision(**kwargs: object) -> CodeQLProvisionResult:
        spec = kwargs["spec"]
        assert isinstance(spec, ContainerCodeQLProvisionSpec)
        spec.database_destination.joinpath("codeql-database.yml").write_text(
            "primaryLanguage: python\n", encoding="utf-8"
        )
        return CodeQLProvisionResult(
            CodeQLProvisionStatus.SUCCEEDED,
            None,
            spec.database_destination,
        )

    monkeypatch.chdir(tmp_path)
    result = run_provision(
        config=config,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id=COMMIT_ID,
        language="python",
        repository_root=Path("repository"),
        git_executable=executable,
        docker_executable=executable,
        source_preparer=prepare,
        docker_port_factory=lambda _path: object(),
        provision_runner=provision,
    )

    assert result.code == ExitCode.OK
    assert observed["repository_root"] == repository.resolve(strict=True)


def test_provision_failure_never_registers_a_partial_database(tmp_path: Path) -> None:
    config = _config(tmp_path)
    repository = tmp_path / "repository"
    repository.mkdir()
    executable = Path(__file__).resolve()

    def prepare(**kwargs: object) -> PreparedCodeQLSource:
        destination = kwargs["destination"]
        assert isinstance(destination, Path)
        return PreparedCodeQLSource(
            root=destination.resolve(),
            tracked_manifest_sha256=TRACKED_MANIFEST_SHA256,
        )

    async def provision(**_kwargs: object) -> CodeQLProvisionResult:
        return CodeQLProvisionResult(
            CodeQLProvisionStatus.FAILED,
            "CODEQL_PROVISION_EXIT_NONZERO",
            None,
        )

    result = run_provision(
        config=config,
        repository_url="https://example.invalid/owner/repository.git",
        commit_id=COMMIT_ID,
        language="python",
        repository_root=repository,
        git_executable=executable,
        docker_executable=executable,
        source_preparer=prepare,
        docker_port_factory=lambda _path: object(),
        provision_runner=provision,
    )

    assert result.code == ExitCode.BLOCKED
    assert result.data == {
        "reason_code": "CODEQL_PROVISION_EXIT_NONZERO",
        "status": "BLOCKED",
    }
    assert tuple(config.database_registry_root.iterdir()) == ()
