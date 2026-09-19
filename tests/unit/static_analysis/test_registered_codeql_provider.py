"""Read-only resolution of exact registered CodeQL databases."""

from __future__ import annotations

from dataclasses import fields, replace
from pathlib import Path

import pytest

from sastsimi.config.codeql_container import CodeQLContainerRuntimeConfig
from sastsimi.static_analysis import registered_codeql_provider as provider_module
from sastsimi.static_analysis.codeql_registry import (
    CodeQLDatabaseIdentity,
    lookup_codeql_database,
    publish_codeql_database,
)
from sastsimi.static_analysis.registered_codeql_provider import (
    RegisteredCodeQLDatabase,
    RegisteredCodeQLDatabaseProvider,
    RegisteredCodeQLProviderError,
)

_REPOSITORY_URL = "https://example.invalid/owner/repository.git"
_COMMIT_ID = "a" * 40
_MANIFEST_SHA256 = "b" * 64
_EVIDENCE_SHA256 = "c" * 64


def _config(tmp_path: Path, **changes: object) -> CodeQLContainerRuntimeConfig:
    registry = tmp_path / "registry"
    registry.mkdir(exist_ok=True)
    query_pack = tmp_path / "query-pack"
    query_pack.mkdir(exist_ok=True)
    values: dict[str, object] = {
        "schema_version": 1,
        "image": "ghcr.io/example/codeql@sha256:" + "d" * 64,
        "expected_codeql_version": "2.23.1",
        "database_registry_root": registry,
        "query_pack_root": query_pack,
        "query_pack_sha256": "e" * 64,
        "database_provider_key": "controlled-codeql-db",
        "database_provider_revision": "2026-09-19.1",
        "database_provider_evidence_sha256": _EVIDENCE_SHA256,
        "database_limit_bytes": 268_435_456,
        "output_limit_bytes": 16_777_216,
        "pids_limit": 64,
        "memory_limit_bytes": 536_870_912,
        "nano_cpus": 500_000_000,
        "container_uid": 65532,
        "container_gid": 65532,
    }
    values.update(changes)
    return CodeQLContainerRuntimeConfig.model_validate(values)


def _identity(config: CodeQLContainerRuntimeConfig) -> CodeQLDatabaseIdentity:
    return CodeQLDatabaseIdentity(
        repository_url=_REPOSITORY_URL,
        commit_id=_COMMIT_ID,
        language="python",
        tracked_manifest_sha256=_MANIFEST_SHA256,
        provider_key=config.database_provider_key,
        provider_revision=config.database_provider_revision,
        provider_evidence_sha256=config.database_provider_evidence_sha256,
    )


def _publish(tmp_path: Path, config: CodeQLContainerRuntimeConfig) -> None:
    source = tmp_path / "source-database"
    source.mkdir()
    (source / "codeql-database.yml").write_bytes(b"primaryLanguage: python\n")
    publish_codeql_database(
        registry_root=config.database_registry_root,
        database_root=source,
        identity=_identity(config),
    )


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        item.relative_to(root).as_posix(): item.read_bytes()
        for item in sorted(root.rglob("*"))
        if item.is_file()
    }


def test_resolves_only_exact_immutable_database_without_mutating_registry(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    _publish(tmp_path, config)
    before = _tree_bytes(config.database_registry_root)

    resolved = RegisteredCodeQLDatabaseProvider(config).resolve(
        repository_url=_REPOSITORY_URL,
        commit_id=_COMMIT_ID,
        language="python",
        tracked_manifest_sha256=_MANIFEST_SHA256,
    )

    assert tuple(field.name for field in fields(RegisteredCodeQLDatabase)) == (
        "database_root",
        "database_digest",
        "artifact_key",
    )
    assert resolved.database_root == (
        config.database_registry_root / resolved.artifact_key / "database"
    )
    assert resolved.database_digest == (
        "7151472550cdd212c25357723b009abdc0d32154a7e6ad9bf48cf630d7bed7af"
    )
    assert _tree_bytes(config.database_registry_root) == before


@pytest.mark.parametrize(
    ("changes"),
    [
        {"repository_url": _REPOSITORY_URL + "/other"},
        {"commit_id": "f" * 40},
        {"language": "javascript-typescript"},
        {"tracked_manifest_sha256": "f" * 64},
    ],
)
def test_exact_input_mismatch_never_falls_back_to_another_database(
    tmp_path: Path, changes: dict[str, str]
) -> None:
    config = _config(tmp_path)
    _publish(tmp_path, config)
    inputs = {
        "repository_url": _REPOSITORY_URL,
        "commit_id": _COMMIT_ID,
        "language": "python",
        "tracked_manifest_sha256": _MANIFEST_SHA256,
    }
    inputs.update(changes)

    with pytest.raises(
        RegisteredCodeQLProviderError,
        match="^REGISTERED_CODEQL_DATABASE_NOT_FOUND$",
    ):
        RegisteredCodeQLDatabaseProvider(config).resolve(**inputs)  # type: ignore[arg-type]


def test_provider_identity_mismatch_fails_with_stable_error(tmp_path: Path) -> None:
    published_config = _config(tmp_path)
    _publish(tmp_path, published_config)
    runtime_config = _config(
        tmp_path,
        database_provider_revision="2026-09-19.2",
    )

    with pytest.raises(
        RegisteredCodeQLProviderError,
        match="^REGISTERED_CODEQL_DATABASE_INVALID$",
    ) as captured:
        RegisteredCodeQLDatabaseProvider(runtime_config).resolve(
            repository_url=_REPOSITORY_URL,
            commit_id=_COMMIT_ID,
            language="python",
            tracked_manifest_sha256=_MANIFEST_SHA256,
        )

    assert str(runtime_config.database_registry_root) not in str(captured.value)


def test_registry_integrity_failure_is_sanitized(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _publish(tmp_path, config)
    artifact_key = _identity(config).artifact_key
    database_file = (
        config.database_registry_root
        / artifact_key
        / "database"
        / "codeql-database.yml"
    )
    database_file.write_bytes(b"tampered\n")

    with pytest.raises(
        RegisteredCodeQLProviderError,
        match="^REGISTERED_CODEQL_DATABASE_INVALID$",
    ) as captured:
        RegisteredCodeQLDatabaseProvider(config).resolve(
            repository_url=_REPOSITORY_URL,
            commit_id=_COMMIT_ID,
            language="python",
            tracked_manifest_sha256=_MANIFEST_SHA256,
        )

    assert str(database_file) not in str(captured.value)


def test_invalid_input_and_registry_path_use_stable_errors(tmp_path: Path) -> None:
    config = _config(tmp_path)
    with pytest.raises(
        RegisteredCodeQLProviderError,
        match="^REGISTERED_CODEQL_INPUT_INVALID$",
    ) as invalid_input:
        RegisteredCodeQLDatabaseProvider(config).resolve(
            repository_url="https://example.invalid/secret\npath",
            commit_id=_COMMIT_ID,
            language="python",
            tracked_manifest_sha256=_MANIFEST_SHA256,
        )
    assert "secret" not in str(invalid_input.value)

    missing = tmp_path / "missing-registry"
    missing_config = _config(tmp_path, database_registry_root=missing)
    with pytest.raises(
        RegisteredCodeQLProviderError,
        match="^REGISTERED_CODEQL_REGISTRY_INVALID$",
    ) as invalid_registry:
        RegisteredCodeQLDatabaseProvider(missing_config).resolve(
            repository_url=_REPOSITORY_URL,
            commit_id=_COMMIT_ID,
            language="python",
            tracked_manifest_sha256=_MANIFEST_SHA256,
        )
    assert str(missing) not in str(invalid_registry.value)


def test_rejects_a_registry_result_whose_database_path_escapes_configured_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    _publish(tmp_path, config)
    published = lookup_codeql_database(
        registry_root=config.database_registry_root,
        identity=_identity(config),
    )
    assert published is not None
    outside = tmp_path / "outside" / "database"
    monkeypatch.setattr(
        provider_module,
        "lookup_codeql_database",
        lambda **_kwargs: replace(published, database_root=outside),
    )

    with pytest.raises(
        RegisteredCodeQLProviderError,
        match="^REGISTERED_CODEQL_DATABASE_INVALID$",
    ):
        RegisteredCodeQLDatabaseProvider(config).resolve(
            repository_url=_REPOSITORY_URL,
            commit_id=_COMMIT_ID,
            language="python",
            tracked_manifest_sha256=_MANIFEST_SHA256,
        )
