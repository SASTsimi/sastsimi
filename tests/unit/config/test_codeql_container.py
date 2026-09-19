from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sastsimi.config.codeql_container import CodeQLContainerRuntimeConfig

_DIGEST = "a" * 64
_QUERY_PACK_DIGEST = "b" * 64
_PROVIDER_EVIDENCE_DIGEST = "c" * 64


def _values(tmp_path: Path) -> dict[str, object]:
    return {
        "schema_version": 1,
        "image": f"ghcr.io/sastsimi/codeql@sha256:{_DIGEST}",
        "expected_codeql_version": "2.27.0",
        "database_registry_root": str(tmp_path / "codeql-databases"),
        "query_pack_root": str(tmp_path / "codeql-query-pack"),
        "query_pack_sha256": _QUERY_PACK_DIGEST,
        "database_provider_key": "approved-codeql-db-provider",
        "database_provider_revision": "2026-09-19-r1",
        "database_provider_evidence_sha256": _PROVIDER_EVIDENCE_DIGEST,
        "database_limit_bytes": 4 * 1024**3,
        "output_limit_bytes": 256 * 1024**2,
        "pids_limit": 256,
        "memory_limit_bytes": 8 * 1024**3,
        "nano_cpus": 2_000_000_000,
        "container_uid": 65532,
        "container_gid": 65532,
    }


def test_accepts_secret_free_digest_pinned_configuration(tmp_path: Path) -> None:
    config = CodeQLContainerRuntimeConfig.model_validate(_values(tmp_path))

    assert config.image == f"ghcr.io/sastsimi/codeql@sha256:{_DIGEST}"
    assert config.expected_codeql_version == "2.27.0"
    assert config.database_registry_root == tmp_path / "codeql-databases"
    assert config.query_pack_root == tmp_path / "codeql-query-pack"
    assert config.container_user == "65532:65532"
    assert config.model_dump(mode="json") == _values(tmp_path)


@pytest.mark.parametrize(
    "image",
    [
        "ghcr.io/sastsimi/codeql:2.27.0",
        f"ghcr.io/sastsimi/codeql:2.27.0@sha256:{_DIGEST}",
        "ghcr.io/sastsimi/codeql@sha256:latest",
        f"GHCR.IO/sastsimi/codeql@sha256:{_DIGEST}",
        f"https://ghcr.io/sastsimi/codeql@sha256:{_DIGEST}",
    ],
)
def test_rejects_unpinned_tagged_or_unsafe_images(tmp_path: Path, image: str) -> None:
    values = _values(tmp_path)
    values["image"] = image

    with pytest.raises(ValidationError, match="CODEQL_CONTAINER_IMAGE_INVALID"):
        CodeQLContainerRuntimeConfig.model_validate(values)


@pytest.mark.parametrize(
    "version", ["latest", ">=2.27.0", "2.27", " 2.27.0", "2.27.0 "]
)
def test_rejects_non_exact_codeql_versions(tmp_path: Path, version: str) -> None:
    values = _values(tmp_path)
    values["expected_codeql_version"] = version

    with pytest.raises(ValidationError, match="CODEQL_VERSION_INVALID"):
        CodeQLContainerRuntimeConfig.model_validate(values)


@pytest.mark.parametrize("field", ["database_registry_root", "query_pack_root"])
def test_rejects_relative_and_filesystem_root_paths(tmp_path: Path, field: str) -> None:
    relative = _values(tmp_path)
    relative[field] = "relative/path"
    with pytest.raises(ValidationError, match="CODEQL_CONTAINER_PATH_INVALID"):
        CodeQLContainerRuntimeConfig.model_validate(relative)

    filesystem_root = _values(tmp_path)
    filesystem_root[field] = str(Path(tmp_path.anchor))
    with pytest.raises(ValidationError, match="CODEQL_CONTAINER_PATH_INVALID"):
        CodeQLContainerRuntimeConfig.model_validate(filesystem_root)


@pytest.mark.parametrize("registry_contains_pack", [True, False])
def test_rejects_overlapping_registry_and_query_pack_paths(
    tmp_path: Path, registry_contains_pack: bool
) -> None:
    values = _values(tmp_path)
    parent = tmp_path / "shared"
    child = parent / "nested"
    if registry_contains_pack:
        values["database_registry_root"] = str(parent)
        values["query_pack_root"] = str(child)
    else:
        values["database_registry_root"] = str(child)
        values["query_pack_root"] = str(parent)

    with pytest.raises(ValidationError, match="CODEQL_CONTAINER_PATHS_OVERLAP"):
        CodeQLContainerRuntimeConfig.model_validate(values)


@pytest.mark.parametrize(
    "field",
    [
        "database_limit_bytes",
        "output_limit_bytes",
        "pids_limit",
        "memory_limit_bytes",
        "nano_cpus",
        "container_uid",
        "container_gid",
    ],
)
def test_rejects_zero_resource_limits_and_root_identity(
    tmp_path: Path, field: str
) -> None:
    values = _values(tmp_path)
    values[field] = 0

    with pytest.raises(ValidationError):
        CodeQLContainerRuntimeConfig.model_validate(values)


@pytest.mark.parametrize(
    "field",
    ["query_pack_sha256", "database_provider_evidence_sha256"],
)
def test_rejects_invalid_digests(tmp_path: Path, field: str) -> None:
    values = _values(tmp_path)
    values[field] = "A" * 64

    with pytest.raises(ValidationError):
        CodeQLContainerRuntimeConfig.model_validate(values)


def test_rejects_secret_fields_and_unsafe_provider_identity(tmp_path: Path) -> None:
    with_secret = _values(tmp_path)
    with_secret["credential_ref"] = "env:CODEQL_TOKEN"
    with pytest.raises(ValidationError):
        CodeQLContainerRuntimeConfig.model_validate(with_secret)

    unsafe_identity = _values(tmp_path)
    unsafe_identity["database_provider_revision"] = " revision\nchanged"
    with pytest.raises(ValidationError, match="CODEQL_PROVIDER_IDENTITY_INVALID"):
        CodeQLContainerRuntimeConfig.model_validate(unsafe_identity)
