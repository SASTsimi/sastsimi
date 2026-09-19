from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.ports.dto import StaticOutputQuotaBinding
from sastsimi.static_analysis.codeql_adapter import digest_path
from sastsimi.static_analysis.prebuilt_codeql_database import (
    FilesystemPrebuiltCodeQLDatabaseProvider,
    codeql_database_artifact_key,
)


def _profile_ref() -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId("codeql-profile"),
        data_kind="static_tool_profile",
        content_hash="a" * 64,
        host_id="host-one",
        publication_analysis_id=AnalysisId("analysis-one"),
        publication_workspace_id=WorkspaceId("workspace-one"),
        publication_commit_id=CommitId("b" * 40),
        record_id=RecordId("codeql-profile-record"),
    )


def _quota(root: Path, profile_ref: HostConfigurationRef) -> StaticOutputQuotaBinding:
    return StaticOutputQuotaBinding(
        binding_id="binding-one",
        lease_id="lease-one",
        backend_key="test-hard-quota",
        enforcement_evidence="cap-plus-one-denied",
        root=root,
        action_id="action-one",
        attempt_id="attempt-one",
        profile_ref=profile_ref,
        effective_limit_bytes=1024 * 1024,
        hard_enforced=True,
        limit_breached=False,
        breach_evidence=None,
    )


def _artifact(
    registry: Path,
    *,
    repository_url: str,
    commit_id: str,
    language: str,
    tracked_manifest_sha256: str,
) -> Path:
    key = codeql_database_artifact_key(
        repository_url=repository_url,
        commit_id=commit_id,
        language=language,
        tracked_manifest_sha256=tracked_manifest_sha256,
    )
    artifact = registry / key
    database = artifact / "database"
    database.mkdir(parents=True)
    (database / "codeql-database.yml").write_text("primaryLanguage: python\n")
    digest = digest_path(database)
    manifest = {
        "schema_version": 1,
        "provider_key": "filesystem-prebuilt-v1",
        "provider_revision": "revision-1",
        "provider_evidence_sha256": "e" * 64,
        "repository_url": repository_url,
        "commit_id": commit_id,
        "language": language,
        "tracked_manifest_sha256": tracked_manifest_sha256,
        "database_digest": digest,
    }
    (artifact / "sastsimi-codeql-database.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return artifact


def test_provider_materializes_only_the_exact_prebuilt_database(tmp_path: Path) -> None:
    registry = tmp_path / "registry"
    registry.mkdir()
    output = tmp_path / "quota"
    output.mkdir()
    repository_url = "https://example.invalid/org/repo.git"
    commit_id = "b" * 40
    tracked_digest = hashlib.sha256(b"tracked").hexdigest()
    _artifact(
        registry,
        repository_url=repository_url,
        commit_id=commit_id,
        language="python",
        tracked_manifest_sha256=tracked_digest,
    )
    profile_ref = _profile_ref()
    provider = FilesystemPrebuiltCodeQLDatabaseProvider(
        registry_root=registry,
        provider_key="filesystem-prebuilt-v1",
        provider_revision="revision-1",
        provider_evidence_sha256="e" * 64,
        profile_ref=profile_ref,
    )

    database = provider.materialize(
        workspace_id="workspace-one",
        repository_url=repository_url,
        commit_id=commit_id,
        language="python",
        tracked_manifest_sha256=tracked_digest,
        profile_ref=profile_ref,
        quota_binding=_quota(output, profile_ref),
    )

    assert database is not None
    assert database.database_root == (output / "database").resolve(strict=True)
    assert database.database_digest == digest_path(database.database_root)


def test_provider_returns_none_without_an_exact_artifact(tmp_path: Path) -> None:
    registry = tmp_path / "registry"
    registry.mkdir()
    output = tmp_path / "quota"
    output.mkdir()
    profile_ref = _profile_ref()
    provider = FilesystemPrebuiltCodeQLDatabaseProvider(
        registry_root=registry,
        provider_key="filesystem-prebuilt-v1",
        provider_revision="revision-1",
        provider_evidence_sha256="e" * 64,
        profile_ref=profile_ref,
    )

    assert (
        provider.materialize(
            workspace_id="workspace-one",
            repository_url="https://example.invalid/org/repo.git",
            commit_id="b" * 40,
            language="python",
            tracked_manifest_sha256="c" * 64,
            profile_ref=profile_ref,
            quota_binding=_quota(output, profile_ref),
        )
        is None
    )


def test_provider_rejects_manifest_or_profile_substitution(tmp_path: Path) -> None:
    registry = tmp_path / "registry"
    registry.mkdir()
    output = tmp_path / "quota"
    output.mkdir()
    repository_url = "https://example.invalid/org/repo.git"
    commit_id = "b" * 40
    tracked_digest = "c" * 64
    artifact = _artifact(
        registry,
        repository_url=repository_url,
        commit_id=commit_id,
        language="python",
        tracked_manifest_sha256=tracked_digest,
    )
    manifest_path = artifact / "sastsimi-codeql-database.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["commit_id"] = "d" * 40
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    profile_ref = _profile_ref()
    provider = FilesystemPrebuiltCodeQLDatabaseProvider(
        registry_root=registry,
        provider_key="filesystem-prebuilt-v1",
        provider_revision="revision-1",
        provider_evidence_sha256="e" * 64,
        profile_ref=profile_ref,
    )

    with pytest.raises(ValueError, match="CODEQL_DATABASE_MANIFEST_MISMATCH"):
        provider.materialize(
            workspace_id="workspace-one",
            repository_url=repository_url,
            commit_id=commit_id,
            language="python",
            tracked_manifest_sha256=tracked_digest,
            profile_ref=profile_ref,
            quota_binding=_quota(output, profile_ref),
        )

    assert not (output / "database").exists()
