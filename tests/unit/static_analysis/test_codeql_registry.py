"""Controlled CodeQL database publication never runs target code."""

from __future__ import annotations

import json
import os
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
from sastsimi.static_analysis.codeql_registry import (
    CodeQLDatabaseIdentity,
    lookup_codeql_database,
    publish_codeql_database,
    read_codeql_database_manifest,
)
from sastsimi.static_analysis.prebuilt_codeql_database import (
    FilesystemPrebuiltCodeQLDatabaseProvider,
)

REPOSITORY_URL = "https://example.invalid/owner/repository.git"
COMMIT_ID = "a" * 40
TRACKED_MANIFEST_SHA256 = "b" * 64
PROVIDER_EVIDENCE_SHA256 = "c" * 64
EXPECTED_DATABASE_DIGEST = (
    "10963ab03d3386c3262b92536a388378a271f59ef70b42bea5c2b9be8e99d972"
)


def _identity(**changes: object) -> CodeQLDatabaseIdentity:
    values: dict[str, object] = {
        "repository_url": REPOSITORY_URL,
        "commit_id": COMMIT_ID,
        "language": "python",
        "tracked_manifest_sha256": TRACKED_MANIFEST_SHA256,
        "provider_key": "controlled-codeql-db",
        "provider_revision": "2026-09-19.1",
        "provider_evidence_sha256": PROVIDER_EVIDENCE_SHA256,
    }
    values.update(changes)
    return CodeQLDatabaseIdentity(**values)  # type: ignore[arg-type]


def _database(root: Path) -> Path:
    database = root / "created-database"
    (database / "nested").mkdir(parents=True)
    (database / "a.txt").write_bytes(b"alpha\n")
    (database / "nested" / "b.bin").write_bytes(bytes((0, 1)))
    return database


def _profile_ref() -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId("codeql-profile"),
        data_kind="static_tool_profile",
        content_hash="d" * 64,
        host_id="host-one",
        publication_analysis_id=AnalysisId("analysis-one"),
        publication_workspace_id=WorkspaceId("workspace-one"),
        publication_commit_id=CommitId(COMMIT_ID),
        record_id=RecordId("codeql-profile-record"),
    )


def test_publish_creates_exact_immutable_provider_compatible_artifact(
    tmp_path: Path,
) -> None:
    """Catches a non-atomic or shape-incompatible registry publication."""

    registry = tmp_path / "registry"
    registry.mkdir()
    identity = _identity()

    published = publish_codeql_database(
        registry_root=registry,
        database_root=_database(tmp_path),
        identity=identity,
    )

    assert published.database_digest == EXPECTED_DATABASE_DIGEST
    assert published.artifact_root.parent == registry
    assert published.database_root == published.artifact_root / "database"
    assert published.manifest_path == (
        published.artifact_root / "sastsimi-codeql-database.json"
    )
    assert json.loads(published.manifest_path.read_bytes()) == {
        "schema_version": 1,
        "provider_key": "controlled-codeql-db",
        "provider_revision": "2026-09-19.1",
        "provider_evidence_sha256": PROVIDER_EVIDENCE_SHA256,
        "repository_url": REPOSITORY_URL,
        "commit_id": COMMIT_ID,
        "language": "python",
        "tracked_manifest_sha256": TRACKED_MANIFEST_SHA256,
        "database_digest": EXPECTED_DATABASE_DIGEST,
    }
    assert (
        lookup_codeql_database(registry_root=registry, identity=identity) == published
    )


def test_existing_runtime_provider_materializes_published_artifact(
    tmp_path: Path,
) -> None:
    """Catches divergence from the manifest consumed by the runtime provider."""

    registry = tmp_path / "registry"
    registry.mkdir()
    identity = _identity()
    published = publish_codeql_database(
        registry_root=registry,
        database_root=_database(tmp_path),
        identity=identity,
    )
    quota_root = tmp_path / "quota"
    quota_root.mkdir()
    profile_ref = _profile_ref()
    provider = FilesystemPrebuiltCodeQLDatabaseProvider(
        registry_root=registry,
        provider_key=identity.provider_key,
        provider_revision=identity.provider_revision,
        provider_evidence_sha256=identity.provider_evidence_sha256,
        profile_ref=profile_ref,
    )

    materialized = provider.materialize(
        workspace_id="workspace-one",
        repository_url=identity.repository_url,
        commit_id=identity.commit_id,
        language=identity.language,
        tracked_manifest_sha256=identity.tracked_manifest_sha256,
        profile_ref=profile_ref,
        quota_binding=StaticOutputQuotaBinding(
            binding_id="binding-one",
            lease_id="lease-one",
            backend_key="test-hard-quota",
            enforcement_evidence="cap-plus-one-denied",
            root=quota_root,
            action_id="action-one",
            attempt_id="attempt-one",
            profile_ref=profile_ref,
            effective_limit_bytes=1024 * 1024,
            hard_enforced=True,
            limit_breached=False,
            breach_evidence=None,
        ),
    )

    assert materialized is not None
    assert materialized.database_digest == published.database_digest
    assert materialized.database_root == (quota_root / "database").resolve(strict=True)


def test_duplicate_publication_never_overwrites_existing_artifact(
    tmp_path: Path,
) -> None:
    """Catches replacement of an already-published immutable database."""

    registry = tmp_path / "registry"
    registry.mkdir()
    identity = _identity()
    first = publish_codeql_database(
        registry_root=registry,
        database_root=_database(tmp_path / "first"),
        identity=identity,
    )
    before = first.manifest_path.read_bytes()
    different = tmp_path / "different"
    different.mkdir()
    (different / "changed.txt").write_text("changed", encoding="utf-8")

    with pytest.raises(FileExistsError, match="CODEQL_DATABASE_ALREADY_PUBLISHED"):
        publish_codeql_database(
            registry_root=registry,
            database_root=different,
            identity=identity,
        )

    assert first.manifest_path.read_bytes() == before
    assert not (first.database_root / "changed.txt").exists()


def test_lookup_rejects_identity_or_database_mismatch(tmp_path: Path) -> None:
    """Catches stale metadata and post-publication database mutation."""

    registry = tmp_path / "registry"
    registry.mkdir()
    identity = _identity()
    published = publish_codeql_database(
        registry_root=registry,
        database_root=_database(tmp_path),
        identity=identity,
    )

    assert (
        lookup_codeql_database(
            registry_root=registry,
            identity=_identity(commit_id="d" * 40),
        )
        is None
    )
    (published.database_root / "a.txt").write_bytes(b"mutated")
    with pytest.raises(ValueError, match="CODEQL_DATABASE_DIGEST_MISMATCH"):
        lookup_codeql_database(registry_root=registry, identity=identity)


def test_manifest_reader_rejects_canonical_but_invalid_identity_fields(
    tmp_path: Path,
) -> None:
    """Catches a well-formed JSON manifest with invalid security identifiers."""

    registry = tmp_path / "registry"
    registry.mkdir()
    published = publish_codeql_database(
        registry_root=registry,
        database_root=_database(tmp_path),
        identity=_identity(),
    )
    manifest = json.loads(published.manifest_path.read_bytes())
    manifest["database_digest"] = "not-a-digest"
    published.manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="CODEQL_DATABASE_MANIFEST_INVALID"):
        read_codeql_database_manifest(published.artifact_root)


def test_publish_rejects_hard_linked_database_input(tmp_path: Path) -> None:
    """Catches link-based mutation or escape from the controlled source tree."""

    registry = tmp_path / "registry"
    registry.mkdir()
    database = tmp_path / "database"
    database.mkdir()
    source = tmp_path / "outside.bin"
    source.write_bytes(b"outside")
    try:
        os.link(source, database / "linked.bin")
    except OSError:
        pytest.skip("hard links are unavailable on this test filesystem")

    with pytest.raises(ValueError, match="CODEQL_DATABASE_TREE_INVALID"):
        publish_codeql_database(
            registry_root=registry,
            database_root=database,
            identity=_identity(),
        )

    assert tuple(registry.iterdir()) == ()


def test_cancelled_publication_removes_only_owned_temporary_state(
    tmp_path: Path,
) -> None:
    """Catches partial registry entries left behind after cancellation."""

    registry = tmp_path / "registry"
    registry.mkdir()
    unrelated = registry / "operator-owned.txt"
    unrelated.write_text("keep", encoding="utf-8")
    database = tmp_path / "database"
    database.mkdir()
    (database / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))
    checks = 0

    def cancelled() -> bool:
        nonlocal checks
        checks += 1
        return checks >= 4

    with pytest.raises(ValueError, match="CODEQL_DATABASE_PROVISION_CANCELLED"):
        publish_codeql_database(
            registry_root=registry,
            database_root=database,
            identity=_identity(),
            cancellation_requested=cancelled,
        )

    assert unrelated.read_text(encoding="utf-8") == "keep"
    assert tuple(registry.iterdir()) == (unrelated,)


@pytest.mark.parametrize(
    "changes",
    [
        {"commit_id": "../branch"},
        {"language": "java"},
        {"tracked_manifest_sha256": "not-a-digest"},
        {"provider_key": ""},
        {"provider_revision": "revision\nwith-newline"},
        {"provider_evidence_sha256": "f" * 63},
    ],
)
def test_identity_rejects_ambiguous_or_unsafe_values(
    changes: dict[str, object],
) -> None:
    """Catches ambiguous registry keys and path/control-character injection."""

    with pytest.raises(ValueError, match="CODEQL_DATABASE_IDENTITY_INVALID"):
        _identity(**changes)
