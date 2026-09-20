from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.storage.integrity import artifact_hashes


def _ref(kind: str, digest: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"{kind}-{digest}"),
        data_kind=kind,
        content_hash=digest,
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("commit-1"),
        record_id=None,
    )


def test_integrity_only_opens_content_backed_artifact_refs() -> None:
    artifact_digest = "a" * 64
    recipe_identity_digest = "b" * 64

    assert tuple(artifact_hashes(_ref("artifact", artifact_digest))) == (
        artifact_digest,
    )
    assert tuple(artifact_hashes(_ref("recipe_source", recipe_identity_digest))) == ()

