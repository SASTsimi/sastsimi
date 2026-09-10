import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.static_analysis.normalizer import decoder_key


def test_decoder_registry_key_requires_full_record_identity() -> None:
    artifact = StoredDataRef(
        stored_data_id=StoredDataId("a" * 64),
        data_kind="artifact",
        record_id=None,
        content_hash="a" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )

    with pytest.raises(ValueError, match="STATIC_DECODER_PROFILE_INVALID"):
        decoder_key(artifact, "AST", "1")
