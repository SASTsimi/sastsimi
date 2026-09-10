import pytest

from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.orchestration.static_publication import StaticNormalizationPublisher
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


def test_normalization_sources_are_set_equal_including_failed_tool_work() -> None:
    first = StoredDataRef(
        stored_data_id=StoredDataId("a" * 64),
        data_kind="work_execution_state",
        record_id=RecordId("tool-work-a"),
        content_hash="a" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )
    failed = first.model_copy(
        update={
            "stored_data_id": StoredDataId("b" * 64),
            "record_id": RecordId("tool-work-failed"),
            "content_hash": "b" * 64,
        }
    )

    with pytest.raises(ValueError, match="STATIC_NORMALIZATION_PUBLICATION_INVALID"):
        StaticNormalizationPublisher._validate_source_set((first, failed), (first,))

    StaticNormalizationPublisher._validate_source_set((first, failed), (failed, first))
