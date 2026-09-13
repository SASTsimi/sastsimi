from __future__ import annotations

import pytest

from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.static_tool import validate_static_material_ref


def _artifact() -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId("a" * 64),
        data_kind="artifact",
        content_hash="a" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=None,
    )


def test_static_material_accepts_common_route_artifact_reference() -> None:
    validate_static_material_ref(_artifact(), legacy_data_kind="analysis_config")


def test_static_material_rejects_uncommitted_semantic_reference() -> None:
    invalid = _artifact().model_copy(
        update={
            "data_kind": "analysis_config",
            "record_id": RecordId("config-record"),
            "content_hash": "b" * 64,
        }
    )

    with pytest.raises(ValueError, match="STATIC_MATERIAL_REFERENCE_INVALID"):
        validate_static_material_ref(invalid, legacy_data_kind="rule_catalog")
