from __future__ import annotations

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import _validate_schema
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def test_nullable_union_and_array_bounds_are_enforced() -> None:
    schema = {
        "type": "object",
        "required": ["items"],
        "additionalProperties": False,
        "properties": {
            "items": {
                "type": "array",
                "maxItems": 1,
                "items": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            }
        },
    }
    _validate_schema({"items": [None]}, schema)
    with pytest.raises(ValueError):
        _validate_schema({"items": [123]}, schema)
    with pytest.raises(ValueError):
        _validate_schema({"items": ["one", "two"]}, schema)


def test_legacy_report_checkpoint_has_no_bundle_refs() -> None:
    checkpoint = StageCheckpoint(
        identity=CheckpointIdentity(
            analysis_id="a1",
            workspace_id="ws1",
            commit_id="a" * 40,
            hypothesis_id="h1",
        ),
        stage=SimpleStage.REPORT_DONE,
        stage_version="3",
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
    )
    restored = StageCheckpoint.model_validate_json(checkpoint.model_dump_json())
    assert restored.bundle_manifest_ref is None
    assert restored.bundle_archive_ref is None


def test_checkpoint_completion_persists_both_bundle_refs(tmp_path) -> None:
    identity = CheckpointIdentity(
        analysis_id="a1",
        workspace_id="ws1",
        commit_id="a" * 40,
        hypothesis_id="h1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    manifest_ref = artifacts.put_bytes(b"manifest", "application/json")
    archive_ref = artifacts.put_bytes(b"zip", "application/zip")
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.REPORT_DONE,
        stage_version="3",
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
    )
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    store.save_checkpoint(checkpoint)

    completed = store.complete(
        checkpoint,
        StageResult(
            output_refs=(),
            bundle_manifest_ref=manifest_ref,
            bundle_archive_ref=archive_ref,
        ),
    )
    reloaded = store.require(identity, SimpleStage.REPORT_DONE)
    assert completed.bundle_manifest_ref == manifest_ref
    assert completed.bundle_archive_ref == archive_ref
    assert reloaded.bundle_manifest_ref == manifest_ref
    assert reloaded.bundle_archive_ref == archive_ref
