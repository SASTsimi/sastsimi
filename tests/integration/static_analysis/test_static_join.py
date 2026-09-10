from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, StaticFactBundle
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.static_publication import (
    StaticNormalizationPublisher,
    StaticNormalizationSource,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.normalizer import StaticNormalizer, decoder_key
from tests.unit.static_analysis.test_normalizer import _material, meta


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


def test_candidate_bundle_is_fully_validated_before_complete() -> None:
    material, observation = _material()
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            {
                "meta": meta("code_workspace", run=True),
                "workspace_id": "ws1",
                "analysis_id": "a1",
                "repository_url": "https://example.invalid/repo",
                "commit_id": "c1",
                "status": "READY",
            }
        )
    )
    bundle_meta = RecordMeta.model_validate_json(
        canonical_bytes(meta("static_fact_bundle", attempt=None))
    )
    normalizer = StaticNormalizer(
        {
            decoder_key(
                material.profile_ref,
                material.result.tool_name,
                material.result.tool_version,
            ): lambda raw, result, profile, catalog: observation
        }
    )
    valid = normalizer.normalize(
        bundle_meta=bundle_meta,
        workspace=workspace,
        materials=(material,),
    )
    invalid = valid.model_copy(update={"tool_runs": ()})
    config_ref = StoredDataRef(
        stored_data_id=StoredDataId("c" * 64),
        data_kind="analysis_configuration",
        record_id=None,
        content_hash="c" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )
    work = cast(
        WorkExecutionState,
        SimpleNamespace(
            work_id="normalize-work",
            meta=RecordMeta.model_validate_json(
                canonical_bytes(meta("work_execution_state", attempt=None))
            ),
            status="RUNNING",
            work_type="STATIC_NORMALIZE",
            active_attempt_id="normalize-attempt",
            input_hash="f" * 64,
            input_refs=(config_ref,),
        ),
    )
    completed: list[StaticFactBundle] = []
    runner = cast(
        WorkflowRunner,
        SimpleNamespace(
            runtime=SimpleNamespace(work=SimpleNamespace(get=lambda _work_id: work)),
            metadata=lambda _meta, _kind: bundle_meta.model_dump(),
            complete=lambda _work, _identity, _role, outputs, **_values: (
                completed.append(outputs[0])
            ),
        ),
    )
    publisher = StaticNormalizationPublisher(
        runner,
        cast(StaticNormalizer, SimpleNamespace(normalize=lambda **_values: invalid)),
    )
    dynamic = cast(Any, publisher)
    dynamic._validate_workspace_and_sources = lambda *_values: None
    dynamic._resolve_source = lambda *_values: material
    dynamic._current_running_attempt = lambda _work: SimpleNamespace(
        input_hash="f" * 64
    )
    source = StaticNormalizationSource(
        tool_work_ref=StoredDataRef(
            stored_data_id=StoredDataId("e" * 64),
            data_kind="work_execution_state",
            record_id=RecordId("tool-work"),
            content_hash="a" * 64,
            workspace_id=WorkspaceId("ws1"),
            commit_id=CommitId("c1"),
        ),
        profile_ref=material.profile_ref,
    )

    with pytest.raises(ValueError, match="STATIC_NORMALIZATION_PUBLICATION_INVALID"):
        publisher.publish(
            work,
            config_ref,
            workspace,
            (source,),
        )

    assert completed == []
    assert reference(valid) != reference(invalid)
