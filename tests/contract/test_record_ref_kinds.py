import json

import pytest

from sastsimi.contracts.ids import AnalysisId
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, validate_exact_ref


def test_run_ref_checks_analysis_record_and_hash() -> None:
    meta = RunMeta.model_validate_json(
        json.dumps(
            dict(
                record_id="r1",
                logical_record_id="l1",
                record_type="work_execution_state",
                schema_version="1.0.0",
                analysis_id="a1",
                revision_number=1,
                previous_record_id=None,
                created_at="2026-09-07T00:00:00Z",
            )
        )
    )
    data = dict(
        stored_data_id="s1",
        data_kind="work_execution_state",
        content_hash="a" * 64,
        analysis_id="a1",
        record_id="r1",
    )
    validate_exact_ref(
        RunStoredDataRef.model_validate_json(json.dumps(data)),
        meta,
        "a" * 64,
        analysis_id=AnalysisId("a1"),
    )
    for key, value in [
        ("analysis_id", "a2"),
        ("record_id", "r2"),
        ("content_hash", "b" * 64),
        ("record_id", None),
    ]:
        with pytest.raises(ValueError):
            validate_exact_ref(
                RunStoredDataRef.model_validate_json(json.dumps(data | {key: value})),
                meta,
                "a" * 64,
                analysis_id=AnalysisId("a1"),
            )


def test_code_ref_checks_workspace_commit_and_consuming_analysis() -> None:
    meta = RecordMeta.model_validate_json(
        json.dumps(
            dict(
                record_id="r1",
                logical_record_id="l1",
                record_type="work_execution_state",
                schema_version="1.0.0",
                analysis_id="a1",
                workspace_id="w1",
                commit_id="c1",
                hypothesis_id=None,
                attempt_id=None,
                revision_number=1,
                previous_record_id=None,
                created_at="2026-09-07T00:00:00Z",
            )
        )
    )
    data = dict(
        stored_data_id="s1",
        data_kind="work_execution_state",
        content_hash="a" * 64,
        workspace_id="w1",
        commit_id="c1",
        record_id="r1",
    )
    for key, value in [
        ("workspace_id", "w2"),
        ("commit_id", "c2"),
        ("record_id", "r2"),
        ("content_hash", "b" * 64),
    ]:
        with pytest.raises(ValueError):
            validate_exact_ref(
                StoredDataRef.model_validate_json(json.dumps(data | {key: value})),
                meta,
                "a" * 64,
                analysis_id=AnalysisId("a1"),
            )
    with pytest.raises(ValueError):
        validate_exact_ref(
            StoredDataRef.model_validate_json(json.dumps(data)),
            meta,
            "a" * 64,
            analysis_id=AnalysisId("a2"),
        )
    assert (
        StoredDataRef.model_validate_json(
            json.dumps(data | {"record_id": None})
        ).record_id
        is None
    )


def test_policy_cache_is_the_only_run_neutral_ref() -> None:
    from sastsimi.contracts.records import PolicyCacheMeta
    from sastsimi.contracts.refs import PolicyCacheRef

    meta = PolicyCacheMeta.model_validate_json(
        json.dumps(
            dict(
                record_id="r1",
                logical_record_id="l1",
                record_type="policy_cache_record",
                schema_version="1.0.0",
                program_id="p1",
                revision_number=1,
                previous_record_id=None,
                created_at="2026-09-07T00:00:00Z",
            )
        )
    )
    data = dict(
        stored_data_id="s1",
        data_kind="policy_cache_record",
        record_id="r1",
        content_hash="a" * 64,
        program_id="p1",
        schema_version="1.0.0",
    )
    validate_exact_ref(
        PolicyCacheRef.model_validate_json(json.dumps(data)), meta, "a" * 64
    )
    for key, value in [
        ("program_id", "p2"),
        ("schema_version", "2.0.0"),
        ("record_id", "r2"),
        ("content_hash", "b" * 64),
    ]:
        with pytest.raises(ValueError):
            validate_exact_ref(
                PolicyCacheRef.model_validate_json(json.dumps(data | {key: value})),
                meta,
                "a" * 64,
            )
