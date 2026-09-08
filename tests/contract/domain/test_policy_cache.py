from datetime import UTC, datetime

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.policy import (
    PolicyCacheRecord,
    PolicyCollectionResult,
    PolicyParserResult,
    ProgramPolicyRecord,
    RunPolicyState,
    validate_run_policy,
)
from sastsimi.contracts.refs import PolicyCacheRef

from .canonical_fixtures import make
from .fixtures import ref, wire
from .success_fixture import bound


def test_cache_reuse_preserves_original_policy_and_parser_closure() -> None:
    from sastsimi.contracts.policy import validate_policy_cache_reuse

    source_ref = ref("official_source", record=False)
    parser = wire(
        PolicyParserResult, make("PolicyParserResult") | {"source_ref": source_ref}
    )
    policy = wire(
        ProgramPolicyRecord,
        make("ProgramPolicyRecord")
        | dict(
            source_refs=[source_ref],
            source_checks=[
                make("PolicySourceCheck")
                | dict(source_ref=source_ref, evidence_refs=[source_ref])
            ],
            parser_result_refs=[bound(parser)],
            freshness_status="CURRENT",
            freshness_criterion_ref=ref("freshness_criterion"),
            freshness_checked_at="2026-09-08T00:00:00Z",
            freshness_valid_until="2026-09-09T00:00:00Z",
            freshness_evidence_refs=[source_ref],
        ),
    )
    collection = wire(
        PolicyCollectionResult,
        make("PolicyCollectionResult")
        | dict(
            policy_record_ref=bound(policy),
            official_source_refs=[source_ref],
            parser_result_refs=[bound(parser)],
        ),
    )
    cache = wire(
        PolicyCacheRecord,
        make("PolicyCacheRecord")
        | dict(
            freshness_criterion_ref=ref("freshness_criterion"),
            freshness_evidence_refs=[source_ref],
            collection_result_ref=bound(collection),
            policy_record_ref=bound(policy),
            parser_result_refs=[bound(parser)],
        ),
    )
    cache_ref = wire(
        PolicyCacheRef,
        dict(
            stored_data_id="cache",
            data_kind="policy_cache_record",
            record_id=cache.meta.record_id.root,
            content_hash=content_hash(cache),
            program_id="program1",
            schema_version="1.0.0",
        ),
    )
    new_policy_data = policy.model_dump(mode="json")
    new_policy_data["meta"] = new_policy_data["meta"] | dict(
        analysis_id="a2",
        workspace_id="ws2",
        record_id="new-policy",
        logical_record_id="new-policy-logical",
    )
    new_policy = wire(
        ProgramPolicyRecord,
        new_policy_data
        | dict(
            policy_record_id="new-policy",
            preparation_source="REUSED_CACHE",
            source_cache_ref=cache_ref.model_dump(mode="json"),
        ),
    )
    new_collection_data = collection.model_dump(mode="json")
    new_collection_data["meta"] = new_collection_data["meta"] | dict(
        analysis_id="a2",
        workspace_id="ws2",
        record_id="new-collection",
        logical_record_id="new-collection-logical",
    )
    new_collection = wire(
        PolicyCollectionResult,
        new_collection_data
        | dict(
            collection_result_id="new-collection",
            preparation_source="REUSED_CACHE",
            source_cache_ref=cache_ref.model_dump(mode="json"),
            policy_record_ref=bound(new_policy),
        ),
    )
    validate_policy_cache_reuse(
        cache,
        cache_ref,
        collection,
        policy,
        (parser,),
        new_collection,
        new_policy,
        started_at=datetime(2026, 9, 8, tzinfo=UTC),
    )
    state_data = make("RunPolicyState")
    state_data["meta"] = new_collection_data["meta"] | dict(
        record_type="run_policy_state", attempt_id=None
    )
    state_data.update(
        status="CURRENT",
        preparation_source="REUSED_CACHE",
        source_config_ref=ref("policy_source_config") | dict(workspace_id="ws2"),
        policy_cache_ref=cache_ref.model_dump(mode="json"),
        collection_result_ref=bound(new_collection),
        policy_record_ref=bound(new_policy),
        policy_work_ref=ref("work_execution_state") | dict(workspace_id="ws2"),
        freshness_criterion_ref=ref("freshness_criterion"),
        freshness_evidence_refs=[source_ref],
        freshness_checked_at="2026-09-08T00:00:00Z",
        freshness_valid_until="2026-09-09T00:00:00Z",
    )
    state = wire(RunPolicyState, state_data)
    validate_run_policy(
        state,
        new_collection,
        new_policy,
        cache=cache,
        started_at=datetime(2026, 9, 8, tzinfo=UTC),
    )
    for patch in (
        dict(freshness_status="UNVERIFIED"),
        dict(freshness_evidence_refs=[ref("unrelated", record=False)]),
        dict(freshness_valid_until="2026-09-10T00:00:00Z"),
    ):
        changed_policy = wire(
            ProgramPolicyRecord, new_policy.model_dump(mode="json") | patch
        )
        changed_collection = wire(
            PolicyCollectionResult,
            new_collection.model_dump(mode="json")
            | dict(policy_record_ref=bound(changed_policy)),
        )
        changed_state = wire(
            RunPolicyState,
            state.model_dump(mode="json")
            | dict(
                policy_record_ref=bound(changed_policy),
                collection_result_ref=bound(changed_collection),
            ),
        )
        with pytest.raises(ValueError, match="POLICY_STATE_FRESHNESS_MISMATCH"):
            validate_run_policy(
                changed_state,
                changed_collection,
                changed_policy,
                cache=cache,
                started_at=datetime(2026, 9, 8, tzinfo=UTC),
            )
    with pytest.raises(ValueError, match="POLICY_SOURCE_STALE"):
        validate_policy_cache_reuse(
            cache,
            cache_ref,
            collection,
            policy,
            (parser,),
            new_collection,
            new_policy,
            started_at=datetime(2026, 9, 10, tzinfo=UTC),
        )
    with pytest.raises(ValueError, match="CACHE_POLICY_CONTENT_DRIFT"):
        validate_policy_cache_reuse(
            cache,
            cache_ref,
            collection,
            policy,
            (parser,),
            new_collection,
            wire(
                ProgramPolicyRecord,
                new_policy.model_dump(mode="json") | {"policy_version": "changed"},
            ),
            started_at=datetime(2026, 9, 8, tzinfo=UTC),
        )
