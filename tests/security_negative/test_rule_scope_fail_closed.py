from __future__ import annotations

from dataclasses import replace

import pytest

from sastsimi.agents.rule_scope_gate import (
    RuleScopeEvidenceSelection,
    RuleScopeMissingInfoProposal,
    RuleScopeProposal,
)
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.reporting.rule_scope_gate_workflow import OfficialSourceBinding
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import wire
from tests.integration.reporting.test_rule_scope_gate import _fixture


def test_redacted_official_body_keeps_original_source_digest() -> None:
    source_ref = StoredDataRef.model_validate(
        {
            "stored_data_id": "a" * 64,
            "data_kind": "official_policy_source",
            "record_id": None,
            "content_hash": "a" * 64,
            "workspace_id": "ws1",
            "commit_id": "c1",
        }
    )

    binding = OfficialSourceBinding(
        source_ref=source_ref,
        source_locator="https://program.example/policy",
        content_hash=source_ref.content_hash,
        redacted_body="[REDACTED:CREDENTIAL]",
    )

    assert binding.content_hash == source_ref.content_hash


@pytest.mark.asyncio
async def test_collection_failed_does_not_create_work_call_or_review() -> None:
    fixture = _fixture()
    collection = wire(
        PolicyCollectionResult,
        make("PolicyCollectionResult")
        | {
            "status": "COLLECTION_FAILED",
            "official_source_refs": [],
            "parser_result_refs": [],
            "policy_record_ref": None,
            "error_ids": ["policy-fetch-failed"],
        },
    )
    collection_ref = reference(collection)
    state_data = make("RunPolicyState")
    state_data.update(
        status="FAILED",
        preparation_source="COLLECTED",
        collection_result_ref=collection_ref.model_dump(mode="json"),
    )
    state = wire(RunPolicyState, state_data)
    state_ref = reference(state)
    assert isinstance(state_ref, StoredDataRef)
    fixture.current_policy_states[0] = state_ref
    inputs = replace(
        fixture.inputs,
        collection=collection,
        collection_ref=collection_ref,
        run_policy_state=state,
        run_policy_state_ref=state_ref,
        policy=None,
        policy_ref=None,
        official_sources=(),
    )

    result = await fixture.service.review(inputs)

    assert result.review_ref is None
    assert result.review is None
    assert result.stop_reason == "POLICY_COLLECTION_FAILED"
    assert fixture.agent.calls == 0
    assert fixture.starts == []
    assert fixture.published == []
    assert fixture.prompt_checks == []


@pytest.mark.asyncio
async def test_unrelated_collection_failure_cannot_stop_current_run_gate() -> None:
    fixture = _fixture()
    collection = wire(
        PolicyCollectionResult,
        make("PolicyCollectionResult")
        | {
            "status": "COLLECTION_FAILED",
            "official_source_refs": [],
            "parser_result_refs": [],
            "policy_record_ref": None,
            "error_ids": ["different-policy-fetch-failed"],
        },
    )
    collection_ref = reference(collection)
    state_data = make("RunPolicyState")
    state_data.update(
        status="FAILED",
        preparation_source="COLLECTED",
        collection_result_ref=collection_ref.model_dump(mode="json"),
    )
    stale_state = wire(RunPolicyState, state_data)
    inputs = replace(
        fixture.inputs,
        collection=collection,
        collection_ref=collection_ref,
        run_policy_state=stale_state,
        run_policy_state_ref=reference(stale_state),
        policy=None,
        policy_ref=None,
        official_sources=(),
    )

    with pytest.raises(ValueError, match="STALE_RUN_POLICY_STATE"):
        await fixture.service.review(inputs)

    assert fixture.agent.calls == 0
    assert fixture.starts == []


@pytest.mark.asyncio
async def test_missing_official_source_fails_before_provider_call() -> None:
    fixture = _fixture()
    inputs = replace(fixture.inputs, official_sources=())

    with pytest.raises(ValueError, match="OFFICIAL_POLICY_SOURCE_SET_MISMATCH"):
        await fixture.service.review(inputs)

    assert fixture.agent.calls == 0
    assert fixture.starts == []


@pytest.mark.asyncio
async def test_official_source_locator_cannot_contradict_verified_source() -> None:
    fixture = _fixture()
    source = fixture.inputs.official_sources[0]
    changed = replace(
        fixture.inputs,
        official_sources=(
            OfficialSourceBinding(
                source_ref=source.source_ref,
                source_locator="https://attacker.invalid/policy",
                content_hash=source.content_hash,
                redacted_body=source.redacted_body,
            ),
        ),
    )

    with pytest.raises(ValueError, match="OFFICIAL_POLICY_SOURCE_LOCATOR_MISMATCH"):
        await fixture.service.review(changed)

    assert fixture.agent.calls == 0


@pytest.mark.asyncio
async def test_unrelated_evidence_cannot_be_added_to_gate_prompt() -> None:
    fixture = _fixture()
    unrelated = StoredDataRef.model_validate(
        {
            "stored_data_id": "unrelated-s1",
            "data_kind": "observation",
            "record_id": None,
            "content_hash": "f" * 64,
            "workspace_id": "ws1",
            "commit_id": "c1",
        }
    )
    changed = replace(
        fixture.inputs,
        available_evidence_refs=(*fixture.inputs.available_evidence_refs, unrelated),
    )

    with pytest.raises(ValueError, match="RULE_SCOPE_EVIDENCE_CLOSURE_MISMATCH"):
        await fixture.service.review(changed)

    assert fixture.agent.calls == 0


@pytest.mark.asyncio
async def test_pass_axis_requires_an_exact_official_policy_item() -> None:
    fixture = _fixture()
    proposal = fixture.agent.proposal
    fixture.agent.proposal = RuleScopeProposal(
        **proposal.model_dump()
        | {
            "evidence_links": tuple(
                RuleScopeEvidenceSelection(
                    area=link.area,
                    policy_item_ids=() if link.area == "RULE" else link.policy_item_ids,
                    evidence_indexes=link.evidence_indexes,
                )
                for link in proposal.evidence_links
            )
        }
    )

    with pytest.raises(ValueError, match="POLICY_ITEM_EVIDENCE_REQUIRED"):
        await fixture.service.review(fixture.inputs)

    assert fixture.published == []


@pytest.mark.asyncio
@pytest.mark.parametrize("state_status", ["ABSENT", "UNVERIFIED"])
async def test_absent_or_unverified_policy_is_canonical_uncertain_deny(
    state_status: str,
) -> None:
    fixture = _fixture()
    inputs = fixture.inputs
    if state_status == "ABSENT":
        collection = PolicyCollectionResult.model_validate(
            inputs.collection.model_dump()
            | {
                "meta": inputs.collection.meta.model_copy(
                    update={
                        "record_id": "absent-collection-r1",
                        "logical_record_id": "absent-collection-l1",
                    }
                ),
                "status": "ABSENT_CONFIRMED",
                "policy_record_ref": None,
                "gap_ids": ("official-policy-absent",),
            }
        )
        collection_ref = reference(collection)
        policy = None
        policy_ref = None
    else:
        assert inputs.policy is not None
        policy = ProgramPolicyRecord.model_validate(
            inputs.policy.model_dump()
            | {
                "meta": inputs.policy.meta.model_copy(
                    update={
                        "record_id": "unverified-policy-r1",
                        "logical_record_id": "unverified-policy-l1",
                    }
                ),
                "freshness_status": "UNVERIFIED",
            }
        )
        policy_ref = reference(policy)
        collection = PolicyCollectionResult.model_validate(
            inputs.collection.model_dump()
            | {
                "meta": inputs.collection.meta.model_copy(
                    update={
                        "record_id": "unverified-collection-r1",
                        "logical_record_id": "unverified-collection-l1",
                    }
                ),
                "policy_record_ref": policy_ref,
            }
        )
        collection_ref = reference(collection)
    state = RunPolicyState.model_validate(
        inputs.run_policy_state.model_dump()
        | {
            "meta": inputs.run_policy_state.meta.model_copy(
                update={
                    "record_id": f"{state_status.lower()}-state-r1",
                    "logical_record_id": f"{state_status.lower()}-state-l1",
                }
            ),
            "status": state_status,
            "policy_cache_ref": (
                None
                if state_status == "UNVERIFIED"
                else inputs.run_policy_state.policy_cache_ref
            ),
            "collection_result_ref": collection_ref,
            "policy_record_ref": policy_ref,
        }
    )
    state_ref = reference(state)
    assert isinstance(state_ref, StoredDataRef)
    fixture.current_policy_states[0] = state_ref
    fixture.agent.proposal = RuleScopeProposal(
        rule_compliance="UNCERTAIN",
        scope_compliance="UNCERTAIN",
        testing_restriction_compliance="UNCERTAIN",
        security_impact="UNCERTAIN",
        report_permission="DENY",
        evidence_links=(),
        reasons=("Official policy is absent or not verified.",),
        missing_information=tuple(
            RuleScopeMissingInfoProposal(
                area=area,
                description="An exact official decision is unavailable.",
                policy_item_ids=(),
                evidence_indexes=(),
            )
            for area in ("RULE", "SCOPE", "TESTING_RESTRICTION", "IMPACT")
        ),
    )
    changed = replace(
        inputs,
        run_policy_state=state,
        run_policy_state_ref=state_ref,
        collection=collection,
        collection_ref=collection_ref,
        policy=policy,
        policy_ref=policy_ref,
    )

    outcome = await fixture.service.review(changed)

    assert outcome.review is not None
    assert outcome.review.review_status == "UNCERTAIN"
    assert outcome.review.report_permission == "DENY"
    assert outcome.review.evidence_links == ()
