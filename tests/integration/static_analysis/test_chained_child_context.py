"""A chained child starts only from its exact two Primitive parents."""

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import (
    ChainingResult,
    Primitive,
    PrimitiveMatchCandidate,
)
from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import ContextRetrievalLimits
from sastsimi.contracts.verification import PrimitiveDraft
from sastsimi.ports.context import (
    ChainingContextRecords,
    ContextCeilingProfile,
    ContextRetrievalIntent,
)
from sastsimi.static_analysis.context_retrieval import plan_context_retrieval
from tests.unit.static_analysis.test_context_retrieval import (
    _fixture,
    _ref,
    _work,
    _workspace,
)


def _chained_lineage() -> ChainingContextRecords:
    bundle, symbols = _fixture()
    _ = bundle
    workspace_id = WorkspaceId.model_validate("ws1")
    commit_id = CommitId.model_validate("c1")
    upstream = Primitive.model_construct(
        meta=_work().meta.model_copy(
            update={"record_id": "up-r1", "logical_record_id": "up-l1"}
        ),
        primitive_id="up",
        workspace_id=workspace_id,
        commit_id=commit_id,
        inputs=(),
        result=PrimitiveDraft.model_construct(
            draft_id="provided",
            entity_refs=(symbols["seed"],),
            privilege_level=None,
            evidence_refs=(_ref("code_context_response", "context-r1"),),
            description="provided seed",
        ),
        restrictions=(),
        source_hypothesis_id="parent-up",
        source_verification_ref=_ref("verification_result", "verify-up"),
        technical_review_ref=_ref("technical_evidence_review", "tech-up"),
        admission_decision_ref=_ref("primitive_admission_decision", "admit-up"),
        evidence_refs=(_ref("code_context_response", "context-r1"),),
        description="upstream",
    )
    downstream = Primitive.model_construct(
        meta=_work().meta.model_copy(
            update={"record_id": "down-r1", "logical_record_id": "down-l1"}
        ),
        primitive_id="down",
        workspace_id=workspace_id,
        commit_id=commit_id,
        inputs=(
            PrimitiveDraft.model_construct(
                draft_id="required",
                entity_refs=(symbols["callee"],),
                privilege_level=None,
                evidence_refs=(_ref("code_context_response", "context-r2"),),
                description="required seed",
            ),
        ),
        result=None,
        restrictions=(),
        source_hypothesis_id="parent-down",
        source_verification_ref=_ref("verification_result", "verify-down"),
        technical_review_ref=None,
        admission_decision_ref=None,
        evidence_refs=(_ref("code_context_response", "context-r2"),),
        description="downstream",
    )
    upstream_ref = reference(upstream)
    downstream_ref = reference(downstream)
    assert isinstance(upstream_ref, StoredDataRef)
    assert isinstance(downstream_ref, StoredDataRef)
    match = PrimitiveMatchCandidate.model_construct(
        primitive_match_id="match-1",
        upstream_result_ref=upstream_ref,
        downstream_input_ref=downstream_ref,
        matched_input_id="required",
        parent_hypothesis_ids=("parent-up", "parent-down"),
        parent_verification_refs=(
            upstream.source_verification_ref,
            downstream.source_verification_ref,
        ),
        workspace_id=workspace_id,
        commit_id=commit_id,
        evidence_refs=(_ref("code_context_response", "context-r1"),),
        candidate_state="UNVALIDATED",
    )
    proposal = HypothesisProposal.model_construct(
        meta=_work().meta.model_copy(
            update={
                "record_id": "proposal-r1",
                "logical_record_id": "proposal-l1",
                "record_type": "hypothesis_proposal",
            }
        ),
        proposal_id="proposal-1",
        origin="CHAINING",
        target_entities=(),
        target_locations=(),
        suspected_path=(),
        falsification_questions=(),
        validation_checks=(),
        parent_hypothesis_ids=("parent-up", "parent-down"),
        source_primitive_match_id="match-1",
        proposal_state="HYPOTHESIS_ONLY",
        assertion_mode="NON_FINAL",
        vulnerability_type_candidates=(),
        observed_facts=(),
        assumptions=(),
        restrictions=(),
    )
    proposal_ref = reference(proposal)
    assert isinstance(proposal_ref, StoredDataRef)
    result = ChainingResult.model_construct(
        meta=_work().meta.model_copy(
            update={
                "record_id": "chain-r1",
                "logical_record_id": "chain-l1",
                "record_type": "chaining_result",
            }
        ),
        source_result_refs=(),
        considered_primitive_refs=(upstream_ref, downstream_ref),
        input_primitive_refs=(upstream_ref, downstream_ref),
        primitive_match_candidates=(match,),
        chained_hypothesis_proposals=(proposal,),
        excluded_lineage_refs=(),
        no_match_reasons=(),
        errors=(),
    )
    result_ref = reference(result)
    assert isinstance(result_ref, StoredDataRef)
    return ChainingContextRecords(
        proposal_ref,
        proposal,
        result_ref,
        result,
        upstream_ref,
        upstream,
        downstream_ref,
        downstream,
    )


def test_lineage_only_request_recovers_both_parent_entity_locations() -> None:
    lineage = _chained_lineage()
    bundle, _ = _fixture()
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    work = _work()
    ceilings = ContextRetrievalLimits(
        max_depth=1,
        max_fragments=10,
        max_bytes=100_000,
        max_requests_per_hypothesis=2,
        timeout_ms=1000,
    )
    plan = plan_context_retrieval(
        intent=ContextRetrievalIntent(
            proposal_ref=lineage.proposal_ref,
            bundle_ref=bundle_ref,
            requested_entities=(),
            requested_locations=(),
            relation_query=(),
            reason="Recover exact chained parents",
            requested_limits=ceilings,
        ),
        bundle=bundle,
        workspace=_workspace(),
        work=work,
        ceilings=ContextCeilingProfile(_ref("artifact", "e" * 64), ceilings),
        work_timeout_ms=1000,
        lineage=lineage,
    )

    assert {item.symbol_id for item in plan.entities} == {"seed", "callee"}
    assert plan.lineage_refs == tuple(
        sorted(plan.lineage_refs, key=canonical_bytes)
    )
