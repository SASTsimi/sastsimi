import pytest
from pydantic import ValidationError

from .fixtures import meta, ref, verification, wire


def test_admission_denies_only_confirmed_testing_violation() -> None:
    from sastsimi.contracts.chaining import PrimitiveAdmissionDecision

    value = dict(
        meta=meta("primitive_admission_decision", hypothesis="h1"),
        verification_result_ref=ref("verification_result"),
        technical_review_ref=ref("technical_evidence_review"),
        policy_collection_result_ref=ref("policy_collection_result"),
        rule_scope_review_ref=ref("rule_scope_impact_review"),
        testing_restriction_compliance="FAIL",
        decision="DENY",
        reason_code="TESTING_RESTRICTION_VIOLATION",
        decided_at="2026-09-08T00:00:00Z",
    )
    wire(PrimitiveAdmissionDecision, value)
    with pytest.raises(ValidationError, match="ADMISSION"):
        wire(PrimitiveAdmissionDecision, value | {"decision": "ALLOW"})
    wire(
        PrimitiveAdmissionDecision,
        value
        | dict(
            rule_scope_review_ref=None,
            testing_restriction_compliance="NOT_EVALUATED",
            decision="ALLOW",
            reason_code="POLICY_COLLECTION_FAILED",
        ),
    )


def test_hold_primitive_preserves_exact_inputs_and_restrictions() -> None:
    from sastsimi.contracts.canonical_json import content_hash
    from sastsimi.contracts.chaining import Primitive, validate_primitive_source
    from sastsimi.contracts.verification import VerificationResult

    draft = dict(
        draft_id="d1",
        entity_refs=[],
        privilege_level=None,
        evidence_refs=[ref("code", record=False)],
        description="Required capability",
    )
    source = wire(
        VerificationResult, verification() | {"required_primitive_candidates": [draft]}
    )
    value = dict(
        meta=meta("primitive", hypothesis="h1"),
        primitive_id="pr1",
        workspace_id="ws1",
        commit_id="c1",
        inputs=[draft],
        result=None,
        restrictions=[],
        source_hypothesis_id="h1",
        source_verification_ref=ref("verification_result")
        | {"content_hash": content_hash(source)},
        technical_review_ref=None,
        admission_decision_ref=None,
        evidence_refs=[ref("code", record=False)],
        description="Need capability",
    )
    primitive = wire(Primitive, value)
    validate_primitive_source(primitive, source)
    with pytest.raises(ValueError, match="PRIMITIVE_SOURCE_DRIFT"):
        validate_primitive_source(
            wire(Primitive, value | {"inputs": [draft | {"description": "Changed"}]}),
            source,
        )
    with pytest.raises(ValidationError):
        wire(Primitive, value | {"status": "ACTIVE"})


def test_chaining_used_and_excluded_sets_cannot_overlap() -> None:
    from sastsimi.contracts.chaining import ChainingResult

    value = dict(
        meta=meta("chaining_result", hypothesis="h1"),
        source_result_refs=[],
        considered_primitive_refs=[ref("primitive")],
        input_primitive_refs=[],
        primitive_match_candidates=[],
        chained_hypothesis_proposals=[],
        excluded_lineage_refs=[],
        no_match_reasons=[],
        errors=[],
    )
    wire(ChainingResult, value)
    with pytest.raises(ValidationError, match="CHAINING_INPUT_CLOSURE"):
        wire(ChainingResult, value | {"input_primitive_refs": [ref("primitive")]})
