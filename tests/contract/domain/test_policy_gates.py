from typing import Any

import pytest
from pydantic import ValidationError

from .fixtures import meta, mutations, ref, wire


def test_collection_failure_is_not_absence_or_cache_hit() -> None:
    from sastsimi.contracts.policy import PolicyCollectionResult

    value: dict[str, Any] = dict(
        meta=meta("policy_collection_result"),
        collection_result_id="collection1",
        program_id="program1",
        preparation_source="COLLECTED",
        source_cache_ref=None,
        status="COLLECTION_FAILED",
        official_source_refs=[],
        parser_result_refs=[],
        policy_record_ref=None,
        gap_ids=[],
        error_ids=["err1"],
        completed_at="2026-09-08T00:00:00Z",
    )
    wire(PolicyCollectionResult, value)
    for field in value:
        with pytest.raises(ValidationError):
            wire(PolicyCollectionResult, {k: v for k, v in value.items() if k != field})
    for patch in mutations(
        dict(status="ABSENT_CONFIRMED"),
        dict(policy_record_ref=ref("program_policy_record")),
        dict(error_ids=[]),
        dict(preparation_source="REUSED_CACHE"),
    ):
        with pytest.raises(ValidationError):
            wire(PolicyCollectionResult, value | patch)


def test_technical_gate_uses_status_and_requires_ready_accept() -> None:
    from sastsimi.contracts.gates import TechnicalEvidenceReview

    value: dict[str, Any] = dict(
        meta=meta("technical_evidence_review", hypothesis="h1"),
        action_decision_ref=ref("action_decision"),
        verification_result_ref=ref("verification_result"),
        cwe_label_ref=ref("cwe_label"),
        status="ACCEPT",
        evidence_verdict_alignment="Aligned",
        code_flow_linkage="Connected",
        dynamic_linkage="Executed",
        cwe_assessment="Checked",
        restriction_assessment="Preserved",
        handoff_readiness="READY",
        revision_requests=[],
        verification_requests=[],
        rationale="Evidence sufficient",
    )
    wire(TechnicalEvidenceReview, value)
    with pytest.raises(ValidationError):
        wire(TechnicalEvidenceReview, value | dict(status="REVISE"))
    with pytest.raises(ValidationError):
        wire(TechnicalEvidenceReview, value | dict(decision="ACCEPT"))


def test_uncertain_scope_cannot_allow_report() -> None:
    from sastsimi.contracts.gates import RuleScopeImpactReview

    value: dict[str, Any] = dict(
        meta=meta("rule_scope_impact_review", hypothesis="h1"),
        action_decision_ref=ref("action_decision"),
        verification_result_ref=ref("verification_result"),
        technical_review_ref=ref("technical_evidence_review"),
        cwe_label_ref=ref("cwe_label"),
        run_policy_state_ref=ref("run_policy_state"),
        policy_collection_result_ref=ref("policy_collection_result"),
        policy_record_ref=None,
        review_status="UNCERTAIN",
        rule_compliance="UNCERTAIN",
        scope_compliance="UNCERTAIN",
        testing_restriction_compliance="UNCERTAIN",
        security_impact="UNCERTAIN",
        report_permission="DENY",
        evidence_links=[],
        reasons=["Policy absent"],
        missing_information=[
            dict(
                missing_info_id=area,
                area=area,
                blocks_allow=True,
                description="No official criteria",
                policy_item_ids=[],
                evidence_refs=[],
            )
            for area in ["RULE", "SCOPE", "TESTING_RESTRICTION", "IMPACT"]
        ],
    )
    wire(RuleScopeImpactReview, value)
    with pytest.raises(ValidationError, match="REPORT_NOT_READY"):
        wire(RuleScopeImpactReview, value | {"report_permission": "ALLOW"})
    with pytest.raises(ValidationError, match="MISSING_INFORMATION"):
        wire(RuleScopeImpactReview, value | {"missing_information": []})


def test_finding_index_stale_record_cannot_remain_current() -> None:
    from sastsimi.contracts.reporting import FindingIndexState, ReportDraft

    value: dict[str, Any] = dict(
        meta=meta("finding_index_state", hypothesis="h1", attempt=None),
        state_version=1,
        status="EMPTY",
        finding_ref=None,
        stale_finding_ref=None,
        normalization_work_ref=None,
        last_transition_commit_ref=None,
        invalidated_by_refs=[],
    )
    wire(FindingIndexState, value)
    with pytest.raises(ValidationError):
        wire(FindingIndexState, value | {"status": "CURRENT"})
    with pytest.raises(ValidationError):
        wire(FindingIndexState, value | {"finding_ref": ref("finding")})
    assert "disclosure_status" not in ReportDraft.model_fields
