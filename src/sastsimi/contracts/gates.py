"""CWE and the ordered technical/policy Gates; no verdict creation authority."""

from typing import Literal, Self

from pydantic import model_validator

from ._domain import DomainRecord, exact, same_scope, unique
from .base import ContractModel, NonEmptyStr, PositiveInt
from .dynamic import DynamicReproductionResult, PoCBundle
from .ids import WorkId
from .policy import (
    PolicyCollectionResult,
    PolicyMissingInfo,
    ProgramPolicyRecord,
    RunPolicyState,
    validate_policy_freshness,
)
from .refs import StoredDataRef
from .verification import VerificationResult


class CWELabel(DomainRecord):
    KIND = "cwe_label"
    HYPOTHESIS = True
    verification_result_ref: StoredDataRef
    verification_generation: PositiveInt
    cwe_labeling_work_id: WorkId
    llm_call_id: NonEmptyStr
    primary: NonEmptyStr | None
    alternatives: tuple[NonEmptyStr, ...]
    taxonomy_version: NonEmptyStr
    rationale: NonEmptyStr
    evidence_refs: tuple[StoredDataRef, ...]
    uncertainty: NonEmptyStr | None

    @model_validator(mode="after")
    def label_shape(self) -> Self:
        unique(self.alternatives)
        if self.primary in self.alternatives:
            raise ValueError("CWE_LABEL_DUPLICATE")
        if not self.evidence_refs:
            raise ValueError("CWE_EVIDENCE_REQUIRED")
        return self


class TechnicalEvidenceReview(DomainRecord):
    KIND = "technical_evidence_review"
    HYPOTHESIS = True
    action_decision_ref: StoredDataRef
    verification_result_ref: StoredDataRef
    cwe_label_ref: StoredDataRef
    status: Literal["ACCEPT", "REVISE", "REJECT"]
    evidence_verdict_alignment: NonEmptyStr
    code_flow_linkage: NonEmptyStr
    dynamic_linkage: NonEmptyStr
    cwe_assessment: NonEmptyStr
    restriction_assessment: NonEmptyStr
    handoff_readiness: Literal["READY", "NOT_READY"]
    revision_requests: tuple[NonEmptyStr, ...]
    verification_requests: tuple[NonEmptyStr, ...]
    rationale: NonEmptyStr

    @model_validator(mode="after")
    def readiness(self) -> Self:
        if (self.status == "ACCEPT") != (self.handoff_readiness == "READY"):
            raise ValueError("TECHNICAL_READINESS_MISMATCH")
        return self


class RuleScopeEvidenceLink(ContractModel):
    link_id: NonEmptyStr
    area: Literal["RULE", "SCOPE", "IMPACT", "TESTING_RESTRICTION"]
    policy_item_ids: tuple[NonEmptyStr, ...]
    evidence_refs: tuple[StoredDataRef, ...]

    @model_validator(mode="after")
    def actual_evidence(self) -> Self:
        if not self.evidence_refs:
            raise ValueError("GATE_EVIDENCE_REQUIRED")
        unique(self.policy_item_ids)
        unique(self.evidence_refs)
        return self


class RuleScopeImpactReview(DomainRecord):
    KIND = "rule_scope_impact_review"
    HYPOTHESIS = True
    action_decision_ref: StoredDataRef
    verification_result_ref: StoredDataRef
    technical_review_ref: StoredDataRef
    cwe_label_ref: StoredDataRef
    run_policy_state_ref: StoredDataRef
    policy_collection_result_ref: StoredDataRef
    policy_record_ref: StoredDataRef | None
    review_status: Literal["PASS", "FAIL", "UNCERTAIN"]
    rule_compliance: Literal["PASS", "FAIL", "UNCERTAIN"]
    scope_compliance: Literal["PASS", "FAIL", "UNCERTAIN"]
    testing_restriction_compliance: Literal["PASS", "FAIL", "UNCERTAIN"]
    security_impact: Literal["SUFFICIENT", "INSUFFICIENT", "UNCERTAIN"]
    report_permission: Literal["ALLOW", "DENY"]
    evidence_links: tuple[RuleScopeEvidenceLink, ...]
    reasons: tuple[NonEmptyStr, ...]
    missing_information: tuple[PolicyMissingInfo, ...]

    def report_ready(self) -> bool:
        return (
            self.review_status == "PASS"
            and self.rule_compliance == "PASS"
            and self.scope_compliance == "PASS"
            and self.testing_restriction_compliance == "PASS"
            and self.security_impact == "SUFFICIENT"
            and self.report_permission == "ALLOW"
            and not any(item.blocks_allow for item in self.missing_information)
        )

    @model_validator(mode="after")
    def evidence_areas(self) -> Self:
        if self.report_permission == "ALLOW" and not self.report_ready():
            raise ValueError("REPORT_NOT_READY")
        unique(link.link_id for link in self.evidence_links)
        unique(item.missing_info_id for item in self.missing_information)
        for area, verdict in (
            ("RULE", self.rule_compliance),
            ("SCOPE", self.scope_compliance),
            ("TESTING_RESTRICTION", self.testing_restriction_compliance),
            ("IMPACT", self.security_impact),
        ):
            if verdict == "UNCERTAIN":
                if not any(item.area == area for item in self.missing_information):
                    raise ValueError("GATE_MISSING_INFORMATION_REQUIRED")
            elif not any(link.area == area for link in self.evidence_links):
                raise ValueError("GATE_EVIDENCE_REQUIRED")
        return self


def validate_true_dynamic(
    verification: VerificationResult, dynamic: DynamicReproductionResult, poc: PoCBundle
) -> None:
    if (
        verification.verdict != "TRUE"
        or verification.verification_mode != "ALWAYS_DEBATE"
        or dynamic.status != "SUCCEEDED"
        or dynamic.hypothesis_outcome != "SUPPORTED"
    ):
        raise ValueError("TECHNICAL_TRUE_REQUIRED")
    if verification.dynamic_result_ref is None or verification.poc_ref is None:
        raise ValueError("VALIDATED_POC_REQUIRED")
    exact(verification.dynamic_result_ref, dynamic, verification.meta)
    exact(verification.poc_ref, poc, verification.meta)
    same_scope(verification.meta, dynamic.meta)
    same_scope(dynamic.meta, poc.meta, attempt=True)
    if (
        verification.dynamic_request_ref != dynamic.request_ref
        or verification.poc_ref != dynamic.poc_ref
        or poc.request_ref != dynamic.request_ref
    ):
        raise ValueError("DYNAMIC_VERIFICATION_CLOSURE_MISMATCH")


def validate_technical_gate(
    review: TechnicalEvidenceReview,
    verification: VerificationResult,
    label: CWELabel,
    dynamic: DynamicReproductionResult,
    poc: PoCBundle,
    *,
    current_generation: int,
) -> None:
    validate_true_dynamic(verification, dynamic, poc)
    for ref, target in (
        (review.verification_result_ref, verification),
        (review.cwe_label_ref, label),
    ):
        exact(ref, target, review.meta)
        same_scope(review.meta, target.meta)
    if label.verification_generation != current_generation:
        raise ValueError("STALE_RESULT")
    if label.verification_result_ref != review.verification_result_ref:
        raise ValueError("CWE_VERIFICATION_REVISION_MISMATCH")


def validate_rule_scope_gate(
    review: RuleScopeImpactReview,
    technical: TechnicalEvidenceReview,
    state: RunPolicyState,
    collection: PolicyCollectionResult,
    policy: ProgramPolicyRecord | None,
) -> None:
    exact(review.technical_review_ref, technical, review.meta)
    same_scope(review.meta, technical.meta)
    if (
        technical.status != "ACCEPT"
        or technical.verification_result_ref != review.verification_result_ref
        or technical.cwe_label_ref != review.cwe_label_ref
    ):
        raise ValueError("GATE_ORDER_BYPASS")
    exact(review.run_policy_state_ref, state, review.meta)
    exact(review.policy_collection_result_ref, collection, review.meta)
    if collection.status == "COLLECTION_FAILED":
        raise ValueError("COLLECTION_FAILED_GATE_FORBIDDEN")
    if (
        state.status not in {"CURRENT", "ABSENT", "UNVERIFIED"}
        or (state.status == "CURRENT" and collection.status != "FOUND")
        or (state.status == "ABSENT" and collection.status != "ABSENT_CONFIRMED")
    ):
        raise ValueError("POLICY_STATE_STATUS_MISMATCH")
    if (
        state.collection_result_ref != review.policy_collection_result_ref
        or state.policy_record_ref != review.policy_record_ref
        or collection.policy_record_ref != review.policy_record_ref
        or state.program_id != collection.program_id
    ):
        raise ValueError("GATE_POLICY_CLOSURE_MISMATCH")
    if policy is not None:
        validate_policy_freshness(state, policy)
        if review.policy_record_ref is None:
            raise ValueError("POLICY_RECORD_REQUIRED")
        exact(review.policy_record_ref, policy, review.meta)
        if (
            policy.program_id != collection.program_id
            or policy.freshness_status == "STALE"
        ):
            raise ValueError("STALE_RESULT")
        item_ids = {item.policy_item_id for item in policy.items()}
        if any(
            item not in item_ids
            for link in review.evidence_links
            for item in link.policy_item_ids
        ):
            raise ValueError("POLICY_ITEM_CLOSURE_MISMATCH")
    elif collection.status == "FOUND":
        raise ValueError("POLICY_RECORD_REQUIRED")
    if collection.status == "ABSENT_CONFIRMED" or state.status == "UNVERIFIED":
        if (
            review.rule_compliance,
            review.scope_compliance,
            review.testing_restriction_compliance,
            review.review_status,
            review.report_permission,
        ) != ("UNCERTAIN", "UNCERTAIN", "UNCERTAIN", "UNCERTAIN", "DENY"):
            raise ValueError("UNVERIFIED_POLICY_GATE_MISMATCH")


def validate_cwe_evidence(
    label: CWELabel,
    verification: VerificationResult,
    current_generation: int,
    allowed_evidence: tuple[StoredDataRef, ...],
) -> None:
    exact(label.verification_result_ref, verification, label.meta)
    same_scope(label.meta, verification.meta)
    if (
        verification.verdict != "TRUE"
        or label.verification_generation != current_generation
    ):
        raise ValueError("STALE_RESULT")
    unique(label.evidence_refs)
    if any(ref not in allowed_evidence for ref in label.evidence_refs):
        raise ValueError("CWE_EVIDENCE_CLOSURE_MISMATCH")
