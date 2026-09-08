"""Admission, immutable Primitive records and exact parent/child closures."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Literal, Self

from pydantic import AwareDatetime, model_validator

from ._domain import DomainRecord, exact, exact_set, same_scope, unique
from .base import ContractModel, NonEmptyStr
from .canonical_json import canonical_bytes
from .hypothesis import HypothesisProposal
from .ids import CommitId, HypothesisId, WorkspaceId
from .records import validate_revision
from .refs import StoredDataRef
from .static import AnalysisError, Restriction
from .verification import PrimitiveDraft, VerificationResult

if TYPE_CHECKING:
    from .gates import RuleScopeImpactReview, TechnicalEvidenceReview
    from .policy import PolicyCollectionResult, RunPolicyState


class PrimitiveAdmissionDecision(DomainRecord):
    KIND = "primitive_admission_decision"
    HYPOTHESIS = True
    verification_result_ref: StoredDataRef
    technical_review_ref: StoredDataRef
    policy_collection_result_ref: StoredDataRef
    rule_scope_review_ref: StoredDataRef | None
    testing_restriction_compliance: Literal[
        "PASS", "FAIL", "UNCERTAIN", "NOT_EVALUATED"
    ]
    decision: Literal["ALLOW", "DENY"]
    reason_code: Literal[
        "TESTING_RESTRICTION_PASSED",
        "TESTING_RESTRICTION_UNCERTAIN",
        "POLICY_COLLECTION_FAILED",
        "TESTING_RESTRICTION_VIOLATION",
    ]
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def decision_table(self) -> Self:
        expected = {
            "PASS": ("ALLOW", "TESTING_RESTRICTION_PASSED"),
            "FAIL": ("DENY", "TESTING_RESTRICTION_VIOLATION"),
            "UNCERTAIN": ("ALLOW", "TESTING_RESTRICTION_UNCERTAIN"),
            "NOT_EVALUATED": ("ALLOW", "POLICY_COLLECTION_FAILED"),
        }[self.testing_restriction_compliance]
        if (self.decision, self.reason_code) != expected or (
            self.testing_restriction_compliance == "NOT_EVALUATED"
        ) != (self.rule_scope_review_ref is None):
            raise ValueError("ADMISSION_DECISION_MISMATCH")
        return self


class Primitive(DomainRecord):
    KIND = "primitive"
    HYPOTHESIS = True
    primitive_id: NonEmptyStr
    workspace_id: WorkspaceId
    commit_id: CommitId
    inputs: tuple[PrimitiveDraft, ...]
    result: PrimitiveDraft | None
    restrictions: tuple[Restriction, ...]
    source_hypothesis_id: HypothesisId
    source_verification_ref: StoredDataRef
    technical_review_ref: StoredDataRef | None
    admission_decision_ref: StoredDataRef | None
    evidence_refs: tuple[StoredDataRef, ...]
    description: NonEmptyStr

    @model_validator(mode="after")
    def primitive_shape(self) -> Self:
        if self.source_hypothesis_id != self.meta.hypothesis_id:
            raise ValueError("PRIMITIVE_HYPOTHESIS_MISMATCH")
        drafts = (*self.inputs, *((self.result,) if self.result is not None else ()))
        unique(draft.draft_id for draft in drafts)
        unique(r.restriction_id for r in self.restrictions)
        if not drafts or (
            self.result is None
            and (
                self.technical_review_ref is not None
                or self.admission_decision_ref is not None
            )
        ):
            raise ValueError("HOLD_PRIMITIVE_MISMATCH")
        if self.result is not None and (
            self.technical_review_ref is None or self.admission_decision_ref is None
        ):
            raise ValueError("PRIMITIVE_ADMISSION_REQUIRED")
        if not self.evidence_refs:
            raise ValueError("PRIMITIVE_EVIDENCE_REQUIRED")
        return self


class PrimitiveIndexState(DomainRecord):
    KIND = "primitive_index_state"
    HYPOTHESIS = True
    ATTEMPT = False
    current_verification_ref: StoredDataRef
    primitive_refs: tuple[StoredDataRef, ...]
    updated_at: AwareDatetime


class PrimitiveMatchCandidate(ContractModel):
    primitive_match_id: NonEmptyStr
    upstream_result_ref: StoredDataRef
    downstream_input_ref: StoredDataRef
    matched_input_id: NonEmptyStr
    parent_hypothesis_ids: tuple[HypothesisId, ...]
    parent_verification_refs: tuple[StoredDataRef, ...]
    workspace_id: WorkspaceId
    commit_id: CommitId
    evidence_refs: tuple[StoredDataRef, ...]
    candidate_state: Literal["UNVALIDATED"]

    @model_validator(mode="after")
    def match_evidence(self) -> Self:
        if (
            not self.evidence_refs
            or not self.parent_hypothesis_ids
            or not self.parent_verification_refs
        ):
            raise ValueError("MATCH_EVIDENCE_REQUIRED")
        unique(self.parent_hypothesis_ids)
        unique(self.parent_verification_refs)
        return self


class LineageExclusion(ContractModel):
    excluded_primitive_ref: StoredDataRef
    excluded_by_ref: StoredDataRef
    reason_code: Literal["ANCESTOR_REUSE"]


class NoMatchReason(ContractModel):
    upstream_result_ref: StoredDataRef
    downstream_input_ref: StoredDataRef
    checked_input_id: NonEmptyStr
    reason_code: Literal[
        "ENTITY_UNRELATED",
        "PRIVILEGE_UNSATISFIED",
        "ORDER_INVALID",
        "RESTRICTION_CONFLICT",
        "NO_CODE_EVIDENCE",
    ]
    detail: NonEmptyStr


class ChainingResult(DomainRecord):
    KIND = "chaining_result"
    source_result_refs: tuple[StoredDataRef, ...]
    considered_primitive_refs: tuple[StoredDataRef, ...]
    input_primitive_refs: tuple[StoredDataRef, ...]
    primitive_match_candidates: tuple[PrimitiveMatchCandidate, ...]
    chained_hypothesis_proposals: tuple[HypothesisProposal, ...]
    excluded_lineage_refs: tuple[LineageExclusion, ...]
    no_match_reasons: tuple[NoMatchReason, ...]
    errors: tuple[AnalysisError, ...]

    @model_validator(mode="after")
    def input_sets(self) -> Self:
        for refs in (
            self.source_result_refs,
            self.considered_primitive_refs,
            self.input_primitive_refs,
        ):
            unique(refs)
        used = [
            ref
            for candidate in self.primitive_match_candidates
            for ref in (candidate.upstream_result_ref, candidate.downstream_input_ref)
        ]
        if {canonical_bytes(ref) for ref in used} != {
            canonical_bytes(ref) for ref in self.input_primitive_refs
        }:
            raise ValueError("CHAINING_INPUT_CLOSURE")
        if any(
            ref not in self.considered_primitive_refs
            for ref in self.input_primitive_refs
        ):
            raise ValueError("CHAINING_INPUT_CLOSURE")
        unique(c.primitive_match_id for c in self.primitive_match_candidates)
        combinations = [
            (c.upstream_result_ref, c.downstream_input_ref, c.matched_input_id)
            for c in self.primitive_match_candidates
        ]
        combinations.extend(
            (r.upstream_result_ref, r.downstream_input_ref, r.checked_input_id)
            for r in self.no_match_reasons
        )
        unique(combinations, "MATCH_COMBINATION_DUPLICATE")
        for reason in self.no_match_reasons:
            if (
                reason.upstream_result_ref not in self.considered_primitive_refs
                or reason.downstream_input_ref not in self.considered_primitive_refs
            ):
                raise ValueError("CHAINING_INPUT_CLOSURE")
        for exclusion in self.excluded_lineage_refs:
            if (
                exclusion.excluded_primitive_ref not in self.considered_primitive_refs
                or exclusion.excluded_primitive_ref in self.input_primitive_refs
                or exclusion.excluded_by_ref not in self.input_primitive_refs
            ):
                raise ValueError("LINEAGE_EXCLUSION_MISMATCH")
        if any(p.origin != "CHAINING" for p in self.chained_hypothesis_proposals):
            raise ValueError("CHAINING_PROPOSAL_ORIGIN")
        return self


def validate_primitive_source(
    primitive: Primitive,
    verification: VerificationResult,
    technical: TechnicalEvidenceReview | None = None,
    admission: PrimitiveAdmissionDecision | None = None,
) -> None:
    exact(primitive.source_verification_ref, verification, primitive.meta)
    same_scope(primitive.meta, verification.meta)
    if (
        primitive.inputs != verification.required_primitive_candidates
        or primitive.restrictions != verification.restrictions
    ):
        raise ValueError("PRIMITIVE_SOURCE_DRIFT")
    if verification.verdict == "FALSE":
        raise ValueError("FALSE_PRIMITIVE_FORBIDDEN")
    if verification.verdict == "HOLD":
        if primitive.result is not None or not primitive.inputs:
            raise ValueError("HOLD_PRIMITIVE_MISMATCH")
    else:
        if (
            primitive.result not in verification.provided_primitive_candidates
            or technical is None
            or admission is None
            or primitive.technical_review_ref is None
            or primitive.admission_decision_ref is None
        ):
            raise ValueError("PRIMITIVE_ADMISSION_REQUIRED")
        exact(primitive.technical_review_ref, technical, primitive.meta)
        exact(primitive.admission_decision_ref, admission, primitive.meta)
        if (
            technical.status != "ACCEPT"
            or admission.decision != "ALLOW"
            or technical.verification_result_ref != primitive.source_verification_ref
            or admission.verification_result_ref != primitive.source_verification_ref
        ):
            raise ValueError("PRIMITIVE_ADMISSION_DENIED")
    required_evidence = [
        ref
        for draft in (
            *primitive.inputs,
            *((primitive.result,) if primitive.result else ()),
        )
        for ref in draft.evidence_refs
    ]
    if any(ref not in primitive.evidence_refs for ref in required_evidence):
        raise ValueError("PRIMITIVE_EVIDENCE_CLOSURE")


def validate_admission(
    decision: PrimitiveAdmissionDecision,
    verification: VerificationResult,
    technical: TechnicalEvidenceReview,
    collection: PolicyCollectionResult,
    state: RunPolicyState,
    review: RuleScopeImpactReview | None,
) -> None:
    for ref, target in (
        (decision.verification_result_ref, verification),
        (decision.technical_review_ref, technical),
        (decision.policy_collection_result_ref, collection),
    ):
        exact(ref, target, decision.meta)
    if (
        verification.verdict != "TRUE"
        or technical.status != "ACCEPT"
        or technical.verification_result_ref != decision.verification_result_ref
        or state.collection_result_ref != decision.policy_collection_result_ref
    ):
        raise ValueError("ADMISSION_UPSTREAM_MISMATCH")
    if collection.status == "COLLECTION_FAILED":
        if (
            review is not None
            or decision.testing_restriction_compliance != "NOT_EVALUATED"
        ):
            raise ValueError("ADMISSION_COLLECTION_FAILED_MISMATCH")
    else:
        if review is None or decision.rule_scope_review_ref is None:
            raise ValueError("ADMISSION_REVIEW_REQUIRED")
        exact(decision.rule_scope_review_ref, review, decision.meta)
        if (
            review.verification_result_ref != decision.verification_result_ref
            or review.technical_review_ref != decision.technical_review_ref
            or review.policy_collection_result_ref
            != decision.policy_collection_result_ref
            or review.testing_restriction_compliance
            != decision.testing_restriction_compliance
        ):
            raise ValueError("ADMISSION_UPSTREAM_MISMATCH")


def validate_primitive_index_revision(
    previous: PrimitiveIndexState, current: PrimitiveIndexState
) -> None:
    validate_revision(previous.meta, current.meta)
    if any(ref not in current.primitive_refs for ref in previous.primitive_refs):
        raise ValueError("PRIMITIVE_INDEX_APPEND_ONLY")
    unique(current.primitive_refs)


def validate_chaining_closure(
    result: ChainingResult,
    primitives: tuple[Primitive, ...],
    pinned_refs: tuple[StoredDataRef, ...],
    expected_exclusions: tuple[LineageExclusion, ...],
) -> None:
    exact_set(result.considered_primitive_refs, pinned_refs)
    exact_set(result.excluded_lineage_refs, expected_exclusions)
    if len(primitives) != len(pinned_refs):
        raise ValueError("CHAINING_INPUT_CLOSURE")
    by_ref = {}
    for ref, primitive in zip(pinned_refs, primitives, strict=True):
        exact(ref, primitive, result.meta)
        by_ref[canonical_bytes(ref)] = primitive
    used_sources: list[StoredDataRef] = []
    matches = {c.primitive_match_id: c for c in result.primitive_match_candidates}
    for match in result.primitive_match_candidates:
        upstream, downstream = (
            by_ref[canonical_bytes(ref)]
            for ref in (match.upstream_result_ref, match.downstream_input_ref)
        )
        if upstream.result is None or match.matched_input_id not in {
            draft.draft_id for draft in downstream.inputs
        }:
            raise ValueError("PRIMITIVE_MATCH_DIRECTION")
        exact_set(
            match.parent_hypothesis_ids,
            (upstream.source_hypothesis_id, downstream.source_hypothesis_id),
        )
        exact_set(
            match.parent_verification_refs,
            (upstream.source_verification_ref, downstream.source_verification_ref),
        )
        for primitive in (upstream, downstream):
            used_sources.append(primitive.source_verification_ref)
            if primitive.technical_review_ref is not None:
                used_sources.append(primitive.technical_review_ref)
    exact_set(result.source_result_refs, used_sources)
    for reason in result.no_match_reasons:
        downstream = by_ref[canonical_bytes(reason.downstream_input_ref)]
        if reason.checked_input_id not in {
            draft.draft_id for draft in downstream.inputs
        }:
            raise ValueError("PRIMITIVE_MATCH_DIRECTION")
    for proposal in result.chained_hypothesis_proposals:
        proposal_match = matches.get(proposal.source_primitive_match_id or "")
        if proposal_match is None:
            raise ValueError("CHAINING_PARENT_MISMATCH")
        exact_set(proposal.parent_hypothesis_ids, proposal_match.parent_hypothesis_ids)
        restrictions: dict[str, Restriction] = {}
        for ref in (
            proposal_match.upstream_result_ref,
            proposal_match.downstream_input_ref,
        ):
            for restriction in by_ref[canonical_bytes(ref)].restrictions:
                if (
                    restriction.restriction_id in restrictions
                    and restrictions[restriction.restriction_id] != restriction
                ):
                    raise ValueError("RESTRICTION_ID_CONFLICT")
                restrictions[restriction.restriction_id] = restriction
        exact_set(proposal.restrictions, restrictions.values())
        validate_chained_derivation(
            proposal,
            by_ref[canonical_bytes(proposal_match.upstream_result_ref)],
            by_ref[canonical_bytes(proposal_match.downstream_input_ref)],
            proposal_match.matched_input_id,
        )


def validate_chained_derivation(
    proposal: HypothesisProposal,
    upstream: Primitive,
    downstream: Primitive,
    matched_input_id: str,
) -> None:
    drafts = (
        *upstream.inputs,
        *downstream.inputs,
        *((upstream.result,) if upstream.result else ()),
        *((downstream.result,) if downstream.result else ()),
    )
    entities = {entity for draft in drafts for entity in draft.entity_refs}
    locations = {entity.location for entity in entities}
    if (
        not entities
        or not set(proposal.target_entities) <= entities
        or not set(proposal.target_locations) <= locations
        or any(item not in locations for item in proposal.suspected_path)
    ):
        raise ValueError("CHAINING_DERIVATION_MISMATCH")
    remaining = (
        *upstream.inputs,
        *(draft for draft in downstream.inputs if draft.draft_id != matched_input_id),
    )
    if Counter(proposal.assumptions) != Counter(
        draft.description for draft in remaining
    ):
        raise ValueError("CHAINING_ASSUMPTION_MISMATCH")
