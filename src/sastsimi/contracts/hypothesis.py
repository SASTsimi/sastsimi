"""Proposal, duplicate review and registered hypothesis (§08.2)."""

from typing import Literal, Self

from pydantic import AwareDatetime, PositiveInt, model_validator

from ._domain import DomainRecord, exact, exact_set, same_scope, unique
from .base import ContractModel, NonEmptyStr, NonNegativeInt
from .ids import HypothesisId, ProposalId
from .refs import StoredDataRef, require_record_ref
from .static import (
    CodeFact,
    CodeLocation,
    CodeRelation,
    CodeSymbol,
    Restriction,
    StaticFactBundle,
)


class FalsificationQuestion(ContractModel):
    question_id: NonEmptyStr
    question: NonEmptyStr


class ValidationCheck(ContractModel):
    validation_id: NonEmptyStr
    instruction: NonEmptyStr


class HypothesisShape(DomainRecord):
    ATTEMPT = None
    origin: Literal["INITIAL", "VERIFICATION", "CHAINING"]
    target_entities: tuple[CodeSymbol, ...]
    target_locations: tuple[CodeLocation, ...]
    suspected_path: tuple[CodeRelation | CodeLocation, ...]
    falsification_questions: tuple[FalsificationQuestion, ...]
    validation_checks: tuple[ValidationCheck, ...]
    parent_hypothesis_ids: tuple[HypothesisId, ...]
    source_primitive_match_id: NonEmptyStr | None

    @model_validator(mode="after")
    def origin_shape(self) -> Self:
        if not self.falsification_questions or not self.validation_checks:
            raise ValueError("HYPOTHESIS_QUESTIONS_REQUIRED")
        unique(q.question_id for q in self.falsification_questions)
        unique(v.validation_id for v in self.validation_checks)
        unique(self.parent_hypothesis_ids)
        if self.origin == "CHAINING":
            if not self.source_primitive_match_id or not self.parent_hypothesis_ids:
                raise ValueError("CHAINING_ORIGIN_REQUIRED")
        elif self.source_primitive_match_id is not None:
            raise ValueError("CHAINING_ORIGIN_FORBIDDEN")
        if self.origin == "INITIAL" and self.parent_hypothesis_ids:
            raise ValueError("INITIAL_PARENT_FORBIDDEN")
        if self.origin != "CHAINING" and not self.target_locations:
            raise ValueError("HYPOTHESIS_LOCATION_REQUIRED")
        return self


class HypothesisProposal(HypothesisShape):
    KIND = "hypothesis_proposal"
    proposal_id: ProposalId
    proposal_state: Literal["HYPOTHESIS_ONLY"]
    assertion_mode: Literal["NON_FINAL"]
    statement: NonEmptyStr
    vulnerability_type_candidates: tuple[NonEmptyStr, ...]
    observed_facts: tuple[CodeFact, ...]
    assumptions: tuple[NonEmptyStr, ...]
    restrictions: tuple[Restriction, ...]

    @model_validator(mode="after")
    def observations(self) -> Self:
        unique(self.vulnerability_type_candidates)
        unique(fact.fact_id for fact in self.observed_facts)
        unique(restriction.restriction_id for restriction in self.restrictions)
        observed = {fact.fact_id for fact in self.observed_facts}
        restricted = {
            ref.fact_id
            for restriction in self.restrictions
            for ref in restriction.fact_refs
        }
        if observed & restricted:
            raise ValueError("FACT_RESTRICTION_OVERLAP")
        if self.origin == "INITIAL" and any(
            not restriction.fact_refs for restriction in self.restrictions
        ):
            raise ValueError("INITIAL_RESTRICTION_FACT_REQUIRED")
        if self.origin == "CHAINING" and self.observed_facts:
            raise ValueError("CHAINING_FACT_FORBIDDEN")
        return self


class ProposalProcessState(DomainRecord):
    """Trusted pre-hypothesis validation and duplicate-registration state."""

    KIND = "proposal_process_state"
    HYPOTHESIS = False
    ATTEMPT = False
    proposal_ref: StoredDataRef
    status: Literal[
        "PROPOSED", "SCHEMA_VALID", "DUPLICATE", "INVALID_OUTPUT", "CANCELLED"
    ]
    duplicate_review_ref: StoredDataRef | None
    duplicate_of_hypothesis_ref: StoredDataRef | None
    registration_reason: Literal[
        "NOT_CHECKED",
        "NO_CANDIDATES",
        "UNIQUE",
        "UNCERTAIN",
        "CHECK_FAILED",
        "INVALID_DUPLICATE_TARGET",
        "DUPLICATE",
    ]
    started_at: AwareDatetime
    finished_at: AwareDatetime | None
    elapsed_ms: NonNegativeInt

    @model_validator(mode="after")
    def process_shape(self) -> Self:
        if self.meta.hypothesis_id is not None or self.meta.attempt_id is not None:
            raise ValueError("PROPOSAL_PROCESS_SCOPE_MISMATCH")
        require_record_ref(self.proposal_ref, "hypothesis_proposal")
        unfinished = self.status == "PROPOSED"
        if unfinished != (self.finished_at is None):
            raise ValueError("PROPOSAL_PROCESS_TIME_MISMATCH")
        if unfinished and (
            self.registration_reason != "NOT_CHECKED"
            or self.duplicate_review_ref is not None
            or self.duplicate_of_hypothesis_ref is not None
        ):
            raise ValueError("PROPOSAL_PROCESS_STATE_MISMATCH")
        if self.status == "SCHEMA_VALID":
            if self.registration_reason not in {
                "NO_CANDIDATES",
                "UNIQUE",
                "UNCERTAIN",
                "CHECK_FAILED",
                "INVALID_DUPLICATE_TARGET",
            }:
                raise ValueError("PROPOSAL_REGISTRATION_REASON_MISMATCH")
            reviewed = self.registration_reason in {"UNIQUE", "UNCERTAIN"}
            if reviewed != (self.duplicate_review_ref is not None) or (
                self.duplicate_of_hypothesis_ref is not None
            ):
                raise ValueError("PROPOSAL_DUPLICATE_REVIEW_MISMATCH")
        elif self.status == "DUPLICATE":
            if (
                self.registration_reason != "DUPLICATE"
                or self.duplicate_review_ref is None
                or self.duplicate_of_hypothesis_ref is None
            ):
                raise ValueError("PROPOSAL_DUPLICATE_REVIEW_MISMATCH")
        elif self.status in {"INVALID_OUTPUT", "CANCELLED"} and (
            self.registration_reason != "NOT_CHECKED"
            or self.duplicate_review_ref is not None
            or self.duplicate_of_hypothesis_ref is not None
        ):
            raise ValueError("PROPOSAL_PROCESS_STATE_MISMATCH")
        return self


class HypothesisDuplicateReview(DomainRecord):
    KIND = "hypothesis_duplicate_review"
    HYPOTHESIS = False
    proposal_ref: StoredDataRef
    candidate_hypothesis_refs: tuple[StoredDataRef, ...]
    decision: Literal["UNIQUE", "DUPLICATE", "UNCERTAIN"]
    duplicate_of_hypothesis_ref: StoredDataRef | None
    rationale: NonEmptyStr
    llm_call_id: NonEmptyStr

    @model_validator(mode="after")
    def duplicate_shape(self) -> Self:
        require_record_ref(self.proposal_ref, "hypothesis_proposal")
        if not self.candidate_hypothesis_refs:
            raise ValueError("DUPLICATE_CANDIDATES_REQUIRED")
        unique(self.candidate_hypothesis_refs)
        for ref in self.candidate_hypothesis_refs:
            require_record_ref(ref, "vulnerability_hypothesis")
        if self.decision == "DUPLICATE":
            if self.duplicate_of_hypothesis_ref not in self.candidate_hypothesis_refs:
                raise ValueError("INVALID_DUPLICATE_TARGET")
        elif self.duplicate_of_hypothesis_ref is not None:
            raise ValueError("INVALID_DUPLICATE_TARGET")
        return self


class VulnerabilityHypothesis(HypothesisShape):
    KIND = "vulnerability_hypothesis"
    HYPOTHESIS = True
    proposal_ref: StoredDataRef
    statement: NonEmptyStr


class VerificationAssignment(DomainRecord):
    KIND = "verification_assignment"
    HYPOTHESIS = True
    ATTEMPT = False
    assignment_id: NonEmptyStr
    owner_identity_ref: StoredDataRef
    assignment_generation: PositiveInt
    status: Literal["ACTIVE", "SUPERSEDED"]
    previous_assignment_ref: StoredDataRef | None
    assigned_at: AwareDatetime

    @model_validator(mode="after")
    def assignment_chain(self) -> Self:
        if (self.assignment_generation == 1) != (self.previous_assignment_ref is None):
            raise ValueError("ASSIGNMENT_PREVIOUS_REQUIRED")
        if self.previous_assignment_ref is not None:
            require_record_ref(self.previous_assignment_ref, self.KIND)
        return self


class HypothesisProcessState(DomainRecord):
    """Canonical current owner/generation projection; mutation belongs to workflows."""

    KIND = "hypothesis_process_state"
    HYPOTHESIS = True
    ATTEMPT = False
    proposal_ref: StoredDataRef
    status: Literal[
        "REGISTERED", "ASSIGNED", "VERIFYING", "TERMINAL", "FAILED", "CANCELLED"
    ]
    verification_assignment_ref: StoredDataRef | None
    verification_generation: NonNegativeInt
    verification_work_ref: StoredDataRef | None
    verification_result_ref: StoredDataRef | None
    started_at: AwareDatetime
    finished_at: AwareDatetime | None
    elapsed_ms: NonNegativeInt

    @model_validator(mode="after")
    def process_shape(self) -> Self:
        terminal = self.status in {"TERMINAL", "FAILED", "CANCELLED"}
        if terminal != (self.finished_at is not None):
            raise ValueError("PROCESS_TERMINAL_TIME_MISMATCH")
        if self.status == "REGISTERED" and (
            self.verification_generation != 0
            or any(
                ref is not None
                for ref in (
                    self.verification_assignment_ref,
                    self.verification_work_ref,
                    self.verification_result_ref,
                )
            )
        ):
            raise ValueError("REGISTERED_PROCESS_HAS_NO_ASSIGNMENT")
        if (
            self.status in {"ASSIGNED", "VERIFYING", "TERMINAL", "FAILED"}
            and self.verification_assignment_ref is None
        ):
            raise ValueError("PROCESS_ASSIGNMENT_REQUIRED")
        if (
            self.status in {"VERIFYING", "FAILED"}
            and self.verification_work_ref is None
        ):
            raise ValueError("PROCESS_WORK_REQUIRED")
        if self.status == "TERMINAL" and (
            self.verification_work_ref is not None
            or self.verification_result_ref is None
        ):
            raise ValueError("TERMINAL_PROCESS_RESULT_REQUIRED")
        if self.status == "FAILED" and self.verification_result_ref is not None:
            raise ValueError("FAILED_PROCESS_HAS_NO_VERDICT")
        for ref, kind in (
            (self.verification_assignment_ref, "verification_assignment"),
            (self.verification_work_ref, "work_execution_state"),
        ):
            if ref is not None:
                require_record_ref(ref, kind)
        return self


def validate_hypothesis_registration(
    hypothesis: VulnerabilityHypothesis, proposal: HypothesisProposal
) -> None:
    exact(hypothesis.proposal_ref, proposal, hypothesis.meta)
    same_scope(hypothesis.meta, proposal.meta, hypothesis=False)
    for name in (
        "statement",
        "origin",
        "parent_hypothesis_ids",
        "source_primitive_match_id",
        "target_entities",
        "target_locations",
        "suspected_path",
        "falsification_questions",
        "validation_checks",
    ):
        if getattr(hypothesis, name) != getattr(proposal, name):
            raise ValueError("PROPOSAL_REGISTRATION_DRIFT")


def validate_proposal_facts(
    proposal: HypothesisProposal, bundle: StaticFactBundle, bundle_ref: StoredDataRef
) -> None:
    exact(bundle_ref, bundle, proposal.meta)
    facts = {fact.fact_id: fact for fact in bundle.facts()}
    for fact in proposal.observed_facts:
        if facts.get(fact.fact_id) != fact:
            raise ValueError("OBSERVED_FACT_DRIFT")
    for restriction in proposal.restrictions:
        for fact_ref in restriction.fact_refs:
            if fact_ref.bundle_ref != bundle_ref or fact_ref.fact_id not in facts:
                raise ValueError("RESTRICTION_FACT_CLOSURE")


def validate_duplicate_review(
    review: HypothesisDuplicateReview,
    proposal: HypothesisProposal,
    candidates: tuple[VulnerabilityHypothesis, ...],
    candidate_refs: tuple[StoredDataRef, ...],
) -> None:
    exact(review.proposal_ref, proposal, review.meta)
    exact_set(review.candidate_hypothesis_refs, candidate_refs)
    if len(candidates) != len(candidate_refs):
        raise ValueError("DUPLICATE_CANDIDATE_CLOSURE")
    for ref, candidate in zip(candidate_refs, candidates, strict=True):
        exact(ref, candidate, review.meta)
