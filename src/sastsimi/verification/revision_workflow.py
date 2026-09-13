"""Fail-closed wrapper for Technical Gate REVISE generation registration."""

from typing import Protocol

from sastsimi.contracts.gates import TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VerificationAssignment,
)
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import PlaybookApplication, VerificationResult
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.verification_registration import (
    VerificationRegistration,
)


class RevisionRegistrar(Protocol):
    def revise(
        self,
        *,
        technical_review_ref: StoredDataRef,
        hypothesis_ref: StoredDataRef,
        proposal_ref: StoredDataRef,
        policy_ref: StoredDataRef,
        playbook_ref: StoredDataRef,
        expected_process_ref: StoredDataRef,
        owner_identity_ref: StoredDataRef,
        requester_identity_ref: BudgetScopeRef,
        budget_binding_ref: StoredDataRef,
    ) -> VerificationRegistration: ...


class ExactRecordReader(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...

    def is_revision_descendant(
        self, earlier_ref: RecordRef, later_ref: RecordRef
    ) -> bool: ...


class RevisionWorkflow:
    """Start a new generation with the existing ACTIVE Verification owner."""

    def __init__(
        self, *, registrar: RevisionRegistrar, records: ExactRecordReader
    ) -> None:
        self._registrar = registrar
        self._records = records

    def start_new_generation(
        self,
        *,
        technical_review_ref: StoredDataRef,
        hypothesis_ref: StoredDataRef,
        proposal_ref: StoredDataRef,
        policy_ref: StoredDataRef,
        playbook_ref: StoredDataRef,
        expected_process_ref: StoredDataRef,
        owner_identity_ref: StoredDataRef,
        requester_identity_ref: BudgetScopeRef,
        budget_binding_ref: StoredDataRef,
    ) -> VerificationRegistration:
        review = self._exact(technical_review_ref, TechnicalEvidenceReview)
        process = self._exact(expected_process_ref, HypothesisProcessState)
        if (
            review.status != "REVISE"
            or process.status != "TERMINAL"
            or process.verification_result_ref != review.verification_result_ref
            or process.verification_assignment_ref is None
        ):
            raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
        assignment = self._exact(
            process.verification_assignment_ref, VerificationAssignment
        )
        if (
            assignment.status != "ACTIVE"
            or assignment.owner_identity_ref != owner_identity_ref
        ):
            raise ValueError("AUTHORITY_DENIED: same ACTIVE owner required")
        old_result = self._exact(review.verification_result_ref, VerificationResult)
        old_application = self._exact(
            old_result.playbook_application_ref, PlaybookApplication
        )
        registration = self._registrar.revise(
            technical_review_ref=technical_review_ref,
            hypothesis_ref=hypothesis_ref,
            proposal_ref=proposal_ref,
            policy_ref=policy_ref,
            playbook_ref=playbook_ref,
            expected_process_ref=expected_process_ref,
            owner_identity_ref=owner_identity_ref,
            requester_identity_ref=requester_identity_ref,
            budget_binding_ref=budget_binding_ref,
        )
        self._validate_fresh_registration(
            registration=registration,
            prior_process=process,
            prior_result=old_result,
            prior_application=old_application,
            expected_assignment_ref=process.verification_assignment_ref,
        )
        return registration

    def _validate_fresh_registration(
        self,
        *,
        registration: VerificationRegistration,
        prior_process: HypothesisProcessState,
        prior_result: VerificationResult,
        prior_application: PlaybookApplication,
        expected_assignment_ref: StoredDataRef,
    ) -> None:
        work = registration.work
        application = registration.application
        application_ref = reference(application)
        assert isinstance(application_ref, StoredDataRef)
        current_process = self._exact(registration.process_ref, HypothesisProcessState)
        expected_generation = prior_process.verification_generation + 1
        if current_process.verification_work_ref is None:
            raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
        registered_work = self._exact(
            current_process.verification_work_ref, WorkExecutionState
        )
        returned_work_ref = reference(work)
        assert isinstance(returned_work_ref, StoredDataRef)
        same_registered_work = (
            registered_work.work_id == work.work_id
            and registered_work.meta.logical_record_id == work.meta.logical_record_id
            and registered_work.work_type == work.work_type == WorkType.VERIFICATION
            and registered_work.work_generation == work.work_generation
            and registered_work.subject_type == work.subject_type
            and registered_work.subject_id == work.subject_id
            and registered_work.input_refs == work.input_refs
            and registered_work.input_hash == work.input_hash
            and registered_work.dedupe_key == work.dedupe_key
            and registered_work.status == WorkStatus.PENDING
            and work.state_version >= registered_work.state_version
            and self._records.is_revision_descendant(
                current_process.verification_work_ref, returned_work_ref
            )
        )
        if (
            registration.assignment_ref != expected_assignment_ref
            or work.work_generation != expected_generation
            or application.verification_generation != expected_generation
            or application.verification_work_id != work.work_id
            or application_ref == reference(prior_application)
            or application_ref not in work.input_refs
            or current_process.status != "VERIFYING"
            or current_process.verification_generation != expected_generation
            or current_process.verification_assignment_ref != expected_assignment_ref
            or not same_registered_work
            or current_process.verification_result_ref is not None
        ):
            raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
        old_question_ids = {item.question_id for item in prior_application.questions}
        new_question_ids = {item.question_id for item in application.questions}
        if not new_question_ids or old_question_ids & new_question_ids:
            raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
        forbidden_direct_inputs = {
            reference(prior_application),
            reference(prior_result),
            prior_result.pro_evidence_ref,
            prior_result.con_evidence_ref,
        }
        if any(
            ref is not None and ref in work.input_refs
            for ref in forbidden_direct_inputs
        ):
            raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")

    def _exact[T](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:  # type: ignore[arg-type]
            raise ValueError("RECORD_REVISION_MISMATCH")
        return value


__all__ = ["RevisionWorkflow"]
