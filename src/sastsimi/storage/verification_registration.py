"""Atomic initial and Technical REVISE Verification registration."""

from collections.abc import Callable
from typing import Any

from sqlalchemy import select

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.budget import BudgetLedgerEntry, BudgetReservation, BudgetUnits
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import DynamicReproductionState
from sastsimi.contracts.gates import TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    HypothesisProposal,
    VerificationAssignment,
    VulnerabilityHypothesis,
    validate_hypothesis_registration,
)
from sastsimi.contracts.ids import (
    ActionId,
    LedgerEntryId,
    LogicalRecordId,
    RecordId,
    ReservationId,
    WorkId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.contracts.verification import (
    PlaybookApplication,
    PlaybookPolicy,
    VerificationPlaybook,
    validate_playbook_application,
)
from sastsimi.contracts.work import WorkExecutionState, WorkType
from sastsimi.ports.dto import BudgetCommitRequest, BudgetReservationRequest
from sastsimi.ports.verification_registration import VerificationRegistration

from . import models
from .authorization import authorize
from .codec import REF_ADAPTER, reference
from .committed_outputs import require_committed
from .records import next_meta
from .stage_policy import current
from .transition_service import TransitionService


class VerificationRegistrationService:
    def __init__(
        self,
        transitions: TransitionService,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.transitions = transitions
        self.checkpoint = checkpoint or (lambda stage: None)

    def metadata(self, source: RecordMeta, kind: str) -> dict[str, Any]:
        works = self.transitions.works
        record_id = works.ids.new(RecordId)
        return source.model_dump() | dict(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            revision_number=1,
            previous_record_id=None,
            attempt_id=None,
            created_at=works.clock.now(),
        )

    def register(
        self,
        *,
        hypothesis_ref: StoredDataRef,
        proposal_ref: StoredDataRef,
        policy_ref: StoredDataRef,
        playbook_ref: StoredDataRef,
        expected_process_ref: StoredDataRef,
        owner_identity_ref: StoredDataRef,
        requester_identity_ref: BudgetScopeRef,
        budget_binding_ref: StoredDataRef,
    ) -> VerificationRegistration:
        works = self.transitions.works
        records = works.records
        with records.database.write() as connection:
            if records.evidence.identity_role(
                requester_identity_ref
            ) != "ORCHESTRATION" or (
                records.evidence.identity_role(owner_identity_ref) != "VERIFICATION"
            ):
                raise ValueError(
                    "AUTHORITY_DENIED: trusted registration identities required"
                )
            records.resolve(connection, requester_identity_ref)
            records.resolve(connection, owner_identity_ref)
            for ref in (hypothesis_ref, policy_ref, playbook_ref):
                current(records, connection, ref)
            hypothesis = records.resolve(connection, hypothesis_ref)
            proposal = records.resolve(connection, proposal_ref)
            policy = records.resolve(connection, policy_ref)
            book = records.resolve(connection, playbook_ref)
            process = records.resolve(connection, expected_process_ref)
            if (
                not isinstance(hypothesis, VulnerabilityHypothesis)
                or not isinstance(proposal, HypothesisProposal)
                or (
                    not isinstance(policy, PlaybookPolicy)
                    or not isinstance(book, VerificationPlaybook)
                    or not isinstance(process, HypothesisProcessState)
                )
            ):
                raise ValueError("REGISTRATION_INPUT_MISMATCH")
            validate_hypothesis_registration(hypothesis, proposal)
            if process.proposal_ref != proposal_ref or any(
                getattr(process.meta, name) != getattr(hypothesis.meta, name)
                for name in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                )
            ):
                raise ValueError("REGISTRATION_INPUT_MISMATCH")
            generation = max(1, process.verification_generation)
            stable_inputs = (hypothesis_ref, proposal_ref, policy_ref, playbook_ref)
            dedupe = content_hash([stable_inputs, generation])
            key = content_hash(
                [
                    hypothesis.meta.analysis_id,
                    "VERIFICATION",
                    hypothesis.meta.hypothesis_id,
                    generation,
                    dedupe,
                ]
            )
            old = connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.registration_key == key
                )
            ).scalar()
            if old is not None:
                work = WorkExecutionState.model_validate_json(old)
                current_process_ref_raw = connection.execute(
                    select(models.records.c.ref)
                    .join(
                        models.current_records,
                        models.current_records.c.record_id
                        == models.records.c.record_id,
                    )
                    .where(
                        models.current_records.c.logical_record_id
                        == str(process.meta.logical_record_id)
                    )
                ).scalar_one_or_none()
                if current_process_ref_raw is None:
                    raise ValueError("REGISTRATION_INPUT_MISMATCH")
                current_process_ref = REF_ADAPTER.validate_json(current_process_ref_raw)
                current_process = records.resolve(connection, current_process_ref)
                if not isinstance(current_process, HypothesisProcessState):
                    raise ValueError("REGISTRATION_INPUT_MISMATCH")
                app_refs = [
                    ref
                    for ref in work.input_refs
                    if ref.data_kind == "playbook_application"
                ]
                if (
                    len(app_refs) != 1
                    or current_process.verification_assignment_ref is None
                    or current_process.verification_work_ref != reference(work)
                    or current_process.verification_generation != generation
                ):
                    raise ValueError("REGISTRATION_INPUT_MISMATCH")
                application = records.resolve(connection, app_refs[0])
                assignment = records.resolve(
                    connection, current_process.verification_assignment_ref
                )
                if (
                    not isinstance(application, PlaybookApplication)
                    or not isinstance(assignment, VerificationAssignment)
                    or (
                        assignment.status != "ACTIVE"
                        or assignment.owner_identity_ref != owner_identity_ref
                    )
                ):
                    raise ValueError(
                        "AUTHORITY_DENIED: current assignment owner required"
                    )
                validate_playbook_application(
                    application, hypothesis, proposal, policy, book
                )
                existing_assignment_ref = current_process.verification_assignment_ref
                if not isinstance(
                    existing_assignment_ref, StoredDataRef
                ) or not isinstance(current_process_ref, StoredDataRef):
                    raise ValueError("REGISTRATION_ASSIGNMENT_SCOPE_MISMATCH")
                return VerificationRegistration(
                    work,
                    application,
                    existing_assignment_ref,
                    current_process_ref,
                )
            current(records, connection, expected_process_ref)
            if process.status != "REGISTERED" or process.verification_generation != 0:
                raise ValueError("REGISTRATION_STATE_MISMATCH")
            work_id = works.ids.new(WorkId)
            types = proposal.vulnerability_type_candidates
            mappings = {
                item.vulnerability_type: item.playbook_ref
                for item in policy.type_playbooks
            }
            reason = (
                "NO_TYPE"
                if not types
                else "MULTIPLE_TYPES"
                if len(types) > 1
                else "TYPE_MATCH"
                if types[0] in mappings
                else "TYPE_NOT_ALLOWED"
            )
            application = PlaybookApplication.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "playbook_application"),
                        verification_work_id=work_id,
                        verification_generation=generation,
                        hypothesis_ref=hypothesis_ref,
                        proposal_ref=proposal_ref,
                        policy_ref=policy_ref,
                        playbook_ref=playbook_ref,
                        selection=book.scope,
                        selected_type=book.vulnerability_type,
                        selection_reason=reason,
                        questions=tuple(
                            question.model_dump()
                            | dict(question_id=str(works.ids.new(RecordId)))
                            for question in book.falsification_question_templates
                        ),
                    )
                )
            )
            validate_playbook_application(
                application, hypothesis, proposal, policy, book
            )
            app_ref = records.stage(connection, application)
            assert isinstance(app_ref, StoredDataRef)
            # Transaction-local publication makes only this exact derived application
            # resolvable to unchanged REGISTER_WORK checks. Rollback exposes neither.
            records.publish(connection, app_ref)
            self.transitions.publish_pointer(connection, app_ref)
            inputs = (*stable_inputs, app_ref)
            work = WorkExecutionState.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "work_execution_state"),
                        work_id=work_id,
                        parent_work_ref=None,
                        work_type="VERIFICATION",
                        subject_type="HYPOTHESIS",
                        subject_id=hypothesis.meta.hypothesis_id,
                        work_generation=generation,
                        status="PENDING",
                        state_version=1,
                        last_transition_ref=None,
                        last_transition_commit_ref=None,
                        active_attempt_id=None,
                        input_hash=content_hash(inputs),
                        dedupe_key=dedupe,
                        trigger_primitive_ref=None,
                        input_refs=inputs,
                        output_refs=(),
                        gap_ids=(),
                        error_ids=(),
                        waiting_for=(),
                        stop_reason=None,
                        started_at=None,
                        finished_at=None,
                        elapsed_ms=0,
                    )
                )
            )
            work_ref = records.stage(connection, work)
            action = ActionRequest.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "action_request"),
                        action_id=works.ids.new(ActionId),
                        requested_by="ORCHESTRATION",
                        requester_identity_ref=requester_identity_ref,
                        action_type="REGISTER_WORK",
                        work_ref=None,
                        expected_state_version=None,
                        expected_verification_generation=None,
                        generation_restart_reason=None,
                        generation_restart_basis_refs=(),
                        input_refs=inputs,
                        dynamic_request_ref=None,
                        reproduction_plan_ref=None,
                        result_kind=None,
                        candidate_result_ref=None,
                        llm_call_spec_ref=None,
                        tool_name=None,
                        file_paths=(),
                        provider_profile_ref=None,
                        session_mode=None,
                        sandbox_profile_ref=None,
                        resource_profile_ref=None,
                        run_policy_state_ref=None,
                        image_digest=None,
                        network_targets=(),
                        resource_limits=None,
                        reason="Register exact Verification application",
                        requested_at=works.clock.now(),
                    )
                )
            )
            action_ref = records.stage(connection, action)
            units = BudgetUnits(
                elapsed_ms=0,
                work_count=1,
                llm_call_count=0,
                retry_count=0,
                cost_minor_units=0,
                currency="USD",
            )
            reservation = BudgetReservation.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "budget_reservation"),
                        reservation_id=works.ids.new(ReservationId),
                        budget_binding_ref=budget_binding_ref,
                        action_ref=action_ref,
                        work_ref=work_ref,
                        requested_units=units,
                        status="RESERVED",
                        ledger_entry_ref=None,
                        reserved_at=works.clock.now(),
                        finalized_at=None,
                    )
                )
            )
            budget = works.validator.budget
            budget.reserve(
                BudgetReservationRequest(reservation), _connection=connection
            )
            decision = authorize(
                works.validator,
                action,
                work,
                reference(reservation),
                _connection=connection,
            )
            if decision.decision != "ALLOW":
                raise ValueError(
                    "ACTION_DENIED: "
                    + ";".join(
                        c.reason_code
                        for c in decision.check_results
                        if c.result == "FAIL"
                    )
                )
            self.checkpoint("authorized")
            works.register(
                work,
                reference(decision),
                reference(reservation),
                _connection=connection,
            )
            assignment = VerificationAssignment.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "verification_assignment"),
                        assignment_id=str(works.ids.new(RecordId)),
                        owner_identity_ref=owner_identity_ref,
                        assignment_generation=1,
                        status="ACTIVE",
                        previous_assignment_ref=None,
                        assigned_at=works.clock.now(),
                    )
                )
            )
            assignment_ref = records.stage(connection, assignment)
            assert isinstance(assignment_ref, StoredDataRef)
            records.publish(connection, assignment_ref)
            self.transitions.publish_pointer(connection, assignment_ref)
            updated = HypothesisProcessState.model_validate_json(
                canonical_bytes(
                    process.model_dump()
                    | dict(
                        meta=next_meta(process.meta, works.clock, works.ids),
                        status="VERIFYING",
                        verification_assignment_ref=assignment_ref,
                        verification_generation=generation,
                        verification_work_ref=work_ref,
                        verification_result_ref=None,
                    )
                )
            )
            process_ref = records.stage(connection, updated)
            assert isinstance(process_ref, StoredDataRef)
            records.publish(connection, process_ref)
            self.transitions.publish_pointer(connection, process_ref)
            dynamic = DynamicReproductionState.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(
                            hypothesis.meta, "dynamic_reproduction_state"
                        ),
                        verification_generation=generation,
                        dynamic_work_ref=None,
                        status="NOT_REQUESTED",
                        request_ref=None,
                        dynamic_result_ref=None,
                        started_at=None,
                        finished_at=None,
                        elapsed_ms=0,
                    )
                )
            )
            dynamic_ref = records.stage(connection, dynamic)
            records.publish(connection, dynamic_ref)
            self.transitions.publish_pointer(connection, dynamic_ref)
            remaining = budget.available(
                connection, budget_binding_ref, str(hypothesis.meta.analysis_id)
            )
            entry = BudgetLedgerEntry.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "budget_ledger_entry"),
                        ledger_entry_id=works.ids.new(LedgerEntryId),
                        reservation_ref=reference(reservation),
                        budget_binding_ref=budget_binding_ref,
                        action_ref=action_ref,
                        work_ref=work_ref,
                        actual_units=units,
                        usage_refs=(),
                        sequence=remaining.as_of_sequence + 1,
                        committed_at=works.clock.now(),
                    )
                )
            )
            budget.commit_usage(BudgetCommitRequest(entry), _connection=connection)
            self.checkpoint("before_commit")
            result = VerificationRegistration(
                work, application, assignment_ref, process_ref
            )
        self.checkpoint("committed")
        return result

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
    ) -> VerificationRegistration:
        """Atomically start the same owner's generation after Technical REVISE."""
        works = self.transitions.works
        records = works.records
        with records.database.write() as connection:
            if (
                records.evidence.identity_role(requester_identity_ref)
                != "ORCHESTRATION"
                or records.evidence.identity_role(owner_identity_ref) != "VERIFICATION"
            ):
                raise ValueError(
                    "AUTHORITY_DENIED: trusted revision identities required"
                )
            for ref in (
                technical_review_ref,
                hypothesis_ref,
                proposal_ref,
                policy_ref,
                playbook_ref,
                expected_process_ref,
            ):
                current(records, connection, ref)
            review = records.resolve(connection, technical_review_ref)
            hypothesis = records.resolve(connection, hypothesis_ref)
            proposal = records.resolve(connection, proposal_ref)
            policy = records.resolve(connection, policy_ref)
            book = records.resolve(connection, playbook_ref)
            process = records.resolve(connection, expected_process_ref)
            if (
                not isinstance(review, TechnicalEvidenceReview)
                or review.status != "REVISE"
                or not isinstance(hypothesis, VulnerabilityHypothesis)
                or not isinstance(proposal, HypothesisProposal)
                or not isinstance(policy, PlaybookPolicy)
                or not isinstance(book, VerificationPlaybook)
                or not isinstance(process, HypothesisProcessState)
            ):
                raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
            require_committed(records, connection, review, WorkType.TECHNICAL_GATE)
            if (
                process.status != "TERMINAL"
                or process.verification_result_ref != review.verification_result_ref
                or process.verification_assignment_ref is None
                or process.proposal_ref != proposal_ref
                or hypothesis.proposal_ref != proposal_ref
            ):
                raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
            assignment = records.resolve(
                connection, process.verification_assignment_ref
            )
            if (
                not isinstance(assignment, VerificationAssignment)
                or assignment.status != "ACTIVE"
                or assignment.owner_identity_ref != owner_identity_ref
            ):
                raise ValueError("AUTHORITY_DENIED: same ACTIVE owner required")
            generation = process.verification_generation + 1
            stable_inputs = (
                hypothesis_ref,
                proposal_ref,
                policy_ref,
                playbook_ref,
                technical_review_ref,
            )
            dedupe = content_hash([stable_inputs, generation])
            key = content_hash(
                [
                    hypothesis.meta.analysis_id,
                    "VERIFICATION",
                    hypothesis.meta.hypothesis_id,
                    generation,
                    dedupe,
                ]
            )
            old = connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.registration_key == key
                )
            ).scalar()
            if old is not None:
                existing = WorkExecutionState.model_validate_json(old)
                app_refs = tuple(
                    ref
                    for ref in existing.input_refs
                    if ref.data_kind == "playbook_application"
                )
                if len(app_refs) != 1:
                    raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
                application = records.resolve(connection, app_refs[0])
                if not isinstance(application, PlaybookApplication):
                    raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
                current_process_ref = reference(process)
                assert isinstance(current_process_ref, StoredDataRef)
                return VerificationRegistration(
                    existing,
                    application,
                    process.verification_assignment_ref,
                    current_process_ref,
                )
            work_id = works.ids.new(WorkId)
            types = proposal.vulnerability_type_candidates
            mappings = {
                item.vulnerability_type: item.playbook_ref
                for item in policy.type_playbooks
            }
            reason = (
                "NO_TYPE"
                if not types
                else "MULTIPLE_TYPES"
                if len(types) > 1
                else "TYPE_MATCH"
                if types[0] in mappings
                else "TYPE_NOT_ALLOWED"
            )
            application = PlaybookApplication.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "playbook_application"),
                        verification_work_id=work_id,
                        verification_generation=generation,
                        hypothesis_ref=hypothesis_ref,
                        proposal_ref=proposal_ref,
                        policy_ref=policy_ref,
                        playbook_ref=playbook_ref,
                        selection=book.scope,
                        selected_type=book.vulnerability_type,
                        selection_reason=reason,
                        questions=tuple(
                            question.model_dump()
                            | dict(question_id=str(works.ids.new(RecordId)))
                            for question in book.falsification_question_templates
                        ),
                    )
                )
            )
            validate_playbook_application(
                application, hypothesis, proposal, policy, book
            )
            app_ref = records.stage(connection, application)
            assert isinstance(app_ref, StoredDataRef)
            records.publish(connection, app_ref)
            self.transitions.publish_pointer(connection, app_ref)
            inputs = (*stable_inputs, app_ref)
            work = WorkExecutionState.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "work_execution_state"),
                        work_id=work_id,
                        parent_work_ref=None,
                        work_type="VERIFICATION",
                        subject_type="HYPOTHESIS",
                        subject_id=hypothesis.meta.hypothesis_id,
                        work_generation=generation,
                        status="PENDING",
                        state_version=1,
                        last_transition_ref=None,
                        last_transition_commit_ref=None,
                        active_attempt_id=None,
                        input_hash=content_hash(inputs),
                        dedupe_key=dedupe,
                        trigger_primitive_ref=None,
                        input_refs=inputs,
                        output_refs=(),
                        gap_ids=(),
                        error_ids=(),
                        waiting_for=(),
                        stop_reason=None,
                        started_at=None,
                        finished_at=None,
                        elapsed_ms=0,
                    )
                )
            )
            work_ref = records.stage(connection, work)
            action = ActionRequest.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "action_request"),
                        action_id=works.ids.new(ActionId),
                        requested_by="ORCHESTRATION",
                        requester_identity_ref=requester_identity_ref,
                        action_type="REGISTER_WORK",
                        work_ref=None,
                        expected_state_version=None,
                        expected_verification_generation=None,
                        generation_restart_reason=None,
                        generation_restart_basis_refs=(),
                        input_refs=inputs,
                        dynamic_request_ref=None,
                        reproduction_plan_ref=None,
                        result_kind=None,
                        candidate_result_ref=None,
                        llm_call_spec_ref=None,
                        tool_name=None,
                        file_paths=(),
                        provider_profile_ref=None,
                        session_mode=None,
                        sandbox_profile_ref=None,
                        resource_profile_ref=None,
                        run_policy_state_ref=None,
                        image_digest=None,
                        network_targets=(),
                        resource_limits=None,
                        reason="Register Technical REVISE generation",
                        requested_at=works.clock.now(),
                    )
                )
            )
            action_ref = records.stage(connection, action)
            units = BudgetUnits(
                elapsed_ms=0,
                work_count=1,
                llm_call_count=0,
                retry_count=0,
                cost_minor_units=0,
                currency="USD",
            )
            reservation = BudgetReservation.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "budget_reservation"),
                        reservation_id=works.ids.new(ReservationId),
                        budget_binding_ref=budget_binding_ref,
                        action_ref=action_ref,
                        work_ref=work_ref,
                        requested_units=units,
                        status="RESERVED",
                        ledger_entry_ref=None,
                        reserved_at=works.clock.now(),
                        finalized_at=None,
                    )
                )
            )
            budget = works.validator.budget
            budget.reserve(
                BudgetReservationRequest(reservation), _connection=connection
            )
            decision = authorize(
                works.validator,
                action,
                work,
                reference(reservation),
                _connection=connection,
            )
            if decision.decision != "ALLOW":
                raise ValueError("ACTION_DENIED: Technical REVISE registration")
            works.register(
                work,
                reference(decision),
                reference(reservation),
                _connection=connection,
            )
            updated = HypothesisProcessState.model_validate_json(
                canonical_bytes(
                    process.model_dump()
                    | dict(
                        meta=next_meta(process.meta, works.clock, works.ids),
                        status="VERIFYING",
                        verification_generation=generation,
                        verification_work_ref=work_ref,
                        verification_result_ref=None,
                        finished_at=None,
                    )
                )
            )
            process_ref = records.stage(connection, updated)
            assert isinstance(process_ref, StoredDataRef)
            records.publish(connection, process_ref)
            self.transitions.publish_pointer(connection, process_ref)
            dynamic_states = []
            for wire in connection.execute(
                select(models.records.c.ref)
                .join(
                    models.current_records,
                    models.current_records.c.record_id == models.records.c.record_id,
                )
                .where(models.records.c.kind == "dynamic_reproduction_state")
            ).scalars():
                candidate = records.resolve(connection, REF_ADAPTER.validate_json(wire))
                if (
                    isinstance(candidate, DynamicReproductionState)
                    and candidate.meta.hypothesis_id == hypothesis.meta.hypothesis_id
                    and candidate.meta.analysis_id == hypothesis.meta.analysis_id
                ):
                    dynamic_states.append(candidate)
            if len(dynamic_states) != 1:
                raise ValueError("DYNAMIC_STATE_CONFLICT")
            previous_dynamic = dynamic_states[0]
            dynamic = DynamicReproductionState.model_validate_json(
                canonical_bytes(
                    previous_dynamic.model_dump()
                    | dict(
                        meta=next_meta(previous_dynamic.meta, works.clock, works.ids),
                        verification_generation=generation,
                        dynamic_work_ref=None,
                        status="NOT_REQUESTED",
                        request_ref=None,
                        dynamic_result_ref=None,
                        started_at=None,
                        finished_at=None,
                        elapsed_ms=0,
                    )
                )
            )
            dynamic_ref = records.stage(connection, dynamic)
            records.publish(connection, dynamic_ref)
            self.transitions.publish_pointer(connection, dynamic_ref)
            remaining = budget.available(
                connection, budget_binding_ref, str(hypothesis.meta.analysis_id)
            )
            entry = BudgetLedgerEntry.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=self.metadata(hypothesis.meta, "budget_ledger_entry"),
                        ledger_entry_id=works.ids.new(LedgerEntryId),
                        reservation_ref=reference(reservation),
                        budget_binding_ref=budget_binding_ref,
                        action_ref=action_ref,
                        work_ref=work_ref,
                        actual_units=units,
                        usage_refs=(),
                        sequence=remaining.as_of_sequence + 1,
                        committed_at=works.clock.now(),
                    )
                )
            )
            budget.commit_usage(BudgetCommitRequest(entry), _connection=connection)
            return VerificationRegistration(
                work,
                application,
                process.verification_assignment_ref,
                process_ref,
            )
