"""Durable, exact two-phase registration for nested Chaining proposals."""

from dataclasses import dataclass

from sqlalchemy import Connection, insert, select

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.budget import (
    BudgetLedgerEntry,
    BudgetProfileBinding,
    BudgetReservation,
    BudgetUnits,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.chaining import (
    ChainingResult,
    LineageExclusion,
    Primitive,
    validate_chaining_closure,
)
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    HypothesisProposal,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.ids import (
    ActionId,
    LedgerEntryId,
    ProposalId,
    ReservationId,
    TransitionCommitId,
    TransitionId,
    WorkId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.verification import (
    PlaybookPolicy,
    VerificationPlaybook,
    VerificationResult,
)
from sastsimi.contracts.work import (
    CommitState,
    StateTransition,
    TransitionCommit,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.chaining import (
    ChainingLineagePort,
    ChainingProposalRegistration,
    PinnedChainingUniverse,
)
from sastsimi.ports.dto import (
    BudgetCommitRequest,
    BudgetReservationRequest,
    TransitionCommitRequest,
    WorkContext,
)

from . import models
from .authorization import authorize
from .codec import REF_ADAPTER, encode
from .committed_outputs import require_committed
from .records import fresh_meta, next_meta
from .stage_policy import current
from .transition_service import TransitionService
from .verification_registration import VerificationRegistrationService
from .work_service import WorkService


@dataclass(frozen=True, slots=True)
class ChainingChildRegistrationConfig:
    """Trusted dependencies absent from the public child-registration ports."""

    budget_binding_ref: StoredDataRef
    verification_owner_identity_ref: StoredDataRef
    verification_policy_ref: StoredDataRef
    verification_playbook_ref: StoredDataRef


class SQLiteChainingChildRegistration:
    """Persist child handoff and registration without executing either child."""

    def __init__(
        self,
        *,
        works: WorkService,
        transitions: TransitionService,
        verification: VerificationRegistrationService,
        lineage: ChainingLineagePort,
        config: ChainingChildRegistrationConfig,
    ) -> None:
        if (
            transitions.works is not works
            or verification.transitions is not transitions
        ):
            raise ValueError("CHAINING_CHILD_COMPOSITION_MISMATCH")
        self.works = works
        self.transitions = transitions
        self.verification = verification
        self.lineage = lineage
        self.config = config
        self.records = works.records

    def enqueue_ready(
        self,
        *,
        source_result_ref: StoredDataRef,
        proposal_id: ProposalId,
        requester_identity_ref: BudgetScopeRef,
    ) -> WorkExecutionState:
        registration_key = content_hash([source_result_ref, proposal_id])
        with self.records.database.write() as connection:
            source, proposal = self._source(
                connection,
                source_result_ref,
                proposal_id,
                requester_identity_ref,
                allowed_roles=frozenset(
                    (RequesterRole.ORCHESTRATION, RequesterRole.RECOVERY)
                ),
            )
            old = connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.registration_key == registration_key
                )
            ).scalar_one_or_none()
            if old is not None:
                work = WorkExecutionState.model_validate_json(old)
                self._validate_handoff(
                    work, source_result_ref, proposal_id, registration_key
                )
                if work.status == WorkStatus.SUCCEEDED:
                    self._completed_proposal(connection, work, proposal)
                elif work.status not in {WorkStatus.READY, WorkStatus.RUNNING}:
                    raise ValueError("CHAINING_CHILD_REPLAY_STATE_MISMATCH")
                if (
                    self._registration_scope(connection, work)
                    != self.config.budget_binding_ref
                ):
                    raise ValueError("CHAINING_CHILD_SCOPE_MISMATCH")
                return work
            pending = self._register_pending(
                connection,
                self._pending(
                    source.meta,
                    source_result_ref,
                    proposal_id,
                    registration_key,
                ),
                requester_identity_ref,
                registration_key,
            )
            return self._make_ready(
                connection,
                pending,
                requester_identity_ref,
                cause="CHAINING_CHILD_READY",
            )

    def register_claimed(
        self,
        *,
        context: WorkContext,
        source_result_ref: StoredDataRef,
        proposal_id: ProposalId,
        requester_identity_ref: BudgetScopeRef,
    ) -> ChainingProposalRegistration:
        with self.records.database.engine.connect() as connection:
            source, nested = self._source(
                connection,
                source_result_ref,
                proposal_id,
                requester_identity_ref,
                allowed_roles=frozenset((RequesterRole.ORCHESTRATION,)),
            )
            current_work = self._validate_claimed(
                connection, context, source_result_ref, proposal_id
            )
            producer = self._committed_producer(connection, source_result_ref)
            self._validate_lineage(connection, source, producer)
            completed = (
                self._completed_proposal(connection, current_work, nested)
                if current_work.status == WorkStatus.SUCCEEDED
                else None
            )

        proposal = completed or self._commit_proposal(
            context.work, nested, requester_identity_ref
        )
        proposal_ref = reference(proposal)
        assert isinstance(proposal_ref, StoredDataRef)
        hypothesis, process, process_ref = self._projected(proposal_ref)
        hypothesis_ref = reference(hypothesis)
        assert isinstance(hypothesis_ref, StoredDataRef)
        if process.status == "TERMINAL":
            verification_work = self._terminal_verification(
                hypothesis_ref, proposal_ref, process
            )
        else:
            try:
                registration = self.verification.register(
                    hypothesis_ref=hypothesis_ref,
                    proposal_ref=proposal_ref,
                    policy_ref=self.config.verification_policy_ref,
                    playbook_ref=self.config.verification_playbook_ref,
                    expected_process_ref=process_ref,
                    owner_identity_ref=self.config.verification_owner_identity_ref,
                    requester_identity_ref=requester_identity_ref,
                    budget_binding_ref=self.config.budget_binding_ref,
                )
                verification_work = self._ensure_verification_ready(
                    registration.work, requester_identity_ref
                )
            except ValueError:
                _hypothesis, raced_process, _raced_ref = self._projected(
                    proposal_ref
                )
                if raced_process.status != "TERMINAL":
                    raise
                verification_work = self._terminal_verification(
                    hypothesis_ref, proposal_ref, raced_process
                )
        _hypothesis, current_process, current_process_ref = self._projected(
            proposal_ref
        )
        if not self._process_tracks_verification(
            current_process, verification_work
        ):
            raise ValueError("CHAINING_CHILD_VERIFICATION_MISMATCH")
        return ChainingProposalRegistration(
            source_result_ref=source_result_ref,
            proposal=proposal,
            proposal_ref=proposal_ref,
            hypothesis_ref=hypothesis_ref,
            process_ref=current_process_ref,
            verification_work=verification_work,
        )

    def _source(
        self,
        connection: Connection,
        source_ref: StoredDataRef,
        proposal_id: ProposalId,
        requester_ref: BudgetScopeRef,
        *,
        allowed_roles: frozenset[RequesterRole],
    ) -> tuple[ChainingResult, HypothesisProposal]:
        if source_ref.data_kind != "chaining_result":
            raise ValueError("CHAINING_CHILD_REF_KIND")
        if self.records.evidence.identity_role(requester_ref) not in allowed_roles:
            raise ValueError("AUTHORITY_DENIED: Chaining child registrar required")
        self.records.resolve(connection, requester_ref)
        source = self.records.resolve(connection, source_ref)
        if not isinstance(source, ChainingResult) or not isinstance(
            source.meta, RecordMeta
        ):
            raise ValueError("CHAINING_CHILD_SOURCE_MISMATCH")
        require_committed(self.records, connection, source, WorkType.CHAINING)
        matches = tuple(
            proposal
            for proposal in source.chained_hypothesis_proposals
            if proposal.proposal_id == proposal_id
        )
        if len(matches) != 1:
            raise ValueError("CHAINING_CHILD_SOURCE_MISMATCH")
        proposal = matches[0]
        if (
            proposal.origin != "CHAINING"
            or self._scope(proposal.meta) != self._scope(source.meta)
        ):
            raise ValueError("CHAINING_CHILD_SOURCE_MISMATCH")
        self._validate_config(connection, source.meta)
        return source, proposal

    def _validate_config(self, connection: Connection, meta: RecordMeta) -> None:
        binding = self.records.resolve(connection, self.config.budget_binding_ref)
        policy = self.records.resolve(connection, self.config.verification_policy_ref)
        playbook = self.records.resolve(
            connection, self.config.verification_playbook_ref
        )
        self.records.resolve(connection, self.config.verification_owner_identity_ref)
        scoped = (binding, policy, playbook)
        refs = (
            self.config.budget_binding_ref,
            self.config.verification_owner_identity_ref,
            self.config.verification_policy_ref,
            self.config.verification_playbook_ref,
        )
        if (
            not isinstance(binding, BudgetProfileBinding)
            or not isinstance(policy, PlaybookPolicy)
            or not isinstance(playbook, VerificationPlaybook)
            or any(not isinstance(value.meta, RecordMeta) for value in scoped)
            or any(self._scope(value.meta) != self._scope(meta) for value in scoped)
            or any(
                self._scope_ref(value) != self._code_scope(meta) for value in refs
            )
        ):
            raise ValueError("CHAINING_CHILD_SCOPE_MISMATCH")
        current(self.records, connection, self.config.verification_policy_ref)
        current(self.records, connection, self.config.verification_playbook_ref)
        if (
            self.records.evidence.identity_role(
                self.config.verification_owner_identity_ref
            )
            != RequesterRole.VERIFICATION
        ):
            raise ValueError("AUTHORITY_DENIED: Verification owner required")

    def _pending(
        self,
        meta: RecordMeta,
        source_ref: StoredDataRef,
        proposal_id: ProposalId,
        registration_key: str,
    ) -> WorkExecutionState:
        inputs = (source_ref,)
        return WorkExecutionState.model_validate_json(
            canonical_bytes(
                dict(
                meta=fresh_meta(
                    meta,
                    "work_execution_state",
                    self.works.clock,
                    self.works.ids,
                    hypothesis_id=None,
                    attempt_id=None,
                ),
                work_id=self.works.ids.new(WorkId),
                parent_work_ref=None,
                work_type=WorkType.HYPOTHESIS_PROPOSAL,
                subject_type="PROPOSAL",
                subject_id=proposal_id,
                work_generation=1,
                status=WorkStatus.PENDING,
                state_version=1,
                last_transition_ref=None,
                last_transition_commit_ref=None,
                active_attempt_id=None,
                input_hash=content_hash(inputs),
                dedupe_key=registration_key,
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

    def _register_pending(
        self,
        connection: Connection,
        work: WorkExecutionState,
        requester_ref: BudgetScopeRef,
        registration_key: str,
    ) -> WorkExecutionState:
        action = self._action(work, requester_ref, ActionType.REGISTER_WORK)
        work_ref = self.records.stage(connection, work)
        action_ref = self.records.stage(connection, action)
        remaining = self.works.validator.budget.available(
            connection, self.config.budget_binding_ref, str(work.meta.analysis_id)
        )
        units = BudgetUnits(
            elapsed_ms=0,
            work_count=1,
            llm_call_count=0,
            retry_count=0,
            cost_minor_units=0,
            currency=remaining.available_units.currency,
        )
        reservation = BudgetReservation.model_validate_json(
            canonical_bytes(
                dict(
                meta=fresh_meta(
                    work.meta,
                    "budget_reservation",
                    self.works.clock,
                    self.works.ids,
                    attempt_id=None,
                ),
                reservation_id=self.works.ids.new(ReservationId),
                budget_binding_ref=self.config.budget_binding_ref,
                action_ref=action_ref,
                work_ref=work_ref,
                requested_units=units,
                status="RESERVED",
                ledger_entry_ref=None,
                reserved_at=self.works.clock.now(),
                finalized_at=None,
                )
            )
        )
        reserved = self.works.validator.budget.reserve(
            BudgetReservationRequest(reservation), _connection=connection
        )
        reservation_ref = reference(reserved)
        decision = authorize(
            self.works.validator,
            action,
            work,
            reservation_ref,
            _connection=connection,
        )
        if decision.decision != "ALLOW":
            raise ValueError("ACTION_DENIED: Chaining child registration")
        decision_ref = reference(decision)
        self.works.validator.claim(
            connection,
            decision_ref,
            ActionType.REGISTER_WORK,
            work,
            reservation_ref,
            needs_budget=True,
        )
        self.records.publish(connection, work_ref)
        connection.execute(
            insert(models.work_states).values(
                work_id=str(work.work_id),
                analysis_id=str(work.meta.analysis_id),
                registration_key=registration_key,
                status=work.status.value,
                state_version=work.state_version,
                active_attempt_id=None,
                payload=encode(work),
            )
        )
        self.works.point(connection, work)
        remaining = self.works.validator.budget.available(
            connection, self.config.budget_binding_ref, str(work.meta.analysis_id)
        )
        entry = BudgetLedgerEntry.model_validate_json(
            canonical_bytes(
                dict(
                meta=fresh_meta(
                    reservation.meta,
                    "budget_ledger_entry",
                    self.works.clock,
                    self.works.ids,
                ),
                ledger_entry_id=self.works.ids.new(LedgerEntryId),
                reservation_ref=reservation_ref,
                budget_binding_ref=self.config.budget_binding_ref,
                action_ref=action_ref,
                work_ref=work_ref,
                actual_units=units,
                usage_refs=(),
                sequence=remaining.as_of_sequence + 1,
                committed_at=self.works.clock.now(),
                )
            )
        )
        self.works.validator.budget.commit_usage(
            BudgetCommitRequest(entry), _connection=connection
        )
        return work

    def _make_ready(
        self,
        connection: Connection,
        work: WorkExecutionState,
        requester_ref: BudgetScopeRef,
        *,
        cause: str,
    ) -> WorkExecutionState:
        action = self._action(work, requester_ref, ActionType.CHANGE_WORK_STATE)
        decision = authorize(
            self.works.validator, action, work, None, _connection=connection
        )
        if decision.decision != "ALLOW":
            raise ValueError("ACTION_DENIED: Chaining child readiness")
        decision_ref = reference(decision)
        assert isinstance(decision_ref, StoredDataRef)
        self.works.validator.claim(
            connection, decision_ref, ActionType.CHANGE_WORK_STATE, work
        )
        transition = self._transition(work, decision_ref, WorkStatus.READY, cause)
        transition_ref = self.records.stage(connection, transition)
        self.records.publish(connection, transition_ref)
        ready = WorkExecutionState.model_validate_json(
            canonical_bytes(
                work.model_dump()
                | dict(
                meta=next_meta(work.meta, self.works.clock, self.works.ids),
                status=WorkStatus.READY,
                state_version=transition.new_state_version,
                last_transition_ref=transition_ref,
                output_refs=(),
                waiting_for=(),
                stop_reason=None,
                )
            )
        )
        self.works.save(connection, work, ready)
        return ready

    def _validate_claimed(
        self,
        connection: Connection,
        context: WorkContext,
        source_ref: StoredDataRef,
        proposal_id: ProposalId,
    ) -> WorkExecutionState:
        supplied = context.work
        attempt = context.attempt
        supplied_ref = reference(supplied)
        attempt_ref = reference(attempt)
        if (
            not isinstance(supplied_ref, StoredDataRef)
            or not isinstance(attempt_ref, StoredDataRef)
            or supplied.work_type != WorkType.HYPOTHESIS_PROPOSAL
            or supplied.subject_type != "PROPOSAL"
            or supplied.subject_id != proposal_id
            or supplied.status != WorkStatus.RUNNING
            or supplied.input_refs != (source_ref,)
            or supplied.input_hash != content_hash(supplied.input_refs)
            or supplied.dedupe_key != content_hash([source_ref, proposal_id])
            or supplied.active_attempt_id != attempt.attempt_id
            or attempt.status != "RUNNING"
            or attempt.work_id != supplied.work_id
            or attempt.input_hash != supplied.input_hash
            or self.records.resolve(connection, supplied_ref) != supplied
            or self.records.resolve(connection, attempt_ref) != attempt
        ):
            raise ValueError("CHAINING_CHILD_CONTEXT_MISMATCH")
        current_work = self.works.get(str(supplied.work_id), connection)
        if current_work == supplied:
            return current_work
        current_ref = reference(current_work)
        if (
            current_work.status != WorkStatus.SUCCEEDED
            or not isinstance(current_ref, StoredDataRef)
            or not self.records.is_revision_descendant(
                supplied_ref, current_ref, connection=connection
            )
            or current_work.input_refs != supplied.input_refs
            or current_work.subject_id != proposal_id
        ):
            raise ValueError("CHAINING_CHILD_CONTEXT_MISMATCH")
        return current_work

    def _commit_proposal(
        self,
        work: WorkExecutionState,
        nested: HypothesisProposal,
        requester_ref: BudgetScopeRef,
    ) -> HypothesisProposal:
        proposal = HypothesisProposal.model_validate_json(
            canonical_bytes(
                nested.model_dump()
                | dict(
                meta=fresh_meta(
                    work.meta,
                    "hypothesis_proposal",
                    self.works.clock,
                    self.works.ids,
                    hypothesis_id=None,
                    attempt_id=work.active_attempt_id,
                )
                )
            )
        )
        proposal_ref = self.records.stage_record(proposal)
        assert isinstance(proposal_ref, StoredDataRef)
        action = self._action(
            work,
            requester_ref,
            ActionType.SAVE_RESULT,
            result_kind="hypothesis_proposal",
            candidate_result_ref=proposal_ref,
        )
        decision = authorize(self.works.validator, action, work, None)
        if decision.decision != "ALLOW":
            raise ValueError("ACTION_DENIED: Chaining child proposal")
        decision_ref = reference(decision)
        assert isinstance(decision_ref, StoredDataRef)
        transition = self._transition(
            work, decision_ref, WorkStatus.SUCCEEDED, "COMPLETED", (proposal_ref,)
        )
        transition_ref = self.records.stage_record(transition)
        commit = TransitionCommit.model_validate_json(
            canonical_bytes(
                dict(
                meta=fresh_meta(
                    work.meta,
                    "transition_commit",
                    self.works.clock,
                    self.works.ids,
                    attempt_id=work.active_attempt_id,
                ),
                transition_commit_id=self.works.ids.new(TransitionCommitId),
                work_id=work.work_id,
                transition_ref=transition_ref,
                expected_state_version=work.state_version,
                target_state_version=work.state_version + 1,
                attempt_id=work.active_attempt_id,
                target_status=WorkStatus.SUCCEEDED,
                output_refs=(proposal_ref,),
                gap_ids=(),
                error_ids=(),
                state=CommitState.PREPARED,
                prepared_at=self.works.clock.now(),
                committed_at=None,
                abort_reason=None,
                )
            )
        )
        self.transitions.commit(
            TransitionCommitRequest(transition, commit, (proposal,))
        )
        return proposal

    def _completed_proposal(
        self,
        connection: Connection,
        work: WorkExecutionState,
        nested: HypothesisProposal,
    ) -> HypothesisProposal:
        if (
            len(work.output_refs) != 1
            or work.output_refs[0].data_kind != "hypothesis_proposal"
            or work.last_transition_commit_ref is None
        ):
            raise ValueError("CHAINING_CHILD_REPLAY_STATE_MISMATCH")
        commit = self.records.resolve(connection, work.last_transition_commit_ref)
        proposal = self.records.resolve(connection, work.output_refs[0])
        if (
            not isinstance(commit, TransitionCommit)
            or commit.state != CommitState.COMMITTED
            or commit.work_id != work.work_id
            or commit.output_refs != work.output_refs
            or not isinstance(proposal, HypothesisProposal)
            or proposal.model_dump(exclude={"meta"})
            != nested.model_dump(exclude={"meta"})
            or proposal.meta.attempt_id != commit.attempt_id
        ):
            raise ValueError("CHAINING_CHILD_REPLAY_STATE_MISMATCH")
        return proposal

    def _projected(
        self, proposal_ref: StoredDataRef
    ) -> tuple[VulnerabilityHypothesis, HypothesisProcessState, StoredDataRef]:
        with self.records.database.engine.connect() as connection:
            hypotheses = tuple(
                value
                for wire in connection.execute(
                    select(models.records.c.ref)
                    .join(
                        models.current_records,
                        models.current_records.c.record_id
                        == models.records.c.record_id,
                    )
                    .where(models.records.c.kind == "vulnerability_hypothesis")
                ).scalars()
                if isinstance(
                    value := self.records.resolve(
                        connection, REF_ADAPTER.validate_json(wire)
                    ),
                    VulnerabilityHypothesis,
                )
                and value.proposal_ref == proposal_ref
            )
            if len(hypotheses) != 1:
                raise ValueError("CHAINING_CHILD_PROJECTION_MISMATCH")
            hypothesis = hypotheses[0]
            processes = tuple(
                value
                for wire in connection.execute(
                    select(models.records.c.ref)
                    .join(
                        models.current_records,
                        models.current_records.c.record_id
                        == models.records.c.record_id,
                    )
                    .where(models.records.c.kind == "hypothesis_process_state")
                ).scalars()
                if isinstance(
                    value := self.records.resolve(
                        connection, REF_ADAPTER.validate_json(wire)
                    ),
                    HypothesisProcessState,
                )
                and value.meta.hypothesis_id == hypothesis.meta.hypothesis_id
            )
            if len(processes) != 1:
                raise ValueError("CHAINING_CHILD_PROJECTION_MISMATCH")
            process = processes[0]
            process_ref = reference(process)
            assert isinstance(process_ref, StoredDataRef)
            return hypothesis, process, process_ref

    def _ensure_verification_ready(
        self, work: WorkExecutionState, requester_ref: BudgetScopeRef
    ) -> WorkExecutionState:
        current_work = self.works.get(str(work.work_id))
        if current_work.status in {
            WorkStatus.READY,
            WorkStatus.RUNNING,
            WorkStatus.BLOCKED,
            WorkStatus.SUCCEEDED,
            WorkStatus.FAILED,
            WorkStatus.CANCELLED,
        }:
            return current_work
        if current_work.status != WorkStatus.PENDING or current_work != work:
            raise ValueError("CHAINING_CHILD_VERIFICATION_MISMATCH")
        action = self._action(
            current_work, requester_ref, ActionType.CHANGE_WORK_STATE
        )
        decision = authorize(self.works.validator, action, current_work, None)
        if decision.decision != "ALLOW":
            raise ValueError("ACTION_DENIED: Verification readiness")
        decision_ref = reference(decision)
        assert isinstance(decision_ref, StoredDataRef)
        transition = self._transition(
            current_work,
            decision_ref,
            WorkStatus.READY,
            "CHAINING_CHILD_VERIFICATION_READY",
        )
        try:
            return self.works.make_ready(transition)
        except ValueError as error:
            replay = self.works.get(str(work.work_id))
            if replay.status in {
                WorkStatus.READY,
                WorkStatus.RUNNING,
                WorkStatus.BLOCKED,
                WorkStatus.SUCCEEDED,
                WorkStatus.FAILED,
                WorkStatus.CANCELLED,
            }:
                return replay
            raise error

    def _terminal_verification(
        self,
        hypothesis_ref: StoredDataRef,
        proposal_ref: StoredDataRef,
        process: HypothesisProcessState,
    ) -> WorkExecutionState:
        stable_inputs = (
            hypothesis_ref,
            proposal_ref,
            self.config.verification_policy_ref,
            self.config.verification_playbook_ref,
        )
        with self.records.database.engine.connect() as connection:
            candidates = tuple(
                work
                for payload in connection.execute(
                    select(models.work_states.c.payload).where(
                        models.work_states.c.analysis_id
                        == str(process.meta.analysis_id)
                    )
                ).scalars()
                if (
                    (work := WorkExecutionState.model_validate_json(payload)).work_type
                    == WorkType.VERIFICATION
                    and work.subject_id == process.meta.hypothesis_id
                    and work.work_generation == process.verification_generation
                    and work.input_refs[:4] == stable_inputs
                    and work.status == WorkStatus.SUCCEEDED
                )
            )
            if len(candidates) != 1:
                raise ValueError("CHAINING_CHILD_VERIFICATION_MISMATCH")
            work = candidates[0]
            work_ref = reference(work)
            if not isinstance(work_ref, StoredDataRef):
                raise ValueError("CHAINING_CHILD_VERIFICATION_MISMATCH")
            current(self.records, connection, work_ref)
            if (
                self._registration_scope(connection, work)
                != self.config.budget_binding_ref
                or len(work.output_refs) != 1
                or process.verification_result_ref != work.output_refs[0]
            ):
                raise ValueError("CHAINING_CHILD_VERIFICATION_MISMATCH")
            result = self.records.resolve(connection, work.output_refs[0])
            if not isinstance(result, VerificationResult):
                raise ValueError("CHAINING_CHILD_VERIFICATION_MISMATCH")
            require_committed(
                self.records, connection, result, WorkType.VERIFICATION
            )
            return work

    @staticmethod
    def _process_tracks_verification(
        process: HypothesisProcessState, work: WorkExecutionState
    ) -> bool:
        if process.status == "TERMINAL":
            return (
                work.status == WorkStatus.SUCCEEDED
                and process.verification_work_ref is None
                and process.verification_result_ref is not None
                and work.output_refs == (process.verification_result_ref,)
            )
        if process.status == "VERIFYING":
            return (
                work.status
                in {WorkStatus.READY, WorkStatus.RUNNING, WorkStatus.BLOCKED}
                and process.verification_work_ref == reference(work)
            )
        if process.status in {"FAILED", "CANCELLED"}:
            return (
                work.status.value == process.status
                and process.verification_work_ref == reference(work)
            )
        return False

    def _committed_producer(
        self, connection: Connection, source_ref: StoredDataRef
    ) -> WorkExecutionState:
        commits = tuple(
            commit
            for payload in connection.execute(
                select(models.transition_commits.c.payload).where(
                    models.transition_commits.c.state == CommitState.COMMITTED.value
                )
            ).scalars()
            if source_ref
            in (commit := TransitionCommit.model_validate_json(payload)).output_refs
        )
        if len(commits) != 1:
            raise ValueError("RESULT_NOT_COMMITTED")
        return self.works.get(str(commits[0].work_id), connection)

    def _validate_lineage(
        self,
        connection: Connection,
        source: ChainingResult,
        producer: WorkExecutionState,
    ) -> None:
        source_ref = reference(source)
        assert isinstance(source_ref, StoredDataRef)
        primitive_refs = tuple(
            ref
            for ref in producer.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == "primitive"
        )
        index_refs = tuple(
            ref
            for ref in producer.input_refs
            if isinstance(ref, StoredDataRef)
            and ref.data_kind == "primitive_index_state"
        )
        if (
            producer.work_type != WorkType.CHAINING
            or producer.status != WorkStatus.SUCCEEDED
            or producer.output_refs != (source_ref,)
            or producer.trigger_primitive_ref is None
            or {canonical_bytes(ref) for ref in primitive_refs}
            != {canonical_bytes(ref) for ref in source.considered_primitive_refs}
        ):
            raise ValueError("CHAINING_CHILD_SOURCE_MISMATCH")
        primitives = tuple(
            value
            for ref in source.considered_primitive_refs
            if isinstance(
                value := self.records.resolve(connection, ref), Primitive
            )
        )
        if len(primitives) != len(source.considered_primitive_refs):
            raise ValueError("CHAINING_INPUT_CLOSURE")
        universe = PinnedChainingUniverse(
            trigger_primitive_ref=producer.trigger_primitive_ref,
            index_refs=index_refs,
            considered_primitive_refs=source.considered_primitive_refs,
        )
        expected: list[LineageExclusion] = []
        used = set(source.input_primitive_refs)
        seen: set[tuple[StoredDataRef, StoredDataRef]] = set()
        for match in source.primitive_match_candidates:
            for matched_ref in (
                match.upstream_result_ref,
                match.downstream_input_ref,
            ):
                ancestors = self.lineage.ancestors(
                    primitive_ref=matched_ref, universe=universe
                )
                if len(set(ancestors)) != len(ancestors) or any(
                    ancestor == matched_ref
                    or ancestor not in source.considered_primitive_refs
                    for ancestor in ancestors
                ):
                    raise ValueError("CHAINING_LINEAGE_RESOLUTION_INVALID")
                if any(ancestor in used for ancestor in ancestors):
                    raise ValueError("CHAINING_LINEAGE_REUSED_ANCESTOR")
                for ancestor in ancestors:
                    pair = (ancestor, matched_ref)
                    if pair in seen:
                        continue
                    seen.add(pair)
                    expected.append(
                        LineageExclusion(
                            excluded_primitive_ref=ancestor,
                            excluded_by_ref=matched_ref,
                            reason_code="ANCESTOR_REUSE",
                        )
                    )
        validate_chaining_closure(
            source,
            primitives,
            source.considered_primitive_refs,
            tuple(expected),
        )

    def _registration_scope(
        self, connection: Connection, work: WorkExecutionState
    ) -> BudgetScopeRef:
        matches: list[BudgetScopeRef] = []
        for payload in connection.execute(
            select(models.budget_reservations.c.payload).where(
                models.budget_reservations.c.analysis_id == str(work.meta.analysis_id)
            )
        ).scalars():
            reservation = BudgetReservation.model_validate_json(payload)
            candidate = self.records.resolve(
                connection, reservation.work_ref, candidate=True
            )
            action = self.records.resolve(connection, reservation.action_ref)
            if (
                isinstance(candidate, WorkExecutionState)
                and candidate.work_id == work.work_id
                and isinstance(action, ActionRequest)
                and action.action_type == ActionType.REGISTER_WORK
            ):
                matches.append(reservation.budget_binding_ref)
        if len(matches) != 1:
            raise ValueError("CHAINING_CHILD_SCOPE_MISMATCH")
        return matches[0]

    @staticmethod
    def _validate_handoff(
        work: WorkExecutionState,
        source_ref: StoredDataRef,
        proposal_id: ProposalId,
        registration_key: str,
    ) -> None:
        if (
            work.work_type != WorkType.HYPOTHESIS_PROPOSAL
            or work.subject_type != "PROPOSAL"
            or work.subject_id != proposal_id
            or work.work_generation != 1
            or work.input_refs != (source_ref,)
            or work.input_hash != content_hash(work.input_refs)
            or work.dedupe_key != registration_key
            or work.status
            not in {WorkStatus.READY, WorkStatus.RUNNING, WorkStatus.SUCCEEDED}
            or (
                work.status == WorkStatus.READY
                and (work.active_attempt_id is not None or work.output_refs)
            )
            or (
                work.status == WorkStatus.RUNNING
                and (work.active_attempt_id is None or work.output_refs)
            )
            or (
                work.status == WorkStatus.SUCCEEDED
                and work.active_attempt_id is not None
            )
        ):
            raise ValueError("CHAINING_CHILD_REPLAY_MISMATCH")

    def _action(
        self,
        work: WorkExecutionState,
        requester_ref: BudgetScopeRef,
        action_type: ActionType,
        *,
        result_kind: str | None = None,
        candidate_result_ref: StoredDataRef | None = None,
    ) -> ActionRequest:
        requester_role = self.records.evidence.identity_role(requester_ref)
        if requester_role is None:
            raise ValueError("AUTHORITY_DENIED: Chaining child registrar required")
        return ActionRequest.model_validate_json(
            canonical_bytes(
                dict(
                meta=fresh_meta(
                    work.meta,
                    "action_request",
                    self.works.clock,
                    self.works.ids,
                    attempt_id=work.active_attempt_id,
                ),
                action_id=self.works.ids.new(ActionId),
                requested_by=requester_role,
                requester_identity_ref=requester_ref,
                action_type=action_type,
                work_ref=(
                    None
                    if action_type == ActionType.REGISTER_WORK
                    else reference(work)
                ),
                expected_state_version=(
                    None
                    if action_type == ActionType.REGISTER_WORK
                    else work.state_version
                ),
                expected_verification_generation=None,
                generation_restart_reason=None,
                generation_restart_basis_refs=(),
                input_refs=work.input_refs,
                dynamic_request_ref=None,
                reproduction_plan_ref=None,
                result_kind=result_kind,
                candidate_result_ref=candidate_result_ref,
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
                reason="Register exact committed Chaining child",
                requested_at=self.works.clock.now(),
                )
            )
        )

    def _transition(
        self,
        work: WorkExecutionState,
        decision_ref: BudgetScopeRef,
        status: WorkStatus,
        cause: str,
        outputs: tuple[StoredDataRef, ...] = (),
    ) -> StateTransition:
        return StateTransition.model_validate_json(
            canonical_bytes(
                dict(
                meta=fresh_meta(
                    work.meta,
                    "state_transition",
                    self.works.clock,
                    self.works.ids,
                    attempt_id=work.active_attempt_id,
                ),
                transition_id=self.works.ids.new(TransitionId),
                work_id=work.work_id,
                action_decision_ref=decision_ref,
                from_status=work.status,
                to_status=status,
                expected_state_version=work.state_version,
                new_state_version=work.state_version + 1,
                attempt_id=work.active_attempt_id,
                cause=cause,
                output_refs=outputs,
                gap_ids=(),
                error_ids=(),
                dedupe_key=content_hash(
                    [work.work_id, work.state_version, status, outputs]
                ),
                created_at=self.works.clock.now(),
                )
            )
        )

    @staticmethod
    def _scope(meta: object) -> tuple[object, object, object]:
        return (
            getattr(meta, "analysis_id", None),
            getattr(meta, "workspace_id", None),
            getattr(meta, "commit_id", None),
        )

    @staticmethod
    def _code_scope(meta: RecordMeta) -> tuple[object, object]:
        return meta.workspace_id, meta.commit_id

    @staticmethod
    def _scope_ref(ref: StoredDataRef) -> tuple[object, object]:
        return ref.workspace_id, ref.commit_id


__all__ = [
    "ChainingChildRegistrationConfig",
    "SQLiteChainingChildRegistration",
]
