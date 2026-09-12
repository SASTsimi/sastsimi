"""Local workflow execution through the public durable runtime services."""

from collections.abc import Awaitable, Callable
from contextlib import AbstractContextManager, nullcontext
from datetime import timedelta
from typing import Any

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.budget import BudgetLedgerEntry, BudgetReservation, BudgetUnits
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import (
    ActionId,
    AttemptId,
    LedgerEntryId,
    LogicalRecordId,
    RecordId,
    ReservationId,
    TransitionCommitId,
    TransitionId,
    WorkId,
)
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.records import RecordMeta, RecordMetadata
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef
from sastsimi.contracts.work import (
    CommitState,
    CommitTargetStatus,
    StateTransition,
    TransitionCommit,
    TransitionTargetStatus,
    WorkAttempt,
    WorkExecutionState,
)
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import (
    BudgetCommitRequest,
    BudgetReleaseRequest,
    BudgetReservationRequest,
    Record,
    TransitionCommitRequest,
)
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.policy_runtime import PolicyPreparation

from .services import RuntimeServices

type OutputApproval = Callable[
    [ActionRequest, WorkExecutionState, tuple[RecordRef, ...]],
    AbstractContextManager[None],
]


class WorkflowRunner:
    def __init__(
        self,
        runtime: RuntimeServices,
        clock: Clock,
        ids: IdGenerator,
        output_approval: OutputApproval | None = None,
    ) -> None:
        self.runtime, self.clock, self.ids = runtime, clock, ids
        self._output_approval = output_approval

    def metadata(
        self,
        source: RecordMetadata,
        kind: str,
        *,
        attempt_id: AttemptId | None = None,
    ) -> dict[str, Any]:
        record_id = self.ids.new(RecordId)
        data = source.model_dump() | dict(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            revision_number=1,
            previous_record_id=None,
            created_at=self.clock.now(),
        )
        if isinstance(source, RecordMeta):
            data["attempt_id"] = attempt_id
        return data

    def revision_metadata(
        self,
        source: RecordMetadata,
        *,
        attempt_id: AttemptId | None = None,
    ) -> dict[str, Any]:
        """Build the next immutable revision for a runtime-owned logical record."""
        data = source.model_dump() | dict(
            record_id=self.ids.new(RecordId),
            previous_record_id=source.record_id,
            revision_number=source.revision_number + 1,
            created_at=self.clock.now(),
        )
        if isinstance(source, RecordMeta):
            data["attempt_id"] = attempt_id
        return data

    def publish_intermediate(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        role: str,
        outputs: tuple[Record, ...],
        *,
        action_input_refs: tuple[RecordRef, ...] | None = None,
    ) -> tuple[RecordRef, ...]:
        """Authorize and atomically publish same-attempt continuing outputs."""
        if not outputs:
            raise ValueError("OUTPUT_BINDING_MISMATCH")
        records = self.runtime.unit_of_work.records
        refs = tuple(records.stage_record(output) for output in outputs)
        action = self.action(
            work,
            identity,
            role,
            "SAVE_RESULT",
            result_kind=refs[0].data_kind,
            candidate_result_ref=refs[0],
            input_refs=(
                work.input_refs if action_input_refs is None else action_input_refs
            ),
        )
        approval = (
            self._output_approval(action, work, refs)
            if self._output_approval is not None
            else nullcontext()
        )
        with approval:
            decision = self.authorize(work, action)
        return self.runtime.intermediate.publish(str(work.work_id), decision, outputs)

    def units(self, **values: int) -> BudgetUnits:
        return BudgetUnits(
            elapsed_ms=values.get("elapsed_ms", 0),
            work_count=values.get("work_count", 0),
            llm_call_count=values.get("llm_call_count", 0),
            retry_count=values.get("retry_count", 0),
            cost_minor_units=values.get("cost_minor_units", 0),
            currency="USD",
        )

    def action(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        role: str,
        kind: str,
        **fields: Any,
    ) -> ActionRequest:
        return ActionRequest.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.metadata(
                        work.meta, "action_request", attempt_id=work.active_attempt_id
                    ),
                    action_id=self.ids.new(ActionId),
                    requested_by=role,
                    requester_identity_ref=identity,
                    action_type=kind,
                    work_ref=None
                    if kind == "REGISTER_WORK"
                    else self.runtime.unit_of_work.records.stage_record(work),
                    expected_state_version=None
                    if kind == "REGISTER_WORK"
                    else work.state_version,
                    expected_verification_generation=None,
                    generation_restart_reason=None,
                    generation_restart_basis_refs=(),
                    input_refs=work.input_refs,
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
                    reason="Execute the authorized local workflow",
                    requested_at=self.clock.now(),
                )
                | fields
            )
        )

    def reserve(
        self,
        work: WorkExecutionState,
        scope: BudgetScopeRef,
        action: ActionRequest,
        units: BudgetUnits,
    ) -> BudgetReservation:
        records = self.runtime.unit_of_work.records
        reservation = BudgetReservation.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.metadata(
                        work.meta,
                        "budget_reservation",
                        attempt_id=work.active_attempt_id,
                    ),
                    reservation_id=self.ids.new(ReservationId),
                    budget_binding_ref=scope,
                    action_ref=records.stage_record(action),
                    work_ref=records.stage_record(work),
                    requested_units=units,
                    status="RESERVED",
                    ledger_entry_ref=None,
                    reserved_at=self.clock.now(),
                    finalized_at=None,
                )
            )
        )
        return self.runtime.budget.reserve(BudgetReservationRequest(reservation))

    def authorize(
        self,
        work: WorkExecutionState,
        action: ActionRequest,
        reservation: BudgetReservation | None = None,
    ) -> RecordRef:
        records = self.runtime.unit_of_work.records
        decision = self.runtime.validator.authorize(
            action,
            work,
            records.stage_record(reservation) if reservation is not None else None,
        )
        if decision.decision != "ALLOW":
            if reservation is not None:
                self._release_reservation(reservation)
            reasons = "; ".join(
                check.reason_code
                for check in decision.check_results
                if check.result == "FAIL"
            )
            raise ValueError("ACTION_DENIED: " + reasons)
        return records.stage_record(decision)

    def _release_reservation(self, reservation: BudgetReservation) -> None:
        released = BudgetReservation.model_validate_json(
            canonical_bytes(
                reservation.model_dump()
                | dict(
                    meta=reservation.meta.model_dump()
                    | dict(
                        record_id=self.ids.new(RecordId),
                        previous_record_id=reservation.meta.record_id,
                        revision_number=reservation.meta.revision_number + 1,
                        created_at=self.clock.now(),
                    ),
                    status="RELEASED",
                    finalized_at=self.clock.now(),
                )
            )
        )
        self.runtime.budget.release(BudgetReleaseRequest(released))

    def account(self, reservation: BudgetReservation, actual: BudgetUnits) -> None:
        records = self.runtime.unit_of_work.records
        remaining = self.runtime.budget.remaining(
            reservation.budget_binding_ref, str(reservation.meta.analysis_id)
        )
        entry = BudgetLedgerEntry.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.metadata(reservation.meta, "budget_ledger_entry"),
                    ledger_entry_id=self.ids.new(LedgerEntryId),
                    reservation_ref=records.stage_record(reservation),
                    budget_binding_ref=reservation.budget_binding_ref,
                    action_ref=reservation.action_ref,
                    work_ref=reservation.work_ref,
                    actual_units=actual,
                    usage_refs=(),
                    sequence=remaining.as_of_sequence + 1,
                    committed_at=self.clock.now(),
                )
            )
        )
        self.runtime.budget.commit_usage(BudgetCommitRequest(entry))

    def transition(
        self,
        work: WorkExecutionState,
        decision: RecordRef,
        status: str,
        attempt_id: AttemptId | None = None,
    ) -> StateTransition:
        return StateTransition.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.metadata(
                        work.meta, "state_transition", attempt_id=attempt_id
                    ),
                    transition_id=self.ids.new(TransitionId),
                    work_id=work.work_id,
                    action_decision_ref=decision,
                    from_status=work.status,
                    to_status=status,
                    expected_state_version=work.state_version,
                    new_state_version=work.state_version + 1,
                    attempt_id=attempt_id,
                    cause="READY" if status == "READY" else "STARTED",
                    output_refs=(),
                    gap_ids=(),
                    error_ids=(),
                    dedupe_key=content_hash([work.work_id, work.state_version, status]),
                    created_at=self.clock.now(),
                )
            )
        )

    def start(
        self,
        scope: BudgetScopeRef,
        metadata: RecordMetadata,
        work_type: str,
        subject_type: str,
        subject_id: str,
        identity: BudgetScopeRef,
        *,
        role: str = "ORCHESTRATION",
        generation: int = 1,
        inputs: tuple[RecordRef, ...] = (),
        parent: RecordRef | None = None,
        trigger_primitive_ref: RecordRef | None = None,
    ) -> WorkExecutionState:
        registered = self._register_pending(
            scope,
            self._pending_work(
                metadata,
                work_type,
                subject_type,
                subject_id,
                generation=generation,
                inputs=inputs,
                parent=parent,
                trigger_primitive_ref=trigger_primitive_ref,
            ),
            identity,
            role=role,
        )
        return self.activate(registered, scope, identity, role=role)

    def enqueue(
        self,
        scope: BudgetScopeRef,
        metadata: RecordMetadata,
        work_type: str,
        subject_type: str,
        subject_id: str,
        identity: BudgetScopeRef,
        *,
        role: str = "ORCHESTRATION",
        generation: int = 1,
        inputs: tuple[RecordRef, ...] = (),
        parent: RecordRef | None = None,
        trigger_primitive_ref: RecordRef | None = None,
    ) -> WorkExecutionState:
        """Register and authorize downstream work, stopping before attempt claim."""
        registered = self._register_pending(
            scope,
            self._pending_work(
                metadata,
                work_type,
                subject_type,
                subject_id,
                generation=generation,
                inputs=inputs,
                parent=parent,
                trigger_primitive_ref=trigger_primitive_ref,
            ),
            identity,
            role=role,
        )
        return self.enqueue_registered(
            registered,
            scope,
            identity,
            role=role,
        )

    def begin_policy(
        self,
        scope: BudgetScopeRef,
        metadata: RecordMetadata,
        identity: BudgetScopeRef,
        *,
        program_id: str,
        source_config_ref: BudgetScopeRef,
        parser_name: str,
        parser_version: str,
        generation: int = 1,
        role: str = "ORCHESTRATION",
    ) -> PolicyPreparation:
        """Atomically register PENDING policy work and its PREPARING state."""
        analysis_id = getattr(metadata, "analysis_id", None)
        if analysis_id is None:
            raise ValueError("POLICY_WORK_REQUIRES_RUN_SCOPE")
        candidate = self._pending_work(
            metadata,
            "POLICY_FETCH",
            "ANALYSIS",
            str(analysis_id),
            generation=generation,
            inputs=(source_config_ref,),
            parent=None,
            trigger_primitive_ref=None,
        )
        records = self.runtime.unit_of_work.records
        request = self.action(candidate, identity, role, "REGISTER_WORK")
        reservation = self.reserve(candidate, scope, request, self.units(work_count=1))
        decision_ref = self.authorize(candidate, request, reservation)
        work_ref = records.stage_record(candidate)
        if not isinstance(work_ref, StoredDataRef):
            raise ValueError("POLICY_WORK_REQUIRES_CODE_SCOPE")
        state = RunPolicyState.model_validate(
            dict(
                meta=self.metadata(candidate.meta, "run_policy_state"),
                program_id=program_id,
                status="PREPARING",
                preparation_source=None,
                source_config_ref=source_config_ref,
                parser_name=parser_name,
                parser_version=parser_version,
                policy_work_ref=work_ref,
                policy_cache_ref=None,
                collection_result_ref=None,
                policy_record_ref=None,
                freshness_criterion_ref=None,
                freshness_checked_at=None,
                freshness_evidence_refs=(),
                freshness_valid_until=None,
            )
        )
        try:
            started = self.runtime.policy.begin(
                candidate,
                decision_ref,
                records.stage_record(reservation),
                state,
            )
        except Exception:
            self._release_reservation(reservation)
            raise
        self.account(reservation, reservation.requested_units)
        return started

    def _pending_work(
        self,
        metadata: RecordMetadata,
        work_type: str,
        subject_type: str,
        subject_id: str,
        *,
        generation: int,
        inputs: tuple[RecordRef, ...],
        parent: RecordRef | None,
        trigger_primitive_ref: RecordRef | None,
    ) -> WorkExecutionState:
        metadata_analysis_id = getattr(metadata, "analysis_id", None)
        if subject_type == "ANALYSIS" and subject_id != str(metadata_analysis_id):
            raise ValueError("ANALYSIS_SCOPE_MISMATCH")
        work_id = self.ids.new(WorkId)
        candidate = WorkExecutionState.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.metadata(metadata, "work_execution_state"),
                    work_id=work_id,
                    parent_work_ref=parent,
                    work_type=work_type,
                    subject_type=subject_type,
                    subject_id=subject_id,
                    work_generation=generation,
                    status="PENDING",
                    state_version=1,
                    last_transition_ref=None,
                    last_transition_commit_ref=None,
                    active_attempt_id=None,
                    input_hash=content_hash(inputs),
                    dedupe_key=content_hash([work_id, inputs]),
                    trigger_primitive_ref=trigger_primitive_ref,
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
        records = self.runtime.unit_of_work.records
        for input_ref in inputs:
            try:
                input_record = records.get_exact(input_ref)
            except (LookupError, ValueError):
                continue
            input_analysis_id = getattr(
                getattr(input_record, "meta", None), "analysis_id", None
            )
            if (
                input_analysis_id is not None
                and input_analysis_id != candidate.meta.analysis_id
            ):
                raise ValueError("ANALYSIS_SCOPE_MISMATCH")
        return candidate

    def _register_pending(
        self,
        scope: BudgetScopeRef,
        candidate: WorkExecutionState,
        identity: BudgetScopeRef,
        *,
        role: str,
    ) -> WorkExecutionState:
        records = self.runtime.unit_of_work.records
        request = self.action(candidate, identity, role, "REGISTER_WORK")
        reservation = self.reserve(candidate, scope, request, self.units(work_count=1))
        registered = self.runtime.work.register(
            candidate,
            self.authorize(candidate, request, reservation),
            records.stage_record(reservation),
        )
        self.account(reservation, reservation.requested_units)
        return registered

    def enqueue_registered(
        self,
        registered: WorkExecutionState,
        scope: BudgetScopeRef,
        identity: BudgetScopeRef,
        *,
        role: str = "ORCHESTRATION",
    ) -> WorkExecutionState:
        """Move one exact existing PENDING work to READY without an attempt."""
        if registered.status != "PENDING":
            raise ValueError("READY_ENQUEUE_REQUIRES_PENDING")
        current = self.runtime.work.get(str(registered.work_id))
        if current != registered:
            raise ValueError("STALE_REGISTERED_WORK")
        if self.runtime.work.registration_scope(str(registered.work_id)) != scope:
            raise ValueError("READY_ENQUEUE_SCOPE_MISMATCH")
        ready_action = self.action(registered, identity, role, "CHANGE_WORK_STATE")
        return self.runtime.work.make_ready(
            self.transition(
                registered,
                self.authorize(registered, ready_action),
                "READY",
            )
        )

    def activate(
        self,
        registered: WorkExecutionState,
        scope: BudgetScopeRef,
        identity: BudgetScopeRef,
        *,
        role: str = "ORCHESTRATION",
    ) -> WorkExecutionState:
        records = self.runtime.unit_of_work.records
        metadata = registered.meta
        work_id = registered.work_id
        if registered.status == "PENDING":
            # Existing trusted aggregate registrars may atomically create a
            # PENDING work without using WorkflowRunner's REGISTER_WORK
            # reservation.  `activate` immediately claims an attempt under
            # the supplied scope, whereas the downstream-only
            # `enqueue_registered` boundary deliberately requires the exact
            # registration scope before exposing READY work to another worker.
            ready_action = self.action(registered, identity, role, "CHANGE_WORK_STATE")
            ready = self.runtime.work.make_ready(
                self.transition(
                    registered,
                    self.authorize(registered, ready_action),
                    "READY",
                )
            )
        elif registered.status == "READY":
            ready = self.runtime.work.get(str(registered.work_id))
            if ready != registered:
                raise ValueError("STALE_REGISTERED_WORK")
        else:
            raise ValueError("ATTEMPT_START_REQUIRES_PENDING_OR_READY")
        attempt_id = self.ids.new(AttemptId)
        attempt_metadata = self.metadata(metadata, "work_attempt")
        if isinstance(metadata, RecordMeta):
            attempt_metadata["attempt_id"] = attempt_id
        attempt = WorkAttempt.model_validate_json(
            canonical_bytes(
                dict(
                    meta=attempt_metadata,
                    work_id=work_id,
                    attempt_id=attempt_id,
                    attempt_number=1,
                    trigger="INITIAL",
                    input_hash=ready.input_hash,
                    status="RUNNING",
                    output_refs=(),
                    gap_ids=(),
                    error_ids=(),
                    started_at=self.clock.now(),
                    finished_at=None,
                    elapsed_ms=0,
                )
            )
        )
        start_action = self.action(ready, identity, role, "START_ATTEMPT")
        reservation = self.reserve(ready, scope, start_action, self.units())
        running = self.runtime.attempts.start(
            self.transition(
                ready,
                self.authorize(ready, start_action, reservation),
                "RUNNING",
                attempt_id,
            ),
            attempt,
            records.stage_record(reservation),
            "local-workflow",
            self.clock.now() + timedelta(minutes=5),
        )
        self.account(reservation, reservation.requested_units)
        return running

    async def external[T](
        self,
        work: WorkExecutionState,
        scope: BudgetScopeRef,
        identity: BudgetScopeRef,
        role: str,
        kind: str,
        operation: Callable[[], Awaitable[T]],
        *,
        requested_units: BudgetUnits,
        actual_units: BudgetUnits,
        **fields: Any,
    ) -> T:
        request = self.action(work, identity, role, kind, **fields)
        reservation = self.reserve(work, scope, request, requested_units)
        decision = self.authorize(work, request, reservation)
        result = await self.runtime.external.invoke(
            str(work.work_id),
            decision,
            self.runtime.unit_of_work.records.stage_record(reservation),
            operation,
            idempotency_key=str(request.action_id),
        )
        self.account(reservation, actual_units)
        return result

    def complete(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        role: str,
        outputs: tuple[Record, ...],
        *,
        status: str = "SUCCEEDED",
        cause: str = "COMPLETED",
        error_ids: tuple[str, ...] = (),
        gap_ids: tuple[str, ...] = (),
        action_input_refs: tuple[RecordRef, ...] | None = None,
    ) -> WorkExecutionState:
        empty_hypothesis_batch = not outputs and work.work_type == "HYPOTHESIS_PROPOSAL"
        if not outputs and not empty_hypothesis_batch:
            raise ValueError("A successful result work requires its exact output")
        records = self.runtime.unit_of_work.records
        refs = tuple(records.stage_record(output) for output in outputs)
        action = self.action(
            work,
            identity,
            role,
            "CHANGE_WORK_STATE" if empty_hypothesis_batch else "SAVE_RESULT",
            result_kind=None if empty_hypothesis_batch else refs[0].data_kind,
            candidate_result_ref=None if empty_hypothesis_batch else refs[0],
            input_refs=(
                work.input_refs if action_input_refs is None else action_input_refs
            ),
        )
        approval = (
            self._output_approval(action, work, refs)
            if self._output_approval is not None
            else nullcontext()
        )
        with approval:
            decision = self.authorize(work, action)
        transition = StateTransition.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.metadata(
                        work.meta, "state_transition", attempt_id=work.active_attempt_id
                    ),
                    transition_id=self.ids.new(TransitionId),
                    work_id=work.work_id,
                    action_decision_ref=decision,
                    from_status=work.status,
                    to_status=status,
                    expected_state_version=work.state_version,
                    new_state_version=work.state_version + 1,
                    attempt_id=work.active_attempt_id,
                    cause=cause,
                    output_refs=refs,
                    gap_ids=gap_ids,
                    error_ids=error_ids,
                    dedupe_key=content_hash([work.work_id, work.state_version, refs]),
                    created_at=self.clock.now(),
                )
            )
        )
        commit = TransitionCommit.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.metadata(
                        work.meta,
                        "transition_commit",
                        attempt_id=work.active_attempt_id,
                    ),
                    transition_commit_id=self.ids.new(TransitionCommitId),
                    work_id=work.work_id,
                    transition_ref=records.stage_record(transition),
                    expected_state_version=work.state_version,
                    target_state_version=work.state_version + 1,
                    attempt_id=work.active_attempt_id,
                    target_status=status,
                    output_refs=refs,
                    gap_ids=gap_ids,
                    error_ids=error_ids,
                    state="PREPARED",
                    prepared_at=self.clock.now(),
                    committed_at=None,
                    abort_reason=None,
                )
            )
        )
        self.runtime.transitions.commit(
            TransitionCommitRequest(transition, commit, outputs)
        )
        return self.runtime.work.get(str(work.work_id))

    def block(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        cause: str,
        *,
        role: str = "ORCHESTRATION",
        error_ids: tuple[str, ...] = (),
        gap_ids: tuple[str, ...] = (),
    ) -> WorkExecutionState:
        """Atomically end the current attempt without publishing a result."""
        current = self.runtime.work.get(str(work.work_id))
        if current != work or current.status != "RUNNING":
            raise ValueError("WORK_CONTEXT_NOT_CURRENT")
        action = self.action(
            current,
            identity,
            role,
            "CHANGE_WORK_STATE",
            input_refs=current.input_refs,
            reason=cause,
        )
        decision = self.authorize(current, action)
        transition = StateTransition.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.metadata(
                        current.meta,
                        "state_transition",
                        attempt_id=current.active_attempt_id,
                    ),
                    transition_id=self.ids.new(TransitionId),
                    work_id=current.work_id,
                    action_decision_ref=decision,
                    from_status=current.status,
                    to_status=TransitionTargetStatus.BLOCKED,
                    expected_state_version=current.state_version,
                    new_state_version=current.state_version + 1,
                    attempt_id=current.active_attempt_id,
                    cause=cause,
                    output_refs=(),
                    gap_ids=gap_ids,
                    error_ids=error_ids,
                    dedupe_key=content_hash(
                        [current.work_id, current.state_version, "BLOCKED", cause]
                    ),
                    created_at=self.clock.now(),
                )
            )
        )
        commit = TransitionCommit.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.metadata(
                        current.meta,
                        "transition_commit",
                        attempt_id=current.active_attempt_id,
                    ),
                    transition_commit_id=self.ids.new(TransitionCommitId),
                    work_id=current.work_id,
                    transition_ref=self.runtime.unit_of_work.records.stage_record(
                        transition
                    ),
                    expected_state_version=current.state_version,
                    target_state_version=current.state_version + 1,
                    attempt_id=current.active_attempt_id,
                    target_status=CommitTargetStatus.BLOCKED,
                    output_refs=(),
                    gap_ids=gap_ids,
                    error_ids=error_ids,
                    state=CommitState.PREPARED,
                    prepared_at=self.clock.now(),
                    committed_at=None,
                    abort_reason=None,
                )
            )
        )
        self.runtime.transitions.commit(TransitionCommitRequest(transition, commit, ()))
        return self.runtime.work.get(str(current.work_id))
