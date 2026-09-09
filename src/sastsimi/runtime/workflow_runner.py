"""Local workflow execution through the public durable runtime services."""

from collections.abc import Awaitable, Callable
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
from sastsimi.contracts.records import RecordMeta, RecordMetadata
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef
from sastsimi.contracts.work import (
    StateTransition,
    TransitionCommit,
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

from .services import RuntimeServices


class WorkflowRunner:
    def __init__(
        self, runtime: RuntimeServices, clock: Clock, ids: IdGenerator
    ) -> None:
        self.runtime, self.clock, self.ids = runtime, clock, ids

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
        return source.model_dump() | dict(
            record_id=self.ids.new(RecordId),
            previous_record_id=source.record_id,
            revision_number=source.revision_number + 1,
            attempt_id=attempt_id,
            created_at=self.clock.now(),
        )

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
                    meta=self.metadata(work.meta, "budget_reservation"),
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
            reasons = "; ".join(
                check.reason_code
                for check in decision.check_results
                if check.result == "FAIL"
            )
            raise ValueError("ACTION_DENIED: " + reasons)
        return records.stage_record(decision)

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
        request = self.action(candidate, identity, role, "REGISTER_WORK")
        reservation = self.reserve(candidate, scope, request, self.units(work_count=1))
        registered = self.runtime.work.register(
            candidate,
            self.authorize(candidate, request, reservation),
            records.stage_record(reservation),
        )
        self.account(reservation, reservation.requested_units)
        return self.activate(registered, scope, identity, role=role)

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
        ready_action = self.action(registered, identity, role, "CHANGE_WORK_STATE")
        ready = self.runtime.work.make_ready(
            self.transition(
                registered,
                self.authorize(registered, ready_action),
                "READY",
            )
        )
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
    ) -> WorkExecutionState:
        if not outputs:
            raise ValueError("A successful result work requires its exact output")
        records = self.runtime.unit_of_work.records
        refs = tuple(records.stage_record(output) for output in outputs)
        action = self.action(
            work,
            identity,
            role,
            "SAVE_RESULT",
            result_kind=refs[0].data_kind,
            candidate_result_ref=refs[0],
        )
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
