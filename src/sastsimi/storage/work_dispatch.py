"""Atomic SQLite scheduler claim over latch, budget, attempt, lease, and work CAS."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Connection, select, update

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    Decision,
)
from sastsimi.contracts.budget import (
    BudgetLedgerEntry,
    BudgetReservation,
    BudgetUnits,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import (
    ActionId,
    AttemptId,
    LedgerEntryId,
    ReservationId,
    TransitionId,
)
from sastsimi.contracts.records import RecordMeta, RecordMetadata
from sastsimi.contracts.refs import BudgetScopeRef
from sastsimi.contracts.work import (
    AttemptTrigger,
    StateTransition,
    TransitionTargetStatus,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
)
from sastsimi.ports.dto import (
    BudgetCommitRequest,
    BudgetReservationRequest,
    WorkContext,
)

from . import models
from .attempt_service import AttemptService
from .authorization import authorize
from .codec import encode, reference
from .records import fresh_meta, next_meta
from .run_control import cancel_latched, reject_cancelled
from .run_states import get_run
from .work_service import WorkService


class WorkDispatchStore:
    """The sole production READY-to-RUNNING storage boundary."""

    def __init__(self, works: WorkService) -> None:
        self.works = works
        self.attempts = AttemptService(works)

    def ready_work(
        self, analysis_id: str, limit: int
    ) -> tuple[WorkExecutionState, ...]:
        return self.works.ready_work(analysis_id, limit)

    def work_for_run(self, analysis_id: str) -> tuple[WorkExecutionState, ...]:
        return self.works.work_for_run(analysis_id)

    def attempts_for_work(self, work_id: str) -> tuple[WorkAttempt, ...]:
        return self.works.attempts_for_work(work_id)

    def try_claim_ready(
        self,
        analysis_id: str,
        work_id: str,
        expected_state_version: int,
        worker_id: str,
        lease_expires_at: datetime,
    ) -> WorkContext | None:
        if (
            not analysis_id
            or not work_id
            or expected_state_version < 1
            or not worker_id
            or lease_expires_at <= self.works.clock.now()
        ):
            raise ValueError("SCHEDULER_CLAIM_INVALID")
        records = self.works.records
        with records.database.write() as connection:
            if records.database.recovery_failed:
                raise ValueError("RECOVERY_FAILED")
            if cancel_latched(connection, analysis_id):
                return None
            run = get_run(connection, analysis_id)
            if run.status != "RUNNING":
                return None
            row = (
                connection.execute(
                    select(models.work_states).where(
                        models.work_states.c.analysis_id == analysis_id,
                        models.work_states.c.work_id == work_id,
                        models.work_states.c.status == "READY",
                        models.work_states.c.state_version == expected_state_version,
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                return None
            work = WorkExecutionState.model_validate_json(row["payload"])
            if (
                str(work.meta.analysis_id) != analysis_id
                or str(work.work_id) != work_id
                or work.status != "READY"
                or work.state_version != expected_state_version
                or row["active_attempt_id"] is not None
                or row["worker_id"] is not None
                or row["lease_expires_at"] is not None
            ):
                return None
            current = (
                connection.execute(
                    select(models.current_records).where(
                        models.current_records.c.logical_record_id
                        == str(work.meta.logical_record_id)
                    )
                )
                .mappings()
                .one()
            )
            if (
                current["record_id"] != str(work.meta.record_id)
                or current["state_version"] != work.state_version
            ):
                return None

            scope, registration = self._registration_context(connection, work)
            budget = self.works.validator.budget
            profile = budget.registry.execution(connection, scope, analysis_id)
            running = connection.execute(
                select(models.work_states.c.work_id).where(
                    models.work_states.c.analysis_id == analysis_id,
                    models.work_states.c.status == "RUNNING",
                )
            ).all()
            if len(running) >= profile.max_parallel_work:
                return None
            remaining = budget.available(connection, scope, analysis_id)
            if any(
                getattr(remaining.available_units, field) <= 0
                for field in (
                    "elapsed_ms",
                    "cost_minor_units",
                    "llm_call_count",
                    "work_count",
                )
            ):
                return None

            prior_payload = (
                connection.execute(
                    select(models.work_attempts.c.payload)
                    .where(models.work_attempts.c.work_id == work_id)
                    .order_by(models.work_attempts.c.attempt_number.desc())
                )
                .scalars()
                .first()
            )
            prior = (
                WorkAttempt.model_validate_json(prior_payload)
                if prior_payload is not None
                else None
            )
            if prior is not None and prior.status == "RUNNING":
                return None
            attempt_number = 1 if prior is None else prior.attempt_number + 1
            trigger = AttemptTrigger.INITIAL if prior is None else AttemptTrigger.RETRY
            if work.last_transition_ref is not None:
                last_transition = records.resolve(connection, work.last_transition_ref)
                if not isinstance(last_transition, StateTransition):
                    raise ValueError("WORK_LAST_TRANSITION_INVALID")
                if (
                    last_transition.work_id != work.work_id
                    or last_transition.to_status != TransitionTargetStatus.READY
                    or last_transition.new_state_version != work.state_version
                ):
                    raise ValueError("WORK_LAST_TRANSITION_INVALID")
                if last_transition.from_status == WorkStatus.BLOCKED:
                    trigger = AttemptTrigger.RESUME
            attempt_id = self.works.ids.new(AttemptId)
            now = self.works.clock.now()
            action = self._start_action(work, registration)
            action_ref = reference(action)
            reservation = BudgetReservation.model_validate_json(
                canonical_bytes(
                    {
                        "meta": fresh_meta(
                            work.meta,
                            "budget_reservation",
                            self.works.clock,
                            self.works.ids,
                        ),
                        "reservation_id": self.works.ids.new(ReservationId),
                        "budget_binding_ref": scope,
                        "action_ref": action_ref,
                        "work_ref": reference(work),
                        "requested_units": BudgetUnits(
                            elapsed_ms=0,
                            work_count=0,
                            llm_call_count=0,
                            retry_count=0 if prior is None else 1,
                            cost_minor_units=0,
                            currency=profile.currency,
                        ),
                        "status": "RESERVED",
                        "ledger_entry_ref": None,
                        "reserved_at": now,
                        "finalized_at": None,
                    }
                )
            )
            try:
                with connection.begin_nested():
                    records.stage(connection, action)
                    reservation = budget.reserve(
                        BudgetReservationRequest(reservation), _connection=connection
                    )
                    reservation_ref = reference(reservation)
                    decision = authorize(
                        self.works.validator,
                        action,
                        work,
                        reservation_ref,
                        _connection=connection,
                    )
                    if decision.decision != Decision.ALLOW:
                        reasons = "; ".join(
                            check.reason_code
                            for check in decision.check_results
                            if check.result == "FAIL"
                        )
                        raise ValueError("ACTION_DENIED: " + reasons)
                    transition = self._start_transition(work, decision, attempt_id)
                    attempt = WorkAttempt.model_validate_json(
                        canonical_bytes(
                            {
                                "meta": self._attempt_meta(
                                    work.meta, "work_attempt", attempt_id
                                ),
                                "work_id": work.work_id,
                                "attempt_id": attempt_id,
                                "attempt_number": attempt_number,
                                "trigger": trigger,
                                "input_hash": work.input_hash,
                                "status": "RUNNING",
                                "output_refs": (),
                                "gap_ids": (),
                                "error_ids": (),
                                "started_at": now,
                                "finished_at": None,
                                "elapsed_ms": 0,
                            }
                        )
                    )
                    claimed = self.attempts.start(
                        transition,
                        attempt,
                        reservation_ref,
                        worker_id,
                        lease_expires_at,
                        _connection=connection,
                    )
                    remaining = budget.available(connection, scope, analysis_id)
                    entry = BudgetLedgerEntry.model_validate_json(
                        canonical_bytes(
                            {
                                "meta": fresh_meta(
                                    work.meta,
                                    "budget_ledger_entry",
                                    self.works.clock,
                                    self.works.ids,
                                ),
                                "ledger_entry_id": self.works.ids.new(LedgerEntryId),
                                "reservation_ref": reservation_ref,
                                "budget_binding_ref": scope,
                                "action_ref": action_ref,
                                "work_ref": reference(work),
                                "actual_units": reservation.requested_units,
                                "usage_refs": (),
                                "sequence": remaining.as_of_sequence + 1,
                                "committed_at": self.works.clock.now(),
                            }
                        )
                    )
                    budget.commit_usage(
                        BudgetCommitRequest(entry), _connection=connection
                    )
            except ValueError as error:
                if str(error).startswith(("BUDGET_EXCEEDED", "BUDGET unavailable")):
                    return None
                raise
            return WorkContext(claimed, attempt)

    def renew_lease(
        self,
        context: WorkContext,
        worker_id: str,
        lease_expires_at: datetime,
        elapsed_ms: int,
    ) -> WorkContext:
        if (
            not worker_id
            or lease_expires_at <= self.works.clock.now()
            or elapsed_ms < context.attempt.elapsed_ms
        ):
            raise ValueError("LEASE_RENEWAL_INVALID")
        records = self.works.records
        with records.database.write() as connection:
            reject_cancelled(connection, str(context.work.meta.analysis_id))
            row = (
                connection.execute(
                    select(models.work_states).where(
                        models.work_states.c.work_id == str(context.work.work_id)
                    )
                )
                .mappings()
                .one()
            )
            current = WorkExecutionState.model_validate_json(row["payload"])
            attempt_payload = connection.execute(
                select(models.work_attempts.c.payload).where(
                    models.work_attempts.c.attempt_id == str(context.attempt.attempt_id)
                )
            ).scalar_one()
            current_attempt = WorkAttempt.model_validate_json(attempt_payload)
            old_expiry = (
                datetime.fromisoformat(row["lease_expires_at"])
                if row["lease_expires_at"] is not None
                else None
            )
            if (
                current != context.work
                or current_attempt != context.attempt
                or current.status != "RUNNING"
                or current.active_attempt_id != current_attempt.attempt_id
                or row["worker_id"] != worker_id
                or old_expiry is None
                or old_expiry <= self.works.clock.now()
            ):
                raise ValueError("LEASE_NOT_ACTIVE")
            renewed_attempt = current_attempt.model_copy(
                update={
                    "meta": next_meta(
                        current_attempt.meta, self.works.clock, self.works.ids
                    ),
                    "elapsed_ms": elapsed_ms,
                }
            )
            records.publish(connection, records.stage(connection, renewed_attempt))
            connection.execute(
                update(models.work_attempts)
                .where(
                    models.work_attempts.c.attempt_id
                    == str(current_attempt.attempt_id),
                    models.work_attempts.c.payload == encode(current_attempt),
                )
                .values(payload=encode(renewed_attempt))
            )
            changed = connection.execute(
                update(models.work_states)
                .where(
                    models.work_states.c.work_id == str(current.work_id),
                    models.work_states.c.state_version == current.state_version,
                    models.work_states.c.active_attempt_id
                    == str(current_attempt.attempt_id),
                    models.work_states.c.worker_id == worker_id,
                    models.work_states.c.lease_expires_at == row["lease_expires_at"],
                )
                .values(lease_expires_at=lease_expires_at.isoformat())
            )
            if changed.rowcount != 1:
                raise ValueError("LEASE_NOT_ACTIVE")
            return WorkContext(current, renewed_attempt)

    def _registration_context(
        self, connection: Connection, work: WorkExecutionState
    ) -> tuple[BudgetScopeRef, ActionRequest]:
        matches: list[tuple[BudgetScopeRef, ActionRequest]] = []
        for payload in connection.execute(
            select(models.budget_reservations.c.payload).where(
                models.budget_reservations.c.analysis_id == str(work.meta.analysis_id)
            )
        ).scalars():
            reservation = BudgetReservation.model_validate_json(payload)
            candidate = self.works.records.resolve(
                connection, reservation.work_ref, candidate=True
            )
            action = self.works.records.resolve(connection, reservation.action_ref)
            if (
                isinstance(candidate, WorkExecutionState)
                and candidate.work_id == work.work_id
                and isinstance(action, ActionRequest)
                and action.action_type == ActionType.REGISTER_WORK
            ):
                matches.append((reservation.budget_binding_ref, action))
        if len(matches) != 1:
            raise ValueError("WORK_REGISTRATION_SCOPE_MISSING")
        return matches[0]

    def _start_action(
        self, work: WorkExecutionState, registration: ActionRequest
    ) -> ActionRequest:
        return ActionRequest.model_validate_json(
            canonical_bytes(
                {
                    "meta": fresh_meta(
                        work.meta, "action_request", self.works.clock, self.works.ids
                    ),
                    "action_id": self.works.ids.new(ActionId),
                    "requested_by": registration.requested_by,
                    "requester_identity_ref": registration.requester_identity_ref,
                    "action_type": ActionType.START_ATTEMPT,
                    "work_ref": reference(work),
                    "expected_state_version": work.state_version,
                    "expected_verification_generation": None,
                    "generation_restart_reason": None,
                    "generation_restart_basis_refs": (),
                    "input_refs": work.input_refs,
                    "dynamic_request_ref": None,
                    "reproduction_plan_ref": None,
                    "result_kind": None,
                    "candidate_result_ref": None,
                    "llm_call_spec_ref": None,
                    "tool_name": None,
                    "file_paths": (),
                    "provider_profile_ref": None,
                    "session_mode": None,
                    "sandbox_profile_ref": None,
                    "resource_profile_ref": None,
                    "run_policy_state_ref": None,
                    "image_digest": None,
                    "network_targets": (),
                    "resource_limits": None,
                    "reason": "Claim exact READY work",
                    "requested_at": self.works.clock.now(),
                }
            )
        )

    def _start_transition(
        self,
        work: WorkExecutionState,
        decision: ActionDecision,
        attempt_id: AttemptId,
    ) -> StateTransition:
        return StateTransition.model_validate_json(
            canonical_bytes(
                {
                    "meta": self._attempt_meta(
                        work.meta, "state_transition", attempt_id
                    ),
                    "transition_id": self.works.ids.new(TransitionId),
                    "work_id": work.work_id,
                    "action_decision_ref": reference(decision),
                    "from_status": "READY",
                    "to_status": "RUNNING",
                    "expected_state_version": work.state_version,
                    "new_state_version": work.state_version + 1,
                    "attempt_id": attempt_id,
                    "cause": "STARTED",
                    "output_refs": (),
                    "gap_ids": (),
                    "error_ids": (),
                    "dedupe_key": content_hash(
                        [work.work_id, work.state_version, "RUNNING", attempt_id]
                    ),
                    "created_at": self.works.clock.now(),
                }
            )
        )

    def _attempt_meta(
        self, source: RecordMetadata, kind: str, attempt_id: AttemptId
    ) -> RecordMetadata:
        fields: dict[str, object] = {}
        if isinstance(source, RecordMeta):
            fields["attempt_id"] = attempt_id
        return fresh_meta(source, kind, self.works.clock, self.works.ids, **fields)


__all__ = ["WorkDispatchStore"]
