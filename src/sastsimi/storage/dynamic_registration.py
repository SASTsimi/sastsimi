"""Atomic REQUEST_DYNAMIC_REPRO claim, one child work and current state."""

from collections.abc import Callable

from sqlalchemy import insert, select

from sastsimi.contracts.actions import ActionDecision, ActionRequest, ActionType
from sastsimi.contracts.budget import BudgetLedgerEntry, BudgetReservation, BudgetUnits
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionState,
)
from sastsimi.contracts.ids import LedgerEntryId, WorkId
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import WorkExecutionState, validate_parent_work
from sastsimi.ports.dto import BudgetCommitRequest

from . import models
from .action_context import check_owner, current_process
from .action_policy import check_role
from .codec import REF_ADAPTER, encode, reference
from .dynamic_state import current_dynamic
from .intermediate_policy import prepublished_output
from .records import fresh_meta, next_meta
from .stage_policy import check_stage, current, resolved
from .transition_service import TransitionService


class DynamicRegistrationService:
    def __init__(
        self,
        transitions: TransitionService,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.transitions = transitions
        self.checkpoint = checkpoint or (lambda stage: None)

    def register(
        self, work_id: str, decision_ref: RecordRef, reservation_ref: RecordRef
    ) -> WorkExecutionState:
        works = self.transitions.works
        records = works.records
        with records.database.write() as connection:
            parent = works.get(work_id, connection)
            decision = resolved(records, connection, decision_ref, ActionDecision)
            action = resolved(records, connection, decision.action_ref, ActionRequest)
            if (
                action.action_type != ActionType.REQUEST_DYNAMIC_REPRO
                or action.work_ref != reference(parent)
            ):
                raise ValueError("DYNAMIC_REQUEST_ACTION_MISMATCH")
            check_role(
                action, records.evidence.identity_role(action.requester_identity_ref)
            )
            check_owner(records, connection, action, parent)
            check_stage(records, connection, action, parent)
            request = resolved(
                records,
                connection,
                action.dynamic_request_ref,
                DynamicReproductionRequest,
            )
            request_ref = reference(request)
            current(records, connection, request_ref)
            if (
                request.meta.attempt_id != parent.active_attempt_id
                or not prepublished_output(records, connection, request_ref, parent)
            ):
                raise ValueError("DYNAMIC_REQUEST_OWNER_RECEIPT_REQUIRED")
            process = current_process(records, connection, parent)
            state = current_dynamic(records, connection, parent)
            previous = (
                connection.execute(
                    select(models.action_decisions).where(
                        models.action_decisions.c.action_id == str(action.action_id)
                    )
                )
                .mappings()
                .first()
            )
            if previous is not None:
                issued = connection.execute(
                    select(models.action_requests.c.decision_ref).where(
                        models.action_requests.c.action_id == str(action.action_id)
                    )
                ).scalar_one()
                used = ActionDecision.model_validate_json(previous["payload"])
                outcomes = used.outcome_refs
                if (
                    REF_ADAPTER.validate_json(issued) != decision_ref
                    or used.use_status != "USED"
                    or len(outcomes) != 2
                ):
                    raise ValueError("DYNAMIC_HANDOFF_RECEIPT_MISMATCH")
                child = resolved(records, connection, outcomes[0], WorkExecutionState)
                if child.input_refs != (
                    request_ref,
                ) or child.parent_work_ref != reference(parent):
                    raise ValueError("DYNAMIC_HANDOFF_RECEIPT_MISMATCH")
                reservation = resolved(
                    records, connection, reservation_ref, BudgetReservation
                )
                if reservation.action_ref != reference(action):
                    raise ValueError("DYNAMIC_HANDOFF_RECEIPT_MISMATCH")
                return works.get(str(child.work_id), connection)
            works.validator.check(
                connection,
                decision_ref,
                ActionType.REQUEST_DYNAMIC_REPRO,
                parent,
                reservation_ref,
                needs_budget=True,
            )
            reservation = resolved(
                records, connection, reservation_ref, BudgetReservation
            )
            if (
                reservation.requested_units.work_count != 1
                or state.status != "NOT_REQUESTED"
            ):
                raise ValueError("DYNAMIC_GENERATION_ALREADY_REQUESTED_OR_UNFUNDED")
            if (
                request.verification_assignment_ref
                != process.verification_assignment_ref
            ):
                raise ValueError("DYNAMIC_ASSIGNMENT_MISMATCH")
            child = WorkExecutionState.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=fresh_meta(
                            parent.meta,
                            "work_execution_state",
                            works.clock,
                            works.ids,
                            attempt_id=None,
                        ),
                        work_id=works.ids.new(WorkId),
                        parent_work_ref=reference(parent),
                        work_type="DYNAMIC_REPRO",
                        subject_type="HYPOTHESIS",
                        subject_id=parent.subject_id,
                        work_generation=parent.work_generation,
                        status="PENDING",
                        state_version=1,
                        last_transition_ref=None,
                        last_transition_commit_ref=None,
                        active_attempt_id=None,
                        input_hash=content_hash((request_ref,)),
                        dedupe_key=content_hash([request_ref, parent.work_generation]),
                        trigger_primitive_ref=None,
                        input_refs=(request_ref,),
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
            validate_parent_work(child, parent)
            claimed = works.validator.claim(
                connection,
                decision_ref,
                ActionType.REQUEST_DYNAMIC_REPRO,
                parent,
                reservation_ref,
                needs_budget=True,
            )
            self.checkpoint("claimed")
            child_ref = records.stage(connection, child)
            records.publish(connection, child_ref)
            connection.execute(
                insert(models.work_states).values(
                    work_id=str(child.work_id),
                    analysis_id=str(child.meta.analysis_id),
                    registration_key=content_hash(
                        [
                            child.meta.analysis_id,
                            child.work_type,
                            child.subject_id,
                            child.work_generation,
                            child.dedupe_key,
                        ]
                    ),
                    status="PENDING",
                    state_version=1,
                    active_attempt_id=None,
                    payload=encode(child),
                )
            )
            works.point(connection, child)
            updated = DynamicReproductionState.model_validate(
                state.model_dump()
                | dict(
                    meta=next_meta(state.meta, works.clock, works.ids),
                    status="RUNNING",
                    dynamic_work_ref=child_ref,
                    request_ref=request_ref,
                    started_at=works.clock.now(),
                )
            )
            state_ref = records.stage(connection, updated)
            records.publish(connection, state_ref)
            self.transitions.publish_pointer(connection, state_ref)
            works.validator.record_outcome(connection, claimed, (child_ref, state_ref))
            budget = works.validator.budget
            remaining = budget.available(
                connection, reservation.budget_binding_ref, str(parent.meta.analysis_id)
            )
            entry = BudgetLedgerEntry.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=fresh_meta(
                            reservation.meta,
                            "budget_ledger_entry",
                            works.clock,
                            works.ids,
                        ),
                        ledger_entry_id=works.ids.new(LedgerEntryId),
                        reservation_ref=reservation_ref,
                        budget_binding_ref=reservation.budget_binding_ref,
                        action_ref=reference(action),
                        work_ref=reference(parent),
                        actual_units=BudgetUnits(
                            elapsed_ms=0,
                            work_count=1,
                            llm_call_count=0,
                            retry_count=0,
                            cost_minor_units=0,
                            currency=reservation.requested_units.currency,
                        ),
                        usage_refs=(),
                        sequence=remaining.as_of_sequence + 1,
                        committed_at=works.clock.now(),
                    )
                )
            )
            budget.commit_usage(BudgetCommitRequest(entry), _connection=connection)
            self.checkpoint("before_commit")
        self.checkpoint("committed")
        return child
