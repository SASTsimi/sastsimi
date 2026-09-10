"""Applicable Verification and dynamic caps within the reservation transaction."""

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionRequest, ActionType
from sastsimi.contracts.budget import (
    BudgetLedgerEntry,
    BudgetProfileBinding,
    BudgetReservation,
    BudgetUnits,
    DynamicReproductionLifecycleProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
    select_work_limit,
)
from sastsimi.contracts.work import WorkExecutionState, WorkType

from . import models
from .budget_limits import EXTERNAL_ACTIONS, operation
from .repositories import SQLiteRecordStore


def verification_root(
    records: SQLiteRecordStore, connection: Connection, work: WorkExecutionState
) -> str | None:
    seen = set()
    while work.work_id not in seen:
        seen.add(work.work_id)
        if work.work_type == WorkType.VERIFICATION:
            return str(work.work_id)
        if work.parent_work_ref is None:
            return None
        parent = records.resolve(connection, work.parent_work_ref)
        if not isinstance(parent, WorkExecutionState):
            raise ValueError("BUDGET invalid verification ancestor")
        work = parent
    raise ValueError("BUDGET cyclic work ancestry")


def check_hierarchy(
    records: SQLiteRecordStore,
    connection: Connection,
    reservation: BudgetReservation,
    work: WorkExecutionState,
    action: ActionRequest,
    binding: BudgetProfileBinding,
) -> None:
    root = verification_root(records, connection, work)
    profile = records.resolve(connection, binding.verification_budget_profile_ref)
    dynamic = records.resolve(connection, binding.dynamic_lifecycle_profile_ref)
    assert isinstance(profile, VerificationBudgetProfile)
    assert isinstance(dynamic, DynamicReproductionLifecycleProfile)
    scope_units: list[BudgetUnits] = [reservation.requested_units]
    work_units: list[BudgetUnits] = [reservation.requested_units]
    attempts = 1 if action.action_type == ActionType.START_ATTEMPT else 0
    evidence_calls = (
        1
        if work.work_type in {WorkType.PRO_EVIDENCE, WorkType.CON_EVIDENCE}
        and action.action_type in EXTERNAL_ACTIONS
        else 0
    )
    for payload in connection.execute(
        select(models.budget_reservations.c.payload).where(
            models.budget_reservations.c.analysis_id == str(work.meta.analysis_id),
            models.budget_reservations.c.status != "RELEASED",
        )
    ).scalars():
        other = BudgetReservation.model_validate_json(payload)
        if other.reservation_id == reservation.reservation_id:
            continue
        other_work = records.resolve(connection, other.work_ref, candidate=True)
        assert isinstance(other_work, WorkExecutionState)
        other_action = records.resolve(connection, other.action_ref)
        if (
            evidence_calls
            and other.status.value == "RESERVED"
            and other_work.work_type in {WorkType.PRO_EVIDENCE, WorkType.CON_EVIDENCE}
            and verification_root(records, connection, other_work) == root
            and isinstance(other_action, ActionRequest)
            and other_action.action_type in EXTERNAL_ACTIONS
        ):
            evidence_calls += 1
        units = other.requested_units
        if other.ledger_entry_ref is not None:
            entry = records.resolve(connection, other.ledger_entry_ref)
            assert isinstance(entry, BudgetLedgerEntry)
            units = entry.actual_units
        if (
            root is not None
            and verification_root(records, connection, other_work) == root
        ):
            scope_units.append(units)
        if other_work.work_id == work.work_id:
            work_units.append(units)
            other_action = records.resolve(connection, other.action_ref)
            if (
                isinstance(other_action, ActionRequest)
                and other_action.action_type == ActionType.START_ATTEMPT
            ):
                attempts += 1
    if root is not None:
        for name, maximum in (
            ("work_count", profile.max_work_per_verification),
            ("elapsed_ms", profile.max_verification_elapsed_ms),
            ("llm_call_count", profile.max_llm_calls_per_verification),
        ):
            if sum(getattr(units, name) for units in scope_units) > maximum:
                raise ValueError("BUDGET_EXCEEDED: Verification " + name)
        if (
            sum(units.retry_count for units in work_units)
            > profile.max_retries_per_work
        ):
            raise ValueError("BUDGET_EXCEEDED: retries per work")
    if evidence_calls > profile.max_parallel_evidence_calls:
        raise ValueError("BUDGET_EXCEEDED: parallel evidence calls")
    if (
        work.work_type == WorkType.DYNAMIC_REPRO
        and attempts > dynamic.max_new_attempts + 1
    ):
        raise ValueError("BUDGET_EXCEEDED: dynamic attempts")
    if work.work_type == WorkType.DYNAMIC_REPRO:
        preflight = records.resolve(connection, dynamic.preflight_budget_ref)
        if (
            not isinstance(preflight, WorkBudgetProfile)
            or dynamic.preflight_budget_ref != binding.work_budget_profile_ref
            or dynamic.preflight_budget_source != "WORK_REMAINING_TIME"
        ):
            raise ValueError(
                "BLOCKED waiting_for=BUDGET: preflight evidence unavailable"
            )
        kind, role = operation(work.work_type, action)
        work_maximum = select_work_limit(
            preflight, work.work_type, kind, role
        ).timeout_ms
        if work_maximum is None:
            raise ValueError("BLOCKED waiting_for=BUDGET: work timeout unavailable")
        previous_elapsed = sum(units.elapsed_ms for units in work_units[1:])
        if (
            previous_elapsed >= work_maximum
            or reservation.requested_units.elapsed_ms > work_maximum - previous_elapsed
        ):
            raise ValueError("BUDGET_EXCEEDED: dynamic remaining time")
