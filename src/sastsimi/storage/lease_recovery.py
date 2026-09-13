"""Attempt-local uncertainty and atomic release of proven unperformed effects."""

from sqlalchemy import Connection, select, update

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.budget import BudgetReservation, ReservationStatus
from sastsimi.contracts.work import WorkExecutionState

from . import models
from .budget_limits import EXTERNAL_ACTIONS
from .budget_service import BudgetService
from .codec import reference
from .records import next_meta


def uncertain(connection: Connection, work: WorkExecutionState) -> bool:
    """Return whether any attempt of this work has an unresolved side effect.

    An outcome that arrives after its attempt was replaced is still uncertain;
    treating it as unrelated would allow the replacement attempt to resend the
    same operation.  Recovery therefore isolates unresolved dispatches by work,
    while publication continues to require the exact active attempt elsewhere.
    """
    table = models.external_dispatches
    return (
        connection.execute(
            select(table.c.action_id).where(
                table.c.work_id == str(work.work_id),
                table.c.dispatched_at.is_not(None),
                table.c.returned_at.is_(None),
                table.c.reconciled_at.is_(None),
            )
        ).first()
        is not None
    )


def retire_undispatched(
    connection: Connection, budget: BudgetService, work: WorkExecutionState
) -> None:
    records = budget.records
    for row in connection.execute(
        select(models.budget_reservations).where(
            models.budget_reservations.c.analysis_id == str(work.meta.analysis_id),
            models.budget_reservations.c.status == "RESERVED",
        )
    ).mappings():
        reservation = BudgetReservation.model_validate_json(row["payload"])
        if reservation.work_ref != reference(work):
            continue
        action = records.resolve(connection, reservation.action_ref)
        if (
            not isinstance(action, ActionRequest)
            or action.action_type not in EXTERNAL_ACTIONS
        ):
            continue
        dispatch = (
            connection.execute(
                select(models.external_dispatches).where(
                    models.external_dispatches.c.action_id == str(action.action_id),
                )
            )
            .mappings()
            .first()
        )
        if dispatch is not None and (
            dispatch["dispatched_at"] is not None
            or dispatch["attempt_id"] != str(work.active_attempt_id)
        ):
            continue
        released = BudgetReservation.model_validate(
            reservation.model_dump()
            | dict(
                meta=next_meta(reservation.meta, budget.clock, budget.ids),
                status=ReservationStatus.RELEASED,
                finalized_at=budget.clock.now(),
            )
        )
        budget.finalize(connection, reservation, released)
        connection.execute(
            update(models.budget_reservations)
            .where(
                models.budget_reservations.c.reservation_id
                == str(reservation.reservation_id)
            )
            .values(claimed=0)
        )
        if dispatch is not None:
            connection.execute(
                update(models.external_dispatches)
                .where(models.external_dispatches.c.action_id == str(action.action_id))
                .values(reconciled_at=budget.clock.now().isoformat())
            )
