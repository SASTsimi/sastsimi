"""Durable side-effect boundary. Unknown dispatches never authorize retransmit."""

from sqlalchemy import Connection, select, update

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import RecordRef
from sastsimi.ports.clock import Clock

from . import models
from .repositories import SQLiteRecordStore


def reject_uncertain(connection: Connection, work_id: str) -> None:
    if connection.execute(
        select(models.external_dispatches.c.action_id).where(
            models.external_dispatches.c.work_id == work_id,
            models.external_dispatches.c.dispatched_at.is_not(None),
            models.external_dispatches.c.returned_at.is_(None),
            models.external_dispatches.c.reconciled_at.is_(None),
        )
    ).first():
        raise ValueError(
            "BLOCKED waiting_for=INPUT: external request outcome is unknown"
        )


def mark_dispatched(
    records: SQLiteRecordStore,
    clock: Clock,
    decision_ref: RecordRef,
    provider_request_id: str | None,
    idempotency_key: str | None,
) -> None:
    with records.database.write() as connection:
        table = models.external_dispatches
        row = (
            connection.execute(
                select(table).where(
                    table.c.decision_ref == canonical_bytes(decision_ref).decode()
                )
            )
            .mappings()
            .one()
        )
        reject_uncertain(connection, row["work_id"])
        active = connection.execute(
            select(models.work_states.c.active_attempt_id).where(
                models.work_states.c.work_id == row["work_id"],
                models.work_states.c.status == "RUNNING",
            )
        ).scalar()
        if active != row["attempt_id"]:
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        result = connection.execute(
            update(table)
            .where(
                table.c.action_id == row["action_id"], table.c.dispatched_at.is_(None)
            )
            .values(
                dispatched_at=clock.now().isoformat(),
                provider_request_id=provider_request_id,
                idempotency_key=idempotency_key,
            )
        )
        if result.rowcount != 1:
            raise ValueError("ACTION_ALREADY_USED")


def mark_returned(
    records: SQLiteRecordStore, clock: Clock, decision_ref: RecordRef
) -> None:
    with records.database.write() as connection:
        result = connection.execute(
            update(models.external_dispatches)
            .where(
                models.external_dispatches.c.decision_ref
                == canonical_bytes(decision_ref).decode(),
                models.external_dispatches.c.dispatched_at.is_not(None),
                models.external_dispatches.c.returned_at.is_(None),
            )
            .values(returned_at=clock.now().isoformat())
        )
        if result.rowcount != 1:
            raise ValueError("EXTERNAL_DISPATCH_MISMATCH")
