"""SQLite-backed durable cancellation latch for one analysis run."""

from __future__ import annotations

import re

from sqlalchemy import Connection, insert, select, update

from sastsimi.ports.clock import Clock
from sastsimi.ports.scheduler import CancellationTarget

from . import models
from .database import Database

_SAFE_REASON = re.compile(r"[A-Z0-9_]{1,64}\Z")


class RunControlStore:
    def __init__(self, database: Database, clock: Clock) -> None:
        self._database = database
        self._clock = clock

    def request_cancel(self, analysis_id: str, reason: str) -> None:
        if not analysis_id or _SAFE_REASON.fullmatch(reason) is None:
            raise ValueError("RUN_CONTROL_INPUT_INVALID")
        with self._database.write() as connection:
            exists = connection.execute(
                select(models.run_controls.c.analysis_id).where(
                    models.run_controls.c.analysis_id == analysis_id
                )
            ).scalar_one_or_none()
            if exists is None:
                connection.execute(
                    insert(models.run_controls).values(
                        analysis_id=analysis_id,
                        cancel_requested_at=self._clock.now().isoformat(),
                        cancel_reason=reason,
                        quiescent_at=None,
                    )
                )

    def cancel_requested(self, analysis_id: str) -> bool:
        if not analysis_id:
            raise ValueError("RUN_CONTROL_INPUT_INVALID")
        with self._database.engine.connect() as connection:
            return cancel_latched(connection, analysis_id)

    def cancellation_targets(self, analysis_id: str) -> tuple[CancellationTarget, ...]:
        if not analysis_id:
            raise ValueError("RUN_CONTROL_INPUT_INVALID")
        from .cancellation_targets import CancellationTargetStore

        return CancellationTargetStore(self._database).cancellation_targets(analysis_id)

    def mark_quiescent(self, analysis_id: str) -> None:
        if not analysis_id:
            raise ValueError("RUN_CONTROL_INPUT_INVALID")
        with self._database.write() as connection:
            result = connection.execute(
                update(models.run_controls)
                .where(models.run_controls.c.analysis_id == analysis_id)
                .values(quiescent_at=self._clock.now().isoformat())
            )
            if result.rowcount != 1:
                raise LookupError("RUN_CONTROL_NOT_FOUND")


def cancel_latched(connection: Connection, analysis_id: str) -> bool:
    """Read the durable latch on the caller's transaction snapshot."""
    return (
        connection.execute(
            select(models.run_controls.c.analysis_id).where(
                models.run_controls.c.analysis_id == analysis_id
            )
        ).scalar_one_or_none()
        is not None
    )


def reject_cancelled(connection: Connection, analysis_id: str) -> None:
    if cancel_latched(connection, analysis_id):
        raise ValueError("RUN_CANCELLED")


__all__ = ["RunControlStore", "cancel_latched", "reject_cancelled"]
