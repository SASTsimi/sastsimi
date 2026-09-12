"""Read-only SQLite projections for production status and terminal results."""

from __future__ import annotations

from collections import Counter

from sqlalchemy import select

from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.refs import reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.scheduler import AnalysisStatusView

from . import models
from .database import Database
from .repositories import SQLiteRecordStore
from .run_control import cancel_latched
from .run_states import get_run


class SQLiteProductionQuery:
    """Read current durable state without activating providers or workers."""

    def __init__(self, database: Database) -> None:
        database.check_ready()
        self._database = database
        self._records = SQLiteRecordStore(database)

    def status(self, analysis_id: str) -> AnalysisStatusView:
        if not analysis_id:
            raise ValueError("ANALYSIS_ID_REQUIRED")
        with self._database.engine.connect() as connection:
            state = get_run(connection, analysis_id)
            works = tuple(
                WorkExecutionState.model_validate_json(payload)
                for payload in connection.execute(
                    select(models.work_states.c.payload)
                    .where(models.work_states.c.analysis_id == analysis_id)
                    .order_by(models.work_states.c.work_id)
                ).scalars()
            )
            cancelled = cancel_latched(connection, analysis_id)
        counts = Counter(
            f"{item.work_type.value}:{item.status.value}" for item in works
        )
        run_status: str = state.status
        if state.status == "RUNNING":
            active = any(item.status in {"READY", "RUNNING"} for item in works)
            blocked = any(item.status == "BLOCKED" for item in works)
            if cancelled:
                run_status = "CANCELLING"
            elif blocked and not active:
                run_status = "BLOCKED"
        return AnalysisStatusView(
            analysis_id=analysis_id,
            run_status=run_status,
            work_counts=tuple(sorted(counts.items())),
            cancel_requested=cancelled,
            waiting_for=tuple(
                sorted({reason.value for item in works for reason in item.waiting_for})
            ),
            result_ref=state.analysis_result_ref,
        )

    def result(self, analysis_id: str) -> AnalysisRunResult:
        if not analysis_id:
            raise ValueError("ANALYSIS_ID_REQUIRED")
        with self._database.engine.connect() as connection:
            state = get_run(connection, analysis_id)
        if state.status == "RUNNING" or state.analysis_result_ref is None:
            raise ValueError("RESULT_NOT_TERMINAL")
        result = self._records.get_exact(state.analysis_result_ref)
        if (
            not isinstance(result, AnalysisRunResult)
            or reference(result) != state.analysis_result_ref
            or str(result.meta.analysis_id) != analysis_id
            or result.status != state.status
        ):
            raise ValueError("ANALYSIS_RESULT_EXACT_REF_MISMATCH")
        return result


__all__ = ["SQLiteProductionQuery"]
