"""Exact run-local state and immutable CAS revisions."""

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.records import validate_revision

from . import models
from .codec import encode, reference
from .repositories import SQLiteRecordStore


def get_run(connection: Connection, analysis_id: str) -> AnalysisRunState:
    payload = connection.execute(
        select(models.analysis_runs.c.payload).where(
            models.analysis_runs.c.analysis_id == analysis_id
        )
    ).scalar()
    if payload is None:
        raise ValueError("BUDGET run state is unavailable")
    return AnalysisRunState.model_validate_json(payload)


def save_run(
    records: SQLiteRecordStore,
    connection: Connection,
    state: AnalysisRunState,
    previous: AnalysisRunState | None = None,
) -> None:
    if previous is not None:
        validate_revision(previous.meta, state.meta)
        for name in (
            "purpose",
            "eval_config_refs",
            "program_id",
            "execution_budget_profile_ref",
        ):
            if getattr(previous, name) != getattr(state, name):
                raise ValueError("RUN_STATE_IMMUTABLE")
        for name in ("workspace_id", "commit_id", "budget_binding_ref"):
            if getattr(previous, name) is not None and getattr(
                previous, name
            ) != getattr(state, name):
                raise ValueError("RUN_STATE_IMMUTABLE")
    records.publish(connection, records.stage(connection, state))
    if previous is None:
        connection.execute(
            insert(models.analysis_runs).values(
                analysis_id=str(state.meta.analysis_id), payload=encode(state)
            )
        )
        connection.execute(
            insert(models.current_records).values(
                logical_record_id=str(state.meta.logical_record_id),
                record_id=str(state.meta.record_id),
                state_version=state.meta.revision_number,
            )
        )
    else:
        changed = connection.execute(
            update(models.analysis_runs)
            .where(
                models.analysis_runs.c.analysis_id == str(state.meta.analysis_id),
                models.analysis_runs.c.payload == encode(previous),
            )
            .values(payload=encode(state))
        )
        if changed.rowcount != 1:
            raise ValueError("STATE_VERSION_CONFLICT: analysis")
        changed = connection.execute(
            update(models.current_records)
            .where(
                models.current_records.c.logical_record_id
                == str(state.meta.logical_record_id),
                models.current_records.c.record_id
                == str(reference(previous).record_id),
            )
            .values(
                record_id=str(state.meta.record_id),
                state_version=state.meta.revision_number,
            )
        )
        if changed.rowcount != 1:
            raise ValueError("STATE_VERSION_CONFLICT: analysis pointer")
