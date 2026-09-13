"""Durable operator controls that never construct the execution graph."""

from pathlib import Path
from typing import NoReturn

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.ports.scheduler import AnalysisStatusView
from sastsimi.runtime.system_support import SystemClock
from sastsimi.storage.database import Database
from sastsimi.storage.production_query import SQLiteProductionQuery
from sastsimi.storage.run_control import RunControlStore


def request_production_cancel(data_dir: Path, analysis_id: str) -> AnalysisStatusView:
    """Commit intent before parsing run metadata or inspecting external targets.

    A running owner observes the latch. This command does not claim quiescence
    or activate providers to stop resources after an owner process has exited.
    """
    path = RuntimePaths(data_dir).database
    if not path.is_file():
        raise ValueError("ANALYSIS_NOT_FOUND")
    database = Database(path)
    try:
        RunControlStore(database, SystemClock()).request_cancel(
            analysis_id, "OPERATOR_REQUEST"
        )
        return SQLiteProductionQuery(database).status(analysis_id)
    finally:
        database.engine.dispose()


class ProductionResumeUnavailable(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def inspect_production_resume(data_dir: Path, analysis_id: str) -> NoReturn:
    """Read eligibility only; execution remains explicitly unavailable."""
    import re

    from sastsimi.composition.production_entrypoint import builtin_resource_root
    from sastsimi.orchestration.production_descriptor import load_production_descriptor
    from sastsimi.orchestration.production_onboarding import (
        ProductionOnboardingUnavailable,
    )
    from sastsimi.storage.artifact_store import LocalArtifactStore
    from sastsimi.storage.production_authority import ProductionAuthorityInspector
    from sastsimi.storage.repositories import SQLiteRecordStore
    from sastsimi.storage.run_states import get_run

    path = RuntimePaths(data_dir).database
    if not path.is_file():
        raise ProductionResumeUnavailable("PRODUCTION_RUN_NOT_FOUND")
    database = Database(path)
    try:
        database.check_ready()
        records = SQLiteRecordStore(database)
        with database.engine.connect() as connection:
            state = get_run(connection, analysis_id)
        if str(state.meta.analysis_id) != analysis_id:
            raise ValueError("PRODUCTION_DESCRIPTOR_SCOPE_MISMATCH")
        if state.status != "RUNNING" or RunControlStore(
            database, SystemClock()
        ).cancel_requested(analysis_id):
            raise ValueError("RUN_NOT_RESUMABLE")
        artifacts = LocalArtifactStore(RuntimePaths(data_dir).artifacts, None, None)
        now = SystemClock().now()
        load_production_descriptor(
            state=state,
            records=records,
            artifacts=artifacts,
            repository_root=builtin_resource_root(),
            now=now,
        )
        ProductionAuthorityInspector(records, artifacts).inspect(
            analysis_id, now=now, expected_state=state
        )
        _inspect_work_eligibility(database, analysis_id)
    except (ValueError, LookupError, OSError, ProductionOnboardingUnavailable) as error:
        reason = str(error)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", reason) is None:
            reason = "PRODUCTION_RESUME_INPUT_INVALID"
        raise ProductionResumeUnavailable(reason) from None
    finally:
        database.engine.dispose()
    raise ProductionResumeUnavailable("PRODUCTION_RESUME_DISPATCH_NOT_AVAILABLE")


def _inspect_work_eligibility(database: Database, analysis_id: str) -> None:
    from sqlalchemy import select

    from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
    from sastsimi.runtime.system_support import UUIDIds
    from sastsimi.storage import models
    from sastsimi.storage.budget_registry import BudgetProfileRegistry
    from sastsimi.storage.budget_service import BudgetService
    from sastsimi.storage.dispatches import reject_uncertain
    from sastsimi.storage.repositories import SQLiteRecordStore
    from sastsimi.storage.run_states import get_run

    with database.engine.connect() as connection:
        works = tuple(
            WorkExecutionState.model_validate_json(payload)
            for payload in connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.analysis_id == analysis_id
                )
            ).scalars()
        )
        if any(item.status in {"PENDING", "READY", "RUNNING"} for item in works):
            raise ValueError("RUN_NOT_QUIESCENT")
        blocked = tuple(item for item in works if item.status == "BLOCKED")
        if not blocked:
            raise ValueError("RUN_NOT_RESUMABLE")
        for item in works:
            if str(item.meta.analysis_id) != analysis_id:
                raise ValueError("PRODUCTION_DESCRIPTOR_SCOPE_MISMATCH")
            reject_uncertain(connection, str(item.work_id))
            if connection.execute(
                select(models.transition_commits.c.transition_commit_id).where(
                    models.transition_commits.c.work_id == str(item.work_id),
                    models.transition_commits.c.state == "PREPARED",
                )
            ).first():
                raise ValueError("PRODUCTION_RESUME_RECOVERY_REQUIRED")
        for item in blocked:
            payload = connection.execute(
                select(models.work_attempts.c.payload)
                .where(models.work_attempts.c.work_id == str(item.work_id))
                .order_by(models.work_attempts.c.attempt_number.desc())
                .limit(1)
            ).scalar()
            if payload is None:
                raise ValueError("RESUME_ATTEMPT_HISTORY_REQUIRED")
            previous = WorkAttempt.model_validate_json(payload)
            if (
                previous.meta.analysis_id != item.meta.analysis_id
                or previous.work_id != item.work_id
                or previous.status == "RUNNING"
                or previous.input_hash != item.input_hash
            ):
                raise ValueError("RESUME_INPUT_CHANGED")
        records = SQLiteRecordStore(database)
        clock = SystemClock()
        ids = UUIDIds()
        budgets = BudgetService(
            records, BudgetProfileRegistry(records, clock, ids), clock, ids
        )
        state = get_run(connection, analysis_id)
        available = budgets.available(
            connection, state.execution_budget_profile_ref, analysis_id
        )
        if (
            available.available_units.retry_count < len(blocked)
            or available.available_units.elapsed_ms == 0
        ):
            raise ValueError("PRODUCTION_RESUME_BUDGET_EXHAUSTED")
