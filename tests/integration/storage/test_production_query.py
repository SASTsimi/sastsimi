import json
from pathlib import Path

import pytest
from sqlalchemy import insert

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.storage import models
from sastsimi.storage.budget_registry import BudgetProfileRegistry
from sastsimi.storage.production_query import SQLiteProductionQuery
from tests.integration.runtime_support import Harness
from tests.unit.contracts.test_core_models import ref, work


def test_production_query_reads_durable_run_without_starting_workers(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path)
    registry = BudgetProfileRegistry(harness.records, harness.clock, harness.ids)
    harness.pin_execution(registry, harness.execution())

    query = SQLiteProductionQuery(harness.database)
    status = query.status("a1")

    assert status.analysis_id == "a1"
    assert status.run_status == "RUNNING"
    assert status.work_counts == ()
    assert status.cancel_requested is False
    with pytest.raises(ValueError, match="RESULT_NOT_TERMINAL"):
        query.result("a1")


def test_production_query_exposes_safe_structured_failure_detail(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path)
    registry = BudgetProfileRegistry(harness.records, harness.clock, harness.ids)
    harness.pin_execution(registry, harness.execution())
    blocked = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                work_id="blocked-1",
                status="BLOCKED",
                state_version=2,
                last_transition_ref=ref("state_transition"),
                waiting_for=["AUTH"],
                stop_reason="SANDBOX_CAPABILITY_MISSING",
                started_at="2026-09-07T00:00:00Z",
            )
        )
    )
    with harness.database.write() as connection:
        connection.execute(
            insert(models.work_states).values(
                work_id=str(blocked.work_id),
                analysis_id="a1",
                registration_key="blocked-registration",
                status=blocked.status.value,
                state_version=blocked.state_version,
                active_attempt_id=None,
                payload=canonical_bytes(blocked).decode(),
                worker_id=None,
                lease_expires_at=None,
            )
        )

    view = SQLiteProductionQuery(harness.database).status("a1")

    assert len(view.failures) == 1
    assert view.failures[0].work_id == "blocked-1"
    assert view.failures[0].stop_reason == "SANDBOX_CAPABILITY_MISSING"
    assert view.failures[0].waiting_for == ("AUTH",)
