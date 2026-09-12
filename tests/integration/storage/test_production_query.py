from pathlib import Path

import pytest

from sastsimi.storage.budget_registry import BudgetProfileRegistry
from sastsimi.storage.production_query import SQLiteProductionQuery
from tests.integration.runtime_support import Harness


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
