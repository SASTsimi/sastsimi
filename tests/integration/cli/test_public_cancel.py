"""Public cancellation must latch even when restart metadata cannot be read."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import update

from sastsimi.storage import models
from sastsimi.storage.budget_registry import BudgetProfileRegistry
from sastsimi.storage.run_control import RunControlStore
from tests.integration.runtime_support import Harness


@pytest.mark.parametrize("corrupt", [False, True])
def test_second_process_cancel_latches_legacy_or_corrupt_run(
    tmp_path: Path, corrupt: bool
) -> None:
    harness = Harness(tmp_path)
    registry = BudgetProfileRegistry(harness.records, harness.clock, harness.ids)
    harness.pin_execution(registry, harness.execution())
    if corrupt:
        with harness.database.write() as connection:
            connection.execute(
                update(models.analysis_runs)
                .where(models.analysis_runs.c.analysis_id == "a1")
                .values(payload="corrupt-private-value")
            )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sastsimi",
            "--data-dir",
            str(tmp_path),
            "cancel",
            "a1",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert RunControlStore(harness.database, harness.clock).cancel_requested("a1")
    assert result.returncode == (9 if corrupt else 0)
    wire = result.stderr if corrupt else result.stdout
    output = json.loads(wire)
    if not corrupt:
        assert output["data"] == {
            "analysis_id": "a1",
            "status": "CANCELLING",
            "cancel_requested": True,
        }
    assert "corrupt-private-value" not in wire
    assert str(tmp_path) not in wire
