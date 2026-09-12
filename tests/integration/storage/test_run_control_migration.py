from pathlib import Path

from alembic.script import ScriptDirectory
from sqlalchemy import insert, inspect

from sastsimi.storage import models
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import config, upgrade
from sastsimi.storage.run_control import RunControlStore
from tests.integration.runtime_support import TestClock


def test_run_control_migration_and_cancel_latch_are_durable(tmp_path: Path) -> None:
    database = Database(tmp_path / "runtime.db")
    upgrade(database)

    columns = {
        item["name"] for item in inspect(database.engine).get_columns("run_controls")
    }
    assert columns == {
        "analysis_id",
        "cancel_requested_at",
        "cancel_reason",
        "quiescent_at",
    }
    assert ScriptDirectory.from_config(config(database)).get_heads() == [
        "0006_run_control"
    ]
    with database.write() as connection:
        connection.execute(
            insert(models.analysis_runs).values(analysis_id="analysis-1", payload="{}")
        )

    controls = RunControlStore(database, TestClock())
    assert controls.cancel_requested("analysis-1") is False
    controls.request_cancel("analysis-1", "OPERATOR_REQUEST")
    assert controls.cancel_requested("analysis-1") is True
    controls.mark_quiescent("analysis-1")
    assert controls.cancel_requested("analysis-1") is True
