"""Durable operator controls that never construct the execution graph."""

from pathlib import Path

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
