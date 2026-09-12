from pathlib import Path

import pytest

from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AnalysisId, CommitId, WorkspaceId
from sastsimi.storage import models
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade
from tests.contract.domain.canonical_fixtures import make


def _store_ready_state(database: Database) -> None:
    raw = make("AnalysisRunState")
    raw["analysis_input_ref"]["data_kind"] = "analysis_run_input"
    state = AnalysisRunState.model_validate_json(
        canonical_bytes(
            raw
            | {
                "workspace_id": "workspace-current",
                "commit_id": "a" * 40,
                "status": "RUNNING",
                "finished_at": None,
                "analysis_result_ref": None,
            }
        )
    )
    with database.write() as connection:
        connection.execute(
            models.analysis_runs.insert().values(
                analysis_id="a1", payload=state.model_dump_json()
            )
        )


def test_locates_exact_current_run_scope_from_sqlite(tmp_path: Path) -> None:
    from sastsimi.orchestration.run_scope_locator import RunScopeLocator

    database = Database(tmp_path / "runtime.sqlite3")
    upgrade(database)
    _store_ready_state(database)

    scope = RunScopeLocator(database).locate("a1")

    assert scope.analysis_id == AnalysisId("a1")
    assert scope.workspace_id == WorkspaceId("workspace-current")
    assert scope.commit_id == CommitId("a" * 40)


def test_rejects_stale_expected_run_scope(tmp_path: Path) -> None:
    from sastsimi.orchestration.run_scope_locator import RunScopeError, RunScopeLocator

    database = Database(tmp_path / "runtime.sqlite3")
    upgrade(database)
    _store_ready_state(database)

    with pytest.raises(RunScopeError, match="RUN_SCOPE_STALE"):
        RunScopeLocator(database).locate(
            "a1",
            expected_workspace_id=WorkspaceId("workspace-previous"),
            expected_commit_id=CommitId("b" * 40),
        )
