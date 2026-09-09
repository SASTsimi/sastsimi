from pathlib import Path

import pytest

from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import MigrationRequired, upgrade
from tests.integration.runtime_support import TestClock, TestIds


def test_runtime_composition_requires_explicit_migration_and_runs_recovery(
    tmp_path: Path,
) -> None:
    from sastsimi.bootstrap import build_runtime

    with pytest.raises(MigrationRequired):
        build_runtime(
            tmp_path, WorkspaceId("w1"), CommitId("c1"), TestClock(), TestIds()
        )
    upgrade(Database(tmp_path / "db" / "sastsimi.sqlite3"))
    runtime = build_runtime(
        tmp_path, WorkspaceId("w1"), CommitId("c1"), TestClock(), TestIds()
    )
    assert runtime.recovery.recover().checked_artifacts == 0
    assert runtime.recovery.recover().blocked_work == 0
