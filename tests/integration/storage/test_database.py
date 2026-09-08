from pathlib import Path

import pytest
from sqlalchemy import text


def test_pending_migration_blocks_startup_and_upgrade_sets_every_connection(
    tmp_path: Path,
) -> None:
    from sastsimi.storage.database import Database
    from sastsimi.storage.migrations import MigrationRequired, upgrade

    database = Database(tmp_path / "runtime.sqlite3")
    with pytest.raises(MigrationRequired):
        database.check_ready()
    upgrade(database)
    database.check_ready()
    for _ in range(2):
        with database.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
            assert connection.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
            assert connection.exec_driver_sql("PRAGMA synchronous").scalar() == 2
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar() == 5000


def test_empty_downgrade_reupgrade_and_lossy_downgrade_refusal(tmp_path: Path) -> None:
    from sastsimi.storage.database import Database
    from sastsimi.storage.migrations import downgrade, upgrade

    database = Database(tmp_path / "runtime.sqlite3")
    upgrade(database)
    downgrade(database)
    upgrade(database)
    with database.write() as connection:
        connection.execute(
            text("INSERT INTO analysis_runs (analysis_id, payload) VALUES ('a', '{}')")
        )
    with pytest.raises(ValueError, match="backup"):
        downgrade(database)
    database.check_ready()
    with database.engine.connect() as connection:
        assert (
            connection.execute(text("SELECT analysis_id FROM analysis_runs")).scalar()
            == "a"
        )


def test_failed_write_rolls_back_and_unknown_revision_fails_closed(
    tmp_path: Path,
) -> None:
    from sastsimi.storage.database import Database
    from sastsimi.storage.migrations import MigrationRequired, upgrade

    database = Database(tmp_path / "runtime.sqlite3")
    upgrade(database)
    with pytest.raises(RuntimeError), database.write() as connection:
        connection.execute(text("INSERT INTO analysis_runs VALUES ('a', '{}')"))
        raise RuntimeError("crash")
    with database.engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM analysis_runs")).scalar() == 0
        )
    with database.write() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num='unknown'"))
    with pytest.raises(MigrationRequired):
        database.check_ready()
