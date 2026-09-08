from pathlib import Path

import pytest
from sqlalchemy import event, inspect

from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade


def test_interrupted_migration_does_not_leave_partial_schema(tmp_path: Path) -> None:
    database = Database(tmp_path / "runtime.db")

    def interrupt(
        connection: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        many: bool,
    ) -> None:
        if "CREATE TABLE records" in statement:
            raise RuntimeError("interrupted migration")

    event.listen(database.engine, "before_cursor_execute", interrupt)
    with pytest.raises(RuntimeError, match="interrupted"):
        upgrade(database)
    event.remove(database.engine, "before_cursor_execute", interrupt)
    assert "analysis_runs" not in inspect(database.engine).get_table_names()
    upgrade(database)
    database.check_ready()
