from pathlib import Path

from alembic.script import ScriptDirectory
from sqlalchemy import inspect

from sastsimi.interfaces.cli.main import main
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import config


def test_operator_db_upgrade_explicitly_creates_current_schema(tmp_path: Path) -> None:
    assert main(["--data-dir", str(tmp_path), "db", "upgrade", "--format", "json"]) == 0
    database = Database(tmp_path / "db" / "sastsimi.sqlite3")
    database.check_ready()
    assert set(inspect(database.engine).get_table_names()) >= {
        "chaining_match_reservations",
        "chaining_work_pools",
        "chaining_cohorts",
    }
    assert {
        "work_generation",
        "input_hash",
    } <= {
        column["name"]
        for column in inspect(database.engine).get_columns("chaining_work_pools")
    }
    assert ScriptDirectory.from_config(config(database)).get_heads() == [
        "0007_prompt_analysis_scope"
    ]
