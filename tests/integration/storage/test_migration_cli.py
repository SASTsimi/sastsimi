from pathlib import Path

from sastsimi.interfaces.cli.main import main
from sastsimi.storage.database import Database


def test_operator_db_upgrade_explicitly_creates_current_schema(tmp_path: Path) -> None:
    assert main(["--data-dir", str(tmp_path), "db", "upgrade", "--format", "json"]) == 0
    Database(tmp_path / "state.sqlite3").check_ready()
