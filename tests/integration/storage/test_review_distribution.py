import json
import os
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile

import pytest

from sastsimi.bootstrap import build_runtime, upgrade_database
from sastsimi.interfaces.cli.main import main
from tests.integration.runtime_support import TestClock, TestIds


def test_built_wheel_migrates_outside_source_tree(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[3]
    wheels = tmp_path / "wheels"
    subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", "wheel", "-d", str(wheels)],
        cwd=project,
        check=True,
        capture_output=True,
    )
    installed = tmp_path / "installed"
    with ZipFile(next(wheels.glob("*.whl"))) as wheel:
        wheel.extractall(installed)
    environment = os.environ | {"PYTHONPATH": str(installed)}
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; "
            "from sastsimi.bootstrap import upgrade_database; "
            "upgrade_database(Path('runtime'))",
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "command,revision", [("current", None), ("upgrade", "head"), ("downgrade", "base")]
)
def test_db_commands_emit_command_specific_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    revision: str | None,
) -> None:
    upgrade_database(tmp_path)
    arguments = ["--data-dir", str(tmp_path), "db", command]
    if revision:
        arguments.append(revision)
    assert main([*arguments, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["command"] == "db " + command


def test_unknown_migration_returns_canonical_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "--data-dir",
                str(tmp_path),
                "db",
                "upgrade",
                "unknown",
                "--format",
                "json",
            ]
        )
        == 3
    )
    assert json.loads(capsys.readouterr().err)["command"] == "db upgrade"


def test_runtime_uses_frozen_directory_layout(tmp_path: Path) -> None:
    upgrade_database(tmp_path)
    build_runtime(tmp_path, None, None, TestClock(), TestIds())
    assert (tmp_path / "db" / "sastsimi.sqlite3").is_file()
    assert (tmp_path / "staging").is_dir()
    assert (tmp_path / "quarantine").is_dir()


def test_db_current_reports_valid_older_revision(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["--data-dir", str(tmp_path), "db"]
    assert main([*args, "upgrade", "0001_runtime", "--format", "json"]) == 0
    capsys.readouterr()
    assert main([*args, "current", "--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["data"]["revision"] == "0001_runtime"
    assert result["command"] == "db current"


def test_refused_lossy_downgrade_is_configuration_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.integration.runtime_support import Harness

    h = Harness(tmp_path)
    h.execution()
    assert (
        main(
            ["--data-dir", str(tmp_path), "db", "downgrade", "base", "--format", "json"]
        )
        == 3
    )
    result = json.loads(capsys.readouterr().err)
    assert result["command"] == "db downgrade"
