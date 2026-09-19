"""Public CodeQL registry CLI stays exact, explicit, and path-safe."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.interfaces.cli.main import main
from tests.unit.test_production_profile import _profile_text, _with_codeql_container

_COMMIT_ID = "a" * 40
_TRACKED_MANIFEST_SHA256 = "b" * 64
_REPOSITORY_URL = "https://example.invalid/owner/repository.git"


def _write_profile(tmp_path: Path, *, include_codeql: bool) -> Path:
    profile = tmp_path / "PRIVATE_PROFILE.toml"
    source = _profile_text(tmp_path / "workspaces")
    if include_codeql:
        (tmp_path / "codeql-databases").mkdir()
        (tmp_path / "codeql-query-pack").mkdir()
        source = _with_codeql_container(source, tmp_path)
    profile.write_text(source, encoding="utf-8")
    return profile


def _write_database(tmp_path: Path) -> Path:
    database = tmp_path / "PRIVATE_DATABASE_ROOT"
    database.mkdir()
    (database / "codeql-database.yml").write_text(
        "primaryLanguage: python\n", encoding="utf-8"
    )
    return database


def test_public_register_then_inspect_returns_only_safe_artifact_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catches parser wiring that leaks paths or loses exact lookup identity."""

    profile = _write_profile(tmp_path, include_codeql=True)
    database = _write_database(tmp_path)
    data_dir = tmp_path / "PRIVATE_DATA_DIR"

    assert (
        main(
            [
                "--data-dir",
                str(data_dir),
                "codeql",
                "register",
                "--profile",
                str(profile),
                "--repo",
                _REPOSITORY_URL,
                "--commit",
                _COMMIT_ID,
                "--language",
                "python",
                "--tracked-manifest-sha256",
                _TRACKED_MANIFEST_SHA256,
                "--database-root",
                str(database),
                "--format",
                "json",
            ]
        )
        == 0
    )
    registered = json.loads(capsys.readouterr().out)

    assert registered["command"] == "codeql register"
    assert registered["code"] == "OK"
    assert set(registered["data"]) == {
        "artifact_key",
        "database_digest",
        "status",
    }
    assert registered["data"]["status"] == "REGISTERED"

    assert (
        main(
            [
                "--data-dir",
                str(data_dir),
                "codeql",
                "inspect",
                "--profile",
                str(profile),
                "--repo",
                _REPOSITORY_URL,
                "--commit",
                _COMMIT_ID,
                "--language",
                "python",
                "--tracked-manifest-sha256",
                _TRACKED_MANIFEST_SHA256,
                "--format",
                "json",
            ]
        )
        == 0
    )
    inspected = json.loads(capsys.readouterr().out)

    assert inspected["command"] == "codeql inspect"
    assert inspected["data"] == registered["data"] | {"status": "AVAILABLE"}
    public_wire = json.dumps((registered, inspected))
    assert "PRIVATE_PROFILE" not in public_wire
    assert "PRIVATE_DATABASE_ROOT" not in public_wire
    assert "PRIVATE_DATA_DIR" not in public_wire
    assert str(tmp_path) not in public_wire


def test_public_codeql_requires_the_explicit_codeql_container_table(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catches accidental fallback when the selected profile omits CodeQL."""

    profile = _write_profile(tmp_path, include_codeql=False)
    private_database = tmp_path / "PRIVATE_DATABASE_MUST_NOT_BE_ECHOED"

    assert (
        main(
            [
                "codeql",
                "register",
                "--profile",
                str(profile),
                "--repo",
                _REPOSITORY_URL,
                "--commit",
                _COMMIT_ID,
                "--language",
                "python",
                "--tracked-manifest-sha256",
                _TRACKED_MANIFEST_SHA256,
                "--database-root",
                str(private_database),
                "--format",
                "json",
            ]
        )
        == 3
    )

    output = capsys.readouterr()
    assert output.out == ""
    rejected = json.loads(output.err)
    assert rejected["command"] == "codeql register"
    assert rejected["code"] == "CONFIG_ERROR"
    assert set(rejected["data"]) == {"message"}
    wire = json.dumps(rejected)
    assert "PRIVATE_PROFILE" not in wire
    assert "PRIVATE_DATABASE_MUST_NOT_BE_ECHOED" not in wire
    assert str(tmp_path) not in wire


def test_public_codeql_rejects_invalid_input_without_echoing_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catches argparse reflecting a sensitive or host-specific raw value."""

    private_value = str(tmp_path / "PRIVATE_BRANCH_OR_PATH")
    assert (
        main(
            [
                "codeql",
                "inspect",
                "--profile",
                private_value,
                "--repo",
                _REPOSITORY_URL,
                "--commit",
                private_value,
                "--language",
                "python",
                "--tracked-manifest-sha256",
                _TRACKED_MANIFEST_SHA256,
                "--format",
                "json",
            ]
        )
        == 2
    )

    output = capsys.readouterr()
    assert output.out == ""
    assert "Invalid command or option" in output.err
    assert private_value not in output.err
