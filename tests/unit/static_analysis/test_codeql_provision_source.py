from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from zipfile import ZipFile

import pytest

from sastsimi.static_analysis.codeql_provision_source import prepare_exact_source


def _git() -> Path:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git is unavailable")
    return Path(executable).resolve()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repository"
    root.mkdir()
    commands = (
        ("init",),
        ("config", "core.autocrlf", "false"),
        ("config", "user.email", "test@example.invalid"),
        ("config", "user.name", "SASTSIMI Test"),
    )
    for command in commands:
        subprocess.run(
            (str(_git()), "-C", str(root), *command),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    (root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (root / "app.py").write_text("print('exact')\n", encoding="utf-8")
    subprocess.run(
        (str(_git()), "-C", str(root), "add", "--", ".gitignore", "app.py"),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        (str(_git()), "-C", str(root), "commit", "-m", "fixture"),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    commit = (
        subprocess.run(
            (str(_git()), "-C", str(root), "rev-parse", "HEAD"),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        .stdout.decode("ascii")
        .strip()
    )
    return root, commit


def test_prepared_source_contains_only_safe_files_from_the_exact_commit(
    tmp_path: Path,
) -> None:
    repository, commit = _repository(tmp_path)
    (repository / "ignored.txt").write_text("not part of identity", encoding="utf-8")
    (repository / "untracked.py").write_text("not part of identity", encoding="utf-8")
    destination = tmp_path / "source"
    destination.mkdir()

    prepared = prepare_exact_source(
        git_executable=_git(),
        repository_root=repository,
        commit_id=commit,
        destination=destination,
    )

    assert prepared.root == destination.resolve()
    assert len(prepared.tracked_manifest_sha256) == 64
    assert tuple(
        path.relative_to(destination).as_posix()
        for path in sorted(destination.rglob("*"))
        if path.is_file()
    ) == (".gitignore", "app.py")
    assert not (destination / ".git").exists()
    assert (destination / "app.py").read_text(encoding="utf-8") == "print('exact')\n"
    if os.name == "posix":
        assert destination.stat().st_mode & 0o005 == 0o005
        assert (destination / "app.py").stat().st_mode & 0o004 == 0o004


def test_prepared_source_rejects_wrong_commit_or_modified_tracked_content(
    tmp_path: Path,
) -> None:
    repository, commit = _repository(tmp_path)
    wrong_destination = tmp_path / "wrong"
    wrong_destination.mkdir()
    with pytest.raises(ValueError, match="^CODEQL_PROVISION_SOURCE_MISMATCH$"):
        prepare_exact_source(
            git_executable=_git(),
            repository_root=repository,
            commit_id="f" * 40,
            destination=wrong_destination,
        )

    (repository / "app.py").write_text("print('modified')\n", encoding="utf-8")
    modified_destination = tmp_path / "modified"
    modified_destination.mkdir()
    with pytest.raises(ValueError, match="^CODEQL_PROVISION_SOURCE_MISMATCH$"):
        prepare_exact_source(
            git_executable=_git(),
            repository_root=repository,
            commit_id=commit,
            destination=modified_destination,
        )


def test_prepared_source_omits_test_files_and_test_only_commits_do_not_change_identity(
    tmp_path: Path,
) -> None:
    repository, _ = _repository(tmp_path)
    tests = repository / "tests"
    tests.mkdir()
    test_file = tests / "test_app.py"
    test_file.write_text("def test_app():\n    assert True\n", encoding="utf-8")

    def commit_test_revision() -> str:
        subprocess.run(
            (str(_git()), "-C", str(repository), "add", "--", "tests/test_app.py"),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            (str(_git()), "-C", str(repository), "commit", "-m", "test revision"),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return (
            subprocess.run(
                (str(_git()), "-C", str(repository), "rev-parse", "HEAD"),
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            .stdout.decode("ascii")
            .strip()
        )

    first_commit = commit_test_revision()
    first_destination = tmp_path / "first-source"
    first_destination.mkdir()
    first = prepare_exact_source(
        git_executable=_git(),
        repository_root=repository,
        commit_id=first_commit,
        destination=first_destination,
    )

    test_file.write_text("def test_app():\n    assert 1 == 1\n", encoding="utf-8")
    second_commit = commit_test_revision()
    second_destination = tmp_path / "second-source"
    second_destination.mkdir()
    second = prepare_exact_source(
        git_executable=_git(),
        repository_root=repository,
        commit_id=second_commit,
        destination=second_destination,
    )

    assert first_commit != second_commit
    assert first.tracked_manifest_sha256 == second.tracked_manifest_sha256
    for destination in (first_destination, second_destination):
        assert tuple(
            path.relative_to(destination).as_posix()
            for path in sorted(destination.rglob("*"))
            if path.is_file()
        ) == (".gitignore", "app.py")


def test_pinned_codeql_cli_database_archives_only_staged_product_source(
    tmp_path: Path,
) -> None:
    if os.environ.get("SASTSIMI_TEST_REAL_CODEQL") != "1":
        pytest.skip("explicit real CodeQL CLI verification is not enabled")
    codeql = shutil.which("codeql")
    if codeql is None:
        pytest.skip("CodeQL CLI is unavailable")
    version = (
        subprocess.run(
            (codeql, "version", "--format=terse"),
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
        )
        .stdout.decode("ascii")
        .strip()
    )
    if version != "2.27.0":
        pytest.skip("pinned CodeQL 2.27.0 CLI is unavailable")

    repository, _ = _repository(tmp_path)
    (repository / "tests").mkdir()
    (repository / "tests" / "test_app.py").write_text(
        "def test_app():\n    assert True\n", encoding="utf-8"
    )
    subprocess.run(
        (str(_git()), "-C", str(repository), "add", "--", "tests/test_app.py"),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        (str(_git()), "-C", str(repository), "commit", "-m", "test source"),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    commit = (
        subprocess.run(
            (str(_git()), "-C", str(repository), "rev-parse", "HEAD"),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        .stdout.decode("ascii")
        .strip()
    )
    staged = tmp_path / "staged"
    staged.mkdir()
    prepare_exact_source(
        git_executable=_git(),
        repository_root=repository,
        commit_id=commit,
        destination=staged,
    )
    database = tmp_path / "codeql-database"

    created = subprocess.run(
        (
            codeql,
            "database",
            "create",
            str(database),
            "--language=python",
            f"--source-root={staged}",
            "--threads=1",
            "--ram=1024",
        ),
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=180,
    )

    assert created.returncode == 0, created.stderr.decode(errors="replace")
    with ZipFile(database / "src.zip") as archive:
        paths = tuple(sorted(archive.namelist()))
    assert any(path == "app.py" or path.endswith("/app.py") for path in paths)
    assert not any(path.endswith("/tests/test_app.py") for path in paths)
