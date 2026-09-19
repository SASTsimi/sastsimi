from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

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
    commit = subprocess.run(
        (str(_git()), "-C", str(root), "rev-parse", "HEAD"),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.decode("ascii").strip()
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
