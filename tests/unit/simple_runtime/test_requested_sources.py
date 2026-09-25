from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.retrieval import collect_requested_sources


def test_host_paths_and_bad_spans_are_refused(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("first\nsecond\n", encoding="utf-8")
    result = collect_requested_sources(
        (
            "../secret",
            "C:\\Users\\secret",
            "\\\\host\\share",
            "app.py:0-1",
            "app.py:5-6",
        ),
        workspace=tmp_path,
        tracked=("app.py",),
    )

    assert result["served"] == []
    assert len(result["refused"]) == 5


def test_only_tracked_in_root_lines_are_served(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("first\nsecond\n", encoding="utf-8")
    (tmp_path / "local.env").write_text("SECRET=hidden\n", encoding="utf-8")
    result = collect_requested_sources(
        ("app.py:2-2", "local.env"), workspace=tmp_path, tracked=("app.py",)
    )

    assert len(result["served"]) == 1
    assert result["served"][0]["content"] == "2|second"
    assert result["refused"][0]["reason"] == "NOT_TRACKED"


def test_outside_symlink_is_refused(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-source.txt"
    outside.write_text("private", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        return
    result = collect_requested_sources(
        ("link.txt",), workspace=tmp_path, tracked=("link.txt",)
    )
    assert result["served"] == []
    assert result["refused"][0]["reason"] == "PATH_OUTSIDE_REPOSITORY"


def test_tracked_symlink_to_untracked_local_file_is_refused(tmp_path: Path) -> None:
    local = tmp_path / "local.env"
    local.write_text("SECRET=hidden", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(local)
    except OSError:
        return
    result = collect_requested_sources(
        ("link.txt",), workspace=tmp_path, tracked=("link.txt",)
    )
    assert result["served"] == []


def test_symlink_classification_is_enforced_without_windows_privilege(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = tmp_path / "link.txt"
    link.write_text("SECRET=hidden", encoding="utf-8")
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == link or original(path))

    result = collect_requested_sources(
        ("link.txt",), workspace=tmp_path, tracked=("link.txt",)
    )

    assert result["served"] == []
