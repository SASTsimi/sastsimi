"""The static bootstrap reads only a tracked, bounded repository policy."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sastsimi.simple_runtime import bootstrap_stages


def test_tracked_github_security_policy_wins_over_other_locations(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    (root / ".github").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "SECURITY.md").write_text("Root reporting rule", encoding="utf-8")
    (root / ".github" / "SECURITY.md").write_text(
        "GitHub reporting rule", encoding="utf-8"
    )
    (root / "docs" / "SECURITY.md").write_text("Docs reporting rule", encoding="utf-8")

    result = bootstrap_stages._security_policy(
        root,
        ("docs/SECURITY.md", ".github/SECURITY.md", "SECURITY.md"),
    )

    assert result is not None
    assert result["path"] == ".github/SECURITY.md"
    assert result["content"] == "GitHub reporting rule"


def test_untracked_or_empty_security_policy_is_not_collected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "SECURITY.md").write_text("untracked rule", encoding="utf-8")
    assert bootstrap_stages._security_policy(root, ("app.py",)) is None

    (root / "SECURITY.md").write_text(" \n", encoding="utf-8")
    assert bootstrap_stages._security_policy(root, ("SECURITY.md",)) is None


def test_security_policy_rejects_oversized_file_and_external_symlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "SECURITY.md").write_bytes(b"x" * (256 * 1024 + 1))
    assert bootstrap_stages._security_policy(root, ("SECURITY.md",)) is None

    outside = tmp_path / "outside.md"
    outside.write_text("external policy", encoding="utf-8")
    (root / "SECURITY.md").unlink()
    try:
        os.symlink(outside, root / "SECURITY.md")
    except OSError:
        pytest.skip("Windows symlink privilege is unavailable")
    assert bootstrap_stages._security_policy(root, ("SECURITY.md",)) is None
