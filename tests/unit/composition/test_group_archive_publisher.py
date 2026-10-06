"""Group archive publication must not escape the configured data directory."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sastsimi.composition.simple_runtime_composition import (
    _publish_group_archive_posix,
)
from sastsimi.reporting.grouped_bundle import GroupBundleUnavailable


@pytest.mark.skipif(os.name == "nt", reason="POSIX dir-fd publication")
def test_group_archive_rejects_symlink_before_creating_outside_directory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "reports").symlink_to(outside, target_is_directory=True)

    with pytest.raises((OSError, GroupBundleUnavailable)):
        _publish_group_archive_posix(
            root, ("reports", "A-001", "groups", "g", "hash"), b"archive"
        )

    assert not (outside / "A-001").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX dir-fd publication")
def test_group_archive_is_immutable_and_repeatable(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    parts = ("reports", "A-001", "groups", "g", "hash")
    _publish_group_archive_posix(root, parts, b"archive")
    _publish_group_archive_posix(root, parts, b"archive")
    assert (root.joinpath(*parts) / "bundle.zip").read_bytes() == b"archive"

    with pytest.raises(GroupBundleUnavailable, match="GROUP_PATH_UNSAFE"):
        _publish_group_archive_posix(root, parts, b"different")
    assert (root.joinpath(*parts) / "bundle.zip").read_bytes() == b"archive"
