"""Shared integration fixtures for the private T08 composition seam."""

from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass(frozen=True, slots=True)
class RealStaticSlicePaths:
    """Explicit filesystem roots; no environment or host paths are inferred."""

    executable: Path
    receipt_root: Path
    context_receipt_root: Path
    workspace_root: Path


@pytest.fixture
def real_static_slice_paths(tmp_path: Path) -> RealStaticSlicePaths:
    executable = tmp_path / "trusted-static-tool.bin"
    executable.write_bytes(b"deterministic fixture executable")
    receipt_root = tmp_path / "static-receipts"
    context_receipt_root = tmp_path / "context-receipts"
    workspace_root = tmp_path / "workspaces"
    receipt_root.mkdir()
    context_receipt_root.mkdir()
    workspace_root.mkdir()
    return RealStaticSlicePaths(
        executable, receipt_root, context_receipt_root, workspace_root
    )
