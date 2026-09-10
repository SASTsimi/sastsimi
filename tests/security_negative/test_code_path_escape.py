"""Repository ingress and workspace paths fail closed before process execution."""

from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.ports.dto import MonotonicActionDeadline, TrackedFile
from sastsimi.static_analysis.context_retrieval import read_context_files
from sastsimi.static_analysis.repository_loader import (
    canonicalize_repository_source,
    validate_clone_destination,
)
from tests.unit.static_analysis.test_context_retrieval import _fixture, _plan


@pytest.mark.parametrize(
    "submitted",
    (
        "https://user:password@example.invalid/team/repo.git",
        "https://user%40example.invalid@host.invalid/repo.git",
        "https://example.invalid/repo.git?token=distinct-secret",
        "https://example.invalid/repo.git?x=1",
        "https://example.invalid/repo.git#access-token",
        "https://example.invalid/%2e%2e/repo.git",
        "https://example.invalid/repo%0agit",
        "-https://example.invalid/repo.git",
        "ext::https://example.invalid/repo.git",
        "git@example.invalid:team/repo.git",
        "file:///tmp/repo.git",
    ),
)
def test_repository_source_rejects_secret_and_escape_forms(submitted: str) -> None:
    """Deleting any ingress rejection would expose secrets or Git transport escape."""
    with pytest.raises(ValueError, match="REPOSITORY_SOURCE_INVALID"):
        canonicalize_repository_source(submitted)


def test_repository_source_canonicalizes_one_secret_free_https_identity() -> None:
    """Changing normalization must not create multiple identities for one repository."""
    source = canonicalize_repository_source(
        "https://EXAMPLE.Invalid:443/team/repo%2egit"
    )

    assert source.url == "https://example.invalid/team/repo%2Egit"
    assert source.host == "example.invalid"
    assert source.repository_path == "/team/repo%2Egit"


def test_clone_destination_must_be_private_empty_child(tmp_path: Path) -> None:
    """Relaxing root checks must not allow caller-controlled or linked destinations."""
    storage_root = tmp_path / "leases"
    storage_root.mkdir()
    destination = storage_root / "attempt"
    destination.mkdir()
    validate_clone_destination(destination, storage_root)

    (destination / "occupied").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="WORKSPACE_DESTINATION_INVALID"):
        validate_clone_destination(destination, storage_root)

    with pytest.raises(ValueError, match="WORKSPACE_DESTINATION_INVALID"):
        validate_clone_destination(tmp_path / "outside", storage_root)


@pytest.mark.parametrize("unsafe", ("../outside.py", "/etc/passwd", "C:/secret.py"))
def test_context_plan_rejects_path_escape_before_open(
    monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    _, symbols = _fixture()
    plan = replace(_plan(None, symbols["seed"]), file_paths=(unsafe,))
    monkeypatch.setattr(Path, "open", lambda *_a, **_k: pytest.fail("file opened"))

    with pytest.raises(ValueError, match="CONTEXT_PATH_UNSAFE"):
        read_context_files(
            plan=plan,
            workspace_root=Path(__file__).parents[2],
            tracked_files=(TrackedFile(unsafe, "100644", "0" * 40, 1),),
            deadline=MonotonicActionDeadline("read", 0, 1_000_000_000),
            monotonic_ns=lambda: 1,
        )


def test_context_rejects_git_symlink_mode_before_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, symbols = _fixture()
    plan = _plan(None, symbols["seed"])
    monkeypatch.setattr(Path, "open", lambda *_a, **_k: pytest.fail("file opened"))

    with pytest.raises(ValueError, match="CONTEXT_PATH_UNTRACKED"):
        read_context_files(
            plan=plan,
            workspace_root=Path(__file__).parents[2],
            tracked_files=tuple(
                TrackedFile(path, "120000", "0" * 40, 1) for path in plan.file_paths
            ),
            deadline=MonotonicActionDeadline("read", 0, 1_000_000_000),
            monotonic_ns=lambda: 1,
        )
