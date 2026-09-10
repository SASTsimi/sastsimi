"""Repository ingress and workspace paths fail closed before process execution."""

from pathlib import Path

import pytest

from sastsimi.static_analysis.repository_loader import (
    canonicalize_repository_source,
    validate_clone_destination,
)


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
