"""Locate immutable resources in source checkouts and installed wheels."""

from __future__ import annotations

from pathlib import Path

_LOGICAL_PACKAGE_PREFIX = ("src", "sastsimi")


def builtin_package_root() -> Path:
    """Return the physical ``sastsimi`` package directory."""

    return Path(__file__).resolve().parents[1]


def resolve_builtin_resource(root: Path, logical_path: Path) -> Path:
    """Map one canonical source-layout path to its physical package file.

    Signed prompt approvals keep their stable ``src/sastsimi/...`` logical
    names. Installed wheels omit the source-layout prefix, so only that exact
    prefix is translated. Arbitrary relative paths are never accepted.
    """

    root = root.resolve(strict=True)
    parts = logical_path.parts
    if (
        logical_path.is_absolute()
        or len(parts) <= len(_LOGICAL_PACKAGE_PREFIX)
        or parts[: len(_LOGICAL_PACKAGE_PREFIX)] != _LOGICAL_PACKAGE_PREFIX
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError("BUILTIN_RESOURCE_PATH_DENIED")

    source_package = root.joinpath(*_LOGICAL_PACKAGE_PREFIX)
    if source_package.is_dir():
        candidate = root.joinpath(*parts)
    elif root == builtin_package_root():
        candidate = root.joinpath(*parts[len(_LOGICAL_PACKAGE_PREFIX) :])
    else:
        raise ValueError("BUILTIN_RESOURCE_ROOT_INVALID")

    # Return the lexical path. Security-sensitive readers must inspect every
    # component before resolving so a symlink/reparse point cannot be hidden.
    if not candidate.is_file():
        raise ValueError("BUILTIN_RESOURCE_PATH_DENIED")
    return candidate


__all__ = ["builtin_package_root", "resolve_builtin_resource"]
