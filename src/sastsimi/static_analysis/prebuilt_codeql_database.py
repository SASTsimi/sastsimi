"""Read-only provider for exact, already-built CodeQL databases."""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
from pathlib import Path

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.ports.dto import PrebuiltCodeQLDatabase, StaticOutputQuotaBinding
from sastsimi.static_analysis.codeql_adapter import digest_path

_MANIFEST_NAME = "sastsimi-codeql-database.json"
_MAX_MANIFEST_BYTES = 64 * 1024
_REPARSE_POINT = 0x400


def codeql_database_artifact_key(
    *,
    repository_url: str,
    commit_id: str,
    language: str,
    tracked_manifest_sha256: str,
) -> str:
    """Return the stable registry key for one exact source closure."""

    return hashlib.sha256(
        canonical_bytes(
            {
                "schema_version": 1,
                "repository_url": repository_url,
                "commit_id": commit_id,
                "language": language,
                "tracked_manifest_sha256": tracked_manifest_sha256,
            }
        )
    ).hexdigest()


def _is_link_like(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _safe_directory(path: Path, code: str) -> Path:
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValueError(code) from error
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(info.st_mode)
        or _is_link_like(path)
        or int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
        or resolved != path.absolute()
    ):
        raise ValueError(code)
    return resolved


def _require_safe_tree(root: Path) -> None:
    exact = _safe_directory(root, "CODEQL_DATABASE_ARTIFACT_INVALID")
    for item in exact.rglob("*"):
        info = item.lstat()
        if (
            _is_link_like(item)
            or int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
        ):
            raise ValueError("CODEQL_DATABASE_ARTIFACT_INVALID")
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise ValueError("CODEQL_DATABASE_ARTIFACT_INVALID")
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("CODEQL_DATABASE_ARTIFACT_INVALID")


def _read_manifest(path: Path) -> dict[str, object]:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _is_link_like(path)
            or before.st_size <= 0
            or before.st_size > _MAX_MANIFEST_BYTES
        ):
            raise ValueError
        raw = path.read_bytes()
        after = path.lstat()
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_nlink,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_nlink,
        )
        if before_identity != after_identity or len(raw) != before.st_size:
            raise ValueError
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("CODEQL_DATABASE_MANIFEST_INVALID") from error
    if not isinstance(value, dict):
        raise ValueError("CODEQL_DATABASE_MANIFEST_INVALID")
    return value


class FilesystemPrebuiltCodeQLDatabaseProvider:
    """Copy an exact approved DB artifact into an attempt-owned quota root."""

    def __init__(
        self,
        *,
        registry_root: Path,
        provider_key: str,
        provider_revision: str,
        provider_evidence_sha256: str,
        profile_ref: HostConfigurationRef,
    ) -> None:
        if (
            not provider_key
            or not provider_revision
            or len(provider_evidence_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in provider_evidence_sha256
            )
        ):
            raise ValueError("CODEQL_DATABASE_PROVIDER_IDENTITY_INVALID")
        self.registry_root = _safe_directory(
            registry_root, "CODEQL_DATABASE_REGISTRY_INVALID"
        )
        self.provider_key = provider_key
        self.provider_revision = provider_revision
        self.provider_evidence_sha256 = provider_evidence_sha256
        self._profile_ref = profile_ref

    def materialize(
        self,
        *,
        workspace_id: str,
        repository_url: str,
        commit_id: str,
        language: str,
        tracked_manifest_sha256: str,
        profile_ref: HostConfigurationRef,
        quota_binding: StaticOutputQuotaBinding,
    ) -> PrebuiltCodeQLDatabase | None:
        if (
            not workspace_id
            or not repository_url
            or not commit_id
            or language not in {"python", "javascript-typescript"}
            or len(tracked_manifest_sha256) != 64
            or profile_ref != self._profile_ref
            or quota_binding.profile_ref != profile_ref
            or quota_binding.hard_enforced is not True
            or quota_binding.limit_breached
            or quota_binding.effective_limit_bytes <= 0
        ):
            raise ValueError("CODEQL_DATABASE_REQUEST_INVALID")
        destination_parent = _safe_directory(
            quota_binding.root, "CODEQL_DATABASE_QUOTA_ROOT_INVALID"
        )
        if any(destination_parent.iterdir()):
            raise ValueError("CODEQL_DATABASE_QUOTA_ROOT_NOT_EMPTY")
        key = codeql_database_artifact_key(
            repository_url=repository_url,
            commit_id=commit_id,
            language=language,
            tracked_manifest_sha256=tracked_manifest_sha256,
        )
        artifact = self.registry_root / key
        if not artifact.exists():
            return None
        exact_artifact = _safe_directory(artifact, "CODEQL_DATABASE_ARTIFACT_INVALID")
        database_source = exact_artifact / "database"
        manifest = _read_manifest(exact_artifact / _MANIFEST_NAME)
        expected = {
            "schema_version": 1,
            "provider_key": self.provider_key,
            "provider_revision": self.provider_revision,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "repository_url": repository_url,
            "commit_id": commit_id,
            "language": language,
            "tracked_manifest_sha256": tracked_manifest_sha256,
        }
        if set(manifest) != {*expected, "database_digest"} or any(
            manifest.get(name) != value for name, value in expected.items()
        ):
            raise ValueError("CODEQL_DATABASE_MANIFEST_MISMATCH")
        declared_digest = manifest.get("database_digest")
        if not isinstance(declared_digest, str) or len(declared_digest) != 64:
            raise ValueError("CODEQL_DATABASE_MANIFEST_INVALID")
        _require_safe_tree(database_source)
        source_digest_before = digest_path(database_source)
        if source_digest_before != declared_digest:
            raise ValueError("CODEQL_DATABASE_DIGEST_MISMATCH")
        destination = destination_parent / "database"
        try:
            shutil.copytree(database_source, destination, copy_function=shutil.copy2)
        except OSError as error:
            raise ValueError("CODEQL_DATABASE_COPY_FAILED") from error
        _require_safe_tree(database_source)
        _require_safe_tree(destination)
        if (
            digest_path(database_source) != source_digest_before
            or digest_path(destination) != source_digest_before
        ):
            raise ValueError("CODEQL_DATABASE_CHANGED_DURING_COPY")
        return PrebuiltCodeQLDatabase(
            workspace_id=workspace_id,
            commit_id=commit_id,
            language=language,
            database_root=destination,
            database_digest=source_digest_before,
        )


__all__ = [
    "FilesystemPrebuiltCodeQLDatabaseProvider",
    "codeql_database_artifact_key",
]
