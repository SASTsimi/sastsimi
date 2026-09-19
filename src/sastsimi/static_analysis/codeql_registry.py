"""Controlled publication of exact, already-created CodeQL databases.

This module never invokes CodeQL, a build tool, a package manager, repository
code, or the network.  It only validates and copies a database tree produced by
a separately controlled provisioning step.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.static_analysis.prebuilt_codeql_database import (
    codeql_database_artifact_key,
)

_MANIFEST_NAME = "sastsimi-codeql-database.json"
_MAX_MANIFEST_BYTES = 64 * 1024
_REPARSE_POINT = 0x400
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
type CodeQLLanguage = Literal["python", "javascript-typescript"]


@dataclass(frozen=True, slots=True)
class CodeQLDatabaseIdentity:
    """Exact source and provider closure of one prebuilt database."""

    repository_url: str
    commit_id: str
    language: CodeQLLanguage
    tracked_manifest_sha256: str
    provider_key: str
    provider_revision: str
    provider_evidence_sha256: str

    def __post_init__(self) -> None:
        text = (
            self.repository_url,
            self.provider_key,
            self.provider_revision,
        )
        if (
            any(not item or item != item.strip() or _has_control(item) for item in text)
            or _COMMIT.fullmatch(self.commit_id) is None
            or self.language not in {"python", "javascript-typescript"}
            or _SHA256.fullmatch(self.tracked_manifest_sha256) is None
            or _SHA256.fullmatch(self.provider_evidence_sha256) is None
        ):
            raise ValueError("CODEQL_DATABASE_IDENTITY_INVALID")

    @property
    def artifact_key(self) -> str:
        return codeql_database_artifact_key(
            repository_url=self.repository_url,
            commit_id=self.commit_id,
            language=self.language,
            tracked_manifest_sha256=self.tracked_manifest_sha256,
        )


@dataclass(frozen=True, slots=True)
class PublishedCodeQLDatabase:
    """Validated immutable registry entry returned to the provisioner."""

    artifact_key: str
    artifact_root: Path
    database_root: Path
    manifest_path: Path
    database_digest: str
    identity: CodeQLDatabaseIdentity


def publish_codeql_database(
    *,
    registry_root: Path,
    database_root: Path,
    identity: CodeQLDatabaseIdentity,
    cancellation_requested: Callable[[], bool] | None = None,
) -> PublishedCodeQLDatabase:
    """Publish one validated database atomically without replacing an entry."""

    identity = _require_identity(identity)
    registry = _safe_directory(registry_root, "CODEQL_DATABASE_REGISTRY_INVALID")
    source = _safe_directory(database_root, "CODEQL_DATABASE_TREE_INVALID")
    if _overlaps(registry, source):
        raise ValueError("CODEQL_DATABASE_TREE_INVALID")
    _require_safe_tree(source)
    _require_active(cancellation_requested)
    source_digest = _digest_tree(source, cancellation_requested)
    target = registry / identity.artifact_key
    lock = registry / f".{identity.artifact_key}.publish.lock"
    # The registry key already makes the final directory exact.  A short random
    # staging name avoids exhausting legacy Windows path limits while the
    # exclusive per-key lock still serializes publishers of the same entry.
    staging = registry / f".tmp-{uuid4().hex[:12]}"
    descriptor = _manifest(identity, source_digest)
    lock_descriptor: int | None = None
    try:
        lock_descriptor = os.open(
            lock,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError:
        raise FileExistsError("CODEQL_DATABASE_ALREADY_PUBLISHED") from None
    try:
        if target.exists():
            raise FileExistsError("CODEQL_DATABASE_ALREADY_PUBLISHED")
        staging.mkdir(mode=0o700)
        copied = staging / "database"
        _copy_tree(source, copied, cancellation_requested)
        if (
            _digest_tree(source, cancellation_requested) != source_digest
            or _digest_tree(copied, cancellation_requested) != source_digest
        ):
            raise ValueError("CODEQL_DATABASE_CHANGED_DURING_PUBLICATION")
        _write_exclusive(staging / _MANIFEST_NAME, canonical_bytes(descriptor))
        _require_active(cancellation_requested)
        if target.exists():
            raise FileExistsError("CODEQL_DATABASE_ALREADY_PUBLISHED")
        os.rename(staging, target)
        return _validated_entry(target, identity)
    except FileExistsError:
        raise FileExistsError("CODEQL_DATABASE_ALREADY_PUBLISHED") from None
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


def lookup_codeql_database(
    *, registry_root: Path, identity: CodeQLDatabaseIdentity
) -> PublishedCodeQLDatabase | None:
    """Return an exact verified entry, or ``None`` when that key is absent."""

    identity = _require_identity(identity)
    registry = _safe_directory(registry_root, "CODEQL_DATABASE_REGISTRY_INVALID")
    target = registry / identity.artifact_key
    if not target.exists():
        return None
    return _validated_entry(target, identity)


def read_codeql_database_manifest(artifact_root: Path) -> dict[str, object]:
    """Read a canonical existing manifest without accepting extra fields."""

    root = _safe_directory(artifact_root, "CODEQL_DATABASE_ARTIFACT_INVALID")
    path = root / _MANIFEST_NAME
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _is_link_like(path)
            or not 0 < before.st_size <= _MAX_MANIFEST_BYTES
        ):
            raise ValueError
        raw = path.read_bytes()
        after = path.lstat()
        if (
            _file_identity(before) != _file_identity(after)
            or len(raw) != before.st_size
        ):
            raise ValueError
        value = json.loads(raw)
        if not isinstance(value, dict) or raw != canonical_bytes(value):
            raise ValueError
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        raise ValueError("CODEQL_DATABASE_MANIFEST_INVALID") from None
    expected_fields = {
        "schema_version",
        "provider_key",
        "provider_revision",
        "provider_evidence_sha256",
        "repository_url",
        "commit_id",
        "language",
        "tracked_manifest_sha256",
        "database_digest",
    }
    try:
        language = value.get("language")
        if (
            set(value) != expected_fields
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or not all(
                isinstance(value.get(name), str)
                for name in expected_fields - {"schema_version"}
            )
            or language not in {"python", "javascript-typescript"}
            or _SHA256.fullmatch(str(value.get("database_digest"))) is None
        ):
            raise ValueError
        CodeQLDatabaseIdentity(
            repository_url=cast(str, value["repository_url"]),
            commit_id=cast(str, value["commit_id"]),
            language=cast(CodeQLLanguage, language),
            tracked_manifest_sha256=cast(str, value["tracked_manifest_sha256"]),
            provider_key=cast(str, value["provider_key"]),
            provider_revision=cast(str, value["provider_revision"]),
            provider_evidence_sha256=cast(str, value["provider_evidence_sha256"]),
        )
    except (KeyError, TypeError, ValueError):
        raise ValueError("CODEQL_DATABASE_MANIFEST_INVALID") from None
    return value


def _validated_entry(
    target: Path, identity: CodeQLDatabaseIdentity
) -> PublishedCodeQLDatabase:
    artifact = _safe_directory(target, "CODEQL_DATABASE_ARTIFACT_INVALID")
    manifest = read_codeql_database_manifest(artifact)
    database = _safe_directory(
        artifact / "database", "CODEQL_DATABASE_ARTIFACT_INVALID"
    )
    _require_safe_tree(database)
    expected = _manifest(identity, str(manifest.get("database_digest", "")))
    if manifest != expected:
        raise ValueError("CODEQL_DATABASE_MANIFEST_MISMATCH")
    digest = _digest_tree(database, None)
    if digest != manifest["database_digest"]:
        raise ValueError("CODEQL_DATABASE_DIGEST_MISMATCH")
    return PublishedCodeQLDatabase(
        artifact_key=identity.artifact_key,
        artifact_root=artifact,
        database_root=database,
        manifest_path=artifact / _MANIFEST_NAME,
        database_digest=digest,
        identity=identity,
    )


def _manifest(
    identity: CodeQLDatabaseIdentity, database_digest: str
) -> dict[str, object]:
    if _SHA256.fullmatch(database_digest) is None:
        raise ValueError("CODEQL_DATABASE_MANIFEST_INVALID")
    return {
        "schema_version": 1,
        "provider_key": identity.provider_key,
        "provider_revision": identity.provider_revision,
        "provider_evidence_sha256": identity.provider_evidence_sha256,
        "repository_url": identity.repository_url,
        "commit_id": identity.commit_id,
        "language": identity.language,
        "tracked_manifest_sha256": identity.tracked_manifest_sha256,
        "database_digest": database_digest,
    }


def _require_identity(identity: CodeQLDatabaseIdentity) -> CodeQLDatabaseIdentity:
    if not isinstance(identity, CodeQLDatabaseIdentity):
        raise ValueError("CODEQL_DATABASE_IDENTITY_INVALID")
    return identity


def _has_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _is_link_like(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _safe_directory(path: Path, code: str) -> Path:
    try:
        if not path.is_absolute():
            raise ValueError
        info = path.lstat()
        exact = path.resolve(strict=True)
        if (
            not stat.S_ISDIR(info.st_mode)
            or _is_link_like(path)
            or int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
            or exact != path.absolute()
        ):
            raise ValueError
    except (OSError, ValueError):
        raise ValueError(code) from None
    return exact


def _require_safe_tree(root: Path) -> None:
    _safe_directory(root, "CODEQL_DATABASE_TREE_INVALID")
    try:
        for candidate in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            info = candidate.lstat()
            if (
                _is_link_like(candidate)
                or int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
            ):
                raise ValueError
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise ValueError
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError
    except (OSError, ValueError):
        raise ValueError("CODEQL_DATABASE_TREE_INVALID") from None


def _digest_tree(root: Path, cancellation_requested: Callable[[], bool] | None) -> str:
    entries: list[tuple[str, int, str]] = []
    _require_safe_tree(root)
    for candidate in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        _require_active(cancellation_requested)
        if candidate.is_dir():
            continue
        before = candidate.lstat()
        digest = hashlib.sha256()
        size = 0
        with candidate.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                _require_active(cancellation_requested)
                size += len(chunk)
                digest.update(chunk)
        after = candidate.lstat()
        if _file_identity(before) != _file_identity(after) or size != before.st_size:
            raise ValueError("CODEQL_DATABASE_CHANGED_DURING_PUBLICATION")
        entries.append(
            (candidate.relative_to(root).as_posix(), size, digest.hexdigest())
        )
    return hashlib.sha256(canonical_bytes(entries)).hexdigest()


def _copy_tree(
    source: Path,
    destination: Path,
    cancellation_requested: Callable[[], bool] | None,
) -> None:
    def copy_file(source_name: str, destination_name: str) -> str:
        _require_active(cancellation_requested)
        source_path = Path(source_name)
        destination_path = Path(destination_name)
        before = source_path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("CODEQL_DATABASE_TREE_INVALID")
        with source_path.open("rb") as reader, destination_path.open("xb") as writer:
            while chunk := reader.read(1024 * 1024):
                _require_active(cancellation_requested)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        after = source_path.lstat()
        if _file_identity(before) != _file_identity(after):
            raise ValueError("CODEQL_DATABASE_CHANGED_DURING_PUBLICATION")
        shutil.copystat(source_path, destination_path, follow_symlinks=False)
        return str(destination_path)

    try:
        shutil.copytree(source, destination, copy_function=copy_file)
    except OSError as error:
        raise ValueError("CODEQL_DATABASE_COPY_FAILED") from error
    _require_safe_tree(destination)


def _write_exclusive(path: Path, payload: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_nlink,
    )


def _require_active(cancellation_requested: Callable[[], bool] | None) -> None:
    if cancellation_requested is not None and cancellation_requested():
        raise ValueError("CODEQL_DATABASE_PROVISION_CANCELLED")


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


__all__ = [
    "CodeQLDatabaseIdentity",
    "PublishedCodeQLDatabase",
    "lookup_codeql_database",
    "publish_codeql_database",
    "read_codeql_database_manifest",
]
