"""Bounded, manifest-last publication of exact Finding attachments."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import zipfile
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

from pydantic import model_validator

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import assert_safe_provider_text
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.report_export import ReportUnavailable
from sastsimi.reporting.bilingual_bundle import BundleFile, is_safe_sandbox_shell_poc
from sastsimi.reporting.safe_windows_directory import (
    _capture_directory_identity,
    _guarded_windows_replace_directory,
    _locked_windows_directory,
)

MAX_BUNDLE_FILE_BYTES = 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_BUNDLE_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_BUNDLE_MANIFEST_BYTES = 64 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ORDER = (
    "report_en.md",
    "report_kr.md",
    "poc.sh",
    "poc.py",
    "evidence/provenance.json",
    "evidence/stdout.txt",
    "evidence/stderr.txt",
)


def _valid_finding_ref(ref: StoredDataRef) -> bool:
    return (ref.data_kind == "finding" and ref.record_id is not None) or (
        ref.data_kind == "artifact"
        and ref.record_id is None
        and str(ref.stored_data_id) == ref.content_hash
    )


class BundleManifestEntry(ContractModel):
    path: str
    media_type: str
    size: int
    sha256: str
    artifact_ref: StoredDataRef


class ReportBundleManifest(ContractModel):
    schema_version: Literal[1]
    analysis_id: str
    display_id: str
    finding_ref: StoredDataRef
    poc_original_sha256: str
    poc_redacted: bool
    files: tuple[BundleManifestEntry, ...]

    @model_validator(mode="after")
    def validate_bundle(self) -> ReportBundleManifest:
        if (
            _ID.fullmatch(self.analysis_id) is None
            or _ID.fullmatch(self.display_id) is None
            or not _valid_finding_ref(self.finding_ref)
            or _SHA256.fullmatch(self.poc_original_sha256) is None
        ):
            raise ValueError("BUNDLE_MANIFEST_INVALID")
        paths = tuple(item.path for item in self.files)
        if (
            len(paths) != len(set(path.lower() for path in paths))
            or any(path not in _ORDER for path in paths)
            or tuple(sorted(paths, key=_ORDER.index)) != paths
            or not {
                "report_en.md",
                "report_kr.md",
                "evidence/provenance.json",
            }.issubset(paths)
            or ("poc.sh" in paths) == ("poc.py" in paths)
        ):
            raise ValueError("BUNDLE_MANIFEST_INVALID")
        total = 0
        for item in self.files:
            try:
                BundleFile(item.path, b"", item.media_type)
            except ValueError as error:
                raise ValueError("BUNDLE_MANIFEST_INVALID") from error
            if (
                item.size < 0
                or item.size > MAX_BUNDLE_FILE_BYTES
                or _SHA256.fullmatch(item.sha256) is None
            ):
                raise ValueError("BUNDLE_MANIFEST_INVALID")
            _assert_artifact_ref(item.artifact_ref, item.sha256, self.finding_ref)
            total += item.size
        if total > MAX_BUNDLE_BYTES:
            raise ValueError("BUNDLE_MANIFEST_INVALID")
        return self


@dataclass(frozen=True, slots=True)
class PublishedBundle:
    manifest_ref: StoredDataRef
    archive_ref: StoredDataRef
    bundle_dir: Path


@dataclass(frozen=True, slots=True)
class _SafeDirectory:
    path: Path
    fd: int | None


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _posix_flag(name: str) -> int:
    return cast(int, getattr(os, name))


def _assert_artifact_ref(
    ref: StoredDataRef, digest: str, finding_ref: StoredDataRef
) -> None:
    if (
        ref.data_kind != "artifact"
        or ref.record_id is not None
        or str(ref.stored_data_id) != digest
        or ref.content_hash != digest
        or (str(ref.workspace_id), str(ref.commit_id))
        != (str(finding_ref.workspace_id), str(finding_ref.commit_id))
    ):
        raise ValueError("BUNDLE_ARTIFACT_REF_INVALID")


def _ordered_files(files: tuple[BundleFile, ...]) -> tuple[BundleFile, ...]:
    paths = [item.path for item in files]
    if (
        len(paths) != len(set(path.lower() for path in paths))
        or not {"report_en.md", "report_kr.md", "evidence/provenance.json"}.issubset(
            paths
        )
        or ("poc.sh" in paths) == ("poc.py" in paths)
    ):
        raise ValueError("BUNDLE_FILES_INVALID")
    total = 0
    for item in files:
        if len(item.body) > MAX_BUNDLE_FILE_BYTES:
            raise ValueError("BUNDLE_FILE_TOO_LARGE")
        total += len(item.body)
        try:
            if item.path != "poc.sh" or not is_safe_sandbox_shell_poc(item.body):
                assert_safe_provider_text(item.body)
        except ValueError as error:
            raise ValueError("BUNDLE_FILE_UNSAFE") from error
    if total > MAX_BUNDLE_BYTES:
        raise ValueError("BUNDLE_FILES_TOO_LARGE")
    ordered = tuple(sorted(files, key=lambda item: _ORDER.index(item.path)))
    poc = next(item for item in ordered if item.path in {"poc.sh", "poc.py"})
    provenance = next(
        item for item in ordered if item.path == "evidence/provenance.json"
    )
    try:
        metadata = json.loads(provenance.body)
        poc_metadata = metadata["poc"]
        original = poc_metadata["original_sha256"]
        attachment = poc_metadata["attachment_sha256"]
        redacted = poc_metadata["redacted"]
        if (
            poc_metadata["path"] != poc.path
            or _SHA256.fullmatch(original) is None
            or attachment != _digest(poc.body)
            or not isinstance(redacted, bool)
            or redacted != (original != attachment)
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("BUNDLE_PROVENANCE_INVALID") from error
    return ordered


def _poc_metadata(files: tuple[BundleFile, ...]) -> tuple[str, bool]:
    raw = next(item.body for item in files if item.path == "evidence/provenance.json")
    poc = json.loads(raw)["poc"]
    return str(poc["original_sha256"]), bool(poc["redacted"])


def _zip_bytes(files: tuple[BundleFile, ...]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for item in files:
            info = zipfile.ZipInfo(item.path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o600 << 16
            archive.writestr(info, item.body)
    result = output.getvalue()
    if len(result) > MAX_BUNDLE_ARCHIVE_BYTES:
        raise ValueError("BUNDLE_ARCHIVE_TOO_LARGE")
    return result


def parse_bundle_manifest(
    raw: bytes, *, finding_ref: StoredDataRef
) -> ReportBundleManifest:
    if len(raw) > MAX_BUNDLE_MANIFEST_BYTES:
        raise ValueError("BUNDLE_MANIFEST_TOO_LARGE")
    try:
        manifest = ReportBundleManifest.model_validate_json(raw)
        if canonical_bytes(manifest.model_dump(mode="json")) != raw or canonical_bytes(
            manifest.finding_ref
        ) != canonical_bytes(finding_ref):
            raise ValueError("BUNDLE_MANIFEST_INVALID")
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("BUNDLE_MANIFEST_INVALID") from error
    return manifest


def _verified_member(
    entry: BundleManifestEntry, read_verified: Callable[[StoredDataRef], bytes]
) -> bytes:
    body = read_verified(entry.artifact_ref)
    if (
        len(body) != entry.size
        or len(body) > MAX_BUNDLE_FILE_BYTES
        or _digest(body) != entry.sha256
    ):
        raise ValueError("BUNDLE_FILE_HASH_MISMATCH")
    return body


def read_bundle_file(
    manifest: ReportBundleManifest,
    path: str,
    read_verified: Callable[[StoredDataRef], bytes],
) -> tuple[bytes, str]:
    """Read only one manifest-listed member from its exact artifact reference."""

    entry = next((item for item in manifest.files if item.path == path), None)
    if entry is None:
        raise ValueError("BUNDLE_FILE_NOT_LISTED")
    _assert_artifact_ref(entry.artifact_ref, entry.sha256, manifest.finding_ref)
    return _verified_member(entry, read_verified), entry.media_type


def _verify_zip(
    body: bytes,
    manifest: ReportBundleManifest,
    read_verified: Callable[[StoredDataRef], bytes] | None,
) -> None:
    try:
        files: list[BundleFile] = []
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            info = archive.infolist()
            if tuple(item.filename for item in info) != tuple(
                item.path for item in manifest.files
            ):
                raise ValueError
            for member, entry in zip(info, manifest.files, strict=True):
                if (
                    member.compress_type != zipfile.ZIP_STORED
                    or member.file_size != entry.size
                    or member.file_size > MAX_BUNDLE_FILE_BYTES
                    or member.is_dir()
                ):
                    raise ValueError
                data = archive.read(member)
                if _digest(data) != entry.sha256 or (
                    read_verified is not None
                    and data != _verified_member(entry, read_verified)
                ):
                    raise ValueError
                files.append(BundleFile(entry.path, data, entry.media_type))
        if body != _zip_bytes(tuple(files)):
            raise ValueError
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        raise ValueError("BUNDLE_ARCHIVE_INVALID") from error


def read_bundle_archive(
    manifest: ReportBundleManifest,
    archive_ref: StoredDataRef,
    read_verified: Callable[[StoredDataRef], bytes],
) -> bytes:
    """Read ZIP only when every member agrees with the manifest and CAS."""

    body = read_verified(archive_ref)
    if len(body) > MAX_BUNDLE_ARCHIVE_BYTES:
        raise ValueError("BUNDLE_ARCHIVE_INVALID")
    try:
        _assert_artifact_ref(archive_ref, _digest(body), manifest.finding_ref)
    except ValueError as error:
        raise ValueError("BUNDLE_ARCHIVE_INVALID") from error
    _verify_zip(body, manifest, read_verified)
    return body


def _open_child(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | _posix_flag("O_DIRECTORY") | _posix_flag("O_NOFOLLOW")
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise ValueError("BUNDLE_PATH_UNSAFE") from error


@contextmanager
def _bundle_directories(
    root: Path, analysis_id: str, display_id: str
) -> Iterator[tuple[_SafeDirectory, _SafeDirectory]]:
    bundle = root / "reports" / analysis_id / display_id
    evidence = bundle / "evidence"
    if not root.is_dir():
        raise ValueError("BUNDLE_PATH_UNSAFE")
    if os.name == "nt":
        identity = _capture_directory_identity(root)
        try:
            with ExitStack() as stack:
                stack.enter_context(
                    _locked_windows_directory(root, expected_identity=identity)
                )
                stack.enter_context(_locked_windows_directory(root / "reports"))
                stack.enter_context(
                    _locked_windows_directory(root / "reports" / analysis_id)
                )
                stack.enter_context(_guarded_windows_replace_directory(bundle))
                stack.enter_context(_guarded_windows_replace_directory(evidence))
                yield _SafeDirectory(bundle, None), _SafeDirectory(evidence, None)
        except ReportUnavailable as error:
            raise ValueError("BUNDLE_PATH_UNSAFE") from error
        return
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("BUNDLE_PATH_UNSAFE")
    with ExitStack() as stack:
        try:
            root_fd = os.open(
                root,
                os.O_RDONLY | _posix_flag("O_DIRECTORY") | _posix_flag("O_NOFOLLOW"),
            )
            stack.callback(os.close, root_fd)
            parent = root_fd
            for name in ("reports", analysis_id, display_id):
                parent = _open_child(parent, name)
                stack.callback(os.close, parent)
            bundle_fd = parent
            evidence_fd = _open_child(bundle_fd, "evidence")
            stack.callback(os.close, evidence_fd)
        except OSError as error:
            raise ValueError("BUNDLE_PATH_UNSAFE") from error
        yield (
            _SafeDirectory(bundle, bundle_fd),
            _SafeDirectory(evidence, evidence_fd),
        )


def _member_directory(
    bundle: _SafeDirectory, evidence: _SafeDirectory, path: str
) -> tuple[_SafeDirectory, str]:
    if path.startswith("evidence/"):
        return evidence, path.removeprefix("evidence/")
    return bundle, path


def _exists(directory: _SafeDirectory, name: str) -> bool:
    try:
        if directory.fd is None:
            return os.path.lexists(directory.path / name)
        os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _read_file(directory: _SafeDirectory, name: str, limit: int) -> bytes:
    try:
        if directory.fd is None:
            path = directory.path / name
            before = path.lstat()
            if (
                not stat.S_ISREG(before.st_mode)
                or int(getattr(before, "st_file_attributes", 0)) & 0x400
            ):
                raise ValueError("BUNDLE_PUBLISHED_FILE_INVALID")
            with path.open("rb") as stream:
                current = os.fstat(stream.fileno())
                if (before.st_dev, before.st_ino) != (
                    current.st_dev,
                    current.st_ino,
                ) or current.st_size > limit:
                    raise ValueError("BUNDLE_PUBLISHED_FILE_INVALID")
                data = stream.read(limit + 1)
        else:
            handle = os.open(
                name, os.O_RDONLY | _posix_flag("O_NOFOLLOW"), dir_fd=directory.fd
            )
            try:
                current = os.fstat(handle)
                if not stat.S_ISREG(current.st_mode) or current.st_size > limit:
                    raise ValueError("BUNDLE_PUBLISHED_FILE_INVALID")
                with os.fdopen(handle, "rb", closefd=False) as stream:
                    data = stream.read(limit + 1)
            finally:
                os.close(handle)
        if len(data) > limit:
            raise ValueError("BUNDLE_PUBLISHED_FILE_INVALID")
        return data
    except (FileNotFoundError, OSError) as error:
        raise ValueError("BUNDLE_PUBLISHED_FILE_INVALID") from error


def _write_file(directory: _SafeDirectory, name: str, body: bytes) -> None:
    if directory.fd is None:
        temporary_path = directory.path / f".{name}.{uuid4().hex}.tmp"
        try:
            with temporary_path.open("xb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, directory.path / name)
            if _read_file(directory, name, len(body)) != body:
                raise ValueError("BUNDLE_PUBLISHED_FILE_INVALID")
        finally:
            temporary_path.unlink(missing_ok=True)
        return
    temporary = f".{name}.{uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
        dir_fd=directory.fd,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(descriptor)
        os.replace(
            temporary,
            name,
            src_dir_fd=directory.fd,
            dst_dir_fd=directory.fd,
        )
        os.fsync(directory.fd)
        if _read_file(directory, name, len(body)) != body:
            raise ValueError("BUNDLE_PUBLISHED_FILE_INVALID")
    finally:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory.fd)
        except FileNotFoundError:
            pass


def publish_bundle(
    *,
    root: Path,
    analysis_id: str,
    display_id: str,
    finding_ref: StoredDataRef,
    files: tuple[BundleFile, ...],
    put_artifact: Callable[[bytes, str], StoredDataRef],
    allow_revision: bool = False,
) -> PublishedBundle:
    """Publish immutable members and ZIP; the manifest is visible last."""

    if (
        _ID.fullmatch(analysis_id) is None
        or _ID.fullmatch(display_id) is None
        or not _valid_finding_ref(finding_ref)
    ):
        raise ValueError("BUNDLE_ID_INVALID")
    ordered = _ordered_files(files)
    poc_original_sha256, poc_redacted = _poc_metadata(ordered)
    entries: list[BundleManifestEntry] = []
    for item in ordered:
        digest = _digest(item.body)
        ref = put_artifact(item.body, item.media_type)
        _assert_artifact_ref(ref, digest, finding_ref)
        entries.append(
            BundleManifestEntry(
                path=item.path,
                media_type=item.media_type,
                size=len(item.body),
                sha256=digest,
                artifact_ref=ref,
            )
        )
    manifest = ReportBundleManifest(
        schema_version=1,
        analysis_id=analysis_id,
        display_id=display_id,
        finding_ref=finding_ref,
        poc_original_sha256=poc_original_sha256,
        poc_redacted=poc_redacted,
        files=tuple(entries),
    )
    manifest_data = canonical_bytes(manifest.model_dump(mode="json"))
    if len(manifest_data) > MAX_BUNDLE_MANIFEST_BYTES:
        raise ValueError("BUNDLE_MANIFEST_TOO_LARGE")
    archive_data = _zip_bytes(ordered)
    archive_ref = put_artifact(archive_data, "application/zip")
    _assert_artifact_ref(archive_ref, _digest(archive_data), finding_ref)
    manifest_ref = put_artifact(manifest_data, "application/json")
    _assert_artifact_ref(manifest_ref, _digest(manifest_data), finding_ref)
    root = root.absolute()
    directory_names = [display_id]
    if allow_revision:
        directory_names.append(f"{display_id}-{manifest_ref.content_hash}")
    for directory_name in directory_names:
        with _bundle_directories(root, analysis_id, directory_name) as (
            bundle,
            evidence,
        ):
            if _exists(bundle, "manifest.json"):
                previous_data = _read_file(
                    bundle, "manifest.json", MAX_BUNDLE_MANIFEST_BYTES
                )
                previous = parse_bundle_manifest(previous_data, finding_ref=finding_ref)
                for previous_entry in previous.files:
                    directory, name = _member_directory(
                        bundle, evidence, previous_entry.path
                    )
                    if (
                        _digest(_read_file(directory, name, MAX_BUNDLE_FILE_BYTES))
                        != previous_entry.sha256
                    ):
                        raise ValueError("BUNDLE_PUBLISHED_FILE_INVALID")
                previous_zip = _read_file(
                    bundle, "bundle.zip", MAX_BUNDLE_ARCHIVE_BYTES
                )
                _verify_zip(previous_zip, previous, None)
                if previous_data != manifest_data:
                    if directory_name != directory_names[-1]:
                        continue
                    raise ValueError("BUNDLE_ALREADY_PUBLISHED")
                if previous_zip != archive_data:
                    raise ValueError("BUNDLE_PUBLISHED_FILE_INVALID")
            else:
                for item in ordered:
                    directory, name = _member_directory(bundle, evidence, item.path)
                    _write_file(directory, name, item.body)
                _write_file(bundle, "bundle.zip", archive_data)
                _write_file(bundle, "manifest.json", manifest_data)
        return PublishedBundle(
            manifest_ref, archive_ref, root / "reports" / analysis_id / directory_name
        )
    raise AssertionError("unreachable")
