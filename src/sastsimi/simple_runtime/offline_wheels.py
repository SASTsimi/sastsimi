"""Fail-closed import of an operator-approved, offline wheel archive."""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository

MAX_WHEEL_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_WHEEL_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_WHEEL_FILES = 20_000
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SECRET_NAME = re.compile(
    r"(?i)(?:^|[-_.])(?:secret|password|api[-_]?key|token)(?:[-_.]|$)"
)


@dataclass(frozen=True, slots=True)
class VerifiedWheelBundle:
    archive_ref: StoredDataRef
    archive_sha256: str
    wheel_names: tuple[str, ...]


def _read_exact_archive(path: Path) -> bytes:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
        ):
            raise ValueError("WHEEL_ARCHIVE_NOT_REGULAR")
        if before.st_size > MAX_WHEEL_ARCHIVE_BYTES:
            raise ValueError("WHEEL_ARCHIVE_TOO_LARGE")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
        )
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (
                before.st_dev,
                before.st_ino,
                before.st_size,
            ) != (opened.st_dev, opened.st_ino, opened.st_size):
                raise ValueError("WHEEL_ARCHIVE_CHANGED")
            raw = stream.read(MAX_WHEEL_ARCHIVE_BYTES + 1)
        if len(raw) > MAX_WHEEL_ARCHIVE_BYTES:
            raise ValueError("WHEEL_ARCHIVE_TOO_LARGE")
        after = path.lstat()
        if not stat.S_ISREG(after.st_mode) or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("WHEEL_ARCHIVE_CHANGED")
        return raw
    except (OSError, RuntimeError) as error:
        raise ValueError("WHEEL_ARCHIVE_NOT_REGULAR") from error


def _safe_member_name(name: str) -> bool:
    return bool(
        name
        and name == Path(name).name
        and "/" not in name
        and "\\" not in name
        and ":" not in name
        and "\x00" not in name
        and not name.startswith(".")
        and not _SECRET_NAME.search(name)
    )


def _validate_wheel_zip(raw: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
            infos = wheel.infolist()
            if not infos or len(infos) > MAX_WHEEL_FILES:
                raise ValueError("WHEEL_ARCHIVE_INVALID")
            expanded = 0
            files: set[str] = set()
            for info in infos:
                name = info.filename
                parts = name.rstrip("/").split("/")
                if (
                    not name
                    or name.startswith("/")
                    or "\\" in name
                    or ":" in name
                    or any(part in {"", ".", ".."} for part in parts)
                    or stat.S_ISLNK(info.external_attr >> 16)
                ):
                    raise ValueError("WHEEL_ARCHIVE_INVALID")
                expanded += info.file_size
                if expanded > MAX_WHEEL_EXPANDED_BYTES:
                    raise ValueError("WHEEL_ARCHIVE_INVALID")
                if not info.is_dir():
                    files.add(name)
            if not any(name.endswith(".dist-info/WHEEL") for name in files) or not any(
                name.endswith(".dist-info/METADATA") for name in files
            ):
                raise ValueError("WHEEL_ARCHIVE_INVALID")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise ValueError("WHEEL_ARCHIVE_INVALID") from error


def require_target_compatible_wheels(
    wheel_names: tuple[str, ...], target_tags: frozenset[str] | None
) -> None:
    """Unknown Linux target allows only the explicitly universal wheel tag."""

    for name in wheel_names:
        try:
            _project, _version, _build, tags = parse_wheel_filename(name)
        except InvalidWheelFilename as error:
            raise ValueError("WHEEL_ARCHIVE_INVALID") from error
        names = {str(tag) for tag in tags}
        if "py3-none-any" not in names and (
            target_tags is None or not names.intersection(target_tags)
        ):
            raise ValueError("WHEEL_TARGET_INCOMPATIBLE")


def import_wheel_bundle(
    path: Path,
    expected_sha256: str,
    artifacts: SimpleArtifactRepository,
    *,
    target_tags: frozenset[str] | None = None,
) -> VerifiedWheelBundle:
    """Validate all bytes and members before writing the exact archive to CAS."""

    if _SHA256.fullmatch(expected_sha256) is None:
        raise ValueError("WHEEL_ARCHIVE_DIGEST_INVALID")
    raw = _read_exact_archive(path)
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected_sha256:
        raise ValueError("WHEEL_ARCHIVE_DIGEST_MISMATCH")
    names: list[str] = []
    folded: set[str] = set()
    expanded = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            for member in archive:
                name = member.name
                if (
                    not member.isfile()
                    or member.pax_headers
                    or not _safe_member_name(name)
                    or not name.endswith(".whl")
                    or name.casefold() in folded
                    or len(names) >= MAX_WHEEL_FILES
                    or member.size < 1
                ):
                    raise ValueError("WHEEL_ARCHIVE_INVALID")
                expanded += member.size
                if expanded > MAX_WHEEL_EXPANDED_BYTES:
                    raise ValueError("WHEEL_ARCHIVE_INVALID")
                try:
                    parse_wheel_filename(name)
                except InvalidWheelFilename as error:
                    raise ValueError("WHEEL_ARCHIVE_INVALID") from error
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("WHEEL_ARCHIVE_INVALID")
                wheel_bytes = stream.read(member.size + 1)
                if len(wheel_bytes) != member.size:
                    raise ValueError("WHEEL_ARCHIVE_INVALID")
                _validate_wheel_zip(wheel_bytes)
                names.append(name)
                folded.add(name.casefold())
    except (OSError, EOFError, tarfile.TarError) as error:
        raise ValueError("WHEEL_ARCHIVE_INVALID") from error
    if not names:
        raise ValueError("WHEEL_ARCHIVE_INVALID")
    ordered = tuple(sorted(names))
    require_target_compatible_wheels(ordered, target_tags)
    ref = artifacts.put_bytes(raw, "application/x-tar")
    return VerifiedWheelBundle(ref, actual, ordered)
