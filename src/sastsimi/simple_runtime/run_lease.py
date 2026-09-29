"""Crash-released, per-analysis lock for local analyze/resume processes."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO


class AnalysisRunBusy(RuntimeError):
    code = "ANALYSIS_ALREADY_RUNNING"


def _lease_path(data_dir: Path, analysis_id: str) -> Path:
    digest = hashlib.sha256(analysis_id.encode("utf-8")).hexdigest()
    return data_dir / "db" / "analysis-leases" / f"{digest}.lock"


def _try_lock(handle: BinaryIO) -> bool:
    handle.seek(0)
    try:
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EAGAIN} or getattr(
            error, "winerror", None
        ) in {33, 36}:
            return False
        raise
    return True


def _unlock(handle: BinaryIO) -> None:
    handle.seek(0)
    if sys.platform == "win32":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def analysis_run_lease_active(data_dir: Path, analysis_id: str) -> bool | None:
    """Probe an existing OS lock without creating or writing the lease file.

    None means the lock cannot be checked safely, not that the run is idle.
    """

    path = _lease_path(data_dir, analysis_id)
    try:
        parent = path.parent.resolve(strict=True)
        if not parent.is_relative_to(data_dir.resolve(strict=True)):
            return None
        before = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_size < 1:
        return None
    try:
        descriptor = os.open(path, os.O_RDONLY)
        with os.fdopen(descriptor, "rb", buffering=0) as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                return None
            if not _try_lock(handle):
                return True
            try:
                return False
            finally:
                _unlock(handle)
    except OSError:
        return None


@contextmanager
def analysis_run_lease(data_dir: Path, analysis_id: str) -> Iterator[None]:
    """Prevent another process from repeating work on this analysis.

    The lock file remains in place; the OS releases the byte-range lock on
    process exit, including an abrupt crash. Its name is derived from a digest
    so an external analysis ID cannot select a filesystem path.
    """

    path = _lease_path(data_dir, analysis_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "r+b", buffering=0) as handle:
        if os.fstat(descriptor).st_size == 0:
            handle.write(b"\0")
            os.fsync(descriptor)
        if not _try_lock(handle):
            raise AnalysisRunBusy("Another process is running this analysis")
        try:
            yield
        finally:
            _unlock(handle)
