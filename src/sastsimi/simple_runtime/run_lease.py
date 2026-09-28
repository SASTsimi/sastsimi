"""Crash-released, per-analysis lock for local analyze/resume processes."""

from __future__ import annotations

import errno
import hashlib
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO


class AnalysisRunBusy(RuntimeError):
    code = "ANALYSIS_ALREADY_RUNNING"


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


@contextmanager
def analysis_run_lease(data_dir: Path, analysis_id: str) -> Iterator[None]:
    """Prevent another process from repeating work on this analysis.

    The lock file remains in place; the OS releases the byte-range lock on
    process exit, including an abrupt crash. Its name is derived from a digest
    so an external analysis ID cannot select a filesystem path.
    """

    digest = hashlib.sha256(analysis_id.encode("utf-8")).hexdigest()
    path = data_dir / "db" / "analysis-leases" / f"{digest}.lock"
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
