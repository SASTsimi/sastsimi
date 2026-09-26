"""Direct bootstrap process adapter assembled at the composition boundary."""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections.abc import Sequence
from pathlib import Path

from sastsimi.ports.dto import MonotonicActionDeadline, ProcessSpec
from sastsimi.simple_runtime.bootstrap_stages import ProcessResult
from sastsimi.static_analysis.process import PosixProcessBackend, WindowsProcessBackend


class _LimitedOutput:
    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._data = bytearray()

    def write(self, chunk: bytes) -> None:
        remaining = self._limit - len(self._data)
        if remaining > 0:
            self._data.extend(chunk[:remaining])

    @property
    def data(self) -> bytes:
        return bytes(self._data)


class LocalProcessExecutor:
    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: int,
    ) -> ProcessResult:
        attempt_id = uuid.uuid4().hex
        started_ns = time.monotonic_ns()
        directory = cwd or Path.cwd()
        spec = ProcessSpec(
            invocation_id=attempt_id,
            command_kind="SIMPLE_BOOTSTRAP",
            attempt_id=attempt_id,
            argv=tuple(argv),
            cwd=directory,
            env=tuple(self._environment().items()),
            attempt_output_dir=directory,
            stdout_limit_bytes=32 * 1024 * 1024,
            stderr_limit_bytes=1024 * 1024,
            attempt_output_limit_bytes=33 * 1024 * 1024,
            deadline=MonotonicActionDeadline(
                action_id=attempt_id,
                started_ns=started_ns,
                expires_ns=started_ns + timeout_seconds * 1_000_000_000,
            ),
        )
        stdout = _LimitedOutput(32 * 1024 * 1024)
        stderr = _LimitedOutput(1024 * 1024)
        backend = WindowsProcessBackend() if os.name == "nt" else PosixProcessBackend()
        result = await backend.run(
            spec, timeout_seconds * 1000, stdout, stderr, asyncio.Event()
        )
        if result.timed_out:
            raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
        return ProcessResult(
            returncode=result.return_code or 0,
            stdout=stdout.data,
            stderr=stderr.data,
        )

    @staticmethod
    def _environment() -> dict[str, str]:
        allowed = {
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "HOME",
            "USERPROFILE",
            "LANG",
            "LC_ALL",
        }
        return {key: value for key, value in os.environ.items() if key in allowed}


__all__ = ["LocalProcessExecutor"]
