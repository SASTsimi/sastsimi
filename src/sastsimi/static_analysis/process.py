"""Shell-free, deadline-bound process execution for static-analysis adapters."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sys
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict
from pathlib import Path
from threading import Lock
from typing import BinaryIO, Protocol, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.ports.dto import (
    AttemptOutputBudgetPort,
    CancellationResult,
    ProcessReceipt,
    ProcessResult,
    ProcessSpec,
)

from .process_windows import BackendExecution as BackendExecution
from .process_windows import OutputSink as OutputSink
from .process_windows import WindowsProcessBackend as WindowsProcessBackend


class ProcessBackend(Protocol):
    async def run(
        self,
        spec: ProcessSpec,
        timeout_ms: int,
        stdout: OutputSink,
        stderr: OutputSink,
        cancel_event: asyncio.Event,
    ) -> BackendExecution: ...

    async def cancel(self, attempt_id: str) -> bool: ...


async def _complete_cleanup[ResultT](awaitable: Awaitable[ResultT]) -> ResultT:
    """Finish cleanup even when the caller receives repeated cancellation."""
    cleanup = asyncio.ensure_future(awaitable)
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            continue
    return cleanup.result()


class AttemptOutputBudget:
    """Explicit, thread-safe output allocation shared by one work attempt."""

    def __init__(self, *, attempt_id: str, limit_bytes: int) -> None:
        if not attempt_id or limit_bytes <= 0:
            raise ValueError("PROCESS_OUTPUT_LIMIT_INVALID")
        self.attempt_id = attempt_id
        self.limit_bytes = limit_bytes
        self._allocations: dict[tuple[str, str], int] = {}
        self._used_bytes = 0
        self._lock = Lock()

    def grow(self, key: tuple[str, str], desired_bytes: int) -> int:
        if desired_bytes < 0:
            raise ValueError("PROCESS_OUTPUT_LIMIT_INVALID")
        with self._lock:
            current = self._allocations.get(key, 0)
            if desired_bytes <= current:
                return current
            granted = min(desired_bytes - current, self.limit_bytes - self._used_bytes)
            updated = current + granted
            self._allocations[key] = updated
            self._used_bytes += granted
            return updated

    @property
    def used_bytes(self) -> int:
        with self._lock:
            return self._used_bytes


class _BoundedSpool:
    def __init__(
        self,
        path: Path,
        limit: int,
        *,
        tail: bool,
        budget: AttemptOutputBudgetPort | None = None,
        budget_key: tuple[str, str] | None = None,
    ) -> None:
        self.path = path
        self.limit = limit
        self.tail = tail
        self.budget = budget
        self.budget_key = budget_key
        self.truncated = False
        self._data = bytearray()
        self._file: BinaryIO = path.open("xb")

    def write(self, data: bytes) -> None:
        if not data:
            return
        desired = min(self.limit, len(self._data) + len(data))
        allowed = desired
        if self.budget is not None:
            if self.budget_key is None:
                raise ValueError("PROCESS_OUTPUT_BUDGET_KEY_REQUIRED")
            allowed = self.budget.grow(self.budget_key, desired)
        if self.tail:
            combined = bytes(self._data) + data
            if len(combined) > allowed:
                self.truncated = True
                combined = combined[-allowed:] if allowed else b""
            self._data[:] = combined
            return
        remaining = allowed - len(self._data)
        if len(data) > remaining:
            self.truncated = True
        if remaining > 0:
            self._data.extend(data[:remaining])

    def close(self) -> None:
        self._file.write(self._data)
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.close()

    @property
    def data(self) -> bytes:
        return bytes(self._data)


class PosixProcessBackend:
    def __init__(
        self,
        *,
        spawn: Callable[..., object] | None = None,
        drain_timeout_seconds: float = 1.0,
        termination_timeout_seconds: float = 1.0,
    ) -> None:
        if drain_timeout_seconds <= 0:
            raise ValueError("PROCESS_DRAIN_TIMEOUT_INVALID")
        if termination_timeout_seconds <= 0:
            raise ValueError("PROCESS_TERMINATION_TIMEOUT_INVALID")
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._cancelled: set[str] = set()
        self._spawn = spawn or asyncio.create_subprocess_exec
        self._registry_lock = asyncio.Lock()
        self._drain_timeout_seconds = drain_timeout_seconds
        self._termination_timeout_seconds = termination_timeout_seconds

    async def run(
        self,
        spec: ProcessSpec,
        timeout_ms: int,
        stdout: OutputSink,
        stderr: OutputSink,
        cancel_event: asyncio.Event,
    ) -> BackendExecution:
        async def spawn_and_register() -> tuple[
            asyncio.subprocess.Process | None, bool
        ]:
            async with self._registry_lock:
                if cancel_event.is_set() or spec.attempt_id in self._cancelled:
                    return None, True
                spawned = self._spawn(
                    *spec.argv,
                    cwd=spec.cwd,
                    env=dict(spec.env),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
                process = cast(
                    asyncio.subprocess.Process,
                    await spawned,  # type: ignore[misc]
                )
                self._processes[spec.attempt_id] = process
                return process, (
                    cancel_event.is_set() or spec.attempt_id in self._cancelled
                )

        spawn_task = asyncio.create_task(spawn_and_register())
        spawn_cancellation: asyncio.CancelledError | None = None
        try:
            process, cancelled_after_spawn = await asyncio.shield(spawn_task)
        except asyncio.CancelledError as error:
            spawn_cancellation = error
            cancel_event.set()
            try:
                process, cancelled_after_spawn = await _complete_cleanup(spawn_task)
            except BaseException as spawn_error:
                raise spawn_error from error
        if process is None:
            if spawn_cancellation is not None:
                raise spawn_cancellation
            return BackendExecution(None, False, True)

        async def pump(stream: asyncio.StreamReader | None, sink: OutputSink) -> None:
            if stream is None:
                return
            while data := await stream.read(64 * 1024):
                sink.write(data)

        readers = (
            asyncio.create_task(pump(process.stdout, stdout)),
            asyncio.create_task(pump(process.stderr, stderr)),
        )

        async def drain_output() -> None:
            await asyncio.gather(*readers)

        drain_task = asyncio.create_task(drain_output())
        timed_out = False
        wait_error: BaseException | None = spawn_cancellation
        terminate_required = cancelled_after_spawn or spawn_cancellation is not None
        if not terminate_required:
            try:
                await asyncio.wait_for(process.wait(), timeout_ms / 1_000)
            except asyncio.CancelledError as error:
                wait_error = error
                terminate_required = True
                cancel_event.set()
            except TimeoutError:
                timed_out = True
                terminate_required = True
            except BaseException as error:
                wait_error = error
                terminate_required = True

        async def finalize() -> None:
            nonlocal timed_out
            try:
                if terminate_required:
                    await self._terminate(process)
                else:
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(drain_task),
                            self._drain_timeout_seconds,
                        )
                    except TimeoutError:
                        timed_out = True
                        await self._terminate(process)
                if not drain_task.done():
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(drain_task),
                            self._drain_timeout_seconds,
                        )
                    except TimeoutError as error:
                        for reader in readers:
                            reader.cancel()
                        await asyncio.gather(*readers, return_exceptions=True)
                        raise TimeoutError("PROCESS_OUTPUT_DRAIN_TIMEOUT") from error
                else:
                    drain_task.result()
            finally:
                async with self._registry_lock:
                    if self._processes.get(spec.attempt_id) is process:
                        self._processes.pop(spec.attempt_id, None)

        finalize_task = asyncio.create_task(finalize())
        try:
            await asyncio.shield(finalize_task)
        except asyncio.CancelledError as error:
            cancel_event.set()
            if wait_error is None:
                wait_error = error
            cleanup_error: BaseException | None = None
            if not terminate_required:
                try:
                    await _complete_cleanup(self._terminate(process))
                except BaseException as failure:
                    cleanup_error = failure
            try:
                await _complete_cleanup(finalize_task)
            except BaseException as failure:
                if cleanup_error is None:
                    cleanup_error = failure
            if cleanup_error is not None:
                raise cleanup_error from error
        if wait_error is not None:
            raise wait_error
        return BackendExecution(
            return_code=process.returncode,
            timed_out=timed_out,
            cancelled=(
                cancel_event.is_set()
                or cancelled_after_spawn
                or spec.attempt_id in self._cancelled
            ),
        )

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        # A direct child can exit on SIGTERM while a descendant in the same
        # process group ignores it. Always check the group again after the
        # grace period instead of treating the parent's exit as tree cleanup.
        killpg = cast(Callable[[int, int], None], vars(os)["killpg"])
        try:
            killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        await asyncio.sleep(0.5)
        try:
            sigkill = cast(int, vars(signal)["SIGKILL"])
            killpg(process.pid, sigkill)
        except ProcessLookupError:
            pass
        if process.returncode is None:
            reap_task = asyncio.create_task(process.wait())
            try:
                await asyncio.wait_for(
                    asyncio.shield(reap_task), self._termination_timeout_seconds
                )
            except TimeoutError as error:
                reap_task.cancel()
                await asyncio.gather(reap_task, return_exceptions=True)
                raise TimeoutError("PROCESS_TREE_TERMINATION_TIMEOUT") from error

    async def cancel(self, attempt_id: str) -> bool:
        async with self._registry_lock:
            first = attempt_id not in self._cancelled
            self._cancelled.add(attempt_id)
            process = self._processes.get(attempt_id)
        if process is None:
            return first
        cleanup = asyncio.create_task(self._terminate(process))
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            await _complete_cleanup(cleanup)
            raise
        return first


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _link_like(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _receipt_bytes(receipt: ProcessReceipt) -> bytes:
    return canonical_bytes(asdict(receipt))


def process_command_fingerprint(spec: ProcessSpec) -> str:
    """Bind a receipt to the exact shell-free command boundary."""
    command = {
        "argv": spec.argv,
        "cwd": str(spec.cwd),
        "env": spec.env,
    }
    return hashlib.sha256(canonical_bytes(command)).hexdigest()


def validate_receipt(path: Path, spec: ProcessSpec) -> ProcessReceipt:
    try:
        if path.suffix != ".json" or not path.is_file() or path.is_symlink():
            raise ValueError
        raw = path.read_bytes()
        value = json.loads(raw)
        expected = set(ProcessReceipt.__dataclass_fields__)
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError
        receipt = ProcessReceipt(**value)
        if (
            receipt.action_id != spec.deadline.action_id
            or receipt.command_kind != spec.command_kind
            or receipt.invocation_id != spec.invocation_id
            or receipt.attempt_id != spec.attempt_id
            or receipt.command_fingerprint != process_command_fingerprint(spec)
        ):
            raise ValueError
        for name, size, digest in (
            (receipt.stdout_name, receipt.stdout_size, receipt.stdout_sha256),
            (receipt.stderr_name, receipt.stderr_size, receipt.stderr_sha256),
        ):
            if Path(name).name != name:
                raise ValueError
            output = spec.attempt_output_dir / name
            if not output.is_file() or output.is_symlink():
                raise ValueError
            if output.stat().st_size != size or _sha256(output) != digest:
                raise ValueError
        return receipt
    except (OSError, TypeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("PROCESS_RECEIPT_INVALID") from error


class SafeProcessRunner:
    def __init__(
        self,
        *,
        action_id: str,
        attempt_id: str,
        workspace_root: Path,
        output_root: Path,
        executable: Path,
        output_budget: AttemptOutputBudgetPort,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        backend: ProcessBackend | None = None,
    ) -> None:
        self.action_id = action_id
        self.attempt_id = attempt_id
        if _link_like(workspace_root) or _link_like(output_root):
            raise ValueError("PROCESS_PATH_LINK_FORBIDDEN")
        self.workspace_root = workspace_root.resolve(strict=True)
        self.output_root = output_root.resolve(strict=True)
        # Virtual environments normally expose their interpreter through a
        # symlink. Bind that trusted entry point to its immutable resolved path;
        # workspace and output paths remain strictly link-free.
        self.executable = executable.resolve(strict=True)
        if output_budget.attempt_id != attempt_id:
            raise ValueError("PROCESS_OUTPUT_BUDGET_ATTEMPT_MISMATCH")
        self.output_budget = output_budget
        if not self.workspace_root.is_dir() or not self.output_root.is_dir():
            raise ValueError("PROCESS_ROOT_INVALID")
        if not self.executable.is_file():
            raise ValueError("PROCESS_EXECUTABLE_INVALID")
        if _inside(self.output_root, self.workspace_root):
            raise ValueError("PROCESS_OUTPUT_INSIDE_WORKSPACE")
        self.monotonic_ns = monotonic_ns
        if backend is None:
            if sys.platform == "win32":
                backend = WindowsProcessBackend()
            else:
                backend = PosixProcessBackend()
        self.backend = backend
        self._cancelled: set[str] = set()
        self._cancel_events: Mapping[str, asyncio.Event] = {}

    def _validate(self, spec: ProcessSpec) -> None:
        if spec.deadline.action_id != self.action_id:
            raise ValueError("PROCESS_ACTION_MISMATCH")
        if spec.attempt_id != self.attempt_id:
            raise ValueError("PROCESS_ATTEMPT_MISMATCH")
        if not spec.argv or any("\x00" in item for item in spec.argv):
            raise ValueError("PROCESS_ARGV_INVALID")
        if any("\x00" in key or "\x00" in value for key, value in spec.env):
            raise ValueError("PROCESS_ENV_INVALID")
        if _link_like(spec.cwd) or _link_like(spec.attempt_output_dir):
            raise ValueError("PROCESS_PATH_LINK_FORBIDDEN")
        if Path(spec.argv[0]).resolve(strict=True) != self.executable:
            raise ValueError("PROCESS_EXECUTABLE_MISMATCH")
        if _inside(self.executable, self.workspace_root):
            raise ValueError("EXECUTABLE_INSIDE_WORKSPACE")
        if spec.cwd.resolve(strict=True) != self.workspace_root:
            raise ValueError("PROCESS_CWD_MISMATCH")
        if spec.attempt_output_dir.resolve(strict=True) != self.output_root:
            raise ValueError("PROCESS_OUTPUT_ROOT_MISMATCH")
        if len(dict(spec.env)) != len(spec.env):
            raise ValueError("PROCESS_ENV_DUPLICATE")
        if (
            min(
                spec.stdout_limit_bytes,
                spec.stderr_limit_bytes,
                spec.attempt_output_limit_bytes,
            )
            <= 0
        ):
            raise ValueError("PROCESS_OUTPUT_LIMIT_INVALID")
        if spec.attempt_output_limit_bytes != self.output_budget.limit_bytes:
            raise ValueError("PROCESS_OUTPUT_BUDGET_LIMIT_MISMATCH")

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self._validate(spec)
        now_ns = self.monotonic_ns()
        remaining_ms = spec.deadline.remaining_ms(now_ns)
        if spec.attempt_id in self._cancelled:
            return self._without_spawn(spec, "CANCELLED", now_ns)
        if remaining_ms == 0:
            return self._without_spawn(spec, "TIMED_OUT", now_ns)

        prefix = hashlib.sha256(spec.invocation_id.encode("utf-8")).hexdigest()[:24]
        stdout_spool = _BoundedSpool(
            self.output_root / f"{prefix}.stdout",
            spec.stdout_limit_bytes,
            tail=False,
            budget=self.output_budget,
            budget_key=(spec.invocation_id, "stdout"),
        )
        stderr_spool = _BoundedSpool(
            self.output_root / f"{prefix}.stderr",
            spec.stderr_limit_bytes,
            tail=True,
            budget=self.output_budget,
            budget_key=(spec.invocation_id, "stderr"),
        )
        event = asyncio.Event()
        self._cancel_events = {**self._cancel_events, spec.attempt_id: event}
        spools_closed = False
        try:
            outcome = await self.backend.run(
                spec, remaining_ms, stdout_spool, stderr_spool, event
            )
        except asyncio.CancelledError:
            event.set()
            self._cancelled.add(spec.attempt_id)
            await _complete_cleanup(self.backend.cancel(spec.attempt_id))
            stdout_spool.close()
            stderr_spool.close()
            spools_closed = True
            self._finish(
                spec,
                "CANCELLED",
                None,
                now_ns,
                stdout_spool,
                stderr_spool,
            )
            raise
        finally:
            if not spools_closed:
                stdout_spool.close()
                stderr_spool.close()
            self._cancel_events = {
                key: value
                for key, value in self._cancel_events.items()
                if key != spec.attempt_id
            }
        if event.is_set() or outcome.cancelled:
            state = "CANCELLED"
        elif outcome.timed_out:
            state = "TIMED_OUT"
        elif outcome.return_code == 0:
            state = "SUCCEEDED"
        else:
            state = "FAILED"
        return self._finish(
            spec,
            state,
            outcome.return_code,
            now_ns,
            stdout_spool,
            stderr_spool,
        )

    def _without_spawn(
        self, spec: ProcessSpec, outcome: str, started_ns: int
    ) -> ProcessResult:
        prefix = hashlib.sha256(spec.invocation_id.encode("utf-8")).hexdigest()[:24]
        stdout = _BoundedSpool(self.output_root / f"{prefix}.stdout", 0, tail=False)
        stderr = _BoundedSpool(self.output_root / f"{prefix}.stderr", 0, tail=True)
        stdout.close()
        stderr.close()
        return self._finish(spec, outcome, None, started_ns, stdout, stderr)

    def _finish(
        self,
        spec: ProcessSpec,
        outcome: str,
        return_code: int | None,
        started_ns: int,
        stdout: _BoundedSpool,
        stderr: _BoundedSpool,
    ) -> ProcessResult:
        finished_ns = self.monotonic_ns()
        elapsed_ms = max(0, (finished_ns - started_ns) // 1_000_000)
        allowed_outcomes = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"}
        if outcome not in allowed_outcomes:
            raise ValueError("PROCESS_OUTCOME_INVALID")
        receipt = ProcessReceipt(
            action_id=spec.deadline.action_id,
            invocation_id=spec.invocation_id,
            command_kind=spec.command_kind,
            attempt_id=spec.attempt_id,
            command_fingerprint=process_command_fingerprint(spec),
            outcome=outcome,  # type: ignore[arg-type]
            return_code=return_code,
            stdout_name=stdout.path.name,
            stdout_size=len(stdout.data),
            stdout_sha256=hashlib.sha256(stdout.data).hexdigest(),
            stderr_name=stderr.path.name,
            stderr_size=len(stderr.data),
            stderr_sha256=hashlib.sha256(stderr.data).hexdigest(),
            elapsed_ms=elapsed_ms,
        )
        target = self.output_root / f"{stdout.path.stem}.receipt.json"
        temporary = target.with_suffix(".json.tmp")
        with temporary.open("xb") as stream:
            stream.write(_receipt_bytes(receipt))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(target)
        validate_receipt(target, spec)
        return ProcessResult(
            outcome=receipt.outcome,
            return_code=return_code,
            stdout=stdout.data,
            stderr_tail=stderr.data,
            stdout_truncated=stdout.truncated,
            stderr_truncated=stderr.truncated,
            elapsed_ms=elapsed_ms,
            receipt=receipt,
            receipt_path=target,
        )

    async def cancel(self, attempt_id: str) -> CancellationResult:
        if attempt_id != self.attempt_id or attempt_id in self._cancelled:
            return CancellationResult(False, "Attempt is not active")
        self._cancelled.add(attempt_id)
        event = self._cancel_events.get(attempt_id)
        if event is not None:
            event.set()
        cleanup = asyncio.create_task(self.backend.cancel(attempt_id))
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            await _complete_cleanup(cleanup)
            raise
        return CancellationResult(True, None)
