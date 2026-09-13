from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.ports.dto import MonotonicActionDeadline, ProcessSpec


class FakeBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[ProcessSpec, int]] = []
        self.stdout = b""
        self.stderr = b""
        self.return_code = 0
        self.cancelled: set[str] = set()
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.block = False

    async def run(
        self,
        spec: ProcessSpec,
        timeout_ms: int,
        stdout: Any,
        stderr: Any,
        cancel_event: asyncio.Event,
    ) -> Any:
        from sastsimi.static_analysis.process import BackendExecution

        self.calls.append((spec, timeout_ms))
        self.started.set()
        if self.block:
            await self.release.wait()
        stdout.write(self.stdout)
        stderr.write(self.stderr)
        return BackendExecution(
            return_code=self.return_code,
            timed_out=False,
            cancelled=cancel_event.is_set(),
        )

    async def cancel(self, attempt_id: str) -> bool:
        first = attempt_id not in self.cancelled
        self.cancelled.add(attempt_id)
        self.release.set()
        return first


class _BlockingCancelBackend(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.block = True
        self.cancel_started = asyncio.Event()
        self.cancel_release = asyncio.Event()

    async def cancel(self, attempt_id: str) -> bool:
        self.cancel_started.set()
        await self.cancel_release.wait()
        return await super().cancel(attempt_id)


class DiscardSink:
    def write(self, data: bytes) -> None:
        del data


class _BlockingStream:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = False

    async def read(self, size: int) -> bytes:
        del size
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return b""


class _BlockingProcess:
    def __init__(self) -> None:
        self.pid = 1
        self.returncode: int | None = None
        self.stdout = _BlockingStream()
        self.stderr = _BlockingStream()
        self._wait = asyncio.Event()

    async def wait(self) -> int:
        await self._wait.wait()
        return 0


def spec(root: Path, executable: Path, *, invocation: str = "invoke-1") -> ProcessSpec:
    output = root / "attempt"
    output.mkdir(parents=True, exist_ok=True)
    return ProcessSpec(
        invocation_id=invocation,
        command_kind="fixture",
        attempt_id="attempt-1",
        argv=(str(executable), "a; echo injected", "$(whoami)"),
        cwd=root / "workspace",
        env=(("SAFE_KEY", "safe value"),),
        attempt_output_dir=output,
        stdout_limit_bytes=5,
        stderr_limit_bytes=4,
        attempt_output_limit_bytes=64,
        deadline=MonotonicActionDeadline(
            action_id="action-1", started_ns=0, expires_ns=10_000_000_000
        ),
    )


def output_budget(limit: int = 64) -> Any:
    from sastsimi.static_analysis.process import AttemptOutputBudget

    return AttemptOutputBudget(attempt_id="attempt-1", limit_bytes=limit)


def test_command_fingerprint_binds_argv_cwd_and_environment(tmp_path: Path) -> None:
    from sastsimi.static_analysis.process import process_command_fingerprint

    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    (tmp_path / "workspace").mkdir()
    command = spec(tmp_path, executable)

    fingerprint = process_command_fingerprint(command)

    assert len(fingerprint) == 64
    assert (
        process_command_fingerprint(replace(command, argv=(*command.argv, "x")))
        != fingerprint
    )
    assert process_command_fingerprint(replace(command, cwd=tmp_path)) != fingerprint
    assert (
        process_command_fingerprint(replace(command, env=(("SAFE_KEY", "other"),)))
        != fingerprint
    )


@pytest.mark.asyncio
async def test_runner_preserves_arguments_and_uses_only_explicit_environment(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (tmp_path / "attempt").mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    backend = FakeBackend()
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=tmp_path / "attempt",
        executable=executable,
        monotonic_ns=lambda: 1_000_000,
        backend=backend,
        output_budget=output_budget(),
    )

    result = await runner.run(spec(tmp_path, executable))

    assert result.outcome == "SUCCEEDED"
    observed, _ = backend.calls[0]
    assert observed.argv[1:] == ("a; echo injected", "$(whoami)")
    assert dict(observed.env) == {"SAFE_KEY": "safe value"}
    assert observed.cwd == workspace


@pytest.mark.asyncio
async def test_runner_rejects_executable_inside_workspace_before_backend(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (tmp_path / "attempt").mkdir()
    executable = workspace / "tool.exe"
    executable.write_bytes(b"fixture")
    backend = FakeBackend()
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=tmp_path / "attempt",
        executable=executable,
        monotonic_ns=lambda: 0,
        backend=backend,
        output_budget=output_budget(),
    )
    with pytest.raises(ValueError, match="EXECUTABLE_INSIDE_WORKSPACE"):
        await runner.run(spec(tmp_path, executable))
    assert backend.calls == []


@pytest.mark.asyncio
async def test_runner_uses_one_deadline_caps_output_and_writes_safe_receipt(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner, validate_receipt

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (tmp_path / "attempt").mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    ticks = iter((1_000_000_000, 3_000_000_000, 4_000_000_000, 5_000_000_000))
    backend = FakeBackend()
    backend.stdout = b"0123456789"
    backend.stderr = b"abcdefghij"
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=tmp_path / "attempt",
        executable=executable,
        monotonic_ns=lambda: next(ticks),
        backend=backend,
        output_budget=output_budget(),
    )
    first = spec(tmp_path, executable)
    second = replace(first, invocation_id="invoke-2")

    result = await runner.run(first)
    await runner.run(second)

    assert [remaining for _, remaining in backend.calls] == [9_000, 6_000]
    assert result.stdout == b"01234"
    assert result.stderr_tail == b"ghij"
    assert result.stdout_truncated and result.stderr_truncated
    assert validate_receipt(result.receipt_path, first) == result.receipt
    payload = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    assert "argv" not in payload and "env" not in payload
    assert str(tmp_path) not in result.receipt_path.read_text(encoding="utf-8")
    torn = result.receipt_path.with_name("torn.json.tmp")
    torn.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="PROCESS_RECEIPT_INVALID"):
        validate_receipt(torn, first)


@pytest.mark.asyncio
async def test_expired_and_cancelled_attempts_never_spawn_again(tmp_path: Path) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (tmp_path / "attempt").mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    backend = FakeBackend()
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=tmp_path / "attempt",
        executable=executable,
        monotonic_ns=lambda: 11_000_000_000,
        backend=backend,
        output_budget=output_budget(),
    )
    expired = await runner.run(spec(tmp_path, executable))
    assert expired.outcome == "TIMED_OUT"
    assert backend.calls == []

    assert (await runner.cancel("attempt-1")).cancelled is True
    assert (await runner.cancel("attempt-1")).cancelled is False
    cancelled = await runner.run(spec(tmp_path, executable, invocation="invoke-2"))
    assert cancelled.outcome == "CANCELLED"
    assert backend.calls == []


@pytest.mark.asyncio
async def test_cancel_is_attempt_scoped(tmp_path: Path) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (tmp_path / "attempt").mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    backend = FakeBackend()
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=tmp_path / "attempt",
        executable=executable,
        monotonic_ns=lambda: 0,
        backend=backend,
        output_budget=output_budget(),
    )
    assert (await runner.cancel("other-attempt")).cancelled is False
    await runner.run(spec(tmp_path, executable))
    assert len(backend.calls) == 1


@pytest.mark.asyncio
async def test_cancel_stops_active_backend_and_latches_attempt(tmp_path: Path) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (tmp_path / "attempt").mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    backend = FakeBackend()
    backend.block = True
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=tmp_path / "attempt",
        executable=executable,
        monotonic_ns=lambda: 1_000_000,
        backend=backend,
        output_budget=output_budget(),
    )
    running = asyncio.create_task(runner.run(spec(tmp_path, executable)))
    await backend.started.wait()
    assert (await runner.cancel("attempt-1")).cancelled is True
    result = await running
    assert result.outcome == "CANCELLED"
    another = await runner.run(spec(tmp_path, executable, invocation="invoke-2"))
    assert another.outcome == "CANCELLED"
    assert len(backend.calls) == 1


@pytest.mark.asyncio
async def test_cancelling_runner_task_stops_backend_and_latches_attempt(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import (
        SafeProcessRunner,
        process_command_fingerprint,
        validate_receipt,
    )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (tmp_path / "attempt").mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    backend = FakeBackend()
    backend.block = True
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=tmp_path / "attempt",
        executable=executable,
        monotonic_ns=lambda: 1_000_000,
        backend=backend,
        output_budget=output_budget(),
    )

    request = spec(tmp_path, executable)
    running = asyncio.create_task(runner.run(request))
    await backend.started.wait()
    running.cancel()

    with pytest.raises(asyncio.CancelledError):
        await running
    assert backend.cancelled == {"attempt-1"}
    assert backend.release.is_set()
    receipts = list((tmp_path / "attempt").glob("*.receipt.json"))
    assert len(receipts) == 1
    receipt = validate_receipt(receipts[0], request)
    assert receipt.outcome == "CANCELLED"
    assert receipt.action_id == "action-1"
    assert receipt.attempt_id == "attempt-1"
    assert receipt.invocation_id == "invoke-1"
    assert receipt.command_fingerprint == process_command_fingerprint(request)
    assert not list((tmp_path / "attempt").glob("*.tmp"))

    another = await runner.run(spec(tmp_path, executable, invocation="invoke-2"))
    assert another.outcome == "CANCELLED"
    assert len(backend.calls) == 1


@pytest.mark.asyncio
async def test_repeated_runner_task_cancellation_waits_for_receipt(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    backend = _BlockingCancelBackend()
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=output,
        executable=executable,
        monotonic_ns=lambda: 1_000_000,
        backend=backend,
        output_budget=output_budget(),
    )
    running = asyncio.create_task(runner.run(spec(tmp_path, executable)))
    await backend.started.wait()

    running.cancel()
    await backend.cancel_started.wait()
    running.cancel()
    await asyncio.sleep(0)
    assert not running.done()
    backend.cancel_release.set()

    with pytest.raises(asyncio.CancelledError):
        await running
    receipts = list(output.glob("*.receipt.json"))
    assert len(receipts) == 1
    assert json.loads(receipts[0].read_text())["outcome"] == "CANCELLED"


@pytest.mark.asyncio
async def test_cancelling_public_cancel_waits_for_backend_cleanup(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    backend = _BlockingCancelBackend()
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=output,
        executable=executable,
        monotonic_ns=lambda: 1_000_000,
        backend=backend,
        output_budget=output_budget(),
    )
    running = asyncio.create_task(runner.run(spec(tmp_path, executable)))
    await backend.started.wait()
    cancelling = asyncio.create_task(runner.cancel("attempt-1"))
    await backend.cancel_started.wait()

    cancelling.cancel()
    await asyncio.sleep(0)
    assert not cancelling.done()
    backend.cancel_release.set()

    with pytest.raises(asyncio.CancelledError):
        await cancelling
    assert (await running).outcome == "CANCELLED"


@pytest.mark.asyncio
async def test_attempt_output_budget_is_shared_across_streams_and_cap_plus_one(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    backend = FakeBackend()
    backend.stdout = b"12345"
    backend.stderr = b"abcd"
    budget = output_budget(8)
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=output,
        executable=executable,
        monotonic_ns=lambda: 1,
        backend=backend,
        output_budget=budget,
    )
    request = replace(
        spec(tmp_path, executable),
        stdout_limit_bytes=20,
        stderr_limit_bytes=20,
        attempt_output_limit_bytes=8,
    )

    result = await runner.run(request)

    assert len(result.stdout) + len(result.stderr_tail) == 8
    assert result.stdout_truncated or result.stderr_truncated
    assert budget.used_bytes == 8


@pytest.mark.asyncio
async def test_attempt_output_budget_cannot_be_reset_by_a_second_invocation(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    backend = FakeBackend()
    backend.stdout = b"123456"
    budget = output_budget(10)
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=output,
        executable=executable,
        monotonic_ns=lambda: 1,
        backend=backend,
        output_budget=budget,
    )
    first = replace(spec(tmp_path, executable), attempt_output_limit_bytes=10)
    second = replace(first, invocation_id="invoke-2")

    results = (await runner.run(first), await runner.run(second))

    assert sum(len(item.stdout) + len(item.stderr_tail) for item in results) == 10
    assert results[1].stdout_truncated
    assert budget.used_bytes == 10


@pytest.mark.asyncio
async def test_attempt_output_budget_is_atomic_across_concurrent_invocations(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"fixture")
    budget = output_budget(10)
    backends = (FakeBackend(), FakeBackend())
    for backend in backends:
        backend.stdout = b"12345678"
    runners = tuple(
        SafeProcessRunner(
            action_id="action-1",
            attempt_id="attempt-1",
            workspace_root=workspace,
            output_root=output,
            executable=executable,
            monotonic_ns=lambda: 1,
            backend=backend,
            output_budget=budget,
        )
        for backend in backends
    )
    requests = tuple(
        replace(
            spec(tmp_path, executable, invocation=f"invoke-{index}"),
            attempt_output_limit_bytes=10,
            stdout_limit_bytes=20,
        )
        for index in (1, 2)
    )

    results = await asyncio.gather(
        *(
            runner.run(request)
            for runner, request in zip(runners, requests, strict=True)
        )
    )

    assert sum(len(item.stdout) + len(item.stderr_tail) for item in results) == 10
    assert budget.used_bytes == 10


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_real_process_preserves_argv_env_and_kills_descendant(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import SafeProcessRunner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    executable = Path(sys.executable)
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=output,
        executable=executable,
        output_budget=output_budget(4_096),
        monotonic_ns=lambda: 1,
    )
    check = replace(
        spec(tmp_path, executable),
        argv=(
            str(executable),
            "-c",
            "import os,sys;print(sys.argv[1]);print(os.environ.get('SAFE_KEY'))",
            "a; echo not-a-shell",
        ),
        env=(("SAFE_KEY", "only-explicit"),),
        stdout_limit_bytes=1_024,
        stderr_limit_bytes=1_024,
        attempt_output_limit_bytes=4_096,
    )
    checked = await runner.run(check)
    assert checked.stdout.splitlines() == [b"a; echo not-a-shell", b"only-explicit"]

    child_file = output / "child.pid"
    spawn = replace(
        check,
        invocation_id="invoke-descendant",
        argv=(
            str(executable),
            "-c",
            (
                "import pathlib,subprocess,sys,time;"
                "p=subprocess.Popen([sys.executable,'-c',"
                "'import time;time.sleep(30)']);"
                f"pathlib.Path({str(child_file)!r}).write_text(str(p.pid));"
                "time.sleep(30)"
            ),
        ),
    )
    running = asyncio.create_task(runner.run(spawn))
    for _ in range(100):
        if child_file.exists():
            break
        await asyncio.sleep(0.02)
    assert child_file.exists()
    child_pid = int(child_file.read_text())
    assert (await runner.cancel("attempt-1")).cancelled
    assert (await running).outcome == "CANCELLED"
    for _ in range(100):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.02)
    else:
        pytest.fail("POSIX descendant remained alive after process-group cancellation")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_cancel_during_spawn_waits_for_registration_then_kills(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import PosixProcessBackend

    started = asyncio.Event()
    release = asyncio.Event()

    async def delayed_spawn(*argv: str, **kwargs: Any) -> asyncio.subprocess.Process:
        started.set()
        await release.wait()
        return await asyncio.create_subprocess_exec(*argv, **kwargs)

    executable = Path(sys.executable)
    request = replace(
        spec(tmp_path, executable),
        argv=(str(executable), "-c", "import time;time.sleep(30)"),
        cwd=tmp_path,
        attempt_output_dir=tmp_path / "attempt",
    )
    backend = PosixProcessBackend(spawn=delayed_spawn)
    cancel_event = asyncio.Event()

    running = asyncio.create_task(
        backend.run(request, 30_000, DiscardSink(), DiscardSink(), cancel_event)
    )
    await started.wait()
    cancelling = asyncio.create_task(backend.cancel("attempt-1"))
    await asyncio.sleep(0)
    assert not cancelling.done()
    release.set()
    assert await cancelling
    result = await running
    assert result.cancelled


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_task_cancellation_kills_process_group(tmp_path: Path) -> None:
    from sastsimi.static_analysis.process import PosixProcessBackend

    child_file = tmp_path / "attempt" / "cancelled-child.pid"
    executable = Path(sys.executable)
    request = replace(
        spec(tmp_path, executable),
        invocation_id="cancelled-posix-tree",
        argv=(
            str(executable),
            "-c",
            (
                "import pathlib,subprocess,sys,time;"
                "p=subprocess.Popen([sys.executable,'-c',"
                "'import time;time.sleep(30)']);"
                f"pathlib.Path({str(child_file)!r}).write_text(str(p.pid));"
                "time.sleep(30)"
            ),
        ),
        cwd=tmp_path,
        attempt_output_dir=tmp_path / "attempt",
    )
    backend = PosixProcessBackend()
    event = asyncio.Event()
    running = asyncio.create_task(
        backend.run(request, 30_000, DiscardSink(), DiscardSink(), event)
    )
    for _ in range(100):
        if child_file.exists():
            break
        await asyncio.sleep(0.02)
    assert child_file.exists()
    child_pid = int(child_file.read_text())

    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running

    for _ in range(100):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.02)
    else:
        pytest.fail("POSIX descendant remained alive after task cancellation")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_kills_descendant_that_ignores_sigterm_after_parent_exits(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import PosixProcessBackend

    child_file = tmp_path / "attempt" / "stubborn-child.pid"
    executable = Path(sys.executable)
    child_program = (
        "import os,pathlib,signal,time;"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        f"pathlib.Path({str(child_file)!r}).write_text(str(os.getpid()));"
        "time.sleep(30)"
    )
    request = replace(
        spec(tmp_path, executable),
        invocation_id="stubborn-posix-tree",
        argv=(
            str(executable),
            "-c",
            (
                "import subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-c',{child_program!r}]);"
                "time.sleep(30)"
            ),
        ),
        cwd=tmp_path,
        attempt_output_dir=tmp_path / "attempt",
    )
    backend = PosixProcessBackend()
    event = asyncio.Event()
    running = asyncio.create_task(
        backend.run(request, 30_000, DiscardSink(), DiscardSink(), event)
    )
    for _ in range(100):
        if child_file.exists():
            break
        await asyncio.sleep(0.02)
    assert child_file.exists()
    child_pid = int(child_file.read_text())

    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running

    for _ in range(100):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.02)
    else:
        pytest.fail("SIGTERM-ignoring descendant survived process-group cleanup")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_repeated_task_cancellation_waits_for_drain_and_registry_cleanup(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import PosixProcessBackend

    process = _BlockingProcess()

    async def spawn(*argv: str, **kwargs: Any) -> asyncio.subprocess.Process:
        del argv, kwargs
        return cast(asyncio.subprocess.Process, process)

    class DrainAwareBackend(PosixProcessBackend):
        def __init__(self) -> None:
            super().__init__(spawn=spawn)
            self.terminate_done = asyncio.Event()

        async def _terminate(self, active: asyncio.subprocess.Process) -> None:
            assert cast(object, active) is cast(object, process)
            self.terminate_done.set()

    executable = Path(sys.executable)
    request = replace(
        spec(tmp_path, executable),
        argv=(str(executable), "-c", "pass"),
        cwd=tmp_path,
        attempt_output_dir=tmp_path / "attempt",
    )
    backend = DrainAwareBackend()
    event = asyncio.Event()
    running = asyncio.create_task(
        backend.run(request, 30_000, DiscardSink(), DiscardSink(), event)
    )
    await process.stdout.started.wait()
    await process.stderr.started.wait()

    running.cancel()
    await backend.terminate_done.wait()
    await asyncio.sleep(0)
    running.cancel()
    await asyncio.sleep(0)
    completed_before_drain = running.done()
    process.stdout.release.set()
    process.stderr.release.set()

    with pytest.raises(asyncio.CancelledError):
        await running
    assert not completed_before_drain
    assert not process.stdout.cancelled and not process.stderr.cancelled
    assert "attempt-1" not in backend._processes


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_task_cancellation_during_spawn_cleans_spawned_process(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import PosixProcessBackend

    process = _BlockingProcess()
    spawn_started = asyncio.Event()
    spawn_release = asyncio.Event()

    async def spawn(*argv: str, **kwargs: Any) -> asyncio.subprocess.Process:
        del argv, kwargs
        spawn_started.set()
        await spawn_release.wait()
        return cast(asyncio.subprocess.Process, process)

    class SpawnCleanupBackend(PosixProcessBackend):
        def __init__(self) -> None:
            super().__init__(spawn=spawn)
            self.terminated = asyncio.Event()

        async def _terminate(self, active: asyncio.subprocess.Process) -> None:
            assert cast(object, active) is cast(object, process)
            process.returncode = -9
            process._wait.set()
            process.stdout.release.set()
            process.stderr.release.set()
            self.terminated.set()

    executable = Path(sys.executable)
    request = replace(
        spec(tmp_path, executable),
        argv=(str(executable), "-c", "pass"),
        cwd=tmp_path,
        attempt_output_dir=tmp_path / "attempt",
    )
    backend = SpawnCleanupBackend()
    running = asyncio.create_task(
        backend.run(request, 30_000, DiscardSink(), DiscardSink(), asyncio.Event())
    )
    await spawn_started.wait()

    running.cancel()
    running.cancel()
    await asyncio.sleep(0)
    assert not running.done()
    spawn_release.set()

    with pytest.raises(asyncio.CancelledError):
        await running
    assert backend.terminated.is_set()
    assert "attempt-1" not in backend._processes


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_cancellation_while_draining_terminates_process_group(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import PosixProcessBackend

    process = _BlockingProcess()
    process.returncode = 0
    process._wait.set()

    async def spawn(*argv: str, **kwargs: Any) -> asyncio.subprocess.Process:
        del argv, kwargs
        return cast(asyncio.subprocess.Process, process)

    class DrainCleanupBackend(PosixProcessBackend):
        def __init__(self) -> None:
            super().__init__(spawn=spawn)
            self.terminated = asyncio.Event()

        async def _terminate(self, active: asyncio.subprocess.Process) -> None:
            assert cast(object, active) is cast(object, process)
            process.stdout.release.set()
            process.stderr.release.set()
            self.terminated.set()

    executable = Path(sys.executable)
    request = replace(
        spec(tmp_path, executable),
        argv=(str(executable), "-c", "pass"),
        cwd=tmp_path,
        attempt_output_dir=tmp_path / "attempt",
    )
    backend = DrainCleanupBackend()
    running = asyncio.create_task(
        backend.run(request, 30_000, DiscardSink(), DiscardSink(), asyncio.Event())
    )
    await process.stdout.started.wait()
    await process.stderr.started.wait()

    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert backend.terminated.is_set()
    assert not process.stdout.cancelled and not process.stderr.cancelled
    assert "attempt-1" not in backend._processes


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_parent_exit_with_open_descendant_pipe_is_bounded(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import PosixProcessBackend

    process = _BlockingProcess()
    process.returncode = 0
    process._wait.set()

    async def spawn(*argv: str, **kwargs: Any) -> asyncio.subprocess.Process:
        del argv, kwargs
        return cast(asyncio.subprocess.Process, process)

    class LingeringPipeBackend(PosixProcessBackend):
        def __init__(self) -> None:
            super().__init__(spawn=spawn, drain_timeout_seconds=0.01)
            self.terminated = asyncio.Event()

        async def _terminate(self, active: asyncio.subprocess.Process) -> None:
            assert cast(object, active) is cast(object, process)
            process.stdout.release.set()
            process.stderr.release.set()
            self.terminated.set()

    executable = Path(sys.executable)
    request = replace(
        spec(tmp_path, executable),
        argv=(str(executable), "-c", "pass"),
        cwd=tmp_path,
        attempt_output_dir=tmp_path / "attempt",
    )
    backend = LingeringPipeBackend()

    result = await backend.run(
        request, 30_000, DiscardSink(), DiscardSink(), asyncio.Event()
    )

    assert result.timed_out
    assert backend.terminated.is_set()
    assert "attempt-1" not in backend._processes


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_unreapable_process_termination_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sastsimi.static_analysis.process import PosixProcessBackend

    process = _BlockingProcess()
    monkeypatch.setattr(os, "killpg", lambda _pid, _signal: None)
    backend = PosixProcessBackend(termination_timeout_seconds=0.01)

    with pytest.raises(TimeoutError, match="PROCESS_TREE_TERMINATION_TIMEOUT"):
        await asyncio.wait_for(
            backend._terminate(cast(asyncio.subprocess.Process, process)), timeout=1
        )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_cleanup_failure_prevents_cancelled_receipt(
    tmp_path: Path,
) -> None:
    from sastsimi.static_analysis.process import PosixProcessBackend, SafeProcessRunner

    process = _BlockingProcess()
    process.returncode = 0
    process._wait.set()

    async def spawn(*argv: str, **kwargs: Any) -> asyncio.subprocess.Process:
        del argv, kwargs
        return cast(asyncio.subprocess.Process, process)

    class FailingCleanupBackend(PosixProcessBackend):
        async def _terminate(self, active: asyncio.subprocess.Process) -> None:
            assert cast(object, active) is cast(object, process)
            process.stdout.release.set()
            process.stderr.release.set()
            raise OSError("PROCESS_GROUP_KILL_FAILED")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    executable = Path(sys.executable)
    backend = FailingCleanupBackend(spawn=spawn)
    runner = SafeProcessRunner(
        action_id="action-1",
        attempt_id="attempt-1",
        workspace_root=workspace,
        output_root=output,
        executable=executable,
        output_budget=output_budget(),
        monotonic_ns=lambda: 1,
        backend=backend,
    )
    request = replace(
        spec(tmp_path, executable),
        argv=(str(executable), "-c", "pass"),
        cwd=workspace,
        attempt_output_dir=output,
    )
    running = asyncio.create_task(runner.run(request))
    await asyncio.wait_for(process.stdout.started.wait(), timeout=1)
    await asyncio.wait_for(process.stderr.started.wait(), timeout=1)

    running.cancel()
    with pytest.raises(OSError, match="PROCESS_GROUP_KILL_FAILED"):
        await running

    assert not list(output.glob("*.receipt.json"))
    assert not list(output.glob("*.tmp"))
    assert "attempt-1" not in backend._processes


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process boundary")
@pytest.mark.asyncio
async def test_posix_pre_cancelled_event_prevents_spawn(tmp_path: Path) -> None:
    from sastsimi.static_analysis.process import PosixProcessBackend

    called = False

    async def forbidden_spawn(*argv: str, **kwargs: Any) -> asyncio.subprocess.Process:
        del argv, kwargs
        nonlocal called
        called = True
        raise AssertionError("spawned")

    executable = Path(sys.executable)
    request = replace(
        spec(tmp_path, executable),
        argv=(str(executable), "-c", "pass"),
        cwd=tmp_path,
        attempt_output_dir=tmp_path / "attempt",
    )
    event = asyncio.Event()
    event.set()
    sink = DiscardSink()
    result = await PosixProcessBackend(spawn=forbidden_spawn).run(
        request, 1_000, sink, sink, event
    )
    assert result.cancelled and not called
