from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

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


class DiscardSink:
    def write(self, data: bytes) -> None:
        del data


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
