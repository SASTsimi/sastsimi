from __future__ import annotations

import asyncio
import json
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


def spec(root: Path, executable: Path, *, invocation: str = "invoke-1") -> ProcessSpec:
    output = root / "attempt"
    output.mkdir(parents=True, exist_ok=True)
    return ProcessSpec(
        invocation_id=invocation,
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
    )
    running = asyncio.create_task(runner.run(spec(tmp_path, executable)))
    await backend.started.wait()
    assert (await runner.cancel("attempt-1")).cancelled is True
    result = await running
    assert result.outcome == "CANCELLED"
    another = await runner.run(spec(tmp_path, executable, invocation="invoke-2"))
    assert another.outcome == "CANCELLED"
    assert len(backend.calls) == 1
