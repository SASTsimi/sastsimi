"""Real process-tree behavior at the direct bootstrap subprocess boundary."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

from sastsimi.composition.simple_process import LocalProcessExecutor

_DESCENDANT = (
    "import pathlib,sys,time; "
    "time.sleep(float(sys.argv[2])); "
    "pathlib.Path(sys.argv[1]).write_text('survived', encoding='utf-8')"
)
_PARENT_EXITS = (
    "import subprocess,sys; "
    "subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1], '1.8'], "
    "stdout=sys.stdout, stderr=sys.stderr)"
)
_PARENT_WAITS = (
    "import pathlib,subprocess,sys,time; "
    "subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[1], '1.5'], "
    "stdout=sys.stdout, stderr=sys.stderr); "
    "pathlib.Path(sys.argv[2]).write_text('ready', encoding='utf-8'); "
    "time.sleep(2)"
)


@pytest.mark.asyncio
async def test_timeout_kills_descendant_after_direct_parent_exits(
    tmp_path: Path,
) -> None:
    """Leaving the subprocess tree alive must not make a stale scan appear valid."""
    marker = tmp_path / "descendant-survived"
    with pytest.raises(RuntimeError, match="^EXTERNAL_TOOL_TIMEOUT$"):
        await asyncio.wait_for(
            LocalProcessExecutor().run(
                (sys.executable, "-c", _PARENT_EXITS, str(marker), _DESCENDANT),
                timeout_seconds=1,
            ),
            timeout=5,
        )
    await asyncio.sleep(1)
    assert not marker.exists()


@pytest.mark.asyncio
async def test_timeout_kills_descendant_while_direct_parent_runs(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "descendant-survived"
    ready = tmp_path / "parent-ready"
    with pytest.raises(RuntimeError, match="^EXTERNAL_TOOL_TIMEOUT$"):
        await asyncio.wait_for(
            LocalProcessExecutor().run(
                (
                    sys.executable,
                    "-c",
                    _PARENT_WAITS,
                    str(marker),
                    str(ready),
                    _DESCENDANT,
                ),
                timeout_seconds=1,
            ),
            timeout=5,
        )
    assert ready.exists()
    await asyncio.sleep(0.8)
    assert not marker.exists()


@pytest.mark.asyncio
async def test_cancellation_kills_descendant_and_propagates(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived"
    ready = tmp_path / "parent-ready"
    task = asyncio.create_task(
        LocalProcessExecutor().run(
            (
                sys.executable,
                "-c",
                _PARENT_WAITS,
                str(marker),
                str(ready),
                _DESCENDANT,
            ),
            timeout_seconds=10,
        )
    )
    deadline = time.monotonic() + 3
    while not ready.exists() and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    assert ready.exists()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)
    await asyncio.sleep(1.7)
    assert not marker.exists()


@pytest.mark.asyncio
async def test_success_preserves_captured_output() -> None:
    result = await LocalProcessExecutor().run(
        (
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('out'); sys.stderr.write('err')",
        ),
        timeout_seconds=5,
    )
    assert result.returncode == 0
    assert result.stdout == b"out"
    assert result.stderr == b"err"


@pytest.mark.asyncio
async def test_captured_tool_output_is_bounded() -> None:
    result = await LocalProcessExecutor().run(
        (
            sys.executable,
            "-c",
            (
                "import sys; "
                "sys.stdout.buffer.write(b'x' * (32 * 1024 * 1024 + 1)); "
                "sys.stderr.buffer.write(b'y' * (1024 * 1024 + 1))"
            ),
        ),
        timeout_seconds=10,
    )
    assert result.returncode == 0
    assert len(result.stdout) == 32 * 1024 * 1024
    assert len(result.stderr) == 1024 * 1024
    assert result.stdout[-1:] == b"x"
    assert result.stderr[-1:] == b"y"
    assert result.stdout_truncated
    assert result.stderr_truncated


@pytest.mark.asyncio
async def test_tool_cannot_allocate_past_per_call_memory_limit() -> None:
    result = await LocalProcessExecutor(memory_limit_bytes=128 * 1024 * 1024).run(
        (
            sys.executable,
            "-I",
            "-S",
            "-c",
            "data = bytearray(256 * 1024 * 1024); print(len(data))",
        ),
        timeout_seconds=10,
    )

    assert result.returncode != 0
    assert b"268435456" not in result.stdout
