from __future__ import annotations

import asyncio
import json
import sys
from collections import deque
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.static_analysis.container_codeql_runtime import (
    ContainerCodeQLProbeRequest,
)
from sastsimi.static_analysis.docker_codeql_port import (
    ContainerCodeQLDockerError,
    ContainerCodeQLDockerPort,
)

_NAME = "sastsimi-codeql-0123456789abcdef01234567"


class _Stream:
    def __init__(
        self,
        chunks: tuple[bytes, ...] = (),
        *,
        blocked: bool = False,
        read_failure: Exception | None = None,
    ) -> None:
        self._chunks = deque(chunks)
        self._blocked = blocked
        self._read_failure = read_failure
        self._released = asyncio.Event()

    async def read(self, _size: int = -1) -> bytes:
        if self._read_failure is not None:
            raise self._read_failure
        if self._blocked:
            await self._released.wait()
            self._blocked = False
        return self._chunks.popleft() if self._chunks else b""

    def release(self) -> None:
        self._released.set()


class _Process:
    def __init__(
        self,
        *,
        stdout: tuple[bytes, ...] = (),
        exit_code: int = 0,
        blocked: bool = False,
        read_failure: Exception | None = None,
    ) -> None:
        self.stdout = _Stream(
            stdout,
            blocked=blocked,
            read_failure=read_failure,
        )
        self.stderr = None
        self.returncode: int | None = None
        self._exit_code = exit_code
        self.killed = False

    async def wait(self) -> int:
        self.returncode = self._exit_code if not self.killed else -9
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self.stdout.release()


class _Spawn:
    def __init__(self, *processes: _Process) -> None:
        self._processes = deque(processes)
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
        self.spawned = asyncio.Event()

    async def __call__(self, *argv: str, **kwargs: object) -> _Process:
        self.calls.append((argv, kwargs))
        self.spawned.set()
        return self._processes.popleft()


class _FailingSpawn:
    async def __call__(self, *_argv: str, **_kwargs: object) -> _Process:
        raise RuntimeError("daemon at host-path contains secret-token")


def _port(spawn: _Spawn) -> ContainerCodeQLDockerPort:
    return ContainerCodeQLDockerPort(
        docker_executable=Path(sys.executable).resolve(),
        spawn=cast(Any, spawn),
    )


@pytest.mark.asyncio
async def test_executes_exact_shell_free_lifecycle_and_streams_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "secret-must-not-reach-docker")
    inspect_record = {"Config": {"Image": "sha256:" + "a" * 64}}
    spawn = _Spawn(
        _Process(stdout=(b"ignored-container-id\n",)),
        _Process(stdout=(json.dumps(inspect_record).encode(),)),
        _Process(),
        _Process(stdout=(b"137\n",)),
        _Process(stdout=(b"first", b"second")),
        _Process(),
    )
    port = _port(spawn)
    executable = str(Path(sys.executable).resolve())
    create_argv = (
        executable,
        "create",
        "--name",
        _NAME,
        "sha256:" + "a" * 64,
    )

    await port.create(create_argv)
    assert await port.inspect(_NAME) == inspect_record
    await port.start(_NAME)
    assert await port.wait(_NAME) == 137
    chunks = [chunk async for chunk in port.logs(_NAME)]
    await port.remove(_NAME)

    assert chunks == [b"first", b"second"]
    assert [call[0] for call in spawn.calls] == [
        create_argv,
        (
            executable,
            "inspect",
            "--type",
            "container",
            "--format",
            "{{json .}}",
            "--",
            _NAME,
        ),
        (executable, "start", "--", _NAME),
        (executable, "wait", "--", _NAME),
        (executable, "logs", "--", _NAME),
        (executable, "rm", "--force", "--", _NAME),
    ]
    for _argv, kwargs in spawn.calls:
        assert "shell" not in kwargs
        assert kwargs["stdin"] is asyncio.subprocess.DEVNULL
        assert kwargs["stdout"] is asyncio.subprocess.PIPE
        assert kwargs["stderr"] is asyncio.subprocess.DEVNULL
        environment = cast(dict[str, str], kwargs["env"])
        assert "OPENAI_API_KEY" not in environment


@pytest.mark.asyncio
async def test_rejects_oversized_or_malformed_inspect_without_echoing_data() -> None:
    oversized = b"host-path secret " + b"x" * (1024 * 1024)
    spawn = _Spawn(_Process(stdout=(oversized,)))

    with pytest.raises(
        ContainerCodeQLDockerError, match="CODEQL_DOCKER_INSPECT_LIMIT"
    ) as captured:
        await _port(spawn).inspect(_NAME)

    assert "host-path" not in str(captured.value)
    assert "secret" not in str(captured.value)

    malformed = _Spawn(_Process(stdout=(b'{"Config":',)))
    with pytest.raises(
        ContainerCodeQLDockerError, match="CODEQL_DOCKER_INSPECT_INVALID"
    ):
        await _port(malformed).inspect(_NAME)


@pytest.mark.asyncio
async def test_nonzero_docker_exit_returns_only_stable_error() -> None:
    spawn = _Spawn(_Process(exit_code=1))

    with pytest.raises(
        ContainerCodeQLDockerError, match="^CODEQL_DOCKER_START_FAILED$"
    ) as captured:
        await _port(spawn).start(_NAME)

    assert str(captured.value) == "CODEQL_DOCKER_START_FAILED"


@pytest.mark.asyncio
async def test_docker_stream_failure_is_sanitized_and_child_is_terminated() -> None:
    process = _Process(
        read_failure=RuntimeError("daemon at host-path contains secret-token")
    )
    port = _port(_Spawn(process))

    with pytest.raises(
        ContainerCodeQLDockerError, match="^CODEQL_DOCKER_START_FAILED$"
    ) as captured:
        await port.start(_NAME)

    assert str(captured.value) == "CODEQL_DOCKER_START_FAILED"
    assert process.killed is True


@pytest.mark.asyncio
async def test_spawn_failure_is_sanitized() -> None:
    port = ContainerCodeQLDockerPort(
        docker_executable=Path(sys.executable).resolve(),
        spawn=cast(Any, _FailingSpawn()),
    )

    with pytest.raises(
        ContainerCodeQLDockerError, match="^CODEQL_DOCKER_SPAWN_FAILED$"
    ) as captured:
        await port.start(_NAME)

    assert str(captured.value) == "CODEQL_DOCKER_SPAWN_FAILED"


@pytest.mark.asyncio
async def test_log_stream_failure_is_sanitized_and_child_is_terminated() -> None:
    process = _Process(
        read_failure=RuntimeError("daemon at host-path contains secret-token")
    )
    port = _port(_Spawn(process))

    with pytest.raises(
        ContainerCodeQLDockerError, match="^CODEQL_DOCKER_LOGS_FAILED$"
    ) as captured:
        _ = [chunk async for chunk in port.logs(_NAME)]

    assert str(captured.value) == "CODEQL_DOCKER_LOGS_FAILED"
    assert process.killed is True


@pytest.mark.asyncio
async def test_cancellation_terminates_the_active_docker_child() -> None:
    process = _Process(blocked=True)
    spawn = _Spawn(process)
    task = asyncio.create_task(_port(spawn).start(_NAME))
    await asyncio.wait_for(spawn.spawned.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.killed is True
    assert process.returncode == -9


@pytest.mark.asyncio
async def test_remove_accepts_only_one_exact_owned_name() -> None:
    spawn = _Spawn(_Process())
    port = _port(spawn)

    for invalid in (
        "other-container",
        _NAME + ",second",
        "--force",
        _NAME + "\nsecret",
    ):
        with pytest.raises(
            ContainerCodeQLDockerError, match="CODEQL_DOCKER_NAME_INVALID"
        ):
            await port.remove(invalid)

    assert spawn.calls == []
    await port.remove(_NAME)
    assert len(spawn.calls) == 1


@pytest.mark.asyncio
async def test_probe_waits_and_parses_strict_bounded_logs_without_exec() -> None:
    payload = {
        "schema_version": 1,
        "codeql_version": "2.27.0",
        "database": {
            "target": "/work/database",
            "limit_bytes": 100,
            "attempted_bytes": 101,
            "bytes_written": 100,
            "denial_code": "ENOSPC",
        },
        "output": {
            "target": "/work/output",
            "limit_bytes": 50,
            "attempted_bytes": 51,
            "bytes_written": 50,
            "denial_code": "EDQUOT",
        },
    }
    spawn = _Spawn(
        _Process(stdout=(b"0\n",)),
        _Process(stdout=(json.dumps(payload).encode(),)),
    )
    port = _port(spawn)

    observation = await port.probe(
        _NAME,
        ContainerCodeQLProbeRequest(
            expected_codeql_version="2.27.0",
            database_attempted_bytes=101,
            output_attempted_bytes=51,
        ),
    )

    executable = str(Path(sys.executable).resolve())
    assert [call[0] for call in spawn.calls] == [
        (executable, "wait", "--", _NAME),
        (executable, "logs", "--", _NAME),
    ]
    assert observation.codeql_version == "2.27.0"
    assert observation.database.attempted_bytes == 101
    assert observation.output.denial_code == "EDQUOT"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exit_code,payload",
    [
        (1, None),
        (
            0,
            {
                "schema_version": 1,
                "codeql_version": "2.27.0",
                "database": {
                    "target": "/work/database",
                    "limit_bytes": 100,
                    "attempted_bytes": 101,
                    "bytes_written": 100,
                    "denial_code": "ENOSPC",
                    "unexpected": "secret",
                },
                "output": {},
            },
        ),
        (
            0,
            {
                "schema_version": 1,
                "codeql_version": "2.27.0",
                "database": {
                    "target": "/work/database",
                    "limit_bytes": 100,
                    "attempted_bytes": 101,
                    "bytes_written": 101,
                    "denial_code": "ENOSPC",
                },
                "output": {
                    "target": "/work/output",
                    "limit_bytes": 50,
                    "attempted_bytes": 51,
                    "bytes_written": 50,
                    "denial_code": "ENOSPC",
                },
            },
        ),
    ],
)
async def test_probe_rejects_nonzero_extra_fields_and_bad_bounds(
    exit_code: int, payload: dict[str, object] | None
) -> None:
    processes = [_Process(stdout=(f"{exit_code}\n".encode(),))]
    if payload is not None:
        processes.append(_Process(stdout=(json.dumps(payload).encode(),)))
    port = _port(_Spawn(*processes))

    with pytest.raises(ContainerCodeQLDockerError) as captured:
        await port.probe(
            _NAME,
            ContainerCodeQLProbeRequest(
                expected_codeql_version="2.27.0",
                database_attempted_bytes=101,
                output_attempted_bytes=51,
            ),
        )

    assert str(captured.value) in {
        "CODEQL_DOCKER_PROBE_EXIT_NONZERO",
        "CODEQL_DOCKER_PROBE_INVALID",
    }
    assert "secret" not in str(captured.value)
