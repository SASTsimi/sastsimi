"""Shell-free Docker CLI primitives for the container CodeQL runtime."""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import tarfile
import tempfile
from collections.abc import AsyncIterator, Mapping
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Protocol, TypedDict, cast

if TYPE_CHECKING:
    from sastsimi.static_analysis.container_codeql_runtime import (
        ContainerCodeQLProbeObservation,
        ContainerCodeQLProbeRequest,
    )

_CONTAINER_NAME = re.compile(r"^sastsimi-codeql(?:-provision)?-[0-9a-f]{24}$")
_INSPECT_LIMIT_BYTES = 1024 * 1024
_CONTROL_OUTPUT_LIMIT_BYTES = 4096
_PROBE_OUTPUT_LIMIT_BYTES = 64 * 1024
_PROVISION_OUTPUT_LIMIT_BYTES = 1024
_PROVISION_READY = b"CODEQL_PROVISION_READY\n"
_ARCHIVE_OVERHEAD_LIMIT_BYTES = 64 * 1024 * 1024
_ARCHIVE_MEMBER_LIMIT = 100_000
_STREAM_CHUNK_BYTES = 64 * 1024
_TERMINATION_TIMEOUT_SECONDS = 5.0
_PROBE_DENIAL_CODES = frozenset({"ENOSPC", "EDQUOT"})
_SAFE_ENVIRONMENT_NAMES = (
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
)


class ContainerCodeQLDockerError(RuntimeError):
    """Stable Docker boundary error with no daemon or submitted data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _Readable(Protocol):
    async def read(self, size: int = -1) -> bytes: ...


class _Process(Protocol):
    stdout: _Readable | None
    returncode: int | None

    async def wait(self) -> int: ...

    def kill(self) -> None: ...


class _Spawn(Protocol):
    async def __call__(self, *argv: str, **kwargs: object) -> _Process: ...


class _ProbeDenial(TypedDict):
    target: str
    limit_bytes: int
    attempted_bytes: int
    bytes_written: int
    denial_code: str


async def _settle[ResultT](task: asyncio.Task[ResultT]) -> ResultT:
    """Finish cleanup even if repeated cancellation reaches this task."""

    while True:
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.done():
                return task.result()


class ContainerCodeQLDockerPort:
    """Invoke only exact container primitives through ``create_subprocess_exec``.

    Ordering remains owned by ``container_codeql_runtime``. This adapter does
    not turn ``create`` into ``run`` and does not start before the runtime has
    inspected the created container.
    """

    def __init__(
        self,
        *,
        docker_executable: Path,
        spawn: _Spawn | None = None,
    ) -> None:
        try:
            if not docker_executable.is_absolute() or docker_executable.is_symlink():
                raise ValueError
            executable = docker_executable.resolve(strict=True)
            if executable != docker_executable.absolute() or not executable.is_file():
                raise ValueError
        except (OSError, ValueError):
            raise ContainerCodeQLDockerError(
                "CODEQL_DOCKER_EXECUTABLE_INVALID"
            ) from None
        self._executable = executable
        self._spawn = spawn or cast(_Spawn, asyncio.create_subprocess_exec)
        self._environment = self._safe_environment(os.environ)

    @staticmethod
    def _safe_environment(source: Mapping[str, str]) -> dict[str, str]:
        by_upper = {name.upper(): value for name, value in source.items()}
        return {
            name: by_upper[name]
            for name in _SAFE_ENVIRONMENT_NAMES
            if name in by_upper and by_upper[name]
        }

    @staticmethod
    def _name(value: str) -> str:
        if _CONTAINER_NAME.fullmatch(value) is None:
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_NAME_INVALID")
        return value

    def _create_name(self, argv: tuple[str, ...]) -> str:
        try:
            positions = tuple(
                index for index, value in enumerate(argv) if value == "--name"
            )
            if (
                len(argv) < 5
                or argv[0] != str(self._executable)
                or argv[1] != "create"
                or len(positions) != 1
                or any(
                    not value or any(character in value for character in "\x00\r\n")
                    for value in argv
                )
            ):
                raise ValueError
            return self._name(argv[positions[0] + 1])
        except (IndexError, ValueError):
            raise ContainerCodeQLDockerError(
                "CODEQL_DOCKER_CREATE_COMMAND_INVALID"
            ) from None

    def _command(self, *arguments: str) -> tuple[str, ...]:
        return (str(self._executable), *arguments)

    async def _spawn_child(self, argv: tuple[str, ...]) -> _Process:
        kwargs: dict[str, object] = {
            "stdin": asyncio.subprocess.DEVNULL,
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.DEVNULL,
            "env": dict(self._environment),
        }
        if os.name == "nt":
            kwargs["creationflags"] = int(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            ) | int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            kwargs["start_new_session"] = True
        spawn_task = asyncio.create_task(self._spawn(*argv, **kwargs))
        try:
            return await asyncio.shield(spawn_task)
        except asyncio.CancelledError as cancelled:
            try:
                process = await _settle(spawn_task)
            except BaseException:
                raise cancelled from None
            await self._terminate_settled(process)
            raise cancelled
        except Exception:
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_SPAWN_FAILED") from None

    async def _terminate(self, process: _Process) -> None:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except Exception:
                raise ContainerCodeQLDockerError(
                    "CODEQL_DOCKER_CHILD_TERMINATION_FAILED"
                ) from None
        wait_task = asyncio.create_task(process.wait())
        try:
            await asyncio.wait_for(
                asyncio.shield(wait_task), _TERMINATION_TIMEOUT_SECONDS
            )
        except TimeoutError:
            wait_task.cancel()
            await asyncio.gather(wait_task, return_exceptions=True)
            raise ContainerCodeQLDockerError(
                "CODEQL_DOCKER_CHILD_TERMINATION_FAILED"
            ) from None
        except asyncio.CancelledError:
            wait_task.cancel()
            await asyncio.gather(wait_task, return_exceptions=True)
            raise
        except Exception:
            raise ContainerCodeQLDockerError(
                "CODEQL_DOCKER_CHILD_TERMINATION_FAILED"
            ) from None

    async def _terminate_settled(self, process: _Process) -> None:
        cleanup = asyncio.create_task(self._terminate(process))
        await _settle(cleanup)

    async def _capture(
        self,
        argv: tuple[str, ...],
        *,
        failure_code: str,
        limit_code: str,
        max_bytes: int,
    ) -> bytes:
        process = await self._spawn_child(argv)
        stream = process.stdout
        if stream is None:
            await self._terminate_settled(process)
            raise ContainerCodeQLDockerError(failure_code)
        output = bytearray()
        try:
            while chunk := await stream.read(_STREAM_CHUNK_BYTES):
                if not isinstance(chunk, bytes):
                    raise ContainerCodeQLDockerError(failure_code)
                if len(output) + len(chunk) > max_bytes:
                    raise ContainerCodeQLDockerError(limit_code)
                output.extend(chunk)
            return_code = await process.wait()
        except asyncio.CancelledError:
            await self._terminate_settled(process)
            raise
        except ContainerCodeQLDockerError:
            await self._terminate_settled(process)
            raise
        except Exception:
            await self._terminate_settled(process)
            raise ContainerCodeQLDockerError(failure_code) from None
        if return_code != 0:
            raise ContainerCodeQLDockerError(failure_code)
        return bytes(output)

    async def create(self, argv: tuple[str, ...]) -> None:
        self._create_name(argv)
        await self._capture(
            argv,
            failure_code="CODEQL_DOCKER_CREATE_FAILED",
            limit_code="CODEQL_DOCKER_CONTROL_OUTPUT_LIMIT",
            max_bytes=_CONTROL_OUTPUT_LIMIT_BYTES,
        )

    async def start(self, container_name: str) -> None:
        name = self._name(container_name)
        await self._capture(
            self._command("start", "--", name),
            failure_code="CODEQL_DOCKER_START_FAILED",
            limit_code="CODEQL_DOCKER_CONTROL_OUTPUT_LIMIT",
            max_bytes=_CONTROL_OUTPUT_LIMIT_BYTES,
        )

    async def inspect(self, container_name: str) -> Mapping[str, object]:
        name = self._name(container_name)
        payload = await self._capture(
            self._command(
                "inspect",
                "--type",
                "container",
                "--format",
                "{{json .}}",
                "--",
                name,
            ),
            failure_code="CODEQL_DOCKER_INSPECT_FAILED",
            limit_code="CODEQL_DOCKER_INSPECT_LIMIT",
            max_bytes=_INSPECT_LIMIT_BYTES,
        )
        try:
            decoded = json.loads(payload.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_INSPECT_INVALID") from None
        if not isinstance(decoded, dict):
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_INSPECT_INVALID")
        return cast(dict[str, object], decoded)

    async def wait(self, container_name: str) -> int:
        name = self._name(container_name)
        payload = await self._capture(
            self._command("wait", "--", name),
            failure_code="CODEQL_DOCKER_WAIT_FAILED",
            limit_code="CODEQL_DOCKER_CONTROL_OUTPUT_LIMIT",
            max_bytes=32,
        )
        try:
            text = payload.decode("ascii", errors="strict").strip()
            if not text or not text.isascii() or not text.isdecimal():
                raise ValueError
            code = int(text)
            if not 0 <= code <= 255:
                raise ValueError
        except (UnicodeDecodeError, ValueError):
            raise ContainerCodeQLDockerError(
                "CODEQL_DOCKER_WAIT_RESULT_INVALID"
            ) from None
        return code

    async def logs(self, container_name: str) -> AsyncIterator[bytes]:
        """Yield stdout chunks; the runtime owns the aggregate byte ceiling."""

        name = self._name(container_name)
        process = await self._spawn_child(self._command("logs", "--", name))
        stream = process.stdout
        if stream is None:
            await self._terminate_settled(process)
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_LOGS_FAILED")
        try:
            while chunk := await stream.read(_STREAM_CHUNK_BYTES):
                if not isinstance(chunk, bytes):
                    raise ContainerCodeQLDockerError("CODEQL_DOCKER_LOGS_FAILED")
                yield chunk
            if await process.wait() != 0:
                raise ContainerCodeQLDockerError("CODEQL_DOCKER_LOGS_FAILED")
        except asyncio.CancelledError:
            await self._terminate_settled(process)
            raise
        except ContainerCodeQLDockerError:
            raise
        except Exception:
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_LOGS_FAILED") from None
        finally:
            if process.returncode is None:
                await self._terminate_settled(process)

    async def remove(self, container_name: str) -> None:
        name = self._name(container_name)
        await self._capture(
            self._command("rm", "--force", "--", name),
            failure_code="CODEQL_DOCKER_REMOVE_FAILED",
            limit_code="CODEQL_DOCKER_CONTROL_OUTPUT_LIMIT",
            max_bytes=_CONTROL_OUTPUT_LIMIT_BYTES,
        )

    async def _write_bounded_archive(
        self,
        argv: tuple[str, ...],
        destination: Path,
        *,
        max_bytes: int,
    ) -> None:
        process = await self._spawn_child(argv)
        stream = process.stdout
        if stream is None:
            await self._terminate_settled(process)
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_COPY_FAILED")
        written = 0
        try:
            with destination.open("xb") as output:
                while chunk := await stream.read(_STREAM_CHUNK_BYTES):
                    if not isinstance(chunk, bytes):
                        raise ContainerCodeQLDockerError("CODEQL_DOCKER_COPY_FAILED")
                    written += len(chunk)
                    if written > max_bytes:
                        raise ContainerCodeQLDockerError("CODEQL_DOCKER_COPY_LIMIT")
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if await process.wait() != 0:
                raise ContainerCodeQLDockerError("CODEQL_DOCKER_COPY_FAILED")
        except asyncio.CancelledError:
            await self._terminate_settled(process)
            raise
        except ContainerCodeQLDockerError:
            await self._terminate_settled(process)
            raise
        except Exception:
            await self._terminate_settled(process)
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_COPY_FAILED") from None

    @staticmethod
    def _archive_parts(name: str) -> tuple[str, ...]:
        path = PurePosixPath(name)
        parts = tuple(path.parts)
        if parts in ((), (".",)):
            return ()
        if path.is_absolute() or any(
            part in ("", ".", "..")
            or any(character in part for character in "\\:\x00\r\n")
            or part.endswith((" ", "."))
            for part in parts
        ):
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_COPY_ARCHIVE_INVALID")
        return parts

    @classmethod
    def _extract_database_archive(
        cls,
        archive_path: Path,
        destination: Path,
        *,
        max_bytes: int,
    ) -> None:
        seen: set[str] = set()
        total = 0
        try:
            with tarfile.open(archive_path, mode="r:*") as archive:
                members = archive.getmembers()
                if len(members) > _ARCHIVE_MEMBER_LIMIT:
                    raise ContainerCodeQLDockerError("CODEQL_DOCKER_COPY_LIMIT")
                validated: list[tuple[tarfile.TarInfo, tuple[str, ...]]] = []
                for member in members:
                    parts = cls._archive_parts(member.name)
                    if not parts:
                        if member.isdir():
                            continue
                        raise ContainerCodeQLDockerError(
                            "CODEQL_DOCKER_COPY_ARCHIVE_INVALID"
                        )
                    key = "/".join(parts).casefold()
                    if key in seen or not (member.isdir() or member.isfile()):
                        raise ContainerCodeQLDockerError(
                            "CODEQL_DOCKER_COPY_ARCHIVE_INVALID"
                        )
                    seen.add(key)
                    if member.isfile():
                        total += member.size
                        if member.size < 0 or total > max_bytes:
                            raise ContainerCodeQLDockerError("CODEQL_DOCKER_COPY_LIMIT")
                    validated.append((member, parts))

                for member, parts in validated:
                    target = destination.joinpath(*parts)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise ContainerCodeQLDockerError(
                            "CODEQL_DOCKER_COPY_ARCHIVE_INVALID"
                        )
                    remaining = member.size
                    with target.open("xb") as output:
                        while remaining:
                            chunk = source.read(min(_STREAM_CHUNK_BYTES, remaining))
                            if not chunk:
                                raise ContainerCodeQLDockerError(
                                    "CODEQL_DOCKER_COPY_ARCHIVE_INVALID"
                                )
                            output.write(chunk)
                            remaining -= len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
        except ContainerCodeQLDockerError:
            raise
        except (OSError, tarfile.TarError, ValueError):
            raise ContainerCodeQLDockerError(
                "CODEQL_DOCKER_COPY_ARCHIVE_INVALID"
            ) from None

    async def copy_database(
        self,
        container_name: str,
        destination: Path,
        *,
        max_bytes: int,
    ) -> None:
        """Stream the fixed tmpfs DB through a bounded, safely extracted archive."""

        name = self._name(container_name)
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_COPY_LIMIT")
        try:
            info = destination.lstat()
            exact = destination.resolve(strict=True)
            if (
                not destination.is_absolute()
                or destination.is_symlink()
                or int(getattr(info, "st_file_attributes", 0)) & 0x400
                or exact != destination.absolute()
                or not exact.is_dir()
                or any(exact.iterdir())
            ):
                raise ValueError
        except (OSError, ValueError):
            raise ContainerCodeQLDockerError(
                "CODEQL_DOCKER_COPY_DESTINATION_INVALID"
            ) from None
        archive_handle = tempfile.NamedTemporaryFile(
            mode="xb",
            prefix=".sastsimi-codeql-",
            suffix=".tar",
            dir=exact.parent,
            delete=False,
        )
        archive_path = Path(archive_handle.name)
        archive_handle.close()
        archive_path.unlink()
        try:
            archive_limit = max_bytes + _ARCHIVE_OVERHEAD_LIMIT_BYTES
            await self._write_bounded_archive(
                self._command(
                    "exec",
                    name,
                    "/usr/bin/tar",
                    "-C",
                    "/work/database/codeql-db",
                    "-cf",
                    "-",
                    ".",
                ),
                archive_path,
                max_bytes=archive_limit,
            )
            self._extract_database_archive(
                archive_path,
                exact,
                max_bytes=max_bytes,
            )
        except BaseException:
            for candidate in tuple(exact.iterdir()):
                if candidate.is_dir() and not candidate.is_symlink():
                    import shutil

                    shutil.rmtree(candidate, ignore_errors=True)
                else:
                    try:
                        candidate.unlink()
                    except OSError:
                        pass
            raise
        finally:
            try:
                archive_path.unlink()
            except OSError:
                pass

    async def wait_provision_ready(self, container_name: str) -> bool:
        """Wait for the fixed marker while the tmpfs-bearing container runs."""

        name = self._name(container_name)
        while True:
            state_payload = await self._capture(
                self._command(
                    "inspect",
                    "--type",
                    "container",
                    "--format",
                    "{{json .State}}",
                    "--",
                    name,
                ),
                failure_code="CODEQL_DOCKER_PROVISION_STATE_FAILED",
                limit_code="CODEQL_DOCKER_CONTROL_OUTPUT_LIMIT",
                max_bytes=_CONTROL_OUTPUT_LIMIT_BYTES,
            )
            logs = await self._capture(
                self._command("logs", "--", name),
                failure_code="CODEQL_DOCKER_PROVISION_LOGS_FAILED",
                limit_code="CODEQL_DOCKER_CONTROL_OUTPUT_LIMIT",
                max_bytes=_PROVISION_OUTPUT_LIMIT_BYTES,
            )
            try:
                state = json.loads(state_payload.decode("utf-8", errors="strict"))
                if (
                    not isinstance(state, dict)
                    or not isinstance(state.get("Running"), bool)
                    or type(state.get("ExitCode")) is not int
                ):
                    raise ValueError
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                raise ContainerCodeQLDockerError(
                    "CODEQL_DOCKER_PROVISION_STATE_INVALID"
                ) from None
            if state["Running"] is True and logs == _PROVISION_READY:
                return True
            if state["Running"] is False:
                return False
            if logs not in (b"", _PROVISION_READY):
                raise ContainerCodeQLDockerError("CODEQL_DOCKER_PROVISION_LOGS_INVALID")
            await asyncio.sleep(0.1)

    async def probe(
        self,
        container_name: str,
        request: ContainerCodeQLProbeRequest,
    ) -> ContainerCodeQLProbeObservation:
        """Read one already-started fixed-entrypoint probe container.

        The pure command boundary owns ``Cmd=["probe", cap+1, cap+1]`` and the
        runtime validates it before start. This method deliberately performs
        only ``wait`` and bounded ``logs``; it never invokes ``docker exec`` or
        a shell inside the container.
        """

        from sastsimi.static_analysis.container_codeql_runtime import (
            ContainerCodeQLProbeObservation,
            TmpfsCapDenialEvidence,
        )

        name = self._name(container_name)
        database_attempted = request.database_attempted_bytes
        output_attempted = request.output_attempted_bytes
        if (
            type(database_attempted) is not int
            or database_attempted <= 1
            or type(output_attempted) is not int
            or output_attempted <= 1
        ):
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_PROBE_INVALID")
        if await self.wait(name) != 0:
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_PROBE_EXIT_NONZERO")
        payload = await self._capture(
            self._command("logs", "--", name),
            failure_code="CODEQL_DOCKER_PROBE_LOGS_FAILED",
            limit_code="CODEQL_DOCKER_PROBE_LIMIT",
            max_bytes=_PROBE_OUTPUT_LIMIT_BYTES,
        )
        try:
            decoded = json.loads(payload.decode("utf-8", errors="strict"))
            if (
                not isinstance(decoded, dict)
                or set(decoded)
                != {
                    "schema_version",
                    "codeql_version",
                    "database",
                    "output",
                }
                or decoded["schema_version"] != 1
                or decoded["codeql_version"] != request.expected_codeql_version
            ):
                raise ValueError
            database = self._probe_denial(
                decoded["database"],
                target="/work/database",
                attempted_bytes=database_attempted,
            )
            output = self._probe_denial(
                decoded["output"],
                target="/work/output",
                attempted_bytes=output_attempted,
            )
            return ContainerCodeQLProbeObservation(
                codeql_version=request.expected_codeql_version,
                database=TmpfsCapDenialEvidence(**database),
                output=TmpfsCapDenialEvidence(**output),
            )
        except (
            KeyError,
            TypeError,
            UnicodeDecodeError,
            ValueError,
            json.JSONDecodeError,
        ):
            raise ContainerCodeQLDockerError("CODEQL_DOCKER_PROBE_INVALID") from None

    @staticmethod
    def _probe_denial(
        value: object, *, target: str, attempted_bytes: int
    ) -> _ProbeDenial:
        if not isinstance(value, dict) or set(value) != {
            "target",
            "limit_bytes",
            "attempted_bytes",
            "bytes_written",
            "denial_code",
        }:
            raise ValueError
        limit = value["limit_bytes"]
        written = value["bytes_written"]
        denial_code = value["denial_code"]
        if (
            value["target"] != target
            or type(limit) is not int
            or limit != attempted_bytes - 1
            or type(value["attempted_bytes"]) is not int
            or value["attempted_bytes"] != attempted_bytes
            or type(written) is not int
            or not 0 <= written <= limit
            or not isinstance(denial_code, str)
            or denial_code not in _PROBE_DENIAL_CODES
        ):
            raise ValueError
        return _ProbeDenial(
            target=target,
            limit_bytes=limit,
            attempted_bytes=attempted_bytes,
            bytes_written=written,
            denial_code=denial_code,
        )


__all__ = ["ContainerCodeQLDockerError", "ContainerCodeQLDockerPort"]
