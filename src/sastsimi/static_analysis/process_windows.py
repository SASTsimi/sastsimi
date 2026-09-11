"""Win32 suspended-process launcher with pre-resume Job Object containment."""

from __future__ import annotations

import asyncio
import ctypes
import os
import subprocess  # list2cmdline is quoting only; process creation stays Win32-direct.
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from sastsimi.ports.dto import ProcessSpec

CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_FLAGS = (
    CREATE_SUSPENDED
    | CREATE_NEW_PROCESS_GROUP
    | CREATE_UNICODE_ENVIRONMENT
    | EXTENDED_STARTUPINFO_PRESENT
)
ERROR_BROKEN_PIPE = 109


def _win_dll(name: str, *, use_last_error: bool) -> Any:
    """Resolve the Win32-only ctypes loader only after the platform guard."""
    loader = cast(Callable[..., Any], vars(ctypes)["WinDLL"])
    return loader(name, use_last_error=use_last_error)


def _get_last_error() -> int:
    """Read the thread-local Win32 error without Linux typeshed attributes."""
    getter = cast(Callable[[], int], vars(ctypes)["get_last_error"])
    return getter()


def _win_error(code: int, operation: str) -> OSError:
    """Build the native Windows error while remaining importable on Linux."""
    factory = cast(Callable[[int, str], OSError], vars(ctypes)["WinError"])
    return factory(code, operation)


@dataclass(frozen=True)
class BackendExecution:
    return_code: int | None
    timed_out: bool
    cancelled: bool


class OutputSink(Protocol):
    def write(self, data: bytes) -> None: ...


class Win32Api(Protocol):
    def create_pipes(self) -> tuple[object, ...]: ...
    def create_attribute_list(self, child_handles: tuple[object, ...]) -> object: ...
    def create_suspended(
        self,
        executable: Path,
        command_line: str,
        cwd: Path,
        env: tuple[tuple[str, str], ...],
        pipes: tuple[object, ...],
        attributes: object,
        flags: int,
    ) -> tuple[object, object]: ...
    def create_job(self) -> object: ...
    def set_kill_on_close(self, job: object) -> None: ...
    def assign_process(self, job: object, process: object) -> None: ...
    def resume_thread(self, thread: object) -> None: ...
    def close(self, handle: object) -> None: ...
    def delete_attribute_list(self, attributes: object) -> None: ...
    def terminate_process(self, process: object) -> None: ...
    def terminate_job(self, job: object) -> None: ...
    def wait_process(self, process: object, timeout_ms: int) -> int | None: ...
    def read_pipe(self, pipe: object, sink: OutputSink) -> None: ...


@dataclass(frozen=True)
class LaunchedProcess:
    process: object
    job: object
    stdout_read: object
    stderr_read: object


class SuspendedJobLauncher:
    def __init__(self, api: Win32Api) -> None:
        self.api = api

    def launch(self, spec: ProcessSpec) -> LaunchedProcess:
        if any("\x00" in value for value in spec.argv) or any(
            "\x00" in key or "\x00" in value for key, value in spec.env
        ):
            raise ValueError("NUL_IN_WINDOWS_PROCESS_INPUT")
        pipes: tuple[object, ...] = ()
        attributes: object | None = None
        process: object | None = None
        thread: object | None = None
        job: object | None = None
        keep: set[int] = set()
        try:
            pipes = self.api.create_pipes()
            if len(pipes) == 6:
                child_handles: tuple[object, ...] = (pipes[0], pipes[3], pipes[5])
                stdout_read, stderr_read = pipes[2], pipes[4]
            elif len(pipes) == 4:  # deterministic cross-platform contract fake
                child_handles = (pipes[1], pipes[3])
                stdout_read, stderr_read = pipes[0], pipes[2]
            else:
                raise OSError("WIN32_PIPE_SHAPE_INVALID")
            attributes = self.api.create_attribute_list(child_handles)
            process, thread = self.api.create_suspended(
                Path(spec.argv[0]),
                subprocess.list2cmdline(list(spec.argv)),
                spec.cwd,
                spec.env,
                pipes,
                attributes,
                CREATE_FLAGS,
            )
            job = self.api.create_job()
            self.api.set_kill_on_close(job)
            self.api.assign_process(job, process)
            self.api.resume_thread(thread)
            keep = {id(process), id(job), id(stdout_read), id(stderr_read)}
            return LaunchedProcess(process, job, stdout_read, stderr_read)
        except BaseException:
            if process is not None:
                self.api.terminate_process(process)
            raise
        finally:
            if attributes is not None:
                self.api.delete_attribute_list(attributes)
            for handle in (*pipes, thread, process, job):
                if handle is not None and id(handle) not in keep:
                    self.api.close(handle)


class WindowsProcessBackend:
    def __init__(self, api: Win32Api | None = None) -> None:
        self.api = api or CtypesWin32Api()
        self.launcher = SuspendedJobLauncher(self.api)
        self._active: dict[str, LaunchedProcess] = {}

    async def run(
        self,
        spec: ProcessSpec,
        timeout_ms: int,
        stdout: OutputSink,
        stderr: OutputSink,
        cancel_event: asyncio.Event,
    ) -> BackendExecution:
        launched = self.launcher.launch(spec)
        self._active[spec.attempt_id] = launched
        stdout_task = asyncio.create_task(
            asyncio.to_thread(self.api.read_pipe, launched.stdout_read, stdout)
        )
        stderr_task = asyncio.create_task(
            asyncio.to_thread(self.api.read_pipe, launched.stderr_read, stderr)
        )
        timed_out = False
        try:
            return_code = await asyncio.to_thread(
                self.api.wait_process, launched.process, timeout_ms
            )
            if return_code is None:
                timed_out = True
                self.api.terminate_job(launched.job)
                return_code = await asyncio.to_thread(
                    self.api.wait_process, launched.process, 1_000
                )
            await asyncio.gather(stdout_task, stderr_task)
            return BackendExecution(return_code, timed_out, cancel_event.is_set())
        except asyncio.CancelledError:
            cancel_event.set()
            self.api.terminate_job(launched.job)
            await asyncio.shield(
                asyncio.to_thread(self.api.wait_process, launched.process, 1_000)
            )
            await asyncio.shield(
                asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            )
            raise
        finally:
            self._active.pop(spec.attempt_id, None)
            for handle in (
                launched.stdout_read,
                launched.stderr_read,
                launched.process,
                launched.job,
            ):
                self.api.close(handle)

    async def cancel(self, attempt_id: str) -> bool:
        launched = self._active.get(attempt_id)
        if launched is None:
            return False
        self.api.terminate_job(launched.job)
        await asyncio.to_thread(self.api.wait_process, launched.process, 1_000)
        return True


class CtypesWin32Api:
    """Small typed wrapper around the Win32 calls needed by the launcher."""

    def __init__(self, *, kernel32: Any | None = None) -> None:
        if os.name != "nt":
            raise OSError("WIN32_BACKEND_UNAVAILABLE")
        self.kernel32: Any = kernel32 or _win_dll("kernel32", use_last_error=True)
        from ctypes import wintypes

        self.kernel32.CreatePipe.restype = wintypes.BOOL
        self.kernel32.SetHandleInformation.restype = wintypes.BOOL
        self.kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        self.kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
        self.kernel32.CreateProcessW.restype = wintypes.BOOL
        self.kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel32.ResumeThread.restype = wintypes.DWORD
        self.kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        self.kernel32.ReadFile.restype = wintypes.BOOL
        self._attribute_buffers: dict[int, object] = {}

    def _checked(self, ok: object, operation: str) -> None:
        if not ok:
            raise _win_error(_get_last_error(), operation)

    def create_pipes(self) -> tuple[object, ...]:
        from ctypes import wintypes

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [
                ("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", wintypes.LPVOID),
                ("bInheritHandle", wintypes.BOOL),
            ]

        security = SecurityAttributes(ctypes.sizeof(SecurityAttributes), None, True)
        handles: list[object] = []
        try:
            for _ in range(3):
                read_handle = wintypes.HANDLE()
                write_handle = wintypes.HANDLE()
                self._checked(
                    self.kernel32.CreatePipe(
                        ctypes.byref(read_handle),
                        ctypes.byref(write_handle),
                        ctypes.byref(security),
                        0,
                    ),
                    "CreatePipe",
                )
                handles.extend((read_handle, write_handle))
            # Parent stdin-write, stdout-read, and stderr-read ends never inherit.
            for handle in (handles[1], handles[2], handles[4]):
                self._checked(
                    self.kernel32.SetHandleInformation(handle, 1, 0),
                    "SetHandleInformation",
                )
            return tuple(handles)
        except BaseException:
            for handle in handles:
                self.close(handle)
            raise

    def create_attribute_list(self, child_handles: tuple[object, ...]) -> object:
        size = ctypes.c_size_t()
        self.kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        if size.value == 0:
            raise _win_error(_get_last_error(), "InitializeProcThreadAttributeList")
        buffer = ctypes.create_string_buffer(size.value)
        pointer = ctypes.cast(buffer, ctypes.c_void_p)
        initialized = False
        try:
            self._checked(
                self.kernel32.InitializeProcThreadAttributeList(
                    pointer, 1, 0, ctypes.byref(size)
                ),
                "InitializeProcThreadAttributeList",
            )
            initialized = True
            array_type = ctypes.c_void_p * len(child_handles)
            values = array_type(
                *(
                    ctypes.cast(cast(Any, item), ctypes.c_void_p)
                    for item in child_handles
                )
            )
            self._checked(
                self.kernel32.UpdateProcThreadAttribute(
                    pointer,
                    0,
                    0x00020002,
                    ctypes.byref(values),
                    ctypes.sizeof(values),
                    None,
                    None,
                ),
                "UpdateProcThreadAttribute",
            )
            self._attribute_buffers[id(pointer)] = (buffer, values)
            return pointer
        except BaseException:
            if initialized:
                self.kernel32.DeleteProcThreadAttributeList(pointer)
            self._attribute_buffers.pop(id(pointer), None)
            raise

    def create_suspended(
        self,
        executable: Path,
        command_line: str,
        cwd: Path,
        env: tuple[tuple[str, str], ...],
        pipes: tuple[object, ...],
        attributes: object,
        flags: int,
    ) -> tuple[object, object]:
        from ctypes import wintypes

        class StartupInfo(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD),
                ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD),
                ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE),
            ]

        class StartupInfoEx(ctypes.Structure):
            _fields_ = [
                ("StartupInfo", StartupInfo),
                ("lpAttributeList", ctypes.c_void_p),
            ]

        class ProcessInformation(ctypes.Structure):
            _fields_ = [
                ("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),
            ]

        if len(pipes) != 6:
            raise OSError("WIN32_PIPE_SHAPE_INVALID")
        startup = StartupInfoEx()
        startup.StartupInfo.cb = ctypes.sizeof(StartupInfoEx)
        startup.StartupInfo.dwFlags = 0x00000100
        startup.StartupInfo.hStdInput = pipes[0]
        startup.StartupInfo.hStdOutput = pipes[3]
        startup.StartupInfo.hStdError = pipes[5]
        startup.lpAttributeList = ctypes.cast(cast(Any, attributes), ctypes.c_void_p)
        process = ProcessInformation()
        command = ctypes.create_unicode_buffer(command_line)
        environment = ctypes.create_unicode_buffer(
            "\x00".join(f"{key}={value}" for key, value in sorted(env)) + "\x00\x00"
        )
        self._checked(
            self.kernel32.CreateProcessW(
                str(executable),
                command,
                None,
                None,
                True,
                flags,
                environment,
                str(cwd),
                ctypes.byref(startup),
                ctypes.byref(process),
            ),
            "CreateProcessW",
        )
        return process.hProcess, process.hThread

    def create_job(self) -> object:
        job = self.kernel32.CreateJobObjectW(None, None)
        self._checked(job, "CreateJobObjectW")
        return job

    def set_kill_on_close(self, job: object) -> None:
        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_ulonglong)
                for name in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x00002000
        self._checked(
            self.kernel32.SetInformationJobObject(
                job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
            ),
            "SetInformationJobObject",
        )

    def assign_process(self, job: object, process: object) -> None:
        self._checked(
            self.kernel32.AssignProcessToJobObject(job, process),
            "AssignProcessToJobObject",
        )

    def resume_thread(self, thread: object) -> None:
        if self.kernel32.ResumeThread(thread) == 0xFFFFFFFF:
            raise _win_error(_get_last_error(), "ResumeThread")

    def close(self, handle: object) -> None:
        if handle:
            self.kernel32.CloseHandle(handle)

    def delete_attribute_list(self, attributes: object) -> None:
        self.kernel32.DeleteProcThreadAttributeList(attributes)
        self._attribute_buffers.pop(id(attributes), None)

    def terminate_process(self, process: object) -> None:
        self.kernel32.TerminateProcess(process, 1)

    def terminate_job(self, job: object) -> None:
        self.kernel32.TerminateJobObject(job, 1)

    def wait_process(self, process: object, timeout_ms: int) -> int | None:
        from ctypes import wintypes

        result = self.kernel32.WaitForSingleObject(process, timeout_ms)
        if result == 0x00000102:
            return None
        if result != 0:
            raise _win_error(_get_last_error(), "WaitForSingleObject")
        exit_code = wintypes.DWORD()
        self._checked(
            self.kernel32.GetExitCodeProcess(process, ctypes.byref(exit_code)),
            "GetExitCodeProcess",
        )
        return int(exit_code.value)

    def read_pipe(self, pipe: object, sink: OutputSink) -> None:
        buffer = ctypes.create_string_buffer(64 * 1024)
        read = ctypes.c_uint32()
        while True:
            ok = self.kernel32.ReadFile(
                pipe, buffer, len(buffer), ctypes.byref(read), None
            )
            if not ok:
                error = _get_last_error()
                if error == ERROR_BROKEN_PIPE:
                    return
                raise _win_error(error, "ReadFile")
            if read.value:
                sink.write(buffer.raw[: read.value])
            else:
                return
