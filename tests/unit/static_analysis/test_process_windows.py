import asyncio
import ctypes
import sys
import time
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.ports.dto import MonotonicActionDeadline, ProcessSpec


class FakeWin32Api:
    def __init__(self, fail_at: str | None = None) -> None:
        self.fail_at = fail_at
        self.events: list[str] = []
        self.closed: list[str] = []

    def _step(self, name: str, value: Any) -> Any:
        self.events.append(name)
        if self.fail_at == name:
            raise OSError(name)
        return value

    def create_pipes(self) -> tuple[object, ...]:
        return cast(
            tuple[object, ...],
            self._step("pipes", ("stdout-r", "stdout-w", "stderr-r", "stderr-w")),
        )

    def create_attribute_list(self, child_handles: tuple[object, ...]) -> object:
        assert child_handles == ("stdout-w", "stderr-w")
        return self._step("attributes", "attributes")

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
        assert executable == Path("C:/trusted/tool.exe")
        assert "a&b" in command_line
        assert flags & 0x00000004
        assert flags & 0x00080000
        return cast(
            tuple[object, object],
            self._step("create_suspended", ("process", "thread")),
        )

    def create_job(self) -> object:
        return self._step("create_job", "job")

    def set_kill_on_close(self, job: object) -> None:
        self._step("configure_job", None)

    def assign_process(self, job: object, process: object) -> None:
        self._step("assign_job", None)

    def resume_thread(self, thread: object) -> None:
        self._step("resume", None)

    def close(self, handle: object) -> None:
        self.closed.append(str(handle))

    def delete_attribute_list(self, attributes: object) -> None:
        self.events.append("delete_attributes")

    def terminate_process(self, process: object) -> None:
        self.events.append("terminate_process")

    def terminate_job(self, job: object) -> None:
        self.events.append("terminate_job")

    def wait_process(self, process: object, timeout_ms: int) -> int | None:
        return 0

    def read_pipe(self, pipe: object, sink: Any) -> None:
        pass


def win_spec() -> ProcessSpec:
    return ProcessSpec(
        invocation_id="i1",
        attempt_id="a1",
        argv=("C:/trusted/tool.exe", "a&b"),
        cwd=Path("C:/workspace"),
        env=(("SAFE", "value"),),
        attempt_output_dir=Path("C:/out"),
        stdout_limit_bytes=10,
        stderr_limit_bytes=10,
        attempt_output_limit_bytes=30,
        deadline=MonotonicActionDeadline(
            action_id="action", started_ns=0, expires_ns=1_000_000
        ),
    )


def test_windows_launcher_assigns_job_before_resume() -> None:
    from sastsimi.static_analysis.process_windows import SuspendedJobLauncher

    api = FakeWin32Api()
    launch = SuspendedJobLauncher(api).launch(win_spec())
    assert api.events[:7] == [
        "pipes",
        "attributes",
        "create_suspended",
        "create_job",
        "configure_job",
        "assign_job",
        "resume",
    ]
    assert launch.process == "process" and launch.job == "job"


@pytest.mark.parametrize(
    "failure",
    [
        "pipes",
        "attributes",
        "create_suspended",
        "create_job",
        "configure_job",
        "assign_job",
        "resume",
    ],
)
def test_windows_launcher_failure_never_resumes_early_and_cleans_up(
    failure: str,
) -> None:
    from sastsimi.static_analysis.process_windows import SuspendedJobLauncher

    api = FakeWin32Api(failure)
    with pytest.raises(OSError, match=failure):
        SuspendedJobLauncher(api).launch(win_spec())
    if failure != "resume":
        assert "resume" not in api.events
    if failure in {"create_job", "configure_job", "assign_job", "resume"}:
        assert "terminate_process" in api.events
    assert len(api.closed) == len(set(api.closed))


@pytest.mark.parametrize("use_argv", [True, False])
def test_windows_launcher_rejects_nul_before_api_call(use_argv: bool) -> None:
    from dataclasses import replace

    from sastsimi.static_analysis.process_windows import SuspendedJobLauncher

    api = FakeWin32Api()
    changed = (
        replace(win_spec(), argv=("C:/trusted/tool.exe", "bad\x00arg"))
        if use_argv
        else replace(win_spec(), env=(("SAFE", "bad\x00value"),))
    )
    with pytest.raises(ValueError, match="NUL"):
        SuspendedJobLauncher(api).launch(changed)
    assert api.events == []


class NativeCall:
    def __init__(self, callback: Any) -> None:
        self.callback = callback
        self.restype: object | None = None

    def __call__(self, *args: object) -> object:
        return self.callback(*args)


class FakeNativeKernel:
    def __init__(
        self, *, fail_operation: str | None = None, fail_call: int = 1
    ) -> None:
        self.fail_operation = fail_operation
        self.fail_call = fail_call
        self.calls: dict[str, int] = {}
        self.closed: list[int] = []
        self.deleted_attributes = 0
        self.next_handle = 10
        self.pipe_error = 109
        self.CreatePipe = NativeCall(self._create_pipe)
        self.SetHandleInformation = NativeCall(
            lambda *_: self._result("SetHandleInformation")
        )
        self.InitializeProcThreadAttributeList = NativeCall(self._initialize_attributes)
        self.UpdateProcThreadAttribute = NativeCall(
            lambda *_: self._result("UpdateProcThreadAttribute")
        )
        self.DeleteProcThreadAttributeList = NativeCall(self._delete_attributes)
        self.CloseHandle = NativeCall(self._close)
        self.ReadFile = NativeCall(self._read_file)
        for name in (
            "CreateProcessW",
            "CreateJobObjectW",
            "SetInformationJobObject",
            "AssignProcessToJobObject",
            "ResumeThread",
            "WaitForSingleObject",
            "GetExitCodeProcess",
        ):
            setattr(self, name, NativeCall(lambda *_: 1))

    def _result(self, operation: str) -> bool:
        count = self.calls.get(operation, 0) + 1
        self.calls[operation] = count
        failed = self.fail_operation == operation and count == self.fail_call
        if failed:
            ctypes.set_last_error(5)
        return not failed

    def _create_pipe(self, read: Any, write: Any, *_: object) -> bool:
        if not self._result("CreatePipe"):
            return False
        read_handle = self.next_handle
        write_handle = self.next_handle + 1
        self.next_handle += 2
        ctypes.cast(read, ctypes.POINTER(ctypes.c_void_p)).contents.value = read_handle
        ctypes.cast(write, ctypes.POINTER(ctypes.c_void_p)).contents.value = (
            write_handle
        )
        return True

    def _initialize_attributes(
        self, pointer: Any, _count: object, _flags: object, size: Any
    ) -> bool:
        if pointer is None:
            ctypes.cast(size, ctypes.POINTER(ctypes.c_size_t)).contents.value = 64
            return False
        return self._result("InitializeProcThreadAttributeList")

    def _delete_attributes(self, *_: object) -> None:
        self.deleted_attributes += 1

    def _close(self, handle: Any) -> bool:
        value = handle.value if hasattr(handle, "value") else int(handle)
        self.closed.append(int(value))
        return True

    def _read_file(self, *_: object) -> bool:
        ctypes.set_last_error(self.pipe_error)
        return False


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 ctypes boundary")
@pytest.mark.parametrize(
    ("operation", "call_number", "closed"),
    [
        ("CreatePipe", 2, {10, 11}),
        ("CreatePipe", 3, {10, 11, 12, 13}),
        ("SetHandleInformation", 1, {10, 11, 12, 13, 14, 15}),
        ("SetHandleInformation", 3, {10, 11, 12, 13, 14, 15}),
    ],
)
def test_ctypes_create_pipes_closes_every_partial_handle(
    operation: str, call_number: int, closed: set[int]
) -> None:
    from sastsimi.static_analysis.process_windows import CtypesWin32Api

    kernel = FakeNativeKernel(fail_operation=operation, fail_call=call_number)
    api = CtypesWin32Api(kernel32=kernel)

    with pytest.raises(OSError):
        api.create_pipes()

    assert set(kernel.closed) == closed
    assert len(kernel.closed) == len(set(kernel.closed))


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 ctypes boundary")
@pytest.mark.parametrize(
    ("operation", "deleted"),
    [
        ("InitializeProcThreadAttributeList", 0),
        ("UpdateProcThreadAttribute", 1),
    ],
)
def test_ctypes_attribute_failure_releases_each_initialized_resource(
    operation: str, deleted: int
) -> None:
    from sastsimi.static_analysis.process_windows import CtypesWin32Api

    kernel = FakeNativeKernel(fail_operation=operation)
    api = CtypesWin32Api(kernel32=kernel)

    with pytest.raises(OSError):
        api.create_attribute_list((ctypes.c_void_p(10), ctypes.c_void_p(11)))

    assert kernel.deleted_attributes == deleted
    assert api._attribute_buffers == {}


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 ctypes boundary")
def test_ctypes_read_pipe_accepts_only_broken_pipe_as_eof() -> None:
    from sastsimi.static_analysis.process_windows import CtypesWin32Api

    kernel = FakeNativeKernel()
    api = CtypesWin32Api(kernel32=kernel)
    api.read_pipe(ctypes.c_void_p(10), cast(Any, bytearray()))
    kernel.pipe_error = 5
    with pytest.raises(OSError):
        api.read_pipe(ctypes.c_void_p(10), cast(Any, bytearray()))


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 process boundary")
@pytest.mark.asyncio
async def test_real_windows_process_restricts_handles_and_cancels_descendant(
    tmp_path: Path,
) -> None:
    from ctypes import wintypes
    from dataclasses import replace

    from sastsimi.static_analysis.process import AttemptOutputBudget, SafeProcessRunner

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateEventW.restype = wintypes.HANDLE
    sentinel = kernel32.CreateEventW(None, True, False, None)
    assert sentinel
    assert kernel32.SetHandleInformation(sentinel, 1, 1)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "attempt"
    output.mkdir()
    executable = Path(sys.executable)
    budget = AttemptOutputBudget(attempt_id="a1", limit_bytes=4_096)
    runner = SafeProcessRunner(
        action_id="action",
        attempt_id="a1",
        workspace_root=workspace,
        output_root=output,
        executable=executable,
        output_budget=budget,
    )
    try:
        inherit_check = replace(
            win_spec(),
            argv=(
                str(executable),
                "-c",
                (
                    "import ctypes,sys;from ctypes import wintypes;"
                    "k=ctypes.WinDLL('kernel32',use_last_error=True);"
                    "print(int(bool(k.SetEvent(int(sys.argv[1])))))"
                ),
                str(int(sentinel)),
            ),
            cwd=workspace,
            attempt_output_dir=output,
            stdout_limit_bytes=1_024,
            stderr_limit_bytes=1_024,
            attempt_output_limit_bytes=4_096,
            deadline=MonotonicActionDeadline(
                action_id="action",
                started_ns=time.monotonic_ns(),
                expires_ns=time.monotonic_ns() + 10_000_000_000,
            ),
        )
        result = await runner.run(inherit_check)
        assert result.outcome == "SUCCEEDED"
        assert result.stdout.strip() == b"0"
        assert kernel32.WaitForSingleObject(sentinel, 0) == 0x00000102

        child_file = output / "child.pid"
        child_run = replace(
            inherit_check,
            invocation_id="descendant",
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
        running = asyncio.create_task(runner.run(child_run))
        for _ in range(100):
            if child_file.exists():
                break
            await asyncio.sleep(0.02)
        assert child_file.exists()
        child_pid = int(child_file.read_text())
        assert (await runner.cancel("a1")).cancelled
        assert (await running).outcome == "CANCELLED"
        process = kernel32.OpenProcess(0x1000, False, child_pid)
        if process:
            exit_code = wintypes.DWORD()
            assert kernel32.GetExitCodeProcess(process, ctypes.byref(exit_code))
            kernel32.CloseHandle(process)
            assert exit_code.value != 259
    finally:
        kernel32.CloseHandle(sentinel)
