import asyncio
import ctypes
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.ports.dto import MonotonicActionDeadline, ProcessSpec


def _set_last_error(value: int) -> None:
    """Call the Win32-only ctypes hook without exposing it to Linux typing."""
    setter = cast(Callable[[int], int], vars(ctypes)["set_last_error"])
    setter(value)


def _win_dll(name: str, *, use_last_error: bool) -> Any:
    """Load a Win32 DLL only inside tests already guarded by the platform skip."""
    loader = cast(Callable[..., Any], vars(ctypes)["WinDLL"])
    return loader(name, use_last_error=use_last_error)


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

    def cancel_pipe_io(self, pipe: object) -> None:
        self.events.append(f"cancel_pipe_io:{pipe}")

    def release_pipe_io(self, pipe: object) -> None:
        self.events.append(f"release_pipe_io:{pipe}")


def win_spec() -> ProcessSpec:
    return ProcessSpec(
        invocation_id="i1",
        command_kind="fixture",
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


class BlockingFakeWin32Api(FakeWin32Api):
    def __init__(self) -> None:
        super().__init__()
        self.wait_started = threading.Event()
        self.wait_released = threading.Event()

    def wait_process(self, process: object, timeout_ms: int) -> int | None:
        del process, timeout_ms
        self.wait_started.set()
        if not self.wait_released.wait(timeout=5):
            raise TimeoutError("test wait was not released")
        return 1

    def terminate_job(self, job: object) -> None:
        super().terminate_job(job)
        self.wait_released.set()


class DoubleCancelFakeWin32Api(FakeWin32Api):
    def __init__(self) -> None:
        super().__init__()
        self.wait_started = threading.Event()
        self.wait_finished = threading.Event()
        self.terminated = threading.Event()
        self.read_started = threading.Event()
        self.read_release = threading.Event()
        self.closed_before_read_release: list[str] = []

    def wait_process(self, process: object, timeout_ms: int) -> int | None:
        del process, timeout_ms
        self.wait_started.set()
        if not self.terminated.wait(timeout=5):
            raise TimeoutError("test process was not terminated")
        self.wait_finished.set()
        return 1

    def terminate_job(self, job: object) -> None:
        super().terminate_job(job)
        self.terminated.set()

    def read_pipe(self, pipe: object, sink: Any) -> None:
        del pipe, sink
        self.read_started.set()
        if not self.read_release.wait(timeout=5):
            raise TimeoutError("test pipe was not released")

    def close(self, handle: object) -> None:
        if not self.read_release.is_set() or not self.wait_finished.is_set():
            self.closed_before_read_release.append(str(handle))
        super().close(handle)


class BlockingReadAfterExitApi(DoubleCancelFakeWin32Api):
    def wait_process(self, process: object, timeout_ms: int) -> int | None:
        del process, timeout_ms
        self.wait_started.set()
        self.wait_finished.set()
        return 0


class TerminateFailureApi(DoubleCancelFakeWin32Api):
    def terminate_job(self, job: object) -> None:
        del job
        self.events.append("terminate_job_failed")
        raise OSError("TerminateJobObject")

    def close(self, handle: object) -> None:
        if handle == "job":
            self.terminated.set()
            self.read_release.set()
        super().close(handle)


class LingeringJobApi(BlockingReadAfterExitApi):
    def terminate_job(self, job: object) -> None:
        super().terminate_job(job)

    def cancel_pipe_io(self, pipe: object) -> None:
        super().cancel_pipe_io(pipe)
        self.read_release.set()


class DeferredPipeCancelApi(BlockingReadAfterExitApi):
    def __init__(self) -> None:
        super().__init__()
        self.cancel_requested = threading.Event()

    def cancel_pipe_io(self, pipe: object) -> None:
        super().cancel_pipe_io(pipe)
        self.cancel_requested.set()


class HungOriginalWaitApi(FakeWin32Api):
    def __init__(self) -> None:
        super().__init__()
        self.wait_started = threading.Event()
        self.wait_release = threading.Event()

    def wait_process(self, process: object, timeout_ms: int) -> int | None:
        del process, timeout_ms
        self.wait_started.set()
        assert self.wait_release.wait(timeout=2)
        return 1


@pytest.mark.asyncio
async def test_windows_backend_task_cancellation_terminates_job_before_cleanup() -> (
    None
):
    from sastsimi.static_analysis.process_windows import WindowsProcessBackend

    api = BlockingFakeWin32Api()
    backend = WindowsProcessBackend(api)
    running = asyncio.create_task(
        backend.run(
            win_spec(),
            30_000,
            cast(Any, object()),
            cast(Any, object()),
            asyncio.Event(),
        )
    )
    assert await asyncio.to_thread(api.wait_started.wait, 1)

    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running

    assert "terminate_job" in api.events
    assert {"stdout-r", "stderr-r", "process", "job"}.issubset(api.closed)


@pytest.mark.asyncio
async def test_windows_repeated_task_cancellation_waits_for_pipe_drain() -> None:
    from sastsimi.static_analysis.process_windows import WindowsProcessBackend

    api = DoubleCancelFakeWin32Api()
    backend = WindowsProcessBackend(api)
    running = asyncio.create_task(
        backend.run(
            win_spec(),
            30_000,
            cast(Any, object()),
            cast(Any, object()),
            asyncio.Event(),
        )
    )
    assert await asyncio.to_thread(api.wait_started.wait, 1)
    assert await asyncio.to_thread(api.read_started.wait, 1)

    running.cancel()
    assert await asyncio.to_thread(api.terminated.wait, 1)
    await asyncio.sleep(0)
    running.cancel()
    await asyncio.sleep(0)
    completed_before_drain = running.done()
    closed_before_drain = set(api.closed_before_read_release)
    api.read_release.set()

    with pytest.raises(asyncio.CancelledError):
        await running
    assert not completed_before_drain
    assert not ({"stdout-r", "stderr-r", "process", "job"} & closed_before_drain)


@pytest.mark.asyncio
async def test_windows_cancellation_after_process_exit_still_waits_for_pipe_drain() -> (
    None
):
    from sastsimi.static_analysis.process_windows import WindowsProcessBackend

    api = BlockingReadAfterExitApi()
    backend = WindowsProcessBackend(api)
    running = asyncio.create_task(
        backend.run(
            win_spec(),
            30_000,
            cast(Any, object()),
            cast(Any, object()),
            asyncio.Event(),
        )
    )
    assert await asyncio.to_thread(api.wait_started.wait, 1)
    assert await asyncio.to_thread(api.read_started.wait, 1)
    await asyncio.sleep(0)

    running.cancel()
    await asyncio.sleep(0)
    running.cancel()
    await asyncio.sleep(0)
    assert not running.done()
    assert not ({"stdout-r", "stderr-r", "process", "job"} & set(api.closed))
    api.read_release.set()

    with pytest.raises(asyncio.CancelledError):
        await running
    assert "terminate_job" in api.events
    assert len(api.closed) == len(set(api.closed))
    assert not backend._active


@pytest.mark.asyncio
async def test_windows_terminate_failure_uses_job_close_fallback_once() -> None:
    from sastsimi.static_analysis.process_windows import WindowsProcessBackend

    api = TerminateFailureApi()
    backend = WindowsProcessBackend(api)
    running = asyncio.create_task(
        backend.run(
            win_spec(),
            30_000,
            cast(Any, object()),
            cast(Any, object()),
            asyncio.Event(),
        )
    )
    assert await asyncio.to_thread(api.wait_started.wait, 1)
    assert await asyncio.to_thread(api.read_started.wait, 1)

    running.cancel()
    with pytest.raises(OSError, match="TerminateJobObject"):
        await running

    assert api.closed.count("job") == 1
    assert len(api.closed) == len(set(api.closed))
    assert not backend._active


@pytest.mark.asyncio
async def test_windows_parent_exit_with_open_job_pipe_is_bounded() -> None:
    from sastsimi.static_analysis.process_windows import WindowsProcessBackend

    api = LingeringJobApi()
    backend = WindowsProcessBackend(api, drain_timeout_seconds=0.1)

    result = await backend.run(
        win_spec(),
        30_000,
        cast(Any, object()),
        cast(Any, object()),
        asyncio.Event(),
    )

    assert result.timed_out
    assert "terminate_job" in api.events
    assert "cancel_pipe_io:stdout-r" in api.events
    assert "cancel_pipe_io:stderr-r" in api.events
    assert len(api.closed) == len(set(api.closed))
    assert not backend._active


@pytest.mark.asyncio
async def test_windows_closes_pipe_handles_only_after_native_readers_finish() -> None:
    """Closing pipes before drain completion can expose a reused native handle."""
    from sastsimi.static_analysis.process_windows import WindowsProcessBackend

    api = DeferredPipeCancelApi()
    backend = WindowsProcessBackend(api, drain_timeout_seconds=0.1)
    running = asyncio.create_task(
        backend.run(
            win_spec(),
            30_000,
            cast(Any, object()),
            cast(Any, object()),
            asyncio.Event(),
        )
    )
    assert await asyncio.to_thread(api.read_started.wait, 1)
    assert await asyncio.to_thread(api.cancel_requested.wait, 1)

    try:
        assert "stdout-r" not in api.closed
        assert "stderr-r" not in api.closed
    finally:
        api.read_release.set()
        result = await running

    assert result.timed_out
    assert {"stdout-r", "stderr-r"}.issubset(api.closed)


@pytest.mark.asyncio
async def test_windows_job_cancel_bounds_original_process_wait_and_defers_handle() -> (
    None
):
    """Removing the cleanup wait bound makes cancellation follow action timeout."""
    from sastsimi.static_analysis.process_windows import WindowsProcessBackend

    api = HungOriginalWaitApi()
    backend = WindowsProcessBackend(api, termination_timeout_seconds=0.02)
    running = asyncio.create_task(
        backend.run(
            win_spec(),
            30_000,
            cast(Any, object()),
            cast(Any, object()),
            asyncio.Event(),
        )
    )
    assert await asyncio.to_thread(api.wait_started.wait, 1)
    for _ in range(100):
        if "a1" in backend._active:
            break
        await asyncio.sleep(0.001)
    assert "a1" in backend._active
    cancelling = asyncio.create_task(backend.cancel("a1"))

    try:
        with pytest.raises(TimeoutError, match="WINDOWS_PROCESS_TERMINATION_TIMEOUT"):
            await asyncio.wait_for(asyncio.shield(cancelling), timeout=0.5)
        assert "process" not in api.closed
    finally:
        api.wait_release.set()
        await asyncio.gather(cancelling, running, return_exceptions=True)

    for _ in range(100):
        if "process" in api.closed:
            break
        await asyncio.sleep(0.01)
    assert "process" in api.closed


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
        self.GetCurrentThreadId = NativeCall(lambda: 123)
        self.OpenThread = NativeCall(lambda *_: 99)
        self.CancelSynchronousIo = NativeCall(
            lambda *_: self._result("CancelSynchronousIo")
        )
        for name in (
            "CreateProcessW",
            "CreateJobObjectW",
            "SetInformationJobObject",
            "AssignProcessToJobObject",
            "ResumeThread",
            "WaitForSingleObject",
            "GetExitCodeProcess",
            "TerminateProcess",
            "TerminateJobObject",
        ):
            setattr(
                self,
                name,
                NativeCall(lambda *_, operation=name: self._result(operation)),
            )

    def _result(self, operation: str) -> bool:
        count = self.calls.get(operation, 0) + 1
        self.calls[operation] = count
        failed = self.fail_operation == operation and count == self.fail_call
        if failed:
            _set_last_error(5)
        return not failed

    def _create_pipe(self, read: Any, write: Any, *_: object) -> bool:
        if not self._result("CreatePipe"):
            return False
        read_handle = self.next_handle
        write_handle = self.next_handle + 1
        self.next_handle += 2
        ctypes.cast(read, ctypes.POINTER(ctypes.c_void_p)).contents.value = read_handle
        ctypes.cast(
            write, ctypes.POINTER(ctypes.c_void_p)
        ).contents.value = write_handle
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
        _set_last_error(self.pipe_error)
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


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 ctypes boundary")
def test_ctypes_cancel_pipe_io_targets_registered_reader_thread() -> None:
    from sastsimi.static_analysis.process_windows import CtypesWin32Api

    kernel = FakeNativeKernel()
    api = CtypesWin32Api(kernel32=kernel)
    pipe = ctypes.c_void_p(10)
    api._reader_threads[id(pipe)] = ctypes.c_void_p(99)
    api._reader_in_read.add(id(pipe))

    api.cancel_pipe_io(pipe)

    assert kernel.calls["CancelSynchronousIo"] == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 ctypes boundary")
def test_ctypes_cancel_pipe_io_failure_is_not_silently_ignored() -> None:
    from sastsimi.static_analysis.process_windows import CtypesWin32Api

    kernel = FakeNativeKernel(fail_operation="CancelSynchronousIo")
    api = CtypesWin32Api(kernel32=kernel)
    pipe = ctypes.c_void_p(10)
    api._reader_threads[id(pipe)] = ctypes.c_void_p(99)
    api._reader_in_read.add(id(pipe))

    with pytest.raises(OSError):
        api.cancel_pipe_io(pipe)


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 ctypes boundary")
def test_ctypes_cancel_before_reader_registration_latches_stop() -> None:
    """Removing the pre-registration stop latch makes ReadFile run after cancel."""
    from sastsimi.static_analysis.process_windows import CtypesWin32Api

    kernel = FakeNativeKernel()
    open_started = threading.Event()
    open_release = threading.Event()
    read_called = threading.Event()

    def delayed_open_thread(*_args: object) -> int:
        open_started.set()
        assert open_release.wait(timeout=1)
        return 99

    def unexpected_read(*_args: object) -> bool:
        read_called.set()
        _set_last_error(109)
        return False

    kernel.OpenThread = NativeCall(delayed_open_thread)
    kernel.ReadFile = NativeCall(unexpected_read)
    api = CtypesWin32Api(kernel32=kernel)
    pipe = ctypes.c_void_p(10)
    reader = threading.Thread(
        target=api.read_pipe,
        args=(pipe, cast(Any, bytearray())),
    )
    reader.start()
    assert open_started.wait(timeout=1)

    api.cancel_pipe_io(pipe)
    open_release.set()
    reader.join(timeout=1)

    assert not reader.is_alive()
    assert not read_called.is_set()


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 ctypes boundary")
def test_ctypes_error_not_found_between_reads_still_stops_next_read() -> None:
    """Removing the stop latch makes a reader start again after no-I/O cancel."""
    from sastsimi.static_analysis.process_windows import CtypesWin32Api

    kernel = FakeNativeKernel()
    write_started = threading.Event()
    write_release = threading.Event()
    read_calls = 0

    def read_file(
        _pipe: object,
        _buffer: object,
        _size: object,
        read: object,
        _overlapped: object,
    ) -> bool:
        nonlocal read_calls
        read_calls += 1
        if read_calls == 1:
            ctypes.cast(
                cast(Any, read), ctypes.POINTER(ctypes.c_uint32)
            ).contents.value = 1
            return True
        _set_last_error(109)
        return False

    def no_pending_io(*_args: object) -> bool:
        _set_last_error(1168)
        return False

    class BlockingSink:
        def write(self, _data: bytes) -> None:
            write_started.set()
            assert write_release.wait(timeout=1)

    kernel.ReadFile = NativeCall(read_file)
    kernel.CancelSynchronousIo = NativeCall(no_pending_io)
    api = CtypesWin32Api(kernel32=kernel)
    pipe = ctypes.c_void_p(10)
    reader = threading.Thread(target=api.read_pipe, args=(pipe, BlockingSink()))
    reader.start()
    assert write_started.wait(timeout=1)

    api.cancel_pipe_io(pipe)
    write_release.set()
    reader.join(timeout=1)

    assert not reader.is_alive()
    assert read_calls == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 ctypes boundary")
def test_ctypes_retries_cancel_across_readfile_entry_gap() -> None:
    """A single ERROR_NOT_FOUND must not lose an entering ReadFile cancel."""
    from sastsimi.static_analysis.process_windows import CtypesWin32Api

    kernel = FakeNativeKernel()
    read_entered = threading.Event()
    read_release = threading.Event()
    cancel_calls = 0

    def blocking_read(*_args: object) -> bool:
        read_entered.set()
        assert read_release.wait(timeout=1)
        _set_last_error(995)
        return False

    def racing_cancel(*_args: object) -> bool:
        nonlocal cancel_calls
        cancel_calls += 1
        if cancel_calls == 1:
            _set_last_error(1168)
            return False
        read_release.set()
        return True

    kernel.ReadFile = NativeCall(blocking_read)
    kernel.CancelSynchronousIo = NativeCall(racing_cancel)
    api = CtypesWin32Api(kernel32=kernel)
    pipe = ctypes.c_void_p(10)
    reader = threading.Thread(
        target=api.read_pipe,
        args=(pipe, cast(Any, bytearray())),
    )
    reader.start()
    assert read_entered.wait(timeout=1)

    try:
        api.cancel_pipe_io(pipe)
        reader.join(timeout=1)
        assert not reader.is_alive()
        assert cancel_calls >= 2
    finally:
        read_release.set()
        reader.join(timeout=1)


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 ctypes boundary")
@pytest.mark.parametrize("operation", ["TerminateProcess", "TerminateJobObject"])
def test_ctypes_termination_failure_is_not_silently_ignored(operation: str) -> None:
    from sastsimi.static_analysis.process_windows import CtypesWin32Api

    kernel = FakeNativeKernel(fail_operation=operation)
    api = CtypesWin32Api(kernel32=kernel)

    with pytest.raises(OSError):
        if operation == "TerminateProcess":
            api.terminate_process(ctypes.c_void_p(10))
        else:
            api.terminate_job(ctypes.c_void_p(10))


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 process boundary")
@pytest.mark.asyncio
async def test_real_windows_process_restricts_handles_and_cancels_descendant(
    tmp_path: Path,
) -> None:
    from ctypes import wintypes
    from dataclasses import replace

    from sastsimi.static_analysis.process import AttemptOutputBudget, SafeProcessRunner

    kernel32 = _win_dll("kernel32", use_last_error=True)
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
