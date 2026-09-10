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
