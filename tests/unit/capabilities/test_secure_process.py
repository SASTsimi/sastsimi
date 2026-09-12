from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

import pytest

from sastsimi.capabilities.probes import (
    ProductionExecutableRegistry,
    SubprocessCommandProbeRunner,
)


def test_executable_registry_rejects_mutable_or_indirect_paths(tmp_path: Path) -> None:
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"tool")

    with pytest.raises(ValueError, match="CAPABILITY_EXECUTABLE_PATH_DENIED"):
        ProductionExecutableRegistry({"tool": executable}, forbidden_roots=(tmp_path,))

    outside = tmp_path.parent / (tmp_path.name + "-outside.exe")
    outside.write_bytes(b"tool")
    link = tmp_path / "link.exe"
    try:
        link.symlink_to(outside)
    except OSError:
        return
    with pytest.raises(ValueError, match="CAPABILITY_EXECUTABLE_PATH_DENIED"):
        ProductionExecutableRegistry({"tool": link}, forbidden_roots=())


def test_executable_registry_rejects_user_writable_direct_path(tmp_path: Path) -> None:
    executable = tmp_path / "user-controlled.exe"
    executable.write_bytes(b"tool")

    with pytest.raises(ValueError, match="CAPABILITY_EXECUTABLE_PATH_DENIED"):
        ProductionExecutableRegistry({"tool": executable}, forbidden_roots=())


def test_probe_process_receives_only_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SASTSIMI_FORBIDDEN_SECRET", "must-not-propagate")
    monkeypatch.setenv("HOME", "must-not-propagate-home")
    monkeypatch.setenv("USERPROFILE", "must-not-propagate-profile")
    monkeypatch.setenv("DOCKER_CONFIG", "must-not-propagate-docker-config")
    result = SubprocessCommandProbeRunner().run(
        Path(sys.executable),
        (
            "-c",
            "import os; denied={'SASTSIMI_FORBIDDEN_SECRET','HOME',"
            "'USERPROFILE','DOCKER_CONFIG'}; print('leaked' if "
            "denied & os.environ.keys() else 'clean')",
        ),
        timeout_ms=5_000,
    )

    assert result.succeeded is True
    assert result.safe_stdout == "clean"


def test_probe_process_allows_only_fixed_legacy_builder_override() -> None:
    runner = SubprocessCommandProbeRunner()
    result = runner.run(
        Path(sys.executable),
        ("-c", "import os; print(os.environ.get('DOCKER_BUILDKIT', 'missing'))"),
        timeout_ms=5_000,
        environment_overrides={"DOCKER_BUILDKIT": "0"},
    )

    assert result.succeeded is True
    assert result.safe_stdout == "0"
    with pytest.raises(ValueError, match="PROBE_ENVIRONMENT_OVERRIDE_DENIED"):
        runner.run(
            Path(sys.executable),
            ("-c", "print('must-not-run')"),
            timeout_ms=5_000,
            environment_overrides={"DOCKER_CONFIG": "untrusted"},
        )


def test_terminate_tree_targets_saved_group_after_parent_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []

    class ExitedParent:
        pid = 4242

        @staticmethod
        def poll() -> int:
            return 0

        @staticmethod
        def kill() -> None:
            raise AssertionError("process-only fallback must not be used")

    monkeypatch.setattr(
        os,
        "killpg",
        lambda process_group, sig: calls.append((process_group, sig)),
        raising=False,
    )
    monkeypatch.setattr(signal, "SIGKILL", 9, raising=False)

    SubprocessCommandProbeRunner._terminate_tree(ExitedParent())  # type: ignore[arg-type]

    assert calls == [(4242, 9)]


def test_probe_preserves_bounded_structured_output_beyond_version_length() -> None:
    structured_output = (
        '{"results":[{"check_id":"probe","path":"probe.py"}],"padding":"'
        + "x" * 300
        + '"}'
    )

    result = SubprocessCommandProbeRunner().run(
        Path(sys.executable),
        ("-c", f"print({structured_output!r})"),
        timeout_ms=5_000,
    )

    assert result.succeeded is True
    assert result.safe_stdout == structured_output


@pytest.mark.skipif(os.name != "nt", reason="Windows process-tree regression")
def test_timeout_terminates_spawned_process_tree(tmp_path: Path) -> None:
    marker = tmp_path / "child-heartbeat"
    child = (
        "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
        "[(p.write_text(str(i)),time.sleep(.05)) for i in range(200)]"
    )
    parent = (
        "import subprocess,sys,time; "
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); "
        "time.sleep(30)"
    )

    outcome = SubprocessCommandProbeRunner().run(
        Path(sys.executable),
        ("-c", parent, child, str(marker.resolve())),
        timeout_ms=300,
    )
    assert outcome.succeeded is False
    time.sleep(0.4)
    first = marker.read_text(encoding="utf-8")
    time.sleep(0.4)
    assert marker.read_text(encoding="utf-8") == first


@pytest.mark.skipif(os.name != "nt", reason="Windows process-tree regression")
def test_timeout_terminates_descendant_after_parent_exits(tmp_path: Path) -> None:
    marker = tmp_path / "orphan-heartbeat"
    child = (
        "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
        "[(p.write_text(str(i)),time.sleep(.05)) for i in range(200)]"
    )
    parent = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])"
    )

    outcome = SubprocessCommandProbeRunner().run(
        Path(sys.executable),
        ("-c", parent, child, str(marker.resolve())),
        timeout_ms=300,
    )
    assert outcome.succeeded is False
    time.sleep(0.4)
    first = marker.read_text(encoding="utf-8")
    time.sleep(0.4)
    assert marker.read_text(encoding="utf-8") == first
