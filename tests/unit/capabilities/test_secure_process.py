from __future__ import annotations

import os
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


def test_probe_process_receives_only_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SASTSIMI_FORBIDDEN_SECRET", "must-not-propagate")
    result = SubprocessCommandProbeRunner().run(
        Path(sys.executable),
        (
            "-c",
            "import os; print('leaked' if "
            "'SASTSIMI_FORBIDDEN_SECRET' in os.environ else 'clean')",
        ),
        timeout_ms=5_000,
    )

    assert result.succeeded is True
    assert result.safe_stdout == "clean"


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
