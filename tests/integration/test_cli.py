import json
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("system", "release", "version", "machine", "python", "bits", "expected"),
    [
        ("Windows", "11", "", "AMD64", (3, 12, 4), 64, 0),
        ("Windows", "2022Server", "", "AMD64", (3, 12, 4), 64, 0),
        ("Linux", "ubuntu", "24.04", "x86_64", (3, 12, 4), 64, 0),
        ("Windows", "10", "", "AMD64", (3, 12, 4), 64, 4),
        ("Linux", "debian", "12", "x86_64", (3, 12, 4), 64, 4),
        ("Linux", "ubuntu", "22.04", "x86_64", (3, 12, 4), 64, 4),
        ("Darwin", "24", "", "arm64", (3, 12, 4), 64, 4),
        ("Windows", "11", "", "ARM64", (3, 12, 4), 64, 4),
        ("Linux", "ubuntu", "24.04", "x86_64", (3, 13, 0), 64, 4),
        ("Windows", "11", "", "AMD64", (3, 12, 4), 32, 4),
    ],
)
def test_doctor_platform_exit_contract(
    system: str,
    release: str,
    version: str,
    machine: str,
    python: tuple[int, int, int],
    bits: int,
    expected: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from sastsimi.interfaces.cli import commands
    from sastsimi.interfaces.cli.main import main

    host = commands.HostInfo(system, release, version, machine, python, "CPython", bits)
    monkeypatch.setattr(commands, "inspect_host", lambda: host)
    for name in os.environ:
        if name.startswith("SASTSIMI_"):
            monkeypatch.delenv(name)
    assert main(["doctor", "--format", "json"]) == expected
    output = capsys.readouterr()
    event = json.loads(output.out if expected == 0 else output.err)
    assert set(event) == {"schema_version", "command", "status", "code", "data"}
    assert event["schema_version"] == 1
    assert event["code"] == ("OK" if expected == 0 else "CAPABILITY_UNSUPPORTED")
    assert (output.err if expected == 0 else output.out) == ""


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["run"],
        ["doctor", "--format", "yaml"],
        ["doctor", "--unknown", "/home/synthetic/TEST_ONLY_SECRET"],
    ],
)
def test_cli_input_errors_are_safe(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    from sastsimi.interfaces.cli.main import main

    assert main(argv) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "TEST_ONLY_SECRET" not in output.err
    assert "/home/" not in output.err


def test_config_error_and_internal_error_do_not_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sastsimi.interfaces.cli import commands
    from sastsimi.interfaces.cli.main import main

    assert main(["--config", str(tmp_path / "TEST_ONLY_SECRET"), "doctor"]) == 3
    output = capsys.readouterr()
    assert str(tmp_path) not in output.err
    assert "TEST_ONLY_SECRET" not in output.err

    def broken_host() -> commands.HostInfo:
        raise RuntimeError("TEST_ONLY_SECRET /home/synthetic/private")

    monkeypatch.setattr(commands, "inspect_host", broken_host)
    assert main(["doctor"]) == 10
    output = capsys.readouterr()
    assert output.out == ""
    assert "TEST_ONLY_SECRET" not in output.err
    assert "/home/" not in output.err


def test_entrypoints_help_and_doctor_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sastsimi.interfaces.cli.main import main

    monkeypatch.setenv("SASTSIMI_DATA_DIR", str(tmp_path / "new-state"))
    assert main(["--help"]) == 0
    assert "doctor" in capsys.readouterr().out
    assert main(["doctor"]) in (0, 4)
    assert not (tmp_path / "new-state").exists()
    for command in (
        [sys.executable, "-m", "sastsimi", "--help"],
        ["sastsimi", "--help"],
    ):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        assert result.returncode == 0
        assert "doctor" in result.stdout
        assert result.stderr == ""


@pytest.mark.parametrize(
    ("system", "release", "version"),
    [
        ("Windows", "2022Server", ""),
        ("Linux", "ubuntu", "24.04"),
    ],
)
def test_real_probe_reads_platform_sources(
    system: str, release: str, version: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.interfaces.cli import commands

    monkeypatch.setattr(platform, "system", lambda: system)
    monkeypatch.setattr(platform, "win32_ver", lambda: (release, "", "", ""))
    monkeypatch.setattr(
        platform,
        "freedesktop_os_release",
        lambda: {"ID": release, "VERSION_ID": version},
    )
    host = commands.inspect_host()
    assert (host.system, host.release, host.version) == (system, release, version)


def test_non_cpython_is_unsupported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sastsimi.interfaces.cli import commands
    from sastsimi.interfaces.cli.main import main

    monkeypatch.setattr(
        commands,
        "inspect_host",
        lambda: commands.HostInfo("Windows", "11", "", "AMD64", (3, 12, 1), "PyPy", 64),
    )
    assert main(["doctor"]) == 4
    assert "CAPABILITY_UNSUPPORTED" in capsys.readouterr().err
