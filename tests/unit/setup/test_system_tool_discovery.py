# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import subprocess

from sastsimi.setup.service import SystemToolDiscovery


def test_windows_command_path_with_spaces_is_invoked_as_one_argument(
    tmp_path, monkeypatch
) -> None:
    executable = tmp_path / "사용자 도구" / "codex.CMD"
    executable.parent.mkdir()
    executable.write_bytes(b"@echo codex-cli 1.0\r\n")
    calls: list[tuple[tuple[str, ...], bool, int]] = []

    def run(argv, **kwargs):
        calls.append((tuple(argv), bool(kwargs["shell"]), int(kwargs["timeout"])))
        return subprocess.CompletedProcess(argv, 0, "codex-cli 1.0\n", "")

    monkeypatch.setattr("sastsimi.setup.service.shutil.which", lambda _name: executable)
    monkeypatch.setattr("sastsimi.setup.service.subprocess.run", run)

    inspected = SystemToolDiscovery._inspect("codex", ("codex", "--version"))

    assert inspected.available is True
    assert inspected.executable == executable.resolve()
    assert inspected.version == "1.0"
    assert calls == [((str(executable), "--version"), False, 20)]


def test_official_codex_node_launcher_prefers_packaged_native_binary(
    tmp_path, monkeypatch
) -> None:
    package = tmp_path / "lib" / "node_modules" / "@openai" / "codex"
    launcher = package / "bin" / "codex.js"
    native = (
        package
        / "node_modules"
        / "@openai"
        / "codex-linux-x64"
        / "vendor"
        / "x86_64-unknown-linux-musl"
        / "bin"
        / "codex"
    )
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"#!/usr/bin/env node\n")
    native.parent.mkdir(parents=True)
    native.write_bytes(b"native-codex")
    calls: list[tuple[str, ...]] = []

    def run(argv, **_kwargs):
        calls.append(tuple(argv))
        return subprocess.CompletedProcess(argv, 0, "codex-cli 1.0\n", "")

    monkeypatch.setattr("sastsimi.setup.service.shutil.which", lambda _name: launcher)
    monkeypatch.setattr("sastsimi.setup.service.subprocess.run", run)

    inspected = SystemToolDiscovery._inspect("codex", ("codex", "--version"))

    assert inspected.available is True
    assert inspected.executable == native.resolve()
    assert inspected.version == "1.0"
    assert calls == [((str(native), "--version"))]


def test_official_codex_windows_npm_launcher_prefers_packaged_native_binary(
    tmp_path, monkeypatch
) -> None:
    npm_root = tmp_path / "AppData" / "Roaming" / "npm"
    launcher = npm_root / "codex.cmd"
    package = npm_root / "node_modules" / "@openai" / "codex"
    native = (
        package
        / "node_modules"
        / "@openai"
        / "codex-win32-x64"
        / "vendor"
        / "x86_64-pc-windows-msvc"
        / "bin"
        / "codex.exe"
    )
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(
        b'@echo off\r\nnode "%~dp0\\node_modules\\@openai\\codex\\bin\\codex.js" %*\r\n'
    )
    native.parent.mkdir(parents=True)
    native.write_bytes(b"native-codex")
    calls: list[tuple[str, ...]] = []

    def run(argv, **_kwargs):
        calls.append(tuple(argv))
        return subprocess.CompletedProcess(argv, 0, "codex-cli 1.0\n", "")

    monkeypatch.setattr("sastsimi.setup.service.shutil.which", lambda _name: launcher)
    monkeypatch.setattr("sastsimi.setup.service.subprocess.run", run)

    inspected = SystemToolDiscovery._inspect("codex", ("codex", "--version"))

    assert inspected.available is True
    assert inspected.executable == native.resolve()
    assert inspected.version == "1.0"
    assert calls == [((str(native), "--version"))]
