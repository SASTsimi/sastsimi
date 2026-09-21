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
    calls: list[tuple[tuple[str, ...], bool]] = []

    def run(argv, **kwargs):
        calls.append((tuple(argv), bool(kwargs["shell"])))
        return subprocess.CompletedProcess(argv, 0, "codex-cli 1.0\n", "")

    monkeypatch.setattr("sastsimi.setup.service.shutil.which", lambda _name: executable)
    monkeypatch.setattr("sastsimi.setup.service.subprocess.run", run)

    inspected = SystemToolDiscovery._inspect("codex", ("codex", "--version"))

    assert inspected.available is True
    assert inspected.executable == executable.resolve()
    assert calls == [((str(executable), "--version"), False)]
