from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.config.user_config import SimpleToolBinding
from sastsimi.simple_runtime.semgrep_fallback import run_semgrep_fallback


class _Result:
    def __init__(
        self,
        stdout: bytes = (
            b'{"results": [], "errors": [], '
            b'"paths": {"scanned": [], "skipped": []}}'
        ),
        returncode: int = 0,
    ) -> None:
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


class _Process:
    def __init__(self, result: _Result | BaseException) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], Path | None, int]] = []

    async def run(self, argv, *, cwd=None, timeout_seconds: int):
        self.calls.append((tuple(argv), cwd, timeout_seconds))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _fixture(tmp_path: Path) -> tuple[Path, Path, SimpleToolBinding]:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "bad.ts").write_text("foo()", encoding="utf-8")
    (workspace / "good.ts").write_text("foo()", encoding="utf-8")
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n", encoding="utf-8")
    executable = tmp_path / "semgrep.exe"
    executable.write_bytes(b"semgrep-test-binary")
    binding = SimpleToolBinding(
        executable_path=executable,
        version="1.0",
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
    )
    return workspace, rules, binding


@pytest.mark.asyncio
async def test_fallback_only_receives_failed_paths_and_rules(tmp_path: Path) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    process = _Process(
        _Result(
            stdout=json.dumps(
                {
                    "results": [],
                    "errors": [],
                    "paths": {"scanned": ["bad.ts"], "skipped": []},
                }
            ).encode()
        )
    )
    raw = await run_semgrep_fallback(
        process, binding, workspace, rules, ["bad.ts"], ["rule.good"], 23
    )
    argv, cwd, timeout = process.calls[0]
    assert raw.startswith(b'{"results"')
    assert argv[0] == str(binding.executable_path)
    assert "bad.ts" in argv
    assert "good.ts" not in argv
    assert "--exclude-rule" in argv
    assert "rule.good" in argv
    assert str(rules) in argv
    assert "--metrics=off" in argv
    assert "--disable-version-check" in argv
    assert cwd == workspace
    assert timeout == 23


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind,code",
    [
        ("missing", "SEMGREP_TOOL_UNAVAILABLE"),
        ("digest", "SEMGREP_TOOL_UNAVAILABLE"),
        ("timeout", "SEMGREP_EXECUTION_FAILED"),
        ("nonzero", "SEMGREP_EXECUTION_FAILED"),
        ("invalid", "SEMGREP_RESULT_INVALID"),
    ],
)
async def test_fallback_failure_is_explicit(
    tmp_path: Path, kind: str, code: str
) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    process: _Process = _Process(_Result())
    if kind == "missing":
        binding.executable_path.unlink()
    elif kind == "digest":
        binding.executable_path.write_bytes(b"changed")
    elif kind == "timeout":
        process = _Process(TimeoutError())
    elif kind == "nonzero":
        process = _Process(_Result(returncode=2))
    elif kind == "invalid":
        process = _Process(_Result(stdout=b"{"))
    with pytest.raises(RuntimeError, match=code):
        await run_semgrep_fallback(
            process, binding, workspace, rules, ["bad.ts"], [], 23
        )


@pytest.mark.asyncio
async def test_cancelled_fallback_stops_child(tmp_path: Path) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    process = _Process(asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await run_semgrep_fallback(
            process, binding, workspace, rules, ["bad.ts"], [], 23
        )
    assert len(process.calls) == 1


@pytest.mark.asyncio
async def test_fallback_rejects_paths_outside_workspace(tmp_path: Path) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    process = _Process(_Result())
    with pytest.raises(RuntimeError, match="SEMGREP_RESULT_INVALID"):
        await run_semgrep_fallback(
            process, binding, workspace, rules, ["../rules.yml"], [], 23
        )
    assert process.calls == []
