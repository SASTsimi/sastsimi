from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Sequence
from pathlib import Path

import pytest

from sastsimi.config.user_config import SimpleToolBinding
from sastsimi.simple_runtime.semgrep_fallback import (
    SemgrepFallbackError,
    run_semgrep_fallback,
)


class _Result:
    def __init__(
        self,
        stdout: bytes = (
            b'{"results": [], "errors": [], "paths": {"scanned": [], "skipped": []}}'
        ),
        returncode: int = 0,
    ) -> None:
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


class _Process:
    def __init__(
        self,
        result: _Result | BaseException,
        *,
        output_mode: str = "regular",
    ) -> None:
        self.result = result
        self.output_mode = output_mode
        self.calls: list[tuple[tuple[str, ...], Path | None, int]] = []

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: int,
    ) -> _Result:
        self.calls.append((tuple(argv), cwd, timeout_seconds))
        if isinstance(self.result, BaseException):
            raise self.result
        output = Path(argv[argv.index("--output") + 1])
        if self.output_mode == "regular":
            output.write_bytes(self.result.stdout)
        elif self.output_mode == "stale":
            output.write_bytes(self.result.stdout)
            os.utime(output, ns=(1, 1))
        elif self.output_mode == "symlink":
            external = output.parent / "external.json"
            external.write_bytes(self.result.stdout)
            try:
                output.symlink_to(external)
            except OSError as error:
                pytest.skip(f"file symlinks unavailable on this host: {error}")
        return _Result(stdout=b"", returncode=self.result.returncode)


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
        process,
        binding,
        workspace,
        rules,
        ["bad.ts"],
        ["rule.good"],
        23,
        output_dir=tmp_path,
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
    assert "--output" in argv
    assert not Path(argv[argv.index("--output") + 1]).exists()
    assert cwd == workspace
    assert timeout == 23


@pytest.mark.asyncio
async def test_fallback_accepts_nested_and_absolute_targets(tmp_path: Path) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    nested = workspace / "module" / "source.ts"
    nested.parent.mkdir()
    nested.write_text("foo()", encoding="utf-8")
    process = _Process(_Result())

    await run_semgrep_fallback(
        process,
        binding,
        workspace,
        rules,
        ["module/source.ts", str(nested.resolve())],
        [],
        23,
        output_dir=tmp_path,
    )

    argv, _, _ = process.calls[0]
    assert argv.count("module/source.ts") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind,code",
    [
        ("missing", "SEMGREP_TOOL_UNAVAILABLE"),
        ("digest", "SEMGREP_TOOL_UNAVAILABLE"),
        ("timeout", "EXTERNAL_TOOL_TIMEOUT"),
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
            process,
            binding,
            workspace,
            rules,
            ["bad.ts"],
            [],
            23,
            output_dir=tmp_path,
        )


@pytest.mark.asyncio
async def test_cancelled_fallback_stops_child(tmp_path: Path) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    process = _Process(asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await run_semgrep_fallback(
            process,
            binding,
            workspace,
            rules,
            ["bad.ts"],
            [],
            23,
            output_dir=tmp_path,
        )
    assert len(process.calls) == 1


@pytest.mark.asyncio
async def test_fallback_rejects_paths_outside_workspace(tmp_path: Path) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    process = _Process(_Result())
    with pytest.raises(RuntimeError, match="SEMGREP_RESULT_INVALID"):
        await run_semgrep_fallback(
            process,
            binding,
            workspace,
            rules,
            ["../rules.yml"],
            [],
            23,
            output_dir=tmp_path,
        )
    assert process.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["missing", "stale", "symlink"])
async def test_fallback_rejects_missing_stale_or_symlinked_output(
    tmp_path: Path, mode: str
) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    process = _Process(_Result(), output_mode=mode)
    with pytest.raises(SemgrepFallbackError, match="SEMGREP_RESULT_INVALID"):
        await run_semgrep_fallback(
            process,
            binding,
            workspace,
            rules,
            ["bad.ts"],
            [],
            23,
            output_dir=tmp_path,
        )


@pytest.mark.asyncio
async def test_fallback_rejects_oversized_output_without_reading_all(
    tmp_path: Path,
) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    process = _Process(_Result(stdout=b"{" + b"x" * 64))
    with pytest.raises(SemgrepFallbackError, match="SEMGREP_RESULT_INVALID") as caught:
        await run_semgrep_fallback(
            process,
            binding,
            workspace,
            rules,
            ["bad.ts"],
            [],
            23,
            output_dir=tmp_path,
            max_output_bytes=32,
        )
    assert caught.value.raw_output is None


@pytest.mark.asyncio
async def test_nonzero_exit_preserves_bounded_raw_without_claiming_success(
    tmp_path: Path,
) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    raw = b'{"results":[],"errors":[],"paths":{"scanned":[],"skipped":[]}}'
    process = _Process(_Result(stdout=raw, returncode=2))
    with pytest.raises(
        SemgrepFallbackError, match="SEMGREP_EXECUTION_FAILED"
    ) as caught:
        await run_semgrep_fallback(
            process,
            binding,
            workspace,
            rules,
            ["bad.ts"],
            [],
            23,
            output_dir=tmp_path,
        )
    assert caught.value.raw_output == raw


@pytest.mark.asyncio
async def test_isolated_retry_adds_per_file_timeout_only_when_requested(
    tmp_path: Path,
) -> None:
    workspace, rules, binding = _fixture(tmp_path)
    process = _Process(_Result())
    await run_semgrep_fallback(
        process,
        binding,
        workspace,
        rules,
        ["bad.ts"],
        [],
        23,
        output_dir=tmp_path,
        per_file_timeout_seconds=30,
    )
    argv, _, _ = process.calls[0]
    assert argv[argv.index("--timeout") + 1] == "30"
