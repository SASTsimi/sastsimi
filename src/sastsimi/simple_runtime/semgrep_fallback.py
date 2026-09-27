"""Opt-in, locally bound Semgrep CE scan for failed file/rule targets only."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from sastsimi.config.user_config import SimpleToolBinding

_RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class SemgrepFallbackError(RuntimeError):
    def __init__(self, code: str, raw_output: bytes | None = None) -> None:
        super().__init__(code)
        self.raw_output = raw_output


class ScanResult(Protocol):
    @property
    def returncode(self) -> int: ...

    @property
    def stdout(self) -> bytes: ...

    @property
    def stderr(self) -> bytes: ...


class ScanProcess(Protocol):
    async def run(
        self, argv: Sequence[str], *, cwd: Path | None = None, timeout_seconds: int
    ) -> ScanResult: ...


def _verified_target(workspace: Path, raw: str) -> str:
    if not raw or "\x00" in raw:
        raise RuntimeError("SEMGREP_RESULT_INVALID")
    root = workspace.resolve()
    supplied = Path(raw)
    candidate = supplied if supplied.is_absolute() else root / supplied
    try:
        if candidate.is_symlink():
            raise RuntimeError("SEMGREP_RESULT_INVALID")
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(root)
        if not resolved.is_file():
            raise RuntimeError("SEMGREP_RESULT_INVALID")
    except (OSError, ValueError, RuntimeError) as error:
        raise RuntimeError("SEMGREP_RESULT_INVALID") from error
    return relative.as_posix()


def require_semgrep_tool(binding: SimpleToolBinding) -> None:
    """Reject a missing or changed executable, including on cached-result reuse."""
    executable = binding.executable_path
    try:
        digest = hashlib.sha256()
        with executable.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise RuntimeError("SEMGREP_TOOL_UNAVAILABLE") from error
    if digest.hexdigest() != binding.executable_sha256:
        raise RuntimeError("SEMGREP_TOOL_UNAVAILABLE")


async def run_semgrep_fallback(
    process: ScanProcess,
    binding: SimpleToolBinding,
    workspace: Path,
    rules: Path,
    targets: Sequence[str],
    excluded_rule_ids: Sequence[str],
    timeout_seconds: int,
) -> bytes:
    """Run a bounded local-only scan; coverage validation is the caller's job."""

    require_semgrep_tool(binding)
    executable = binding.executable_path
    if not rules.is_file() or rules.suffix.lower() not in {".yml", ".yaml"}:
        raise RuntimeError("SEMGREP_RESULT_INVALID")
    if timeout_seconds < 1 or not targets:
        raise RuntimeError("SEMGREP_RESULT_INVALID")
    if any(_RULE_ID.fullmatch(rule_id) is None for rule_id in excluded_rule_ids):
        raise RuntimeError("SEMGREP_RESULT_INVALID")
    safe_targets = tuple(sorted({_verified_target(workspace, raw) for raw in targets}))
    argv = [
        str(executable),
        "scan",
        "--config",
        str(rules.resolve()),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
    ]
    for rule_id in sorted(set(excluded_rule_ids)):
        argv.extend(("--exclude-rule", rule_id))
    argv.extend(safe_targets)
    try:
        result = await process.run(
            argv, cwd=workspace.resolve(), timeout_seconds=timeout_seconds
        )
    except TimeoutError as error:
        raise RuntimeError("SEMGREP_EXECUTION_FAILED") from error
    except (OSError, RuntimeError) as error:
        raise RuntimeError("SEMGREP_EXECUTION_FAILED") from error
    if result.returncode != 0:
        raise SemgrepFallbackError("SEMGREP_EXECUTION_FAILED", result.stdout)
    try:
        parsed = json.loads(result.stdout)
    except (UnicodeError, ValueError) as error:
        raise SemgrepFallbackError("SEMGREP_RESULT_INVALID", result.stdout) from error
    if (
        not isinstance(parsed, dict)
        or not isinstance(parsed.get("results"), list)
        or not isinstance(parsed.get("errors"), list)
        or not isinstance(parsed.get("paths"), dict)
    ):
        raise SemgrepFallbackError("SEMGREP_RESULT_INVALID", result.stdout)
    return result.stdout
