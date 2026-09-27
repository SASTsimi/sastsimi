"""Opt-in, locally bound Semgrep CE scan for failed file/rule targets only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol
from uuid import uuid4

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


def build_semgrep_argv(
    binding: SimpleToolBinding,
    workspace: Path,
    rules: Path,
    targets: Sequence[str],
    excluded_rule_ids: Sequence[str],
    output_path: Path,
    per_file_timeout_seconds: int | None,
    *,
    targets_verified: bool = False,
) -> tuple[str, ...]:
    """Build the exact command; only trusted coverage-plan paths may skip I/O checks."""
    executable = binding.executable_path
    if not rules.is_file() or rules.suffix.lower() not in {".yml", ".yaml"}:
        raise RuntimeError("SEMGREP_RESULT_INVALID")
    if not targets or (
        per_file_timeout_seconds is not None and per_file_timeout_seconds < 1
    ):
        raise RuntimeError("SEMGREP_RESULT_INVALID")
    if any(_RULE_ID.fullmatch(rule_id) is None for rule_id in excluded_rule_ids):
        raise RuntimeError("SEMGREP_RESULT_INVALID")
    safe_targets = (
        tuple(sorted(set(targets)))
        if targets_verified
        else tuple(sorted({_verified_target(workspace, raw) for raw in targets}))
    )
    argv = [
        str(executable),
        "scan",
        "--config",
        str(rules.resolve()),
        "--json",
        "--output",
        str(output_path),
        "--metrics=off",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
    ]
    if per_file_timeout_seconds is not None:
        argv.extend(("--timeout", str(per_file_timeout_seconds)))
    for rule_id in sorted(set(excluded_rule_ids)):
        argv.extend(("--exclude-rule", rule_id))
    argv.extend(safe_targets)
    return tuple(argv)


def _read_output(path: Path, *, started_ns: int, max_output_bytes: int) -> bytes:
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or int(getattr(info, "st_file_attributes", 0)) & 0x400
            or info.st_mtime_ns < started_ns
            or info.st_size > max_output_bytes
        ):
            raise SemgrepFallbackError("SEMGREP_RESULT_INVALID")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                or opened.st_size > max_output_bytes
            ):
                raise SemgrepFallbackError("SEMGREP_RESULT_INVALID")
            raw = stream.read(max_output_bytes + 1)
        if len(raw) > max_output_bytes:
            raise SemgrepFallbackError("SEMGREP_RESULT_INVALID")
        return raw
    except (OSError, ValueError) as error:
        raise SemgrepFallbackError("SEMGREP_RESULT_INVALID") from error


async def run_semgrep_fallback(
    process: ScanProcess,
    binding: SimpleToolBinding,
    workspace: Path,
    rules: Path,
    targets: Sequence[str],
    excluded_rule_ids: Sequence[str],
    timeout_seconds: int,
    *,
    output_dir: Path,
    per_file_timeout_seconds: int | None = None,
    max_output_bytes: int = 64 * 1024 * 1024,
) -> bytes:
    """Run a bounded local-only scan; coverage validation is the caller's job."""

    require_semgrep_tool(binding)
    if timeout_seconds < 1 or max_output_bytes < 1:
        raise RuntimeError("SEMGREP_RESULT_INVALID")
    try:
        if output_dir.is_symlink() or not output_dir.resolve(strict=True).is_dir():
            raise RuntimeError("SEMGREP_RESULT_INVALID")
    except OSError as error:
        raise RuntimeError("SEMGREP_RESULT_INVALID") from error
    output_path = output_dir / f"semgrep-{uuid4().hex}.json"
    if output_path.exists() or output_path.is_symlink():
        raise RuntimeError("SEMGREP_RESULT_INVALID")
    argv = build_semgrep_argv(
        binding,
        workspace,
        rules,
        targets,
        excluded_rule_ids,
        output_path,
        per_file_timeout_seconds,
    )
    started_ns = time.time_ns()
    try:
        try:
            result = await process.run(
                argv, cwd=workspace.resolve(), timeout_seconds=timeout_seconds
            )
        except TimeoutError as error:
            raise RuntimeError("EXTERNAL_TOOL_TIMEOUT") from error
        except RuntimeError as error:
            if str(error) == "EXTERNAL_TOOL_TIMEOUT":
                raise
            raise RuntimeError("SEMGREP_EXECUTION_FAILED") from error
        except OSError as error:
            raise RuntimeError("SEMGREP_EXECUTION_FAILED") from error
        require_semgrep_tool(binding)
        if not output_path.exists() and not output_path.is_symlink():
            if result.returncode != 0:
                raise SemgrepFallbackError(
                    "SEMGREP_EXECUTION_FAILED", result.stdout[:max_output_bytes] or None
                )
            raise SemgrepFallbackError("SEMGREP_RESULT_INVALID")
        raw = _read_output(
            output_path, started_ns=started_ns, max_output_bytes=max_output_bytes
        )
        if result.returncode != 0:
            raise SemgrepFallbackError("SEMGREP_EXECUTION_FAILED", raw)
        try:
            parsed = json.loads(raw)
        except (UnicodeError, ValueError) as error:
            raise SemgrepFallbackError("SEMGREP_RESULT_INVALID", raw) from error
        if (
            not isinstance(parsed, dict)
            or not isinstance(parsed.get("results"), list)
            or not isinstance(parsed.get("errors"), list)
            or not isinstance(parsed.get("paths"), dict)
        ):
            raise SemgrepFallbackError("SEMGREP_RESULT_INVALID", raw)
        return raw
    finally:
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
