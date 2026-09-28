"""Deterministic target chunks within Windows command-line and process limits."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence

MAX_SEMGREP_COMMAND_UTF16_UNITS = 24_000


def semgrep_command_utf16_units(command: Sequence[str]) -> int:
    """Measure the exact Windows command-line representation of an argv."""

    return len(subprocess.list2cmdline(command).encode("utf-16-le")) // 2


def plan_semgrep_target_chunks(
    targets: Sequence[str],
    command_for: Callable[[tuple[str, ...]], Sequence[str]],
    *,
    max_targets: int = 128,
    max_command_utf16_units: int = MAX_SEMGREP_COMMAND_UTF16_UNITS,
) -> tuple[tuple[str, ...], ...]:
    """Sort targets and greedily emit chunks that fit the exact planned argv."""

    if max_targets < 1 or max_command_utf16_units < 1:
        raise RuntimeError("SEMGREP_COMMAND_TOO_LONG")
    normalized = tuple(sorted({target.replace("\\", "/") for target in targets}))
    if any(not target or "\x00" in target for target in normalized):
        raise RuntimeError("SEMGREP_RESULT_INVALID")

    def fits(chunk: tuple[str, ...]) -> bool:
        if len(chunk) > max_targets:
            return False
        return (
            semgrep_command_utf16_units(command_for(chunk)) <= max_command_utf16_units
        )

    result: list[tuple[str, ...]] = []
    current: tuple[str, ...] = ()
    for target in normalized:
        candidate = (*current, target)
        if fits(candidate):
            current = candidate
            continue
        if current:
            result.append(current)
        if not fits((target,)):
            raise RuntimeError("SEMGREP_COMMAND_TOO_LONG")
        current = (target,)
    if current:
        result.append(current)
    return tuple(result)


def split_target_chunks_by_source_bytes(
    roots: Sequence[Sequence[str]],
    size_for: Callable[[str], int],
    *,
    max_bytes: int,
) -> tuple[tuple[str, ...], ...]:
    """Further split command-safe roots without omitting oversized singletons."""

    if max_bytes < 1:
        raise RuntimeError("SCAN_SOURCE_BYTE_LIMIT_INVALID")
    result: list[tuple[str, ...]] = []
    for root in roots:
        current: list[str] = []
        total = 0
        for target in root:
            size = size_for(target)
            if type(size) is not int or size < 0:
                raise RuntimeError("SCAN_TARGET_SIZE_INVALID")
            if current and total + size > max_bytes:
                result.append(tuple(current))
                current = []
                total = 0
            current.append(target)
            total += size
            if size > max_bytes:
                result.append(tuple(current))
                current = []
                total = 0
        if current:
            result.append(tuple(current))
    return tuple(result)
