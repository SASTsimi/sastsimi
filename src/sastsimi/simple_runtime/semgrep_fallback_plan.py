"""Deterministic target chunks within Windows command-line and process limits."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence


def plan_semgrep_target_chunks(
    targets: Sequence[str],
    command_for: Callable[[tuple[str, ...]], Sequence[str]],
    *,
    max_targets: int = 128,
    max_command_utf16_units: int = 24_000,
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
        command = subprocess.list2cmdline(command_for(chunk))
        return len(command.encode("utf-16-le")) // 2 <= max_command_utf16_units

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
