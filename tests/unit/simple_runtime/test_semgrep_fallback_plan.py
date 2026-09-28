from __future__ import annotations

import subprocess

import pytest

from sastsimi.simple_runtime.semgrep_fallback_plan import plan_semgrep_target_chunks


def _command(targets: tuple[str, ...]) -> tuple[str, ...]:
    return ("semgrep.exe", "--config", "C:\\local rules\\rules.yml", *targets)


def test_planner_uses_128_target_cap() -> None:
    targets = [f"source/{index:03d}.py" for index in range(129)]
    chunks = plan_semgrep_target_chunks(targets, _command)
    assert tuple(map(len, chunks)) == (128, 1)
    assert tuple(path for chunk in chunks for path in chunk) == tuple(targets)


def test_planner_splits_before_quoted_windows_command_limit() -> None:
    targets = [f"{index}-" + "x" * 7000 for index in range(4)]
    chunks = plan_semgrep_target_chunks(targets, _command)
    assert tuple(map(len, chunks)) == (3, 1)
    assert all(
        len(subprocess.list2cmdline(_command(chunk)).encode("utf-16-le")) // 2 <= 24_000
        for chunk in chunks
    )


def test_planner_counts_quotes_spaces_and_non_bmp_utf16_units() -> None:
    targets = ('a/space "quote" 😀.py', "z.py")
    combined = len(subprocess.list2cmdline(_command(targets)).encode("utf-16-le")) // 2
    chunks = plan_semgrep_target_chunks(
        targets, _command, max_command_utf16_units=combined - 1
    )
    assert chunks == ((targets[0],), (targets[1],))


def test_planner_normalizes_sorts_and_deduplicates_without_input_mutation() -> None:
    targets = ["b\\x.py", "a/x.py", "a\\x.py", "a/x.py"]
    assert plan_semgrep_target_chunks(targets, _command) == (("a/x.py", "b/x.py"),)
    assert targets == ["b\\x.py", "a/x.py", "a\\x.py", "a/x.py"]


def test_planner_rejects_single_target_that_cannot_fit() -> None:
    with pytest.raises(RuntimeError, match="^SEMGREP_COMMAND_TOO_LONG$"):
        plan_semgrep_target_chunks(
            ["file/" + "😀" * 100], _command, max_command_utf16_units=100
        )
