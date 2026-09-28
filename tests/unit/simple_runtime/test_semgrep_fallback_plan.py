from __future__ import annotations

import subprocess

import pytest

from sastsimi.simple_runtime import semgrep_fallback_plan as plan_module
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


def test_source_byte_split_keeps_every_target_and_large_singleton() -> None:
    roots = (("a.py", "b.py", "c.py", "large.py", "z.py"),)
    sizes = {"a.py": 2, "b.py": 3, "c.py": 1, "large.py": 20, "z.py": 4}

    chunks = plan_module.split_target_chunks_by_source_bytes(
        roots, sizes.__getitem__, max_bytes=5
    )

    assert chunks == (
        ("a.py", "b.py"),
        ("c.py",),
        ("large.py",),
        ("z.py",),
    )
    assert tuple(path for chunk in chunks for path in chunk) == roots[0]


def test_source_byte_split_preserves_command_bounded_roots() -> None:
    roots = (("a.py", "b.py"), ("c.py", "d.py"))
    chunks = plan_module.split_target_chunks_by_source_bytes(
        roots, lambda _path: 1, max_bytes=5
    )
    assert chunks == roots


def test_source_byte_split_defaults_to_512_kib_and_keeps_oversized_singleton() -> None:
    roots = (("a.py", "b.py", "huge.py", "z.py"),)
    sizes = {"a.py": 300_000, "b.py": 224_288, "huge.py": 600_000, "z.py": 1}

    assert plan_module.split_target_chunks_by_source_bytes(
        roots, sizes.__getitem__
    ) == (("a.py", "b.py"), ("huge.py",), ("z.py",))
