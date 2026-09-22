"""A file missing from the evidence must not look like a file that is absent."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime import bootstrap_stages
from sastsimi.simple_runtime.bootstrap_stages import DirectStaticBootstrap


def _summary(workspace: Path, tracked: tuple[str, ...]) -> dict[str, object]:
    bootstrap = DirectStaticBootstrap.__new__(DirectStaticBootstrap)
    return DirectStaticBootstrap._python_ast(bootstrap, workspace, tracked)


def _repository(root: Path, count: int, *, calls: int = 20) -> tuple[str, ...]:
    # Named so the later directory sorts after the earlier one, the way a real
    # checkout puts "routers" after "config".
    names = []
    for index in range(count):
        folder = "aaa_early" if index < count // 2 else "zzz_routers"
        directory = root / folder
        directory.mkdir(exist_ok=True)
        name = f"{folder}/module_{index}.py"
        (root / name).write_text(
            "\n".join(
                f"def handler_{line}():\n    return open(str(line))"
                for line in range(calls)
            ),
            encoding="utf-8",
        )
        names.append(name)
    return tuple(names)


def test_every_tracked_python_file_reaches_the_summary(tmp_path: Path) -> None:
    # Large enough to pass the ten-thousand-fact cut this replaced: that cut
    # stopped part-way through the list and the later directory vanished.
    tracked = _repository(tmp_path, 60, calls=120)

    summary = _summary(tmp_path, tracked)

    assert len(summary["facts"]) > 10_000  # type: ignore[arg-type]
    assert summary["python_files"] == 60
    assert summary["covered_files"] == 60
    assert summary["truncated"] is False
    assert summary["skipped_files"] == []
    paths = {str(fact["path"]) for fact in summary["facts"]}  # type: ignore[union-attr]
    # The directory that sorts last is the one a prefix cut would lose.
    assert any(path.startswith("zzz_routers/") for path in paths)


def test_a_file_left_out_is_named_not_merely_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tracked = _repository(tmp_path, 10)
    # Force the ceiling low enough that later files cannot fit.
    monkeypatch.setattr(bootstrap_stages, "_MAX_FACTS", 30)

    summary = _summary(tmp_path, tracked)

    assert summary["truncated"] is True
    skipped = summary["skipped_files"]
    assert isinstance(skipped, list)
    named = {item["path"] for item in skipped}
    facts = summary["facts"]
    assert isinstance(facts, list)
    covered = {str(fact["path"]) for fact in facts}

    # Two ways a file goes missing, and both must be named.  A file the budget
    # ran out inside is only partly represented, so it is named even though
    # some of its facts are present; a file never opened is named too.
    assert covered == {"aaa_early/module_0.py"}
    assert "aaa_early/module_0.py" in named, "the partly read file was not named"
    assert set(tracked) - covered <= named, "a file never opened was not named"
    assert all(item["reason"] == "FACT_BUDGET_EXHAUSTED" for item in skipped)


def test_an_oversized_file_is_named_too(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_text("x = 1\n" * 400_000, encoding="utf-8")
    (tmp_path / "small.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    summary = _summary(tmp_path, ("big.py", "small.py"))

    assert summary["skipped_files"] == [{"path": "big.py", "reason": "FILE_TOO_LARGE"}]
    assert summary["covered_files"] == 1
