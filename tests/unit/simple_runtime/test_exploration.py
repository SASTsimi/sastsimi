"""An agent reads over several rounds, and old text yields before its notes."""

from __future__ import annotations

from typing import Any

from sastsimi.simple_runtime.exploration import Exploration


def _sources(*sizes: int) -> dict[str, Any]:
    return {
        "served": [
            {"path": f"f{index}.py", "byte_count": size, "content": "x" * size}
            for index, size in enumerate(sizes)
        ],
        "refused": [],
    }


def _notes(round_number: int) -> dict[str, Any]:
    return {
        "claims": [f"round {round_number} found something"],
        "limitations": [],
    }


def test_every_round_is_remembered_in_order() -> None:
    exploration = Exploration()
    for number in (1, 2, 3):
        exploration.record(
            requested_paths=[f"f{number}.py"],
            sources=_sources(10),
            ast=None,
            notes=_notes(number),
        )

    document = exploration.as_prompt_document()

    assert [entry["round"] for entry in document["rounds"]] == [1, 2, 3]
    assert exploration.requested_so_far() == ("f1.py", "f2.py", "f3.py")


def test_a_path_asked_for_twice_is_listed_once() -> None:
    exploration = Exploration()
    for _ in range(3):
        exploration.record(
            requested_paths=["same.py"], sources=None, ast=None, notes={}
        )

    assert exploration.requested_so_far() == ("same.py",)


def test_the_oldest_text_is_dropped_first_and_its_notes_are_kept() -> None:
    exploration = Exploration()
    for number in (1, 2, 3):
        exploration.record(
            requested_paths=[f"f{number}.py"],
            sources=_sources(100_000),
            ast=None,
            notes=_notes(number),
        )

    exploration.compact(threshold=150_000)

    document = exploration.as_prompt_document()
    rounds = {entry["round"]: entry for entry in document["rounds"]}
    assert "sources" not in rounds[1]
    assert rounds[1]["read_but_no_longer_quoted"] is True
    assert rounds[1]["notes"] == _notes(1)
    assert "sources" in rounds[3]
    assert document["compacted_rounds"] == [1, 2]


def test_a_history_that_fits_is_left_alone() -> None:
    exploration = Exploration()
    exploration.record(
        requested_paths=["small.py"], sources=_sources(1_000), ast=None, notes={}
    )

    exploration.compact(threshold=150_000)

    assert exploration.compacted == []
    assert "sources" in exploration.as_prompt_document()["rounds"][0]


def test_compaction_stops_rather_than_dropping_notes() -> None:
    """Even with nothing left to drop, the notes survive."""

    exploration = Exploration()
    exploration.record(
        requested_paths=["huge.py"],
        sources=_sources(900_000),
        ast=None,
        notes=_notes(1),
    )

    exploration.compact(threshold=1)

    document = exploration.as_prompt_document()
    assert document["rounds"][0]["notes"] == _notes(1)
    assert document["compacted_rounds"] == [1]


def test_parsed_facts_count_towards_the_budget_too() -> None:
    exploration = Exploration()
    exploration.record(
        requested_paths=["a.py"],
        sources=None,
        ast={"served": [{"path": "a.py", "facts": [{}] * 5_000}], "refused": []},
        notes=_notes(1),
    )
    exploration.record(
        requested_paths=["b.py"], sources=_sources(1_000), ast=None, notes=_notes(2)
    )

    exploration.compact(threshold=100_000)

    rounds = {e["round"]: e for e in exploration.as_prompt_document()["rounds"]}
    assert "ast" not in rounds[1]
    assert "sources" in rounds[2]
