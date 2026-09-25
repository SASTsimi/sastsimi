"""The AST reaches an agent as a map, not as three megabytes of facts.

Inlining every fact was what drove one call to roughly half a million tokens,
which the server turned away as a burst.  The index says what exists and where,
and the agent asks for the files it decides are worth reading.
"""

from __future__ import annotations

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.bootstrap_stages import _ast_index


def _facts(*entries: tuple[str, str, int, str]) -> list[dict[str, object]]:
    return [
        {"kind": kind, "path": path, "line": line, "name": name}
        for kind, path, line, name in entries
    ]


def _result(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "kind": "simple_python_ast",
        "facts": _facts(
            ("FunctionDef", "a/one.py", 1, "handler"),
            ("Call", "a/one.py", 3, "open"),
            ("Call", "a/one.py", 4, "os.system"),
            ("ClassDef", "b/two.py", 1, "Thing"),
        ),
        "parse_errors": ["c/broken.py"],
        "skipped_files": [{"path": "d/huge.py", "reason": "FILE_TOO_LARGE"}],
        "skipped_count": 1,
        "python_files": 4,
        "covered_files": 2,
        "truncated": True,
    }
    base.update(overrides)
    return base


def test_the_index_names_every_file_and_counts_its_kinds() -> None:
    index = _ast_index(_result())

    assert index["total_facts"] == 4
    assert index["files"] == [
        {
            "path": "a/one.py",
            "facts": 3,
            "kinds": {"Call": 2, "FunctionDef": 1},
        },
        {"path": "b/two.py", "facts": 1, "kinds": {"ClassDef": 1}},
    ]


def test_the_busiest_file_is_listed_first() -> None:
    """An agent reads the top of the list first, so ordering is information.

    The busy file is named last alphabetically, so a list that merely sorted by
    name would put it at the bottom.
    """

    facts = _facts(
        ("Call", "aaa/quiet.py", 1, "open"),
        *(("Call", "zzz/busy.py", line, "open") for line in range(20)),
    )

    index = _ast_index(_result(facts=facts))

    paths = [entry["path"] for entry in index["files"]]  # type: ignore[index]
    assert paths == ["zzz/busy.py", "aaa/quiet.py"]


def test_what_was_left_out_of_the_facts_survives_into_the_index() -> None:
    """A file missing from the evidence and missing from the record reads as absent."""

    index = _ast_index(_result())

    assert index["parse_errors"] == ["c/broken.py"]
    assert index["skipped_files"] == [{"path": "d/huge.py", "reason": "FILE_TOO_LARGE"}]
    assert index["skipped_count"] == 1
    assert index["truncated"] is True
    assert index["python_files"] == 4
    assert index["covered_files"] == 2


def test_the_index_is_a_small_fraction_of_the_facts_it_describes() -> None:
    # Measured on open-webui: 31,350 facts were 3.17 MB and the index 27 KB.
    facts = _facts(
        *(
            ("Call", f"pkg/module_{index % 40}.py", index, f"call_{index}")
            for index in range(4_000)
        )
    )

    index = _ast_index(_result(facts=facts))

    assert index["total_facts"] == 4_000
    assert len(canonical_bytes(index)) < len(canonical_bytes(facts)) // 20


def test_a_repository_larger_than_the_index_says_how_many_it_left_out() -> None:
    facts = _facts(
        *(("Call", f"pkg/module_{index}.py", 1, "open") for index in range(1_600))
    )

    index = _ast_index(_result(facts=facts))

    assert index["indexed_files"] == 1_500
    assert index["omitted_files"] == 100
    assert len(index["files"]) == 1_500  # type: ignore[arg-type]


def test_facts_that_are_not_facts_are_ignored_rather_than_crashing() -> None:
    index = _ast_index(
        _result(facts=["nonsense", {"kind": "Call"}, {"path": "a.py"}, 7])
    )

    assert index["files"] == []
    assert index["total_facts"] == 4
