"""A graph gap is path-specific only when pinned steps identify its sink."""

from __future__ import annotations

from sastsimi.simple_runtime.surface_graph_gap_attribution import (
    source_bound_gap_event,
)

SOURCE_HASH = "a" * 64


def _raw_path(sink_line: int) -> dict[str, object]:
    return {
        "kind": "stdlib_http_call_path_v5",
        "steps": [
            {
                "role": "ROUTE_ENTRY",
                "path": "app.py",
                "line": 3,
                "source_sha256": SOURCE_HASH,
            },
            {
                "role": "REQUEST_CONTEXT",
                "path": "app.py",
                "line": 4,
                "source_sha256": SOURCE_HASH,
            },
            {
                "role": "SINK",
                "path": "app.py",
                "line": sink_line,
                "source_sha256": SOURCE_HASH,
            },
        ],
    }


def test_two_sinks_in_one_file_have_distinct_source_bound_gap_events() -> None:
    first = source_bound_gap_event(
        "app.py",
        "CONTEXT_BUDGET_EXHAUSTED",
        raw_path=_raw_path(10),
        source_hashes={"app.py": SOURCE_HASH},
        sink_path="app.py",
        sink_line=10,
    )
    second = source_bound_gap_event(
        "app.py",
        "CONTEXT_BUDGET_EXHAUSTED",
        raw_path=_raw_path(20),
        source_hashes={"app.py": SOURCE_HASH},
        sink_path="app.py",
        sink_line=20,
    )

    assert first["attribution"] == second["attribution"] == "PINNED_PATH"
    assert first["sink"] == {
        "path": "app.py",
        "line": 10,
        "source_sha256": SOURCE_HASH,
    }
    second_sink = second["sink"]
    assert isinstance(second_sink, dict)
    assert second_sink["line"] == 20
    assert first["graph_path_id"] != second["graph_path_id"]


def test_unverified_or_missing_path_keeps_gap_unlocated() -> None:
    mismatched = _raw_path(10)
    steps = mismatched["steps"]
    assert isinstance(steps, list)
    request_step = steps[1]
    assert isinstance(request_step, dict)
    request_step["source_sha256"] = "b" * 64
    event = source_bound_gap_event(
        "app.py",
        "PATH_SOURCE_UNAVAILABLE",
        raw_path=mismatched,
        source_hashes={"app.py": SOURCE_HASH},
        sink_path="app.py",
        sink_line=10,
    )
    absent_sink = source_bound_gap_event(
        "app.py",
        "PATH_SOURCE_UNAVAILABLE",
        raw_path=_raw_path(20),
        source_hashes={"app.py": SOURCE_HASH},
        sink_path="app.py",
        sink_line=10,
    )

    assert (
        event
        == absent_sink
        == {
            "path": "app.py",
            "reason": "PATH_SOURCE_UNAVAILABLE",
            "attribution": "UNLOCATED",
        }
    )
