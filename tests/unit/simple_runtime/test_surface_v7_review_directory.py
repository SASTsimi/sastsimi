"""A v7 path part must not advertise another route to the same sink."""

from __future__ import annotations

from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
    v5_review_directory,
)


def test_v7_review_directory_lists_only_its_target_route_to_shared_sink() -> None:
    lines = [
        {"path": "app.py", "line": line, "source_sha256": "a" * 64, "text": "x"}
        for line in range(1, 5)
    ]
    route_a = [
        {"node_id": "a-entry", "path": "app.py", "line": 1, "role": "ROUTE_ENTRY"},
        {
            "node_id": "a-request",
            "path": "app.py",
            "line": 3,
            "role": "REQUEST_CONTEXT",
        },
        {"node_id": "a-sink", "path": "app.py", "line": 4, "role": "SINK"},
    ]
    route_b = [
        {"node_id": "b-entry", "path": "app.py", "line": 2, "role": "ROUTE_ENTRY"},
        {
            "node_id": "b-request",
            "path": "app.py",
            "line": 3,
            "role": "REQUEST_CONTEXT",
        },
        {"node_id": "b-sink", "path": "app.py", "line": 4, "role": "SINK"},
    ]
    graph = {
        "source_lines": lines,
        "edges": [
            {
                "edge_id": f"{route}-{ordinal}",
                "graph_path_id": f"path-{route}",
                "from_node_id": steps[ordinal]["node_id"],
                "to_node_id": steps[ordinal + 1]["node_id"],
            }
            for route, steps in (("a", route_a), ("b", route_b))
            for ordinal in (0, 1)
        ],
        "paths": [
            {"path_id": "path-a", "steps": route_a, "edge_ids": ["a-0", "a-1"]},
            {"path_id": "path-b", "steps": route_b, "edge_ids": ["b-0", "b-1"]},
        ],
    }
    context = {
        "kind": "simple_surface_context_v7",
        "target_path_id": "path-a",
        "items": [
            {"category": "source_lines", "ordinal": ordinal, "value": row}
            for ordinal, row in enumerate(lines)
        ],
    }

    directory = v5_review_directory(context, graph)

    assert len(directory) == 3
    assert {row["graph_path_id"] for row in directory} == {"path-a"}
    assert [row["location"] for row in directory] == [
        "app.py:1",
        "app.py:3",
        "app.py:4",
    ]


def test_v5_review_directory_still_lists_both_routes() -> None:
    source_lines = [{"path": "app.py", "line": 1}]
    graph = {
        "source_lines": source_lines,
        "edges": [],
        "paths": [
            {
                "path_id": path_id,
                "steps": [
                    {"node_id": path_id, "path": "app.py", "line": 1, "role": "SINK"}
                ],
                "edge_ids": [],
            }
            for path_id in ("path-a", "path-b")
        ],
    }
    context = {
        "kind": "simple_surface_context_v5",
        "items": [
            {
                "category": "source_lines",
                "ordinal": 0,
                "value": source_lines[0],
            }
        ],
    }

    directory = v5_review_directory(context, graph)

    assert {row["graph_path_id"] for row in directory} == {"path-a", "path-b"}
