"""Conservative location provenance for successor surface-graph gaps.

The caller must obtain ``raw_path`` from the pinned graph extractors. Matching
indexed digests alone is not a substitute for their source verification. A
missing or malformed location stays UNLOCATED and therefore cannot clear a
coverage gap.
"""

from __future__ import annotations

from collections.abc import Mapping

from .surface_evidence_graph_v4 import _id


def source_bound_gap_event(
    path: str,
    reason: str,
    *,
    raw_path: Mapping[str, object] | None,
    source_hashes: Mapping[str, str],
    sink_path: str,
    sink_line: int,
) -> dict[str, object]:
    """Attribute one failure only to a verified route ending at this exact sink.

    A same-file reason without a complete route and indexed source hashes is
    deliberately unlocated. It must still block any potentially related path.
    """

    unlocated: dict[str, object] = {
        "path": path,
        "reason": reason,
        "attribution": "UNLOCATED",
    }
    if raw_path is None or type(sink_line) is not int or sink_line < 1:
        return unlocated
    steps = raw_path.get("steps")
    if not isinstance(steps, list) or not steps:
        return unlocated
    verified_steps: list[dict[str, object]] = []
    for raw_step in steps:
        if not isinstance(raw_step, dict):
            return unlocated
        step_path = raw_step.get("path")
        step_line = raw_step.get("line")
        digest = raw_step.get("source_sha256")
        role = raw_step.get("role")
        if (
            not isinstance(step_path, str)
            or type(step_line) is not int
            or step_line < 1
            or not isinstance(digest, str)
            or digest != source_hashes.get(step_path)
            or not isinstance(role, str)
        ):
            return unlocated
        verified_steps.append(raw_step)
    entries = [step for step in verified_steps if step["role"] == "ROUTE_ENTRY"]
    sinks = [step for step in verified_steps if step["role"] == "SINK"]
    if (
        len(entries) != 1
        or len(sinks) != 1
        or sinks[0]["path"] != sink_path
        or sinks[0]["line"] != sink_line
        or entries[0] is verified_steps[-1]
        or sinks[0] is not verified_steps[-1]
    ):
        return unlocated
    try:
        graph_path_id = _id("v5-path", raw_path)
    except (TypeError, ValueError):
        return unlocated
    return {
        "path": path,
        "reason": reason,
        "attribution": "PINNED_PATH",
        "graph_path_id": graph_path_id,
        "route_entry": {
            "path": entries[0]["path"],
            "line": entries[0]["line"],
            "source_sha256": entries[0]["source_sha256"],
        },
        "sink": {
            "path": sink_path,
            "line": sink_line,
            "source_sha256": sinks[0]["source_sha256"],
        },
    }
