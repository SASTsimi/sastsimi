"""Validate one bounded v5 Agent review against its exact saved graph.

The wrapper contains an Agent-visible ``context_payload`` and a saved
``graph_payload``. ``context_hash`` is SHA-256 of canonical context bytes;
``graph_hash`` in that payload is SHA-256 of canonical graph bytes; and
``context_id`` is SHA-256 of the canonical v5 identity tuple (kind,
plan_binding_hash, surface_id, part_index, context_hash). A response must
echo the latter two strings. Only exact graph rows may appear as context
items. Operational XML rows are a strict whitelist and never create path
roles or edges. This is source/navigation proof, not a vulnerability verdict.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes

from .attack_surfaces import ReviewPart
from .surface_evidence_validation_v4 import (
    _location,
    _qualified,
    v4_review_directory,
)

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_CATEGORIES = (
    "source_files",
    "source_lines",
    "ast_facts",
    "nodes",
    "edges",
    "paths",
    "operational_routes",
    "gaps",
)
_OPERATIONAL_FIELDS = frozenset(
    {
        "route",
        "module_path",
        "class_symbol",
        "config_path",
        "config_sha256",
        "parser_path",
        "parser_sha256",
        "parser_sites",
        "target_path",
        "target_sha256",
        "launcher_path",
        "launcher_sha256",
    }
)
_ROLES = {
    "ENTRY": "ROUTE_ENTRY",
    "TRUST_BOUNDARY": "REQUEST_CONTEXT",
    "SENSITIVE_OPERATION": "SINK",
}
_REVIEW_FIELDS = frozenset(
    {
        "part",
        "location",
        "context_hash",
        "source_sha256",
        "graph_path_id",
        "edge_ids",
        "explanation",
    }
)


@dataclass(frozen=True, slots=True)
class V5ValidatedResponse:
    status: str
    reason: str
    qualified: tuple[tuple[dict[str, object], dict[str, object]], ...]
    verified_roles: tuple[dict[str, object], ...]
    reviewed_parts: frozenset[ReviewPart]
    evidence_locations: tuple[str, ...]
    verified_path_id: str | None


def _error(code: str) -> ValueError:
    return ValueError(code)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _rows(graph: Mapping[str, object], category: str) -> list[dict[str, object]]:
    value = graph.get(category)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise _error("V5_GRAPH_INVALID")
    return cast(list[dict[str, object]], value)


def _hex(value: object) -> bool:
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _validated_graph(
    graph: Mapping[str, object], payload: Mapping[str, object]
) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    if (
        graph.get("kind") != "simple_surface_evidence_graph_v5"
        or _digest(graph) != payload.get("graph_hash")
        or graph.get("anchor")
        != {
            "surface_id": payload.get("surface_id"),
            "path": payload.get("path"),
            "line": payload.get("line"),
        }
        or graph.get("scope_fingerprint") != payload.get("scope_fingerprint")
        or graph.get("index_hash") != payload.get("surface_index_hash")
        or graph.get("ast_manifest_hash") != payload.get("ast_manifest_hash")
    ):
        raise _error("V5_GRAPH_INVALID")
    files: dict[str, str] = {}
    for row in _rows(graph, "source_files"):
        path, sha = row.get("path"), row.get("source_sha256")
        if not isinstance(path, str) or not path or not _hex(sha) or path in files:
            raise _error("V5_GRAPH_INVALID")
        files[path] = cast(str, sha)
    lines: set[tuple[str, int]] = set()
    for row in _rows(graph, "source_lines"):
        path, line = row.get("path"), row.get("line")
        if (
            not isinstance(path, str)
            or type(line) is not int
            or line < 1
            or (path, line) in lines
            or row.get("source_sha256") != files.get(path)
            or not isinstance(row.get("text"), str)
        ):
            raise _error("V5_GRAPH_INVALID")
        lines.add((path, line))
    nodes: dict[str, dict[str, object]] = {}
    for row in _rows(graph, "nodes"):
        node_id, path, line = row.get("node_id"), row.get("path"), row.get("line")
        if (
            not isinstance(node_id, str)
            or not node_id
            or node_id in nodes
            or not isinstance(path, str)
            or type(line) is not int
            or (path, line) not in lines
            or ("source_sha256" in row and row["source_sha256"] != files.get(path))
        ):
            raise _error("V5_GRAPH_INVALID")
        nodes[node_id] = row
    edges: dict[str, dict[str, object]] = {}
    for row in _rows(graph, "edges"):
        edge_id = row.get("edge_id")
        if not isinstance(edge_id, str) or not edge_id or edge_id in edges:
            raise _error("V5_GRAPH_INVALID")
        edges[edge_id] = row
    paths: dict[str, dict[str, object]] = {}
    used_edges: set[str] = set()
    for path in _rows(graph, "paths"):
        path_id, steps, edge_ids = (
            path.get("path_id"),
            path.get("steps"),
            path.get("edge_ids"),
        )
        if (
            not isinstance(path_id, str)
            or not path_id
            or path_id in paths
            or not isinstance(steps, list)
            or not steps
            or not isinstance(edge_ids, list)
            or len(edge_ids) != len(steps) - 1
        ):
            raise _error("V5_GRAPH_INVALID")
        if (
            graph.get("proof_semantics_revision") == "v5-source-bound-3"
            and "blocking_gaps" in path
        ):
            blocking_gaps = path["blocking_gaps"]
            if (
                not isinstance(blocking_gaps, list)
                or any(
                    not isinstance(gap, str) or not gap.strip() for gap in blocking_gaps
                )
                or len(set(blocking_gaps)) != len(blocking_gaps)
            ):
                raise _error("V5_GRAPH_INVALID")
        for step in steps:
            if (
                not isinstance(step, dict)
                or not isinstance(step.get("node_id"), str)
                or nodes.get(step["node_id"]) != step
            ):
                raise _error("V5_GRAPH_INVALID")
        for first, second, edge_id in zip(steps, steps[1:], edge_ids, strict=False):
            if not isinstance(edge_id, str) or edge_id in used_edges:
                raise _error("V5_GRAPH_INVALID")
            edge = edges.get(edge_id)
            if (
                edge is None
                or edge.get("graph_path_id") != path_id
                or edge.get("from_node_id") != first["node_id"]
                or edge.get("to_node_id") != second["node_id"]
            ):
                raise _error("V5_GRAPH_INVALID")
            used_edges.add(edge_id)
        paths[path_id] = path
    if used_edges != set(edges):
        raise _error("V5_GRAPH_INVALID")
    for row in _rows(graph, "operational_routes"):
        if set(row) != _OPERATIONAL_FIELDS or any(
            not _hex(row[key])
            for key in (
                "config_sha256",
                "parser_sha256",
                "target_sha256",
                "launcher_sha256",
            )
        ):
            raise _error("V5_GRAPH_INVALID")
    return paths, edges


def _validated_context(
    context: Mapping[str, object],
) -> tuple[
    Mapping[str, object],
    Mapping[str, object],
    dict[tuple[str, int], dict[str, object]],
    bool,
    bool,
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
]:
    payload = context.get("context_payload")
    graph = context.get("graph_payload")
    if not isinstance(payload, dict) or not isinstance(graph, dict):
        raise _error("V5_CONTEXT_INVALID")
    if (
        payload.get("kind") != "simple_surface_context_v5"
        or not isinstance(payload.get("surface_id"), str)
        or not isinstance(payload.get("path"), str)
        or type(payload.get("line")) is not int
        or cast(int, payload["line"]) < 1
        or not _hex(payload.get("graph_hash"))
        or not _hex(payload.get("plan_binding_hash"))
        or not _hex(payload.get("scope_fingerprint"))
        or not _hex(payload.get("surface_index_hash"))
        or not _hex(payload.get("ast_manifest_hash"))
        or type(payload.get("part_index")) is not int
        or type(payload.get("part_count")) is not int
        or not 0 <= cast(int, payload["part_index"]) < cast(int, payload["part_count"])
        or type(payload.get("unavailable_item_count")) is not int
        or cast(int, payload["unavailable_item_count"]) < 0
        or not isinstance(payload.get("items"), list)
        or context.get("context_hash") != _digest(payload)
    ):
        raise _error("V5_CONTEXT_INVALID")
    expected_id = _digest(
        {
            "kind": "simple_surface_context_id_v5",
            "plan_binding_hash": payload["plan_binding_hash"],
            "surface_id": payload["surface_id"],
            "part_index": payload["part_index"],
            "context_hash": context["context_hash"],
        }
    )
    if context.get("context_id") != expected_id:
        raise _error("V5_CONTEXT_INVALID")
    successor_fields = {
        "prior_v3_coverage_hash",
        "prior_v5_plan_hash",
        "graph_semantics_revision",
    }
    present = successor_fields.intersection(payload)
    if present and (
        present != successor_fields
        or not _hex(payload.get("prior_v3_coverage_hash"))
        or not _hex(payload.get("prior_v5_plan_hash"))
        or payload.get("graph_semantics_revision") != "v5-source-bound-3"
        or graph.get("proof_semantics_revision") != payload["graph_semantics_revision"]
    ):
        raise _error("V5_CONTEXT_INVALID")
    paths, edges = _validated_graph(graph, payload)
    seen: set[tuple[str, int]] = set()
    visible: dict[tuple[str, int], dict[str, object]] = {}
    for item in cast(list[object], payload["items"]):
        if not isinstance(item, dict) or set(item) != {"category", "ordinal", "value"}:
            raise _error("V5_CONTEXT_INVALID")
        category, ordinal, value = (
            item["category"],
            item["ordinal"],
            item["value"],
        )
        if (
            not isinstance(category, str)
            or category not in _CATEGORIES
            or type(ordinal) is not int
            or ordinal < 0
            or (category, ordinal) in seen
            or not isinstance(value, dict)
            or ordinal >= len(_rows(graph, category))
            or value != _rows(graph, category)[ordinal]
        ):
            raise _error("V5_CONTEXT_INVALID")
        seen.add((category, ordinal))
        if category == "source_lines":
            key = (value.get("path"), value.get("line"))
            if key in visible:
                raise _error("V5_CONTEXT_INVALID")
            visible[cast(tuple[str, int], key)] = value
    complete_items = (
        payload["part_count"] == 1
        and payload["unavailable_item_count"] == 0
        and bool(visible)
        and len(seen) == sum(len(_rows(graph, category)) for category in _CATEGORIES)
    )
    complete = complete_items and not _rows(graph, "gaps")
    return payload, graph, visible, complete, complete_items, paths, edges


def validate_v5_context(context_wrapper: Mapping[str, object]) -> None:
    """Fail closed on a moved, altered, or malformed saved v5 context and graph."""

    _validated_context(context_wrapper)


def v5_review_directory(
    context_payload: Mapping[str, object], graph_payload: Mapping[str, object]
) -> list[dict[str, object]]:
    """Expose visible Python steps; XML bindings are not reviewable path roles."""

    items = context_payload.get("items")
    if not isinstance(items, list) or any(not isinstance(row, dict) for row in items):
        raise _error("V5_CONTEXT_INVALID")
    python_items = [row for row in items if row.get("category") != "operational_routes"]
    return v4_review_directory(
        {**context_payload, "items": python_items}, graph_payload
    )


def validate_v5_response(
    context: Mapping[str, object], response: Mapping[str, object]
) -> V5ValidatedResponse:
    """Accept completion only on one connected pinned entry-to-sink path."""

    (
        payload,
        graph,
        visible,
        complete_context,
        complete_items,
        paths,
        edges,
    ) = _validated_context(context)
    if set(response) != {
        "surface_id",
        "context_id",
        "status",
        "reason",
        "hypotheses",
        "review_evidence",
    }:
        raise _error("V5_RESPONSE_INVALID")
    if (
        response["surface_id"] != payload["surface_id"]
        or response["context_id"] != context["context_id"]
    ):
        raise _error("V5_RESPONSE_BINDING_INVALID")
    status, reason = response["status"], response["reason"]
    if (
        status
        not in {
            "HYPOTHESES",
            "NO_HYPOTHESIS",
            "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        }
        or not isinstance(reason, str)
        or not reason.strip()
    ):
        raise _error("V5_RESPONSE_INVALID")
    if status == "NO_HYPOTHESIS" and not complete_context:
        raise _error("V5_SOURCE_INCOMPLETE")
    qualified = _qualified(response["hypotheses"], status, visible)
    review = response["review_evidence"]
    if not isinstance(review, list) or len(review) > 12:
        raise _error("V5_REVIEW_INVALID")
    verified: list[dict[str, object]] = []
    locations: list[str] = []
    claims: dict[str, dict[str, int]] = {}
    for item in review:
        if not isinstance(item, dict) or set(item) != _REVIEW_FIELDS:
            raise _error("V5_REVIEW_INVALID")
        part, location, path_id = (
            item["part"],
            item["location"],
            item["graph_path_id"],
        )
        if (
            not isinstance(part, str)
            or part not in _ROLES
            or not isinstance(path_id, str)
            or path_id not in paths
            or not isinstance(item["explanation"], str)
            or not item["explanation"].strip()
            or item["context_hash"] != context["context_hash"]
        ):
            raise _error("V5_REVIEW_INVALID")
        key = _location(location)
        source_line = visible.get(key)
        if source_line is None or item["source_sha256"] != source_line.get(
            "source_sha256"
        ):
            raise _error("V5_REVIEW_LOCATION_INVALID")
        path = paths[path_id]
        steps = cast(list[dict[str, object]], path["steps"])
        matched = [
            (ordinal, step)
            for ordinal, step in enumerate(steps)
            if step.get("role") == _ROLES[part]
            and (step.get("path"), step.get("line")) == key
        ]
        if len(matched) != 1:
            raise _error("V5_REVIEW_PATH_INVALID")
        ordinal, node = matched[0]
        claimed_edges = item["edge_ids"]
        if (
            not isinstance(claimed_edges, list)
            or not claimed_edges
            or any(not isinstance(edge_id, str) for edge_id in claimed_edges)
            or len(set(claimed_edges)) != len(claimed_edges)
        ):
            raise _error("V5_REVIEW_EDGE_INVALID")
        for edge_id in claimed_edges:
            edge = edges.get(edge_id)
            if (
                edge is None
                or edge_id not in cast(list[str], path["edge_ids"])
                or edge.get("graph_path_id") != path_id
                or node["node_id"]
                not in {edge.get("from_node_id"), edge.get("to_node_id")}
            ):
                raise _error("V5_REVIEW_EDGE_INVALID")
        by_path = claims.setdefault(path_id, {})
        if part in by_path:
            raise _error("V5_REVIEW_DUPLICATE")
        by_path[part] = ordinal
        verified.append(
            {
                **item,
                "node_id": node["node_id"],
                "edge_ids": list(claimed_edges),
            }
        )
        locations.append(cast(str, location))
    anchored: list[str] = []
    anchor = cast(dict[str, object], graph["anchor"])
    for path_id, roles in claims.items():
        if not set(_ROLES) <= roles.keys():
            continue
        if not (
            roles["ENTRY"] < roles["TRUST_BOUNDARY"] < roles["SENSITIVE_OPERATION"]
        ):
            continue
        sink = cast(list[dict[str, object]], paths[path_id]["steps"])[
            roles["SENSITIVE_OPERATION"]
        ]
        if (sink.get("path"), sink.get("line")) == (
            anchor["path"],
            anchor["line"],
        ):
            anchored.append(path_id)
    if len(anchored) > 1:
        raise _error("V5_REVIEW_PATH_AMBIGUOUS")
    verified_path_id = None
    if anchored:
        candidate = anchored[0]
        if graph.get("proof_semantics_revision") == "v5-source-bound-3":
            # Only the new extractor can attribute a gap to a claimed path.
            # Missing or nonempty attribution never becomes positive proof.
            if complete_items and paths[candidate].get("blocking_gaps") == []:
                verified_path_id = candidate
        elif complete_context:
            verified_path_id = candidate
    if status in {"HYPOTHESES", "NO_HYPOTHESIS"} and verified_path_id is None:
        raise _error("V5_REVIEW_PATH_INCOMPLETE")
    return V5ValidatedResponse(
        status=status,
        reason=reason,
        qualified=qualified,
        verified_roles=tuple(verified),
        reviewed_parts=(
            frozenset(cast(ReviewPart, part) for part in _ROLES)
            if verified_path_id is not None
            else frozenset()
        ),
        evidence_locations=tuple(dict.fromkeys(locations)),
        verified_path_id=verified_path_id,
    )
