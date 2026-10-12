"""Strict, source-bound validation of one v4 surface Agent response.

The graph is pinned syntax/navigation evidence, not taint-flow or proof of a
vulnerability. Model claims are accepted only when they resolve to exact
source lines and edges in the same graph path.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes

from .attack_surfaces import ReviewPart
from .proposals import validate_proposal
from .surface_contexts import SurfaceContext

_ROLES: dict[str, str] = {
    "ENTRY": "ROUTE_ENTRY",
    "TRUST_BOUNDARY": "REQUEST_CONTEXT",
    "SENSITIVE_OPERATION": "SINK",
}
_PROPOSAL_FIELDS = frozenset(
    {
        "title",
        "vulnerability_type",
        "summary",
        "code_locations",
        "source",
        "sink",
        "rationale",
    }
)
_QUALIFICATION_FIELDS = frozenset(
    {
        "attacker_control",
        "sensitive_operation",
        "reachability",
        "trust_boundary",
        "controls",
        "preconditions",
        "evidence_locations",
    }
)
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
class V4ValidatedResponse:
    status: str
    reason: str
    qualified: tuple[tuple[dict[str, object], dict[str, object]], ...]
    verified_roles: tuple[dict[str, object], ...]
    reviewed_parts: frozenset[ReviewPart]
    evidence_locations: tuple[str, ...]


def _error(code: str = "HYPOTHESIS_SURFACE_OUTPUT_INVALID") -> ValueError:
    return ValueError(code)


def _rows(payload: Mapping[str, object], category: str) -> list[dict[str, object]]:
    value = payload.get(category)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise _error("HYPOTHESIS_SURFACE_GRAPH_INVALID")
    return cast(list[dict[str, object]], value)


def validate_v4_context_payload(
    context: SurfaceContext,
    payload: Mapping[str, object],
    static_bundle_hash: str,
) -> None:
    """Reject a v4 context that is not the exact bounded, pinned part."""

    invalid = "HYPOTHESIS_SURFACE_CONTEXT_INVALID"
    if (
        payload.get("kind") != "simple_surface_context_v4"
        or payload.get("surface_id") != context.surface_id
        or payload.get("static_bundle_hash") != static_bundle_hash
        or payload.get("source_sha256") != context.source_sha256
        or payload.get("part_index") != context.part_index
        or payload.get("part_count") != context.part_count
        or type(context.part_index) is not int
        or type(context.part_count) is not int
        or not 0 <= context.part_index < context.part_count
        or not isinstance(payload.get("path"), str)
        or type(payload.get("line")) is not int
        or not isinstance(payload.get("graph_hash"), str)
        or len(cast(str, payload["graph_hash"])) != 64
        or not isinstance(payload.get("plan_binding_hash"), str)
        or not isinstance(payload.get("scope_fingerprint"), str)
        or not isinstance(payload.get("surface_index_hash"), str)
        or payload.get("reader_revision") != "source-bound-v4-1"
        or type(payload.get("unavailable_item_count")) is not int
        or cast(int, payload["unavailable_item_count"]) < 0
        or not isinstance(payload.get("items"), list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"category", "ordinal", "value"}
            or not isinstance(item.get("category"), str)
            or type(item.get("ordinal")) is not int
            or item["ordinal"] < 0
            or not isinstance(item.get("value"), dict)
            for item in cast(list[object], payload["items"])
        )
        or context.context_hash != context.context_ref.content_hash
    ):
        raise ValueError(invalid)
    expected_id = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v4",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": context.surface_id,
                "part_index": context.part_index,
                "context_hash": context.context_hash,
            }
        )
    ).hexdigest()
    if context.context_id != expected_id:
        raise ValueError(invalid)


def _visible_part_lines(
    context_payload: Mapping[str, object],
    graph_payload: Mapping[str, object],
) -> dict[tuple[str, int], dict[str, object]]:
    categories = {
        "source_files",
        "source_lines",
        "ast_facts",
        "nodes",
        "edges",
        "paths",
        "gaps",
    }
    items = context_payload.get("items")
    if not isinstance(items, list):
        raise _error("HYPOTHESIS_SURFACE_CONTEXT_INVALID")
    seen: set[tuple[str, int]] = set()
    visible: dict[tuple[str, int], dict[str, object]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise _error("HYPOTHESIS_SURFACE_CONTEXT_INVALID")
        category, ordinal, value = (
            item.get("category"),
            item.get("ordinal"),
            item.get("value"),
        )
        if (
            not isinstance(category, str)
            or category not in categories
            or type(ordinal) is not int
            or ordinal < 0
            or not isinstance(value, dict)
            or (category, ordinal) in seen
        ):
            raise _error("HYPOTHESIS_SURFACE_CONTEXT_INVALID")
        rows = _rows(graph_payload, category)
        if ordinal >= len(rows) or value != rows[ordinal]:
            raise _error("HYPOTHESIS_SURFACE_CONTEXT_INVALID")
        seen.add((category, ordinal))
        if category == "source_lines":
            path, line = value.get("path"), value.get("line")
            if not isinstance(path, str) or type(line) is not int or line < 1:
                raise _error("HYPOTHESIS_SURFACE_CONTEXT_INVALID")
            key = (path, line)
            if key in visible:
                raise _error("HYPOTHESIS_SURFACE_CONTEXT_INVALID")
            visible[key] = value
    return visible


def v4_review_directory(
    context_payload: Mapping[str, object],
    graph_payload: Mapping[str, object],
) -> list[dict[str, object]]:
    """Small code-free route/edge guide for source lines in this one part."""

    visible = _visible_part_lines(context_payload, graph_payload)
    edges = {
        row["edge_id"]: row
        for row in _rows(graph_payload, "edges")
        if isinstance(row.get("edge_id"), str)
    }
    directory: list[dict[str, object]] = []
    for path in _rows(graph_payload, "paths"):
        path_id, steps, edge_ids = (
            path.get("path_id"),
            path.get("steps"),
            path.get("edge_ids"),
        )
        if (
            not isinstance(path_id, str)
            or not isinstance(steps, list)
            or not isinstance(edge_ids, list)
        ):
            raise _error("HYPOTHESIS_SURFACE_GRAPH_INVALID")
        for step in steps:
            if not isinstance(step, dict):
                raise _error("HYPOTHESIS_SURFACE_GRAPH_INVALID")
            key = (step.get("path"), step.get("line"))
            if key not in visible:
                continue
            node_id = step.get("node_id")
            if not isinstance(node_id, str):
                raise _error("HYPOTHESIS_SURFACE_GRAPH_INVALID")
            incident = [
                edge_id
                for edge_id in edge_ids
                if isinstance(edge_id, str)
                and (edge := edges.get(edge_id)) is not None
                and edge.get("graph_path_id") == path_id
                and node_id in {edge.get("from_node_id"), edge.get("to_node_id")}
            ]
            directory.append(
                {
                    "graph_path_id": path_id,
                    "role": step.get("role"),
                    "location": f"{key[0]}:{key[1]}",
                    "edge_ids": incident,
                }
            )
    return directory


def v4_reviewable_parts(directory: list[dict[str, object]]) -> frozenset[str]:
    """Only graph-defined security roles may be claimed by a v4 review."""

    return frozenset(
        part
        for part, graph_role in _ROLES.items()
        if any(row.get("role") == graph_role for row in directory)
    )


def _location(raw: object) -> tuple[str, int]:
    if not isinstance(raw, str):
        raise _error("HYPOTHESIS_SURFACE_LOCATION_INVALID")
    path, separator, line_text = raw.rpartition(":")
    if (
        not separator
        or not path
        or not line_text.isascii()
        or not line_text.isdecimal()
        or int(line_text) < 1
    ):
        raise _error("HYPOTHESIS_SURFACE_LOCATION_INVALID")
    return path, int(line_text)


def _qualified(
    raw: object,
    status: str,
    visible: Mapping[tuple[str, int], dict[str, object]],
) -> tuple[tuple[dict[str, object], dict[str, object]], ...]:
    if not isinstance(raw, list):
        raise _error()
    if status != "HYPOTHESES":
        if raw:
            raise _error()
        return ()
    if not 1 <= len(raw) <= 4:
        raise _error()
    max_lines: dict[str, int] = {}
    for path, line in visible:
        max_lines[path] = max(max_lines.get(path, 0), line)
    qualified: list[tuple[dict[str, object], dict[str, object]]] = []
    seen: set[bytes] = set()
    for row in raw:
        if not isinstance(row, dict) or set(row) != _PROPOSAL_FIELDS | {
            "qualification"
        }:
            raise _error("HYPOTHESIS_SURFACE_PROPOSAL_INVALID")
        proposal, errors = validate_proposal(
            {key: row[key] for key in _PROPOSAL_FIELDS}, lines=max_lines
        )
        if proposal is None or errors:
            raise _error("HYPOTHESIS_SURFACE_PROPOSAL_INVALID")
        qualification = row["qualification"]
        if not isinstance(qualification, dict) or set(qualification) != (
            _QUALIFICATION_FIELDS
        ):
            raise _error("HYPOTHESIS_SURFACE_QUALIFICATION_INVALID")
        if (
            qualification["attacker_control"] not in {"YES", "POSSIBLE"}
            or qualification["sensitive_operation"] != "YES"
            or qualification["reachability"] not in {"YES", "POSSIBLE"}
            or qualification["controls"] not in {"NONE", "POSSIBLE", "UNKNOWN"}
            or not isinstance(qualification["trust_boundary"], str)
            or not qualification["trust_boundary"].strip()
            or not isinstance(qualification["preconditions"], str)
            or not qualification["preconditions"].strip()
            or not isinstance(qualification["evidence_locations"], list)
            or not qualification["evidence_locations"]
        ):
            raise _error("HYPOTHESIS_SURFACE_QUALIFICATION_INVALID")
        for value in (
            *cast(list[object], proposal["code_locations"]),
            *qualification["evidence_locations"],
        ):
            if _location(value) not in visible:
                raise _error("HYPOTHESIS_SURFACE_LOCATION_INVALID")
        digest = canonical_bytes(proposal)
        if digest in seen:
            raise _error("HYPOTHESIS_SURFACE_PROPOSAL_DUPLICATE")
        seen.add(digest)
        qualified.append((proposal, qualification))
    return tuple(qualified)


def validate_v4_response(
    raw: object,
    context: SurfaceContext,
    context_payload: Mapping[str, object],
    graph_payload: Mapping[str, object],
) -> V4ValidatedResponse:
    """Resolve one model result against exact graph, part, lines and edges."""

    if not isinstance(raw, dict) or set(raw) != {
        "surface_id",
        "context_id",
        "status",
        "reason",
        "hypotheses",
        "review_evidence",
    }:
        raise _error()
    if (
        raw["surface_id"] != context.surface_id
        or raw["context_id"] != context.context_id
    ):
        raise _error("HYPOTHESIS_SURFACE_ID_INVALID")
    status, reason = raw["status"], raw["reason"]
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
        raise _error()
    if (
        graph_payload.get("kind") != "simple_surface_evidence_graph_v4"
        or hashlib.sha256(canonical_bytes(graph_payload)).hexdigest()
        != context_payload.get("graph_hash")
        or graph_payload.get("anchor")
        != {
            "surface_id": context.surface_id,
            "path": context_payload.get("path"),
            "line": context_payload.get("line"),
        }
        or graph_payload.get("scope_fingerprint")
        != context_payload.get("scope_fingerprint")
        or graph_payload.get("index_hash") != context_payload.get("surface_index_hash")
        or graph_payload.get("ast_manifest_hash")
        != context_payload.get("ast_manifest_hash")
    ):
        raise _error("HYPOTHESIS_SURFACE_GRAPH_INVALID")
    source_hashes: dict[str, str] = {}
    for file in _rows(graph_payload, "source_files"):
        path, digest = file.get("path"), file.get("source_sha256")
        if (
            not isinstance(path, str)
            or not isinstance(digest, str)
            or path in source_hashes
        ):
            raise _error("HYPOTHESIS_SURFACE_GRAPH_INVALID")
        source_hashes[path] = digest
    visible = _visible_part_lines(context_payload, graph_payload)
    for (path, _), line in visible.items():
        if line.get("source_sha256") != source_hashes.get(path):
            raise _error("HYPOTHESIS_SURFACE_GRAPH_INVALID")
    graph_row_count = sum(
        len(_rows(graph_payload, category))
        for category in (
            "source_files",
            "source_lines",
            "ast_facts",
            "nodes",
            "edges",
            "paths",
            "gaps",
        )
    )
    part_items = context_payload["items"]
    assert isinstance(part_items, list)
    incomplete = (
        context.part_count != 1
        or context_payload.get("unavailable_item_count") != 0
        or bool(_rows(graph_payload, "gaps"))
        or not visible
        or len(part_items) != graph_row_count
    )
    if status == "NO_HYPOTHESIS" and incomplete:
        raise _error("HYPOTHESIS_SURFACE_SOURCE_INCOMPLETE")

    qualified = _qualified(raw["hypotheses"], cast(str, status), visible)
    paths: dict[str, dict[str, object]] = {}
    for path in _rows(graph_payload, "paths"):
        path_id = path.get("path_id")
        if not isinstance(path_id, str) or not path_id or path_id in paths:
            raise _error("HYPOTHESIS_SURFACE_GRAPH_INVALID")
        paths[path_id] = path
    edges: dict[str, dict[str, object]] = {}
    for edge in _rows(graph_payload, "edges"):
        edge_id = edge.get("edge_id")
        if not isinstance(edge_id, str) or not edge_id or edge_id in edges:
            raise _error("HYPOTHESIS_SURFACE_GRAPH_INVALID")
        edges[edge_id] = edge
    review = raw["review_evidence"]
    if not isinstance(review, list) or len(review) > 12:
        raise _error("HYPOTHESIS_SURFACE_REVIEW_INVALID")
    verified: list[dict[str, object]] = []
    locations: list[str] = []
    for item in review:
        if not isinstance(item, dict) or set(item) != _REVIEW_FIELDS:
            raise _error("HYPOTHESIS_SURFACE_REVIEW_INVALID")
        part, location, graph_path_id = (
            item["part"],
            item["location"],
            item["graph_path_id"],
        )
        if (
            not isinstance(part, str)
            or part not in _ROLES
            or not isinstance(item["explanation"], str)
            or not item["explanation"].strip()
            or item["context_hash"] != context.context_hash
            or not isinstance(graph_path_id, str)
            or graph_path_id not in paths
        ):
            raise _error("HYPOTHESIS_SURFACE_REVIEW_INVALID")
        key = _location(location)
        source_line = visible.get(key)
        if source_line is None or item["source_sha256"] != source_line.get(
            "source_sha256"
        ):
            raise _error("HYPOTHESIS_SURFACE_LOCATION_INVALID")
        path = paths[graph_path_id]
        steps = path.get("steps")
        path_edge_ids = path.get("edge_ids")
        if not isinstance(steps, list) or not isinstance(path_edge_ids, list):
            raise _error("HYPOTHESIS_SURFACE_GRAPH_INVALID")
        matching_nodes = [
            step.get("node_id")
            for step in steps
            if isinstance(step, dict)
            and step.get("role") == _ROLES[part]
            and (step.get("path"), step.get("line")) == key
        ]
        if len(matching_nodes) != 1 or not isinstance(matching_nodes[0], str):
            raise _error("HYPOTHESIS_SURFACE_PATH_INVALID")
        claimed_edges = item["edge_ids"]
        if (
            not isinstance(claimed_edges, list)
            or not claimed_edges
            or any(not isinstance(edge_id, str) for edge_id in claimed_edges)
            or len(set(claimed_edges)) != len(claimed_edges)
        ):
            raise _error("HYPOTHESIS_SURFACE_EDGE_INVALID")
        for edge_id in claimed_edges:
            claimed_edge = edges.get(edge_id)
            if (
                claimed_edge is None
                or edge_id not in path_edge_ids
                or claimed_edge.get("graph_path_id") != graph_path_id
                or matching_nodes[0]
                not in {
                    claimed_edge.get("from_node_id"),
                    claimed_edge.get("to_node_id"),
                }
            ):
                raise _error("HYPOTHESIS_SURFACE_EDGE_INVALID")
        verified.append(
            {
                "part": part,
                "location": location,
                "context_hash": context.context_hash,
                "source_sha256": item["source_sha256"],
                "graph_path_id": graph_path_id,
                "edge_ids": list(claimed_edges),
                "explanation": item["explanation"],
                "node_id": matching_nodes[0],
            }
        )
        assert isinstance(location, str)
        locations.append(location)
    grouped: dict[str, set[str]] = {}
    for row in verified:
        grouped.setdefault(cast(str, row["graph_path_id"]), set()).add(
            cast(str, row["part"])
        )
    complete_path = (
        not incomplete
        and any(set(_ROLES) <= parts for parts in grouped.values())
        and f"{context_payload['path']}:{context_payload['line']}" in locations
    )
    return V4ValidatedResponse(
        status=cast(str, status),
        reason=reason,
        qualified=qualified,
        verified_roles=tuple(verified),
        reviewed_parts=(
            frozenset(cast(ReviewPart, role) for role in _ROLES)
            if complete_path
            else frozenset()
        ),
        evidence_locations=tuple(dict.fromkeys(locations)),
    )
