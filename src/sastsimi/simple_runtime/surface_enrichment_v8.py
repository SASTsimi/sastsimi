"""Pure, versioned role-aware review over exact saved v7 evidence."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .attack_surfaces import (
    AttackSurface,
    SurfaceIndex,
    SurfaceReviewContract,
    surface_review_contract,
)
from .models import CheckpointIdentity
from .surface_contexts import SurfaceContextOverflow
from .surface_enrichment_v5 import (
    _MAX_PART_BYTES,
    _READER_REVISION,
    _graph_items,
    _part_payload,
)
from .surface_enrichment_v7_bindings import SurfaceProgressRow
from .surface_enrichment_v8_bindings import (
    missing_v7_part_set,
    prior_v7_progress_snapshot_hash,
)
from .surface_evidence_validation_v4 import _location, _qualified
from .surface_evidence_validation_v5 import _validated_graph

_REVISION = "v5-source-bound-5"
_CATEGORIES = frozenset(
    {
        "source_files",
        "source_lines",
        "ast_facts",
        "nodes",
        "edges",
        "paths",
        "operational_routes",
        "gaps",
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

if TYPE_CHECKING:
    from .surface_coverage_v5 import SurfaceCoverageV5, SurfaceProofV5


@dataclass(frozen=True, slots=True)
class V8Part:
    payload: dict[str, object]
    surface_id: str
    context_id: str
    context_hash: str
    part_index: int
    part_count: int
    source_sha256: str | None


@dataclass(frozen=True, slots=True)
class V8ReviewSpec:
    target_path_id: str | None
    review_path_kind: Literal["CONNECTED", "LOCAL_ONLY"]
    support: list[dict[str, object]]
    optional: list[dict[str, object]]


@dataclass(frozen=True, slots=True)
class V8ValidatedResponse:
    status: str
    reason: str
    qualified: tuple[tuple[dict[str, object], dict[str, object]], ...]
    verified_roles: tuple[dict[str, object], ...]
    reviewed_parts: frozenset[str]
    evidence_locations: tuple[str, ...]
    verified_path_id: str | None
    proof_level: Literal["CONNECTED", "LOCAL_ONLY", "INSUFFICIENT"]


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _items_by_category(
    items: list[dict[str, object]], category: str
) -> list[dict[str, object]]:
    return [item for item in items if item.get("category") == category]


def _item_value(item: Mapping[str, object]) -> dict[str, object]:
    value = item.get("value")
    if not isinstance(value, dict):
        raise ValueError("SURFACE_ENRICHMENT_V8_GRAPH_INVALID")
    return value


def _anchor_ast_fact(
    items: list[dict[str, object]], surface: AttackSurface
) -> list[dict[str, object]]:
    files = {
        row.get("path"): row
        for item in _items_by_category(items, "source_files")
        if (row := _item_value(item))
    }
    source = files.get(surface.path)
    if not isinstance(source, dict):
        return []
    return [
        item
        for item in _items_by_category(items, "ast_facts")
        if (fact := _item_value(item)).get("path") == surface.path
        and fact.get("line") == surface.line
        and fact.get("kind") in {"Call", "FunctionDef", "AsyncFunctionDef", "ClassDef"}
        and isinstance(fact.get("fact_id"), str)
        and bool(fact["fact_id"])
        and fact.get("source_sha256") == source.get("source_sha256")
        and fact.get("ast_sha256") == source.get("ast_sha256")
    ]


def select_v8_review_parts(
    items: list[dict[str, object]], surface: AttackSurface
) -> tuple[V8ReviewSpec, ...]:
    """Select exact source/control anchor paths; never infer a sink role."""

    if surface_review_contract(surface.type) not in {"SOURCE", "CONTROL"}:
        raise ValueError("SURFACE_ENRICHMENT_V8_ROLE_INVALID")
    anchor_facts = _anchor_ast_fact(items, surface)
    selected: list[V8ReviewSpec] = []
    for path_item in _items_by_category(items, "paths"):
        path = _item_value(path_item)
        steps, path_id, edge_ids = (
            path.get("steps"),
            path.get("path_id"),
            path.get("edge_ids"),
        )
        if (
            not isinstance(path_id, str)
            or not path_id
            or not isinstance(steps, list)
            or any(not isinstance(step, dict) for step in steps)
            or not isinstance(edge_ids, list)
            or any(not isinstance(edge_id, str) for edge_id in edge_ids)
        ):
            raise ValueError("SURFACE_ENRICHMENT_V8_GRAPH_INVALID")
        route = [
            index
            for index, step in enumerate(steps)
            if step.get("role") == "ROUTE_ENTRY"
        ]
        boundary = [
            index
            for index, step in enumerate(steps)
            if step.get("role") == "REQUEST_CONTEXT"
        ]
        anchor = [
            index
            for index, step in enumerate(steps)
            if (step.get("path"), step.get("line")) == (surface.path, surface.line)
        ]
        if path.get("assurance") != "SYNTACTIC_REACHABILITY" or not any(
            r < b < a for r in route for b in boundary for a in anchor
        ):
            continue
        node_ids = {step.get("node_id") for step in steps}
        linked_files = {step.get("path") for step in steps}
        if any(not isinstance(value, str) for value in node_ids | linked_files):
            raise ValueError("SURFACE_ENRICHMENT_V8_GRAPH_INVALID")
        support = [
            item
            for item in items
            if item.get("category") == "paths"
            and item.get("ordinal") == path_item.get("ordinal")
            or item.get("category") == "nodes"
            and _item_value(item).get("node_id") in node_ids
            or item.get("category") == "edges"
            and _item_value(item).get("edge_id") in edge_ids
            or item.get("category") in {"source_files", "source_lines"}
            and _item_value(item).get("path") in linked_files
            or item in anchor_facts
        ]
        optional = [
            item
            for item in items
            if item not in support
            and (
                item.get("category") == "ast_facts"
                and _item_value(item).get("path") in linked_files
                or item.get("category") == "gaps"
                and _item_value(item).get("path") in linked_files
            )
        ]
        selected.append(V8ReviewSpec(path_id, "CONNECTED", support, optional))
    if selected:
        return tuple(selected)
    # A local code citation is useful for investigation, but cannot certify
    # an attacker-to-anchor route or the absence of a vulnerability.
    support = [
        item
        for item in items
        if item.get("category") == "source_files"
        and _item_value(item).get("path") == surface.path
        or item.get("category") == "source_lines"
        and (
            _item_value(item).get("path"),
            _item_value(item).get("line"),
        )
        == (surface.path, surface.line)
        or item in anchor_facts
    ]
    optional = [
        item
        for item in items
        if item not in support
        and item.get("category") in {"source_lines", "ast_facts", "gaps"}
        and _item_value(item).get("path") == surface.path
    ]
    return (V8ReviewSpec(None, "LOCAL_ONLY", support, optional),)


def _validated_v8_context(
    wrapper: Mapping[str, object],
) -> tuple[
    Mapping[str, object],
    Mapping[str, object],
    dict[tuple[str, int], dict[str, object]],
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
    bool,
]:
    payload, graph = wrapper.get("context_payload"), wrapper.get("graph_payload")
    if not isinstance(payload, dict) or not isinstance(graph, dict):
        raise ValueError("V8_CONTEXT_INVALID")
    if (
        payload.get("kind") != "simple_surface_context_v8"
        or payload.get("graph_semantics_revision") != _REVISION
        or graph.get("proof_semantics_revision") != _REVISION
        or payload.get("review_mode") != "ROLE_AWARE"
        or payload.get("anchor_contract") not in {"SOURCE", "CONTROL"}
        or surface_review_contract(str(payload.get("surface_type")))
        != payload["anchor_contract"]
        or payload.get("review_path_kind") not in {"CONNECTED", "LOCAL_ONLY"}
        or not isinstance(payload.get("surface_id"), str)
        or not isinstance(payload.get("path"), str)
        or type(payload.get("line")) is not int
        or not isinstance(payload.get("plan_binding_hash"), str)
        or (
            payload.get("source_sha256") is not None
            and not isinstance(payload.get("source_sha256"), str)
        )
        or not isinstance(payload.get("items"), list)
        or type(payload.get("part_index")) is not int
        or type(payload.get("part_count")) is not int
        or not 0 <= payload["part_index"] < payload["part_count"]
        or type(payload.get("unavailable_item_count")) is not int
        or payload["unavailable_item_count"] < 0
        or wrapper.get("context_hash") != _digest(payload)
        or wrapper.get("context_id")
        != _digest(
            {
                "kind": "simple_surface_context_id_v8",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": payload["surface_id"],
                "part_index": payload["part_index"],
                "context_hash": wrapper["context_hash"],
            }
        )
        or payload.get("graph_hash") != _digest(graph)
    ):
        raise ValueError("V8_CONTEXT_INVALID")
    paths, edges = _validated_graph(graph, payload)
    raw_items = cast(list[object], payload["items"])
    seen: set[tuple[str, int]] = set()
    visible: dict[tuple[str, int], dict[str, object]] = {}
    for raw in raw_items:
        if not isinstance(raw, dict) or set(raw) != {"category", "ordinal", "value"}:
            raise ValueError("V8_CONTEXT_INVALID")
        category, ordinal, value = raw["category"], raw["ordinal"], raw["value"]
        graph_rows = graph.get(category)
        if (
            not isinstance(category, str)
            or category not in _CATEGORIES
            or type(ordinal) is not int
            or ordinal < 0
            or (category, ordinal) in seen
            or not isinstance(graph_rows, list)
            or ordinal >= len(graph_rows)
            or value != graph_rows[ordinal]
            or not isinstance(value, dict)
        ):
            raise ValueError("V8_CONTEXT_INVALID")
        seen.add((category, ordinal))
        if category == "source_lines":
            key = (value.get("path"), value.get("line"))
            if key in visible:
                raise ValueError("V8_CONTEXT_INVALID")
            visible[cast(tuple[str, int], key)] = value
    target = payload.get("target_path_id")
    if (target is not None and not isinstance(target, str)) or (
        payload["review_path_kind"] == "CONNECTED"
    ) != isinstance(target, str):
        raise ValueError("V8_CONTEXT_INVALID")
    selected_path = paths.get(target) if isinstance(target, str) else None
    if isinstance(target, str) and selected_path is None:
        raise ValueError("V8_CONTEXT_INVALID")
    # The graph is the authority: derive mandatory support afresh rather than
    # trusting the payload's own item list to justify omission.
    source_files = {
        row.get("path"): row
        for row in cast(list[dict[str, object]], graph.get("source_files", []))
    }
    anchor = (payload["path"], payload["line"])
    file_row = source_files.get(payload["path"])
    if (payload["source_sha256"] is None and file_row is not None) or (
        payload["source_sha256"] is not None
        and (
            not isinstance(file_row, dict)
            or file_row.get("source_sha256") != payload["source_sha256"]
        )
    ):
        raise ValueError("V8_CONTEXT_SOURCE_INVALID")
    all_items = [
        {"category": category, "ordinal": ordinal, "value": row}
        for category in _CATEGORIES
        for ordinal, row in enumerate(cast(list[object], graph.get(category, [])))
    ]
    anchor_surface = AttackSurface(
        surface_id=cast(str, payload["surface_id"]),
        type=cast(str, payload["surface_type"]),
        path=cast(str, payload["path"]),
        symbol="",
        line=cast(int, payload["line"]),
        linked_candidate_ids=(),
        evidence_refs=(),
        detector="v8-context",
    )
    valid_specs = select_v8_review_parts(all_items, anchor_surface)
    matching = [
        spec
        for spec in valid_specs
        if spec.target_path_id == target
        and spec.review_path_kind == payload["review_path_kind"]
    ]
    if len(matching) != 1:
        raise ValueError("V8_CONTEXT_PATH_INVALID")
    required = {(item["category"], item["ordinal"]) for item in matching[0].support}
    complete = payload["unavailable_item_count"] == 0 and required.issubset(seen)
    if selected_path is not None:
        path_steps = cast(list[dict[str, object]], selected_path["steps"])
        path_ids = {step.get("node_id") for step in path_steps}
        edge_ids = set(cast(list[str], selected_path["edge_ids"]))
        if any(
            category == "paths"
            and value.get("path_id") != target
            or category == "nodes"
            and value.get("node_id") not in path_ids
            or category == "edges"
            and value.get("edge_id") not in edge_ids
            for category, ordinal in seen
            if category in {"paths", "nodes", "edges"}
            for value in [
                cast(dict[str, object], cast(list[object], graph[category])[ordinal])
            ]
        ):
            raise ValueError("V8_CONTEXT_PATH_CONTAMINATION")
    elif any(category in {"paths", "nodes", "edges"} for category, _ in seen):
        raise ValueError("V8_CONTEXT_PATH_CONTAMINATION")
    if anchor not in visible:
        complete = False
    return payload, graph, visible, paths, edges, complete


def validate_v8_context(wrapper: Mapping[str, object]) -> None:
    """Reject a moved, altered, or cross-graph v8 context before any LLM call."""

    _validated_v8_context(wrapper)


def v8_review_readiness(wrapper: Mapping[str, object]) -> tuple[bool, str]:
    """Return whether a bounded review could produce verified role evidence.

    A negative result is not a vulnerability verdict. It allows the caller to
    durably record insufficiency instead of paying for an impossible review.
    Context corruption still raises rather than being treated as insufficiency.
    """

    payload, graph, _visible, paths, _edges, complete = _validated_v8_context(wrapper)
    if not complete:
        return False, "INCOMPLETE_CONTEXT_SUPPORT"
    if not _anchor_fact_visible(payload, graph):
        return False, "ANCHOR_AST_UNAVAILABLE"
    target = payload["target_path_id"]
    if isinstance(target, str) and not _path_gap_free(
        graph,
        paths[target],
        (cast(str, payload["path"]), cast(int, payload["line"])),
    ):
        return False, "RELEVANT_GRAPH_GAP"
    return True, "READY"


def _anchor_fact_visible(
    payload: Mapping[str, object], graph: Mapping[str, object]
) -> bool:
    files = {
        row.get("path"): row
        for row in cast(list[dict[str, object]], graph["source_files"])
    }
    file_row = files.get(payload["path"])
    if not isinstance(file_row, dict):
        return False
    for item in cast(list[dict[str, object]], payload["items"]):
        if item.get("category") != "ast_facts":
            continue
        fact = item.get("value")
        if not isinstance(fact, dict):
            continue
        if (
            fact.get("path") == payload["path"]
            and fact.get("line") == payload["line"]
            and fact.get("kind")
            in {"Call", "FunctionDef", "AsyncFunctionDef", "ClassDef"}
            and fact.get("source_sha256") == payload["source_sha256"]
            and fact.get("ast_sha256") == file_row.get("ast_sha256")
            and isinstance(fact.get("fact_id"), str)
            and bool(fact["fact_id"])
        ):
            return True
    return False


def _path_gap_free(
    graph: Mapping[str, object], path: Mapping[str, object], anchor: tuple[str, int]
) -> bool:
    if path.get("blocking_gaps") != []:
        return False
    events = graph.get("gap_events")
    gaps = graph.get("gaps")
    if not isinstance(events, list) or not isinstance(gaps, list):
        return False
    linked = {step.get("path") for step in cast(list[dict[str, object]], path["steps"])}
    known = Counter(
        (event.get("path"), event.get("reason"))
        for event in events
        if isinstance(event, dict)
    )
    expected = Counter(
        (gap.get("path"), gap.get("reason")) for gap in gaps if isinstance(gap, dict)
    )
    if any(not isinstance(gap, dict) for gap in gaps) or any(
        known[key] < count for key, count in expected.items()
    ):
        return False
    files = {
        row.get("path"): row.get("source_sha256")
        for row in cast(list[dict[str, object]], graph["source_files"])
    }
    for event in events:
        if not isinstance(event, dict):
            return False
        attribution = event.get("attribution")
        if attribution == "UNLOCATED":
            if event.get("path") is None or event.get("path") in linked:
                return False
            continue
        if attribution != "PINNED_PATH":
            return False
        sink, route = event.get("sink"), event.get("route_entry")
        if not isinstance(sink, dict) or not isinstance(route, dict):
            return False
        if any(
            not isinstance(row.get("path"), str)
            or type(row.get("line")) is not int
            or row.get("source_sha256") != files.get(row.get("path"))
            for row in (sink, route)
        ):
            return False
        if (sink["path"], sink["line"]) == anchor:
            return False
    return True


def v8_review_directory(
    context_payload: Mapping[str, object], graph_payload: Mapping[str, object]
) -> list[dict[str, object]]:
    """Expose role-specific source-bound coordinates, never a fake sink."""

    wrapper = {
        "context_payload": context_payload,
        "graph_payload": graph_payload,
        "context_hash": _digest(context_payload),
        "context_id": _digest(
            {
                "kind": "simple_surface_context_id_v8",
                "plan_binding_hash": context_payload.get("plan_binding_hash"),
                "surface_id": context_payload.get("surface_id"),
                "part_index": context_payload.get("part_index"),
                "context_hash": _digest(context_payload),
            }
        ),
    }
    payload, _graph, visible, paths, edges, _ = _validated_v8_context(wrapper)
    target = payload["target_path_id"]
    if not isinstance(target, str):
        return (
            [
                {
                    "part": "ANCHOR",
                    "graph_path_id": "",
                    "location": f"{payload['path']}:{payload['line']}",
                    "edge_ids": [],
                }
            ]
            if (payload["path"], payload["line"]) in visible
            else []
        )
    selected = paths[target]
    path_steps = cast(list[dict[str, object]], selected["steps"])
    path_edge_ids = cast(list[str], selected["edge_ids"])
    directory: list[dict[str, object]] = []
    for part, role in (("ENTRY", "ROUTE_ENTRY"), ("TRUST_BOUNDARY", "REQUEST_CONTEXT")):
        for step in path_steps:
            if (
                step.get("role") != role
                or (step.get("path"), step.get("line")) not in visible
            ):
                continue
            node_id = step["node_id"]
            directory.append(
                {
                    "part": part,
                    "graph_path_id": target,
                    "location": f"{step['path']}:{step['line']}",
                    "edge_ids": [
                        edge_id
                        for edge_id in path_edge_ids
                        if node_id
                        in {
                            edges[edge_id]["from_node_id"],
                            edges[edge_id]["to_node_id"],
                        }
                    ],
                }
            )
    for step in reversed(path_steps):
        if (step.get("path"), step.get("line")) != (payload["path"], payload["line"]):
            continue
        node_id = step["node_id"]
        directory.append(
            {
                "part": "ANCHOR",
                "graph_path_id": target,
                "location": f"{payload['path']}:{payload['line']}",
                "edge_ids": [
                    edge_id
                    for edge_id in path_edge_ids
                    if node_id
                    in {
                        edges[edge_id]["from_node_id"],
                        edges[edge_id]["to_node_id"],
                    }
                ],
            }
        )
        break
    return directory


def validate_v8_response(
    wrapper: Mapping[str, object], response: Mapping[str, object]
) -> V8ValidatedResponse:
    """Validate exact role evidence; local review never certifies a route."""

    payload, graph, visible, paths, edges, complete = _validated_v8_context(wrapper)
    if (
        set(response)
        != {
            "surface_id",
            "context_id",
            "status",
            "reason",
            "hypotheses",
            "review_evidence",
        }
        or response["surface_id"] != payload["surface_id"]
        or response["context_id"] != wrapper["context_id"]
    ):
        raise ValueError("V8_RESPONSE_INVALID")
    status, reason = response["status"], response["reason"]
    if (
        status
        not in {"HYPOTHESES", "NO_HYPOTHESIS", "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"}
        or not isinstance(reason, str)
        or not reason.strip()
    ):
        raise ValueError("V8_RESPONSE_INVALID")
    qualified = _qualified(response["hypotheses"], status, visible)
    review = response["review_evidence"]
    if not isinstance(review, list) or len(review) > 12:
        raise ValueError("V8_REVIEW_INVALID")
    selected_id = payload["target_path_id"]
    selected = paths.get(selected_id) if isinstance(selected_id, str) else None
    selected_steps = (
        cast(list[dict[str, object]], selected["steps"]) if selected is not None else []
    )
    selected_edges = (
        cast(list[str], selected["edge_ids"]) if selected is not None else []
    )
    verified: list[dict[str, object]] = []
    locations: list[str] = []
    ordinals: dict[str, int] = {}
    for item in review:
        if not isinstance(item, dict) or set(item) != _REVIEW_FIELDS:
            raise ValueError("V8_REVIEW_INVALID")
        part = item["part"]
        if part not in {"ENTRY", "TRUST_BOUNDARY", "ANCHOR"} or part in ordinals:
            raise ValueError("V8_REVIEW_INVALID")
        if (
            item["context_hash"] != wrapper["context_hash"]
            or not isinstance(item["explanation"], str)
            or not item["explanation"].strip()
        ):
            raise ValueError("V8_REVIEW_INVALID")
        key = _location(item["location"])
        line = visible.get(key)
        if line is None or item["source_sha256"] != line.get("source_sha256"):
            raise ValueError("V8_REVIEW_SOURCE_INVALID")
        claimed_edges = item["edge_ids"]
        if (
            not isinstance(claimed_edges, list)
            or any(not isinstance(edge, str) for edge in claimed_edges)
            or len(set(claimed_edges)) != len(claimed_edges)
        ):
            raise ValueError("V8_REVIEW_EDGE_INVALID")
        if selected is None:
            if part != "ANCHOR" or item["graph_path_id"] != "" or claimed_edges:
                raise ValueError("V8_REVIEW_PATH_INVALID")
            if key != (payload["path"], payload["line"]):
                raise ValueError("V8_REVIEW_ANCHOR_INVALID")
            ordinals[part] = 0
        else:
            if item["graph_path_id"] != selected_id or not claimed_edges:
                raise ValueError("V8_REVIEW_PATH_INVALID")
            expected_role = {
                "ENTRY": "ROUTE_ENTRY",
                "TRUST_BOUNDARY": "REQUEST_CONTEXT",
            }.get(cast(str, part))
            matches = [
                (ordinal, step)
                for ordinal, step in enumerate(selected_steps)
                if (step.get("path"), step.get("line")) == key
                and (part == "ANCHOR" or step.get("role") == expected_role)
            ]
            if not matches or (part != "ANCHOR" and len(matches) != 1):
                raise ValueError("V8_REVIEW_PATH_INVALID")
            ordinal, node = matches[-1] if part == "ANCHOR" else matches[0]
            if part == "ANCHOR" and key != (payload["path"], payload["line"]):
                raise ValueError("V8_REVIEW_ANCHOR_INVALID")
            for edge_id in claimed_edges:
                edge = edges.get(edge_id)
                if (
                    edge is None
                    or edge_id not in selected_edges
                    or edge.get("graph_path_id") != selected_id
                    or node["node_id"]
                    not in {edge.get("from_node_id"), edge.get("to_node_id")}
                ):
                    raise ValueError("V8_REVIEW_EDGE_INVALID")
            ordinals[cast(str, part)] = ordinal
        verified.append(dict(item))
        locations.append(item["location"])
    proof_level: Literal["CONNECTED", "LOCAL_ONLY", "INSUFFICIENT"] = "INSUFFICIENT"
    verified_path_id: str | None = None
    if "ANCHOR" in ordinals:
        if not _anchor_fact_visible(payload, graph):
            raise ValueError("V8_ANCHOR_AST_MISSING")
        if complete and selected is None:
            proof_level = "LOCAL_ONLY"
        elif (
            selected is not None
            and complete
            and {"ENTRY", "TRUST_BOUNDARY", "ANCHOR"} <= ordinals.keys()
        ):
            if not (
                ordinals["ENTRY"] < ordinals["TRUST_BOUNDARY"] < ordinals["ANCHOR"]
            ):
                raise ValueError("V8_REVIEW_PATH_INVALID")
            if _path_gap_free(
                graph,
                selected,
                (cast(str, payload["path"]), cast(int, payload["line"])),
            ):
                proof_level = "CONNECTED"
                verified_path_id = cast(str, selected_id)
    if status in {"HYPOTHESES", "NO_HYPOTHESIS"} and proof_level == "INSUFFICIENT":
        raise ValueError("V8_REVIEW_PATH_INCOMPLETE")
    return V8ValidatedResponse(
        status=status,
        reason=reason,
        qualified=qualified,
        verified_roles=tuple(verified),
        reviewed_parts=frozenset(ordinals),
        evidence_locations=tuple(dict.fromkeys(locations)),
        verified_path_id=verified_path_id,
        proof_level=proof_level,
    )


def _bound_ref(ref: StoredDataRef, identity: CheckpointIdentity, digest: str) -> bool:
    return (
        str(ref.workspace_id) == identity.workspace_id
        and str(ref.commit_id) == identity.commit_id
        and ref.data_kind == "artifact"
        and ref.record_id is None
        and str(ref.stored_data_id) == ref.content_hash == digest
    )


def _context_payload_v8(
    *,
    identity: CheckpointIdentity,
    scope: str,
    index: SurfaceIndex,
    index_hash: str,
    surface: AttackSurface,
    source_sha256: str | None,
    graph_hash: str,
    binding_hash: str,
    proof_hash: str,
    prior_reasons: list[str],
    v4_plan_hash: str,
    v2_coverage_hash: str,
    child_hash: str,
    prior_v7_plan_hash: str,
    prior_v5_coverage_hash: str,
    progress_hash: str,
    contract: SurfaceReviewContract,
    spec: V8ReviewSpec,
    part_index: int,
    part_count: int,
    items: list[dict[str, object]],
    unavailable_count: int,
) -> dict[str, object]:
    record = _part_payload(
        identity=identity,
        scope=scope,
        index=index,
        index_hash=index_hash,
        surface=surface,
        source_sha256=source_sha256,
        graph_hash=graph_hash,
        plan_binding_hash=binding_hash,
        parent_progress_hash=proof_hash,
        prior_reasons=prior_reasons,
        v4_plan_hash=v4_plan_hash,
        v2_coverage_hash=v2_coverage_hash,
        child_checkpoint_hash=child_hash,
        items=items,
        part_index=part_index,
        part_count=part_count,
        unavailable_count=unavailable_count,
    )
    record.update(
        kind="simple_surface_context_v8",
        graph_semantics_revision=_REVISION,
        prior_v7_plan_hash=prior_v7_plan_hash,
        prior_v5_coverage_hash=prior_v5_coverage_hash,
        prior_progress_hash=progress_hash,
        review_mode="ROLE_AWARE",
        anchor_contract=contract,
        target_path_id=spec.target_path_id,
        review_path_kind=spec.review_path_kind,
    )
    return record


def prepare_surface_enrichment_v8(
    identity: CheckpointIdentity,
    scope: str,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    prior_v7_plan_ref: StoredDataRef,
    prior_v7_plan: Mapping[str, object],
    prior_v5_coverage_ref: StoredDataRef,
    prior_v5_coverage: SurfaceCoverageV5,
    prior_progress: Mapping[tuple[str, str], SurfaceProgressRow],
    graphs: Mapping[str, Mapping[str, object]],
    *,
    required_graph_revision: str,
) -> tuple[dict[str, object], tuple[V8Part, ...]]:
    """Build immutable recertification of every SOURCE/CONTROL parent row."""

    index_hash = _digest(index.to_json())
    prior_coverage_json = prior_v5_coverage.to_json()
    if (
        not scope
        or identity.hypothesis_id is not None
        or index.index_version != 2
        or index.workspace_id != identity.workspace_id
        or index.commit_id != identity.commit_id
        or not _bound_ref(index_ref, identity, index_hash)
        or not _bound_ref(prior_v7_plan_ref, identity, _digest(prior_v7_plan))
        or not _bound_ref(prior_v5_coverage_ref, identity, _digest(prior_coverage_json))
        or prior_v7_plan.get("kind") != "simple_surface_enrichment_plan_v7"
        or prior_v7_plan.get("analysis_id") != identity.analysis_id
        or prior_v7_plan.get("workspace_id") != identity.workspace_id
        or prior_v7_plan.get("commit_id") != identity.commit_id
        or prior_v7_plan.get("scope") != scope
        or prior_v7_plan.get("scope_fingerprint") != index.scope_fingerprint
        or prior_v7_plan.get("static_bundle_hash") != index.static_bundle_hash
        or prior_v7_plan.get("ast_manifest_hash") != index.ast_manifest_hash
        or prior_v7_plan.get("candidate_inventory_hash")
        != index.candidate_inventory_hash
        or prior_v7_plan.get("index_hash") != index_hash
        or prior_v7_plan.get("index_ref") != index_ref.model_dump(mode="json")
        or prior_coverage_json.get("kind") != "simple_attack_surface_coverage_v5"
        or prior_v5_coverage.v7_plan_ref != prior_v7_plan_ref
        or prior_v5_coverage.scope_fingerprint != index.scope_fingerprint
        or prior_v5_coverage.static_bundle_hash != index.static_bundle_hash
        or prior_v5_coverage.ast_manifest_hash != index.ast_manifest_hash
        or prior_v5_coverage.candidate_inventory_hash != index.candidate_inventory_hash
        or prior_v5_coverage.candidate_count != index.candidate_count
        or prior_v5_coverage.index_hash != index_hash
        or len(prior_v5_coverage.surfaces) != len(index.surfaces)
        or any(
            proof.surface_id != surface.surface_id
            or proof.path != surface.path
            or proof.line != surface.line
            for surface, proof in zip(
                index.surfaces, prior_v5_coverage.surfaces, strict=True
            )
        )
    ):
        raise ValueError("SURFACE_ENRICHMENT_V8_PARENT_INVALID")
    if required_graph_revision != _REVISION:
        raise ValueError("SURFACE_ENRICHMENT_V8_GRAPH_REVISION_INVALID")
    progress_hash = prior_v7_progress_snapshot_hash(prior_progress)
    missing = missing_v7_part_set(prior_v7_plan, prior_progress)
    if missing:
        raise ValueError("SURFACE_ENRICHMENT_V8_PARENT_INCOMPLETE")
    targets = tuple(
        (surface, proof)
        for surface, proof in zip(
            index.surfaces, prior_v5_coverage.surfaces, strict=True
        )
        if surface_review_contract(surface.type) in {"SOURCE", "CONTROL"}
    )
    if set(graphs) != {surface.surface_id for surface, _ in targets}:
        raise ValueError("SURFACE_ENRICHMENT_V8_TARGET_SET_INVALID")
    target_bindings: list[dict[str, object]] = []
    selected: list[
        tuple[
            AttackSurface,
            SurfaceProofV5,
            list[dict[str, object]],
            str,
            SurfaceReviewContract,
        ]
    ] = []
    for surface, proof in targets:
        graph = graphs[surface.surface_id]
        if graph.get("proof_semantics_revision") != _REVISION:
            raise ValueError("SURFACE_ENRICHMENT_V8_GRAPH_REVISION_INVALID")
        try:
            items, graph_hash = _graph_items(graph, surface, index, index_hash)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("SURFACE_ENRICHMENT_V8_GRAPH_INVALID") from error
        contract = surface_review_contract(surface.type)
        selected.append((surface, proof, items, graph_hash, contract))
        target_bindings.append(
            {
                "surface_id": surface.surface_id,
                "graph_hash": graph_hash,
                "prior_v5_proof_hash": _digest(proof.to_json()),
                "prior_reasons": list(proof.unresolved_reason_codes),
                "anchor_contract": contract,
                "review_mode": "ROLE_AWARE",
                "item_digests": [_digest(item) for item in items],
            }
        )
    child_hashes = prior_v7_plan.get("child_checkpoint_hashes")
    if not isinstance(child_hashes, dict):
        raise ValueError("SURFACE_ENRICHMENT_V8_PARENT_INVALID")
    binding: dict[str, object] = {
        "kind": "simple_surface_enrichment_binding_v8",
        "reader_revision": _READER_REVISION,
        "graph_semantics_revision": required_graph_revision,
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": scope,
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "candidate_inventory_hash": index.candidate_inventory_hash,
        "candidate_count": index.candidate_count,
        "index_ref": index_ref.model_dump(mode="json"),
        "index_hash": index_hash,
        "prior_v7_plan_ref": prior_v7_plan_ref.model_dump(mode="json"),
        "prior_v7_plan_hash": prior_v7_plan_ref.content_hash,
        "prior_v5_coverage_ref": prior_v5_coverage_ref.model_dump(mode="json"),
        "prior_v5_coverage_hash": prior_v5_coverage_ref.content_hash,
        "prior_progress_hash": progress_hash,
        "missing_v7_parts": missing,
        "v4_plan_ref": prior_v7_plan.get("v4_plan_ref"),
        "v4_plan_hash": prior_v7_plan.get("v4_plan_hash"),
        "v2_coverage_ref": prior_v7_plan.get("v2_coverage_ref"),
        "v2_coverage_hash": prior_v7_plan.get("v2_coverage_hash"),
        "child_checkpoint_hashes": dict(sorted(child_hashes.items())),
        "targets": target_bindings,
    }
    binding_hash = _digest(binding)
    child_hash = _digest(binding["child_checkpoint_hashes"])
    source_hashes = dict(index.ast_source_hashes)
    target_rows: list[dict[str, object]] = []
    expected_parts: list[dict[str, object]] = []
    parts: list[V8Part] = []
    old_ids = {
        row.get("context_id")
        for row in cast(list[dict[str, object]], prior_v7_plan["expected_parts"])
    }
    for surface, proof, items, graph_hash, contract in selected:
        source_sha256 = source_hashes.get(surface.path)
        specs = select_v8_review_parts(items, surface)
        part_count = len(specs)
        unavailable: list[dict[str, object]] = []
        chunks: list[tuple[V8ReviewSpec, list[dict[str, object]], int]] = []
        for ordinal, spec in enumerate(specs):
            payload = partial(
                _context_payload_v8,
                identity=identity,
                scope=scope,
                index=index,
                index_hash=index_hash,
                surface=surface,
                source_sha256=source_sha256,
                graph_hash=graph_hash,
                binding_hash=binding_hash,
                proof_hash=_digest(proof.to_json()),
                prior_reasons=list(proof.unresolved_reason_codes),
                v4_plan_hash=cast(str, prior_v7_plan["v4_plan_hash"]),
                v2_coverage_hash=cast(str, prior_v7_plan["v2_coverage_hash"]),
                child_hash=child_hash,
                prior_v7_plan_hash=prior_v7_plan_ref.content_hash,
                prior_v5_coverage_hash=prior_v5_coverage_ref.content_hash,
                progress_hash=progress_hash,
                contract=contract,
                spec=spec,
                part_index=ordinal,
                part_count=part_count,
            )

            if (
                len(canonical_bytes(payload(items=spec.support, unavailable_count=0)))
                > _MAX_PART_BYTES
            ):
                unavailable.append(
                    {
                        "target_path_id": spec.target_path_id,
                        "reason": "ATOMIC_PATH_SUPPORT_TOO_LARGE",
                        "path_hash": _digest(spec.support),
                    }
                )
                chunk: list[dict[str, object]] = []
                unavailable_count = 1
            else:
                chunk = list(spec.support)
                unavailable_count = 0
                for item in spec.optional:
                    proposed = [*chunk, item]
                    if (
                        len(
                            canonical_bytes(
                                payload(items=proposed, unavailable_count=0)
                            )
                        )
                        <= _MAX_PART_BYTES
                    ):
                        chunk = proposed
            chunks.append((spec, chunk, unavailable_count))
            record = payload(items=chunk, unavailable_count=unavailable_count)
            if len(canonical_bytes(record)) > _MAX_PART_BYTES:
                raise SurfaceContextOverflow(surface.surface_id)
            context_hash = _digest(record)
            context_id = _digest(
                {
                    "kind": "simple_surface_context_id_v8",
                    "plan_binding_hash": binding_hash,
                    "surface_id": surface.surface_id,
                    "part_index": ordinal,
                    "context_hash": context_hash,
                }
            )
            if context_id in old_ids:
                raise ValueError("SURFACE_ENRICHMENT_V8_CONTEXT_COLLISION")
            parts.append(
                V8Part(
                    record,
                    surface.surface_id,
                    context_id,
                    context_hash,
                    ordinal,
                    part_count,
                    source_sha256,
                )
            )
            expected_parts.append(
                {
                    "surface_id": surface.surface_id,
                    "context_id": context_id,
                    "context_hash": context_hash,
                    "part_index": ordinal,
                    "part_count": part_count,
                    "target_path_id": spec.target_path_id,
                    "source_sha256": source_sha256,
                    "anchor_contract": contract,
                    "review_path_kind": spec.review_path_kind,
                }
            )
        target_rows.append(
            {
                "surface_id": surface.surface_id,
                "graph_hash": graph_hash,
                "prior_v5_proof_hash": _digest(proof.to_json()),
                "parent_progress_hash": _digest(proof.to_json()),
                "prior_reasons": list(proof.unresolved_reason_codes),
                "anchor_contract": contract,
                "review_mode": "ROLE_AWARE",
                "item_count": len(items),
                "available_item_count": sum(len(chunk) for _, chunk, _ in chunks),
                "unavailable_items": unavailable,
                "source_sha256": source_sha256,
                "part_count": part_count,
            }
        )
    return (
        {
            **binding,
            "kind": "simple_surface_enrichment_plan_v8",
            "plan_binding_hash": binding_hash,
            "target_surface_ids": [surface.surface_id for surface, _ in targets],
            "targets": target_rows,
            "expected_parts": expected_parts,
        },
        tuple(parts),
    )
