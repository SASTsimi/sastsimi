"""Validate one bounded v9 Hypothesis Agent source/path review.

The response is a proposal, not a coverage certificate. A complete review
requires exact path-specific citations from the pinned context directory;
the coverage evaluator independently recomputes those facts from the graph.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, cast

from sastsimi.contracts.canonical_json import canonical_bytes

from .models import CheckpointIdentity
from .surface_contexts import SurfaceContext
from .surface_enrichment_v9 import V9Part, V9ReviewedPart, V9RoleCitation

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ROLES = frozenset({"ENTRY", "TRUST_BOUNDARY", "ANCHOR"})
_STATUSES = frozenset(
    {"HYPOTHESES", "NO_HYPOTHESIS", "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"}
)
_RESPONSE_FIELDS = frozenset(
    {
        "surface_id",
        "context_id",
        "context_hash",
        "part_id",
        "source_sha256",
        "content_sha256",
        "status",
        "reason",
        "hypotheses",
        "reviewed_path_ids",
        "review_evidence",
    }
)
_CITATION_FIELDS = frozenset(
    {"path_id", "role", "location", "source_sha256", "edge_ids", "explanation"}
)


@dataclass(frozen=True, slots=True)
class V9ValidatedResponse:
    status: str
    reason: str
    reviewed_path_ids: tuple[str, ...]
    role_citations: tuple[dict[str, object], ...]
    reviewed_parts: frozenset[str]
    evidence_locations: tuple[str, ...]
    review_complete: bool


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _is_hash(value: object) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _tracked(path: object) -> bool:
    if (
        not isinstance(path, str)
        or not path
        or "\\" in path
        or ":" in path
        or "\x00" in path
    ):
        return False
    pure = PurePosixPath(path)
    return not pure.is_absolute() and ".." not in pure.parts


def _directory(
    payload: Mapping[str, object], context_part: Mapping[str, object]
) -> tuple[dict[str, object], ...]:
    path_ids = context_part["path_ids"]
    path = context_part["path"]
    start, end = context_part["start_line"], context_part["end_line"]
    source_hash = context_part["source_sha256"]
    rows = payload.get("role_directory")
    if (
        not isinstance(rows, list)
        or not isinstance(path_ids, list)
        or any(not isinstance(item, str) for item in path_ids)
        or not isinstance(path, str)
        or type(start) is not int
        or type(end) is not int
        or not isinstance(source_hash, str)
    ):
        raise ValueError("V9_CONTEXT_INVALID")
    directory: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "path_id",
            "role",
            "location",
            "source_sha256",
            "edge_ids",
        }:
            raise ValueError("V9_CONTEXT_INVALID")
        location = row["location"]
        named_path, separator, line_text = (
            location.rpartition(":") if isinstance(location, str) else ("", "", "")
        )
        edges = row["edge_ids"]
        if (
            row["path_id"] not in path_ids
            or row["role"] not in _ROLES
            or not separator
            or named_path != path
            or not line_text.isascii()
            or not line_text.isdecimal()
            or not start <= int(line_text) <= end
            or row["source_sha256"] != source_hash
            or not isinstance(edges, list)
            or any(not isinstance(edge, str) or not edge for edge in edges)
            or len(edges) != len(set(edges))
        ):
            raise ValueError("V9_CONTEXT_INVALID")
        signature = (
            row["path_id"],
            row["role"],
            location,
            source_hash,
            tuple(edges),
        )
        if signature in seen:
            raise ValueError("V9_CONTEXT_INVALID")
        seen.add(signature)
        directory.append(row)
    return tuple(directory)


def validate_v9_context(
    context: SurfaceContext,
    payload: Mapping[str, object],
    identity: CheckpointIdentity,
    static_bundle_hash: str,
) -> None:
    """Check that the saved part is exactly the one passed to this Agent."""

    part = payload.get("context_part")
    if not isinstance(part, dict):
        raise ValueError("V9_CONTEXT_INVALID")
    path_ids = part.get("path_ids")
    path = part.get("path")
    start, end = part.get("start_line"), part.get("end_line")
    source_hash, content_hash = part.get("source_sha256"), part.get("content_sha256")
    excerpt = payload.get("source_excerpt")
    binding_hash = payload.get("plan_binding_hash")
    if (
        payload.get("kind") != "simple_surface_context_v9"
        or payload.get("analysis_id") != identity.analysis_id
        or payload.get("workspace_id") != identity.workspace_id
        or payload.get("commit_id") != identity.commit_id
        or payload.get("static_bundle_hash") != static_bundle_hash
        or payload.get("surface_id") != context.surface_id
        or payload.get("part_index") != context.part_index
        or payload.get("part_count") != context.part_count
        or not _is_hash(binding_hash)
        or any(
            not _is_hash(payload.get(field))
            for field in (
                "ast_manifest_hash",
                "surface_index_hash",
                "prior_v8_plan_hash",
                "prior_v8_coverage_hash",
                "prior_v8_progress_hash",
                "graph_hash",
                "path_certificate_hash",
            )
        )
        or not isinstance(part.get("part_id"), str)
        or not part["part_id"]
        or not isinstance(path_ids, list)
        or not path_ids
        or any(not isinstance(item, str) or not item for item in path_ids)
        or path_ids != sorted(set(path_ids))
        or not _tracked(path)
        or type(start) is not int
        or type(end) is not int
        or not 1 <= start <= end
        or not _is_hash(source_hash)
        or not _is_hash(content_hash)
        or not isinstance(excerpt, str)
        or len(excerpt.split("\n")) != end - start + 1
        or len(excerpt.encode("utf-8")) > 16 * 1024
        or source_hash != context.source_sha256
        or context.source_unavailable_reason is not None
        or context.ast_unavailable_reason is not None
        or type(context.part_index) is not int
        or type(context.part_count) is not int
        or not 0 <= context.part_index < context.part_count
        or context.context_hash != context.context_ref.content_hash
        or context.prompt_bytes != len(canonical_bytes(payload))
        or context.context_hash != _digest(payload)
    ):
        raise ValueError("V9_CONTEXT_INVALID")
    expected_id = _digest(
        {
            "kind": "simple_surface_context_id_v9",
            "plan_binding_hash": binding_hash,
            "surface_id": context.surface_id,
            "part_id": part["part_id"],
            "context_hash": context.context_hash,
        }
    )
    if context.context_id != expected_id:
        raise ValueError("V9_CONTEXT_INVALID")
    _directory(payload, part)


def validate_v9_response(
    context: SurfaceContext,
    payload: Mapping[str, object],
    response: object,
) -> V9ValidatedResponse:
    """Reject forged roles and distinguish a finding seed from complete review."""

    part = payload.get("context_part")
    if not isinstance(part, dict) or not isinstance(response, dict):
        raise ValueError("V9_RESPONSE_INVALID")
    if set(response) != _RESPONSE_FIELDS:
        raise ValueError("V9_RESPONSE_INVALID")
    status, reason, hypotheses = (
        response["status"],
        response["reason"],
        response["hypotheses"],
    )
    if (
        response["surface_id"] != context.surface_id
        or response["context_id"] != context.context_id
        or response["context_hash"] != context.context_hash
        or response["part_id"] != part.get("part_id")
        or response["source_sha256"] != part.get("source_sha256")
        or response["content_sha256"] != part.get("content_sha256")
        or status not in _STATUSES
        or not isinstance(reason, str)
        or not reason.strip()
        or not isinstance(hypotheses, list)
        or len(hypotheses) > 4
        or (status == "HYPOTHESES" and not hypotheses)
        or (status != "HYPOTHESES" and hypotheses)
    ):
        raise ValueError("V9_RESPONSE_INVALID")
    paths = response["reviewed_path_ids"]
    available = part.get("path_ids")
    if (
        not isinstance(paths, list)
        or not isinstance(available, list)
        or any(not isinstance(item, str) for item in paths)
        or paths != sorted(set(paths))
        or not set(paths) <= set(available)
    ):
        raise ValueError("V9_REVIEW_PATH_INVALID")
    directory = _directory(payload, part)
    allowed: set[tuple[object, ...]] = {
        (
            row["path_id"],
            row["role"],
            row["location"],
            row["source_sha256"],
            tuple(cast(list[str], row["edge_ids"])),
        )
        for row in directory
    }
    review = response["review_evidence"]
    if not isinstance(review, list) or len(review) > len(directory):
        raise ValueError("V9_REVIEW_CITATION_INVALID")
    citations: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for item in review:
        if not isinstance(item, dict) or set(item) != _CITATION_FIELDS:
            raise ValueError("V9_REVIEW_CITATION_INVALID")
        edges = item["edge_ids"]
        if (
            not isinstance(edges, list)
            or any(not isinstance(edge, str) for edge in edges)
            or not isinstance(item["explanation"], str)
            or not item["explanation"].strip()
        ):
            raise ValueError("V9_REVIEW_CITATION_INVALID")
        signature = (
            item["path_id"],
            item["role"],
            item["location"],
            item["source_sha256"],
            tuple(edges),
        )
        if signature not in allowed or signature in seen:
            raise ValueError("V9_REVIEW_CITATION_INVALID")
        if item["path_id"] not in paths:
            raise ValueError("V9_REVIEW_CITATION_INVALID")
        seen.add(signature)
        citations.append(
            {
                "path_id": item["path_id"],
                "role": item["role"],
                "location": item["location"],
                "source_sha256": item["source_sha256"],
                "edge_ids": list(edges),
            }
        )
    expected = {signature for signature in allowed if signature[0] in paths}
    complete = (
        status != "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
        and paths == available
        and expected <= seen
    )
    if status == "NO_HYPOTHESIS" and not complete:
        raise ValueError("V9_REVIEW_INCOMPLETE")
    return V9ValidatedResponse(
        status=status,
        reason=reason,
        reviewed_path_ids=tuple(paths),
        role_citations=tuple(citations),
        reviewed_parts=frozenset(cast(str, row["role"]) for row in citations),
        evidence_locations=tuple(
            dict.fromkeys(cast(str, row["location"]) for row in citations)
        ),
        review_complete=complete,
    )


def validate_saved_v9_result(
    part: V9Part,
    saved: Mapping[str, object],
    expected_seed_ids: Sequence[str],
) -> V9ReviewedPart:
    """Reconstruct a review from an immutable saved artifact, never its flag alone.

    The saved response is deliberately redacted, so replay checks the separately
    recorded citations against the recomputed plan's role directory and checks
    seed IDs against the actual saved hypothesis rows supplied by the caller.
    """

    payload = part.payload
    context_part = payload.get("context_part")
    if not isinstance(context_part, dict):
        raise ValueError("V9_SAVED_RESULT_INVALID")
    try:
        directory = _directory(payload, context_part)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("V9_SAVED_RESULT_INVALID") from exc
    plan_binding_hash = payload.get("plan_binding_hash")
    expected_context_id = _digest(
        {
            "kind": "simple_surface_context_id_v9",
            "plan_binding_hash": plan_binding_hash,
            "surface_id": part.surface_id,
            "part_id": part.part_id,
            "context_hash": part.context_hash,
        }
    )
    status = saved.get("status")
    reason = saved.get("reason")
    paths = saved.get("reviewed_path_ids")
    available = context_part.get("path_ids")
    seeds = saved.get("seed_ids")
    if (
        payload.get("kind") != "simple_surface_context_v9"
        or not _is_hash(plan_binding_hash)
        or part.context_hash != _digest(payload)
        or part.context_id != expected_context_id
        or part.part_id != context_part.get("part_id")
        or part.source_sha256 != context_part.get("source_sha256")
        or part.part_index != payload.get("part_index")
        or part.part_count != payload.get("part_count")
        or saved.get("kind") != "simple_surface_hypothesis_result_v9"
        or saved.get("analysis_id") != payload.get("analysis_id")
        or saved.get("surface_id") != part.surface_id
        or saved.get("context_id") != part.context_id
        or saved.get("context_hash") != part.context_hash
        or saved.get("part_id") != part.part_id
        or saved.get("part_index") != part.part_index
        or saved.get("part_count") != part.part_count
        or saved.get("source_sha256") != part.source_sha256
        or saved.get("content_sha256") != context_part.get("content_sha256")
        or saved.get("static_bundle_hash") != payload.get("static_bundle_hash")
        or saved.get("validation_status") != "VALID"
        or saved.get("validation_feedback") is not None
        or status not in _STATUSES
        or not isinstance(reason, str)
        or not reason.strip()
        or not isinstance(available, list)
        or not isinstance(paths, list)
        or any(not isinstance(path, str) for path in paths)
        or paths != sorted(set(paths))
        or not set(paths) <= set(available)
        or not isinstance(seeds, list)
        or any(not isinstance(seed, str) or not seed for seed in seeds)
        or len(seeds) != len(set(seeds))
        or tuple(seeds) != tuple(expected_seed_ids)
        or (status == "HYPOTHESES" and not seeds)
        or (status != "HYPOTHESES" and bool(seeds))
        or type(saved.get("review_complete")) is not bool
    ):
        raise ValueError("V9_SAVED_RESULT_INVALID")
    allowed = {
        (
            row["path_id"],
            row["role"],
            row["location"],
            row["source_sha256"],
            tuple(cast(list[str], row["edge_ids"])),
        )
        for row in directory
    }
    raw_citations = saved.get("role_citations")
    if not isinstance(raw_citations, list) or len(raw_citations) > len(directory):
        raise ValueError("V9_SAVED_RESULT_INVALID")
    citations: list[V9RoleCitation] = []
    seen: set[tuple[object, ...]] = set()
    for row in raw_citations:
        if not isinstance(row, dict) or set(row) != _CITATION_FIELDS - {"explanation"}:
            raise ValueError("V9_SAVED_RESULT_INVALID")
        edges = row.get("edge_ids")
        if not isinstance(edges, list) or any(
            not isinstance(edge, str) for edge in edges
        ):
            raise ValueError("V9_SAVED_RESULT_INVALID")
        signature = (
            row.get("path_id"),
            row.get("role"),
            row.get("location"),
            row.get("source_sha256"),
            tuple(edges),
        )
        if signature not in allowed or signature in seen or row["path_id"] not in paths:
            raise ValueError("V9_SAVED_RESULT_INVALID")
        seen.add(signature)
        citations.append(
            V9RoleCitation(
                path_id=cast(str, row["path_id"]),
                role=cast(Any, row["role"]),
                location=cast(str, row["location"]),
                source_sha256=cast(str, row["source_sha256"]),
                edge_ids=tuple(edges),
            )
        )
    expected_signatures = {signature for signature in allowed if signature[0] in paths}
    complete = (
        status != "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
        and paths == available
        and expected_signatures <= seen
    )
    if (
        saved["review_complete"] != complete
        or (status == "NO_HYPOTHESIS" and not complete)
        or saved.get("reviewed_parts")
        != (sorted({row.role for row in citations}) if complete else [])
        or saved.get("evidence_locations")
        != (list(dict.fromkeys(row.location for row in citations)) if complete else [])
    ):
        raise ValueError("V9_SAVED_RESULT_INVALID")
    return V9ReviewedPart(
        surface_id=part.surface_id,
        context_id=part.context_id,
        context_hash=part.context_hash,
        part_id=part.part_id,
        source_sha256=part.source_sha256,
        content_sha256=cast(str, context_part["content_sha256"]),
        status=cast(Any, status),
        reviewed_path_ids=tuple(paths),
        role_citations=tuple(citations),
        review_complete=complete,
    )


def v9_response_schema(
    context: SurfaceContext,
    payload: Mapping[str, object],
    hypotheses_schema: Mapping[str, Any],
) -> dict[str, Any]:
    """Constrain the provider's JSON reply before semantic validation."""

    part = payload["context_part"]
    if not isinstance(part, dict):
        raise ValueError("V9_CONTEXT_INVALID")
    rows = _directory(payload, part)
    paths = part["path_ids"]
    return {
        "type": "object",
        "properties": {
            "surface_id": {"type": "string", "enum": [context.surface_id]},
            "context_id": {"type": "string", "enum": [context.context_id]},
            "context_hash": {"type": "string", "enum": [context.context_hash]},
            "part_id": {"type": "string", "enum": [part["part_id"]]},
            "source_sha256": {"type": "string", "enum": [part["source_sha256"]]},
            "content_sha256": {"type": "string", "enum": [part["content_sha256"]]},
            "status": {"type": "string", "enum": sorted(_STATUSES)},
            "reason": {"type": "string"},
            "hypotheses": dict(hypotheses_schema),
            "reviewed_path_ids": {
                "type": "array",
                "items": {"type": "string", "enum": paths},
            },
            "review_evidence": {
                "type": "array",
                "maxItems": len(rows),
                "items": {
                    "type": "object",
                    "properties": {
                        "path_id": {"type": "string", "enum": paths},
                        "role": {"type": "string", "enum": sorted(_ROLES)},
                        "location": {"type": "string"},
                        "source_sha256": {
                            "type": "string",
                            "enum": [part["source_sha256"]],
                        },
                        "edge_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "explanation": {"type": "string"},
                    },
                    "required": sorted(_CITATION_FIELDS),
                    "additionalProperties": False,
                },
            },
        },
        "required": sorted(_RESPONSE_FIELDS),
        "additionalProperties": False,
    }
