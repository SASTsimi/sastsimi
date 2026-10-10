"""Pure construction of supplemental contexts for saved v2 surface slices."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import redact_projected_json

from .attack_surfaces import AttackSurface, SurfaceIndex
from .file_context import PreparedFileContext
from .surface_contexts import SurfaceContext, SurfaceContextOverflow, _surface_payload


@dataclass(frozen=True, slots=True)
class SupplementalSurfaceContext:
    context_id: str
    context_hash: str
    payload: dict[str, object]
    prompt_bytes: int


def _project(value: object) -> object:
    """Compare saved prompt-safe items with the pinned redacted source/AST."""

    return json.loads(redact_projected_json(canonical_bytes(value)).data)


def _saved_v2_orphans(
    index: SurfaceIndex,
    surface: AttackSurface,
    prepared: PreparedFileContext,
    saved_v2: Sequence[tuple[SurfaceContext, Mapping[str, object]]],
    budget_bytes: int,
) -> tuple[tuple[SurfaceContext, tuple[dict[str, Any], ...]], ...]:
    if (
        index.index_version != 2
        or surface not in index.surfaces
        or prepared.path != surface.path
        or prepared.source_unavailable_reason is not None
        or prepared.ast_unavailable_reason is not None
        or prepared.ast_file_ref is None
        or not 1 <= surface.line <= len(prepared.source_lines)
        or not saved_v2
    ):
        raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
    source_hashes = [
        source_hash
        for path, source_hash in index.ast_source_hashes
        if path == surface.path
    ]
    if (
        len(source_hashes) != 1
        or prepared.source_sha256 is None
        or source_hashes[0] != prepared.source_sha256
    ):
        raise ValueError("SURFACE_SUPPLEMENT_SOURCE_MISMATCH")
    expected_ast_ref = prepared.ast_file_ref.model_dump(mode="json")
    expected_evidence = [
        ref.model_dump(mode="json")
        for ref in sorted(surface.evidence_refs, key=lambda item: item.content_hash)
    ]
    available_facts = Counter(
        canonical_bytes(_project(fact)) for fact in prepared.ast_facts
    )
    seen_parts: set[int] = set()
    orphan_groups: list[tuple[SurfaceContext, tuple[dict[str, Any], ...]]] = []
    for context, raw_payload in saved_v2:
        payload = dict(raw_payload)
        encoded = canonical_bytes(payload)
        part_index = payload.get("part_index")
        part_count = payload.get("part_count")
        if (
            payload.get("kind") != "simple_surface_context_v2"
            or payload.get("scope_fingerprint") != index.scope_fingerprint
            or payload.get("static_bundle_hash") != index.static_bundle_hash
            or payload.get("ast_manifest_hash") != index.ast_manifest_hash
            or payload.get("candidate_inventory_hash") != index.candidate_inventory_hash
            or payload.get("workspace_id") != index.workspace_id
            or payload.get("commit_id") != index.commit_id
            or payload.get("surface_id") != surface.surface_id
            or payload.get("surface_type") != surface.type
            or payload.get("path") != surface.path
            or payload.get("symbol") != surface.symbol
            or payload.get("line") != surface.line
            or payload.get("detector") != surface.detector
            or payload.get("flow_identity") != surface.flow_identity
            or payload.get("linked_candidate_count")
            != len(surface.linked_candidate_ids)
            or payload.get("static_evidence_refs") != expected_evidence
            or payload.get("static_evidence_ref_hashes")
            != sorted({ref.content_hash for ref in surface.evidence_refs})
            or payload.get("source_sha256") != prepared.source_sha256
            or payload.get("source_line_count") != len(prepared.source_lines)
            or payload.get("source_status") != "AVAILABLE"
            or payload.get("ast_total_count") != len(prepared.ast_facts)
            or payload.get("ast_file_ref") != expected_ast_ref
            or payload.get("unavailable_source_lines") != []
            or payload.get("unavailable_ast_facts") != []
            or payload.get("unavailable_implementation")
            not in {None, "CALL_RESULT_IMPLEMENTATION_NOT_IN_SAME_FILE"}
            or type(part_index) is not int
            or type(part_count) is not int
            or part_count != len(saved_v2)
            or part_index < 0
            or part_index >= part_count
            or part_index in seen_parts
            or len(encoded) > budget_bytes
            or context.prompt_bytes != len(encoded)
            or context.part_index != part_index
            or context.part_count != part_count
            or context.surface_id != surface.surface_id
            or context.source_sha256 != prepared.source_sha256
            or context.context_ref.content_hash != context.context_hash
            or str(context.context_ref.workspace_id) != index.workspace_id
            or str(context.context_ref.commit_id) != index.commit_id
            or context.context_hash != hashlib.sha256(encoded).hexdigest()
        ):
            raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
        expected_id = hashlib.sha256(
            canonical_bytes(
                {
                    "kind": "simple_surface_context_id_v2",
                    "scope_fingerprint": index.scope_fingerprint,
                    "surface_id": surface.surface_id,
                    "part_index": part_index,
                    "context_hash": context.context_hash,
                }
            )
        ).hexdigest()
        if context.context_id != expected_id:
            raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
        seen_parts.add(part_index)
        raw_lines = payload.get("source_lines")
        raw_facts = payload.get("ast_facts")
        if not isinstance(raw_lines, list) or not isinstance(raw_facts, list):
            raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
        visible: set[int] = set()
        for row in raw_lines:
            if (
                not isinstance(row, dict)
                or type(row.get("line")) is not int
                or not isinstance(row.get("text"), str)
            ):
                raise ValueError("SURFACE_SUPPLEMENT_SOURCE_MISMATCH")
            line = row["line"]
            if line < 1 or line > len(prepared.source_lines) or line in visible:
                raise ValueError("SURFACE_SUPPLEMENT_SOURCE_MISMATCH")
            expected_line = _project(prepared.source_lines[line - 1])
            if row["text"] != expected_line:
                raise ValueError("SURFACE_SUPPLEMENT_SOURCE_MISMATCH")
            visible.add(line)
        orphans: list[dict[str, Any]] = []
        for fact in raw_facts:
            if (
                not isinstance(fact, dict)
                or type(fact.get("line")) is not int
                or fact.get("path") != surface.path
                or not 1 <= fact["line"] <= len(prepared.source_lines)
            ):
                raise ValueError("SURFACE_SUPPLEMENT_AST_MISMATCH")
            encoded_fact = canonical_bytes(fact)
            if available_facts[encoded_fact] <= 0:
                raise ValueError("SURFACE_SUPPLEMENT_AST_MISMATCH")
            available_facts[encoded_fact] -= 1
            if fact["line"] not in visible:
                orphans.append(fact)
        orphan_groups.append((context, tuple(orphans)))
    if seen_parts != set(range(len(saved_v2))):
        raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
    return tuple(sorted(orphan_groups, key=lambda item: item[0].part_index))


def build_surface_context_supplements(
    index: SurfaceIndex,
    surface: AttackSurface,
    prepared: PreparedFileContext,
    saved_v2: Sequence[tuple[SurfaceContext, Mapping[str, object]]],
    *,
    budget_bytes: int = 64 * 1024,
) -> tuple[SupplementalSurfaceContext, ...]:
    """Re-pair orphaned saved-v2 AST facts with pinned source, without I/O."""

    if not 512 <= budget_bytes <= 64 * 1024:
        raise ValueError("SURFACE_CONTEXT_BUDGET_INVALID")
    groups = _saved_v2_orphans(index, surface, prepared, saved_v2, budget_bytes)
    unavailable_by_parent = {
        context.context_id: raw_payload.get("unavailable_implementation")
        for context, raw_payload in saved_v2
    }
    total_orphans = sum(len(facts) for _, facts in groups)
    if total_orphans == 0:
        return ()
    anchor = {
        "line": surface.line,
        "text": prepared.source_lines[surface.line - 1],
    }
    upper = total_orphans + 1
    index_hash = hashlib.sha256(canonical_bytes(index.to_json())).hexdigest()

    def payload(
        parent: SurfaceContext,
        sources: list[dict[str, object]],
        facts: list[dict[str, Any]],
        *,
        part_index: int = upper,
        part_count: int = upper,
    ) -> dict[str, object]:
        result = _surface_payload(
            index,
            surface,
            prepared,
            sources,
            facts,
            [],
            [],
            source_window_count=len({cast(int, source["line"]) for source in sources}),
            ast_nearby_count=len(facts),
            part_index=part_index,
            part_count=part_count,
        )
        result["kind"] = "simple_surface_context_v3"
        result["selection_scope"] = "SAVED_V2_AST_SOURCE_SUPPLEMENT"
        result["selected_source_line_count"] = len(
            {cast(int, source["line"]) for source in sources}
        )
        result["parent_v2_context_id"] = parent.context_id
        result["parent_v2_context_hash"] = parent.context_hash
        result["parent_v2_part_index"] = parent.part_index
        result["unavailable_implementation"] = unavailable_by_parent[parent.context_id]
        result["surface_index_hash"] = index_hash
        return result

    packed: list[
        tuple[SurfaceContext, list[dict[str, object]], list[dict[str, Any]]]
    ] = []
    for parent, facts in groups:
        if not facts:
            continue
        by_line: dict[int, list[dict[str, Any]]] = {}
        for fact in facts:
            by_line.setdefault(cast(int, fact["line"]), []).append(fact)
        current_sources: list[dict[str, object]] = [anchor]
        current_facts: list[dict[str, Any]] = []
        for line in sorted(by_line):
            source = {"line": line, "text": prepared.source_lines[line - 1]}
            for fact in by_line[line]:
                next_sources = (
                    current_sources
                    if line in {cast(int, item["line"]) for item in current_sources}
                    else [*current_sources, source]
                )
                next_facts = [*current_facts, fact]
                proposed = payload(parent, next_sources, next_facts)
                if len(canonical_bytes(proposed)) > budget_bytes:
                    if current_facts:
                        packed.append((parent, current_sources, current_facts))
                    current_sources = (
                        [anchor] if line == surface.line else [anchor, source]
                    )
                    current_facts = []
                    singleton = payload(parent, current_sources, [fact])
                    if len(canonical_bytes(singleton)) > budget_bytes:
                        raise SurfaceContextOverflow(surface.surface_id)
                else:
                    current_sources = next_sources
                current_facts.append(fact)
        if current_facts:
            packed.append((parent, current_sources, current_facts))

    supplements: list[SupplementalSurfaceContext] = []
    for part_index, (parent, sources, chunk_facts) in enumerate(packed):
        record = payload(
            parent,
            sources,
            chunk_facts,
            part_index=part_index,
            part_count=len(packed),
        )
        encoded = canonical_bytes(record)
        if len(encoded) > budget_bytes:
            raise SurfaceContextOverflow(surface.surface_id)
        context_hash = hashlib.sha256(encoded).hexdigest()
        context_id = hashlib.sha256(
            canonical_bytes(
                {
                    "kind": "simple_surface_context_id_v3",
                    "scope_fingerprint": index.scope_fingerprint,
                    "surface_id": surface.surface_id,
                    "parent_v2_context_id": parent.context_id,
                    "part_index": part_index,
                    "context_hash": context_hash,
                }
            )
        ).hexdigest()
        supplements.append(
            SupplementalSurfaceContext(
                context_id=context_id,
                context_hash=context_hash,
                payload=record,
                prompt_bytes=len(encoded),
            )
        )
    return tuple(supplements)
