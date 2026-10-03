"""Bounded, exact context for uncovered Python security surfaces.

The index identifies where to look. This module does not infer that a
surface was reviewed or that unavailable source contains no vulnerability.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import redact_projected_json
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .ast_facts import index_ast_manifest
from .attack_surfaces import AttackSurface, SurfaceCoverage, SurfaceIndex
from .file_context import PreparedFileContext, prepare_file_context

_NEARBY_LINE_RADIUS = 5
_MAX_NEARBY_AST_FACTS = 32


class SurfaceContextOverflow(ValueError):
    """A surface cannot fit even its metadata; it remains unreviewed."""

    def __init__(self, surface_id: str) -> None:
        self.surface_id = surface_id
        super().__init__("SURFACE_CONTEXT_OVERFLOW")


@dataclass(frozen=True, slots=True)
class SurfaceContext:
    surface_id: str
    context_id: str
    context_hash: str
    context_ref: StoredDataRef
    part_index: int
    part_count: int
    prompt_bytes: int
    source_sha256: str | None
    source_unavailable_reason: str | None
    ast_unavailable_reason: str | None
    omitted_source_line_count: int | None
    omitted_ast_fact_count: int | None


def _same_surface(left: AttackSurface, right: AttackSurface) -> bool:
    return (
        left.surface_id,
        left.type,
        left.path,
        left.symbol,
        left.line,
        left.linked_candidate_ids,
        left.evidence_refs,
        left.detector,
        left.flow_identity,
    ) == (
        right.surface_id,
        right.type,
        right.path,
        right.symbol,
        right.line,
        right.linked_candidate_ids,
        right.evidence_refs,
        right.detector,
        right.flow_identity,
    )


def _require_matching_coverage(
    index: SurfaceIndex,
    coverage: SurfaceCoverage,
    artifacts: SimpleArtifactRepository,
) -> None:
    if (
        index.scope_fingerprint != coverage.scope_fingerprint
        or index.static_bundle_hash != coverage.static_bundle_hash
        or index.ast_manifest_hash != coverage.ast_manifest_hash
        or index.candidate_inventory_hash != coverage.candidate_inventory_hash
        or index.candidate_count != coverage.candidate_count
        or index.static_gaps != coverage.static_gaps
        or len(index.surfaces) != len(coverage.surfaces)
        or str(artifacts.identity.workspace_id) != index.workspace_id
        or str(artifacts.identity.commit_id) != index.commit_id
        or any(
            not _same_surface(original, reviewed)
            for original, reviewed in zip(
                index.surfaces, coverage.surfaces, strict=True
            )
        )
    ):
        raise ValueError("SURFACE_CONTEXT_SCOPE_MISMATCH")


def _nearby_ast_facts(
    prepared: PreparedFileContext, line: int
) -> tuple[dict[str, Any], ...]:
    near = tuple(
        fact
        for fact in prepared.ast_facts
        if abs(int(fact["line"]) - line) <= _NEARBY_LINE_RADIUS
    )
    if not near and prepared.ast_facts:
        near = (
            min(
                prepared.ast_facts,
                key=lambda fact: (abs(int(fact["line"]) - line), int(fact["line"])),
            ),
        )
    selected = sorted(
        near,
        key=lambda fact: (
            abs(int(fact["line"]) - line),
            int(fact["line"]),
            str(fact["name"]),
        ),
    )[:_MAX_NEARBY_AST_FACTS]
    return tuple(
        sorted(selected, key=lambda fact: (int(fact["line"]), str(fact["name"])))
    )


def _surface_payload(
    index: SurfaceIndex,
    surface: AttackSurface,
    prepared: PreparedFileContext,
    source_lines: list[dict[str, object]],
    ast_facts: list[dict[str, Any]],
    unavailable_source_lines: list[dict[str, object]],
    unavailable_ast_facts: list[dict[str, object]],
    *,
    source_window_count: int,
    ast_nearby_count: int,
    part_index: int,
    part_count: int,
) -> dict[str, object]:
    total_source = (
        len(prepared.source_lines)
        if prepared.source_unavailable_reason is None
        else None
    )
    total_ast = (
        len(prepared.ast_facts) if prepared.ast_unavailable_reason is None else None
    )
    source_reason = prepared.source_unavailable_reason
    if source_reason is None and total_source is not None:
        if surface.line < 1 or surface.line > total_source:
            source_reason = "SURFACE_LOCATION_BEYOND_SOURCE"
        elif unavailable_source_lines:
            source_reason = "SOURCE_LINE_TOO_LARGE"
    source_status = (
        "UNAVAILABLE"
        if source_reason not in {None, "SOURCE_LINE_TOO_LARGE"}
        else "PARTIAL"
        if unavailable_source_lines
        else "AVAILABLE"
    )
    payload: dict[str, object] = {
        "kind": "simple_surface_context_v1",
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "candidate_inventory_hash": index.candidate_inventory_hash,
        "workspace_id": index.workspace_id,
        "commit_id": index.commit_id,
        "surface_id": surface.surface_id,
        "surface_type": surface.type,
        "path": surface.path,
        "symbol": surface.symbol,
        "line": surface.line,
        "detector": surface.detector,
        "flow_identity": surface.flow_identity,
        "linked_candidate_count": len(surface.linked_candidate_ids),
        "static_evidence_ref_hashes": sorted(
            {ref.content_hash for ref in surface.evidence_refs}
        ),
        "static_evidence_refs": [
            ref.model_dump(mode="json")
            for ref in sorted(surface.evidence_refs, key=lambda item: item.content_hash)
        ],
        "source_sha256": prepared.source_sha256,
        "source_status": source_status,
        "source_unavailable_reason": source_reason,
        "source_line_count": total_source,
        "source_window_line_count": source_window_count,
        "source_lines": source_lines,
        "omitted_source_line_count": (
            total_source - len(source_lines) if total_source is not None else None
        ),
        "unavailable_source_lines": unavailable_source_lines,
        "ast_file_ref": (
            prepared.ast_file_ref.model_dump(mode="json")
            if prepared.ast_file_ref is not None
            else None
        ),
        "ast_unavailable_reason": prepared.ast_unavailable_reason,
        "ast_total_count": total_ast,
        "ast_nearby_count": ast_nearby_count,
        "ast_facts": ast_facts,
        "omitted_ast_fact_count": (
            total_ast - len(ast_facts) if total_ast is not None else None
        ),
        "unavailable_ast_facts": unavailable_ast_facts,
        "redaction_categories": list(prepared.redaction_categories),
        "part_index": part_index,
        "part_count": part_count,
    }
    safe = json.loads(redact_projected_json(canonical_bytes(payload)).data)
    if not isinstance(safe, dict):
        raise ValueError("SURFACE_CONTEXT_REDACTION_FAILED")
    return safe


def _surface_context_parts(
    index: SurfaceIndex,
    surface: AttackSurface,
    prepared: PreparedFileContext,
    budget_bytes: int,
) -> tuple[dict[str, object], ...]:
    source_items: list[dict[str, object]] = []
    if prepared.source_unavailable_reason is None:
        source_items = [
            {"line": number, "text": prepared.source_lines[number - 1]}
            for number in range(
                max(1, surface.line - _NEARBY_LINE_RADIUS),
                min(len(prepared.source_lines), surface.line + _NEARBY_LINE_RADIUS) + 1,
            )
        ]
    ast_items = list(_nearby_ast_facts(prepared, surface.line))
    source_count = len(source_items)
    ast_count = len(ast_items)
    unavailable_source: list[dict[str, object]] = []
    unavailable_ast: list[dict[str, object]] = []
    item_count_upper = max(1, source_count + ast_count + 1)

    def payload(
        sources: list[dict[str, object]], facts: list[dict[str, Any]]
    ) -> dict[str, object]:
        return _surface_payload(
            index,
            surface,
            prepared,
            sources,
            facts,
            unavailable_source,
            unavailable_ast,
            source_window_count=source_count,
            ast_nearby_count=ast_count,
            part_index=item_count_upper,
            part_count=item_count_upper,
        )

    # A single source line or AST fact may be longer than a whole prompt.
    # Record it as unavailable rather than silently slicing its bytes.
    while True:
        changed = False
        remaining_source: list[dict[str, object]] = []
        for item in source_items:
            if len(canonical_bytes(payload([item], []))) > budget_bytes:
                unavailable_source.append(
                    {"line": item["line"], "reason": "SOURCE_LINE_TOO_LARGE"}
                )
                changed = True
            else:
                remaining_source.append(item)
        source_items = remaining_source
        remaining_ast: list[dict[str, Any]] = []
        for item in ast_items:
            if len(canonical_bytes(payload([], [item]))) > budget_bytes:
                unavailable_ast.append(
                    {"line": item["line"], "reason": "AST_FACT_TOO_LARGE"}
                )
                changed = True
            else:
                remaining_ast.append(item)
        ast_items = remaining_ast
        if not changed:
            break
    if len(canonical_bytes(payload([], []))) > budget_bytes:
        raise SurfaceContextOverflow(surface.surface_id)

    chunks: list[tuple[list[dict[str, object]], list[dict[str, Any]]]] = []
    current_source: list[dict[str, object]] = []
    current_ast: list[dict[str, Any]] = []
    for kind, item in [
        *(("source", item) for item in source_items),
        *(("ast", item) for item in ast_items),
    ]:
        next_source = [*current_source, item] if kind == "source" else current_source
        next_ast = [*current_ast, item] if kind == "ast" else current_ast
        if len(canonical_bytes(payload(next_source, next_ast))) > budget_bytes:
            chunks.append((current_source, current_ast))
            current_source = [item] if kind == "source" else []
            current_ast = [item] if kind == "ast" else []
        else:
            current_source = next_source
            current_ast = next_ast
    if current_source or current_ast or not chunks:
        chunks.append((current_source, current_ast))
    return tuple(
        _surface_payload(
            index,
            surface,
            prepared,
            sources,
            facts,
            unavailable_source,
            unavailable_ast,
            source_window_count=source_count,
            ast_nearby_count=ast_count,
            part_index=part_index,
            part_count=len(chunks),
        )
        for part_index, (sources, facts) in enumerate(chunks)
    )


def iter_uncovered_surface_contexts(
    index: SurfaceIndex,
    coverage: SurfaceCoverage,
    budget_bytes: int,
    *,
    artifacts: SimpleArtifactRepository,
    ast_summary: Mapping[str, object],
    workspace: Path,
) -> Iterator[SurfaceContext]:
    """Persist ordered, bounded context parts for surfaces needing review."""

    if budget_bytes < 512:
        raise ValueError("SURFACE_CONTEXT_BUDGET_INVALID")
    _require_matching_coverage(index, coverage, artifacts)
    manifest_index = index_ast_manifest(artifacts, ast_summary)
    prepared_by_path: dict[str, PreparedFileContext] = {}
    for surface in sorted(
        coverage.surfaces, key=lambda item: (item.path, item.line, item.surface_id)
    ):
        if surface.coverage_status == "COVERED":
            continue
        prepared = prepared_by_path.get(surface.path)
        if prepared is None:
            prepared = prepare_file_context(
                artifacts,
                ast_summary,
                workspace,
                surface.path,
                manifest_index=manifest_index,
            )
            prepared_by_path[surface.path] = prepared
        for payload in _surface_context_parts(index, surface, prepared, budget_bytes):
            encoded = canonical_bytes(payload)
            if len(encoded) > budget_bytes:
                raise SurfaceContextOverflow(surface.surface_id)
            context_ref = artifacts.put_json(payload)
            context_hash = context_ref.content_hash
            context_id = hashlib.sha256(
                canonical_bytes(
                    {
                        "kind": "simple_surface_context_id_v1",
                        "scope_fingerprint": index.scope_fingerprint,
                        "surface_id": surface.surface_id,
                        "part_index": payload["part_index"],
                        "context_hash": context_hash,
                    }
                )
            ).hexdigest()
            yield SurfaceContext(
                surface_id=surface.surface_id,
                context_id=context_id,
                context_hash=context_hash,
                context_ref=context_ref,
                part_index=cast(int, payload["part_index"]),
                part_count=cast(int, payload["part_count"]),
                prompt_bytes=len(encoded),
                source_sha256=prepared.source_sha256,
                source_unavailable_reason=cast(
                    str | None, payload["source_unavailable_reason"]
                ),
                ast_unavailable_reason=prepared.ast_unavailable_reason,
                omitted_source_line_count=cast(
                    int | None, payload["omitted_source_line_count"]
                ),
                omitted_ast_fact_count=cast(
                    int | None, payload["omitted_ast_fact_count"]
                ),
            )


def _expanded_source_lines(
    prepared: PreparedFileContext, surface: AttackSurface
) -> tuple[tuple[int, ...], str]:
    """Prefer the enclosing definition and direct same-file callees."""

    if not prepared.source_lines:
        return (), "SOURCE_UNAVAILABLE"
    try:
        tree = ast.parse("\n".join(prepared.source_lines) + "\n")
    except (SyntaxError, ValueError):
        # Redaction can invalidate syntax; retain visible redacted lines instead.
        return tuple(range(1, len(prepared.source_lines) + 1)), "FULL_FILE_FALLBACK"
    definitions = tuple(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and isinstance(getattr(node, "end_lineno", None), int)
    )
    enclosing = [
        node
        for node in definitions
        if node.lineno <= surface.line <= cast(int, node.end_lineno)
    ]
    if not enclosing:
        return tuple(range(1, len(prepared.source_lines) + 1)), "FULL_FILE"
    scope = min(
        enclosing,
        key=lambda node: (cast(int, node.end_lineno) - node.lineno, -node.lineno),
    )
    chosen = set(range(scope.lineno, cast(int, scope.end_lineno) + 1))
    called = {
        node.func.id
        for node in ast.walk(scope)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    for node in definitions:
        if node.name in called and node is not scope:
            chosen.update(range(node.lineno, cast(int, node.end_lineno) + 1))
    chosen.add(surface.line)
    return tuple(sorted(chosen)), "ENCLOSING_DEFINITION"


def expanded_surface_contexts(
    index: SurfaceIndex,
    surface: AttackSurface,
    *,
    artifacts: SimpleArtifactRepository,
    ast_summary: Mapping[str, object],
    workspace: Path,
    budget_bytes: int = 64 * 1024,
) -> tuple[SurfaceContext, ...]:
    """Persist one deterministic, redacted same-file second look in bounded parts."""

    if budget_bytes < 512 or budget_bytes > 64 * 1024:
        raise ValueError("SURFACE_CONTEXT_BUDGET_INVALID")
    if (
        surface not in index.surfaces
        or str(artifacts.identity.workspace_id) != index.workspace_id
    ):
        raise ValueError("SURFACE_CONTEXT_SCOPE_MISMATCH")
    manifest_index = index_ast_manifest(artifacts, ast_summary)
    prepared = prepare_file_context(
        artifacts, ast_summary, workspace, surface.path, manifest_index=manifest_index
    )
    manifest_entry = manifest_index.get(surface.path)
    expected_source = (
        manifest_entry.get("source_sha256") if manifest_entry is not None else None
    )
    if expected_source is not None and prepared.source_sha256 != expected_source:
        raise ValueError("SURFACE_CONTEXT_SOURCE_CHANGED")
    selected, selection_scope = _expanded_source_lines(prepared, surface)
    if prepared.source_unavailable_reason is None:
        all_lines = tuple(range(1, len(prepared.source_lines) + 1))
        full_items = [
            {"line": line, "text": prepared.source_lines[line - 1]}
            for line in all_lines
        ]
        full_probe = _surface_payload(
            index,
            surface,
            prepared,
            full_items,
            list(prepared.ast_facts),
            [],
            [],
            source_window_count=len(all_lines),
            ast_nearby_count=len(prepared.ast_facts),
            part_index=0,
            part_count=1,
        )
        full_probe["kind"] = "simple_surface_context_v2"
        full_probe["selection_scope"] = "FULL_FILE"
        if len(canonical_bytes(full_probe)) <= budget_bytes - min(
            2048, budget_bytes // 8
        ):
            selected, selection_scope = all_lines, "FULL_FILE"
    selected_set = set(selected)
    anchor: list[dict[str, object]] = (
        [{"line": surface.line, "text": prepared.source_lines[surface.line - 1]}]
        if surface.line in selected_set and surface.line <= len(prepared.source_lines)
        else []
    )
    source_items = [
        {"line": line, "text": prepared.source_lines[line - 1]}
        for line in selected
        if line != surface.line and line <= len(prepared.source_lines)
    ]
    ast_items = [
        fact for fact in prepared.ast_facts if int(fact["line"]) in selected_set
    ]
    unavailable_source: list[dict[str, object]] = []
    unavailable_ast: list[dict[str, object]] = []
    upper = max(1, len(source_items) + len(ast_items) + 1)

    def payload(
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
            unavailable_source,
            unavailable_ast,
            source_window_count=len(selected),
            ast_nearby_count=len(ast_items),
            part_index=part_index,
            part_count=part_count,
        )
        result["kind"] = "simple_surface_context_v2"
        result["selection_scope"] = selection_scope
        result["selected_source_line_count"] = len(selected)
        result["unavailable_implementation"] = (
            "CALL_RESULT_IMPLEMENTATION_NOT_IN_SAME_FILE"
            if "()." in surface.symbol
            else None
        )
        return result

    if anchor and len(canonical_bytes(payload(anchor, []))) > budget_bytes:
        unavailable_source.append(
            {"line": surface.line, "reason": "SOURCE_LINE_TOO_LARGE"}
        )
        anchor = []
    usable_source: list[dict[str, object]] = []
    for item in source_items:
        if len(canonical_bytes(payload([*anchor, item], []))) > budget_bytes:
            unavailable_source.append(
                {"line": item["line"], "reason": "SOURCE_LINE_TOO_LARGE"}
            )
        else:
            usable_source.append(item)
    usable_ast: list[dict[str, Any]] = []
    for item in ast_items:
        if len(canonical_bytes(payload(anchor, [item]))) > budget_bytes:
            unavailable_ast.append(
                {"line": item["line"], "reason": "AST_FACT_TOO_LARGE"}
            )
        else:
            usable_ast.append(item)
    if len(canonical_bytes(payload(anchor, []))) > budget_bytes:
        raise SurfaceContextOverflow(surface.surface_id)

    chunks: list[tuple[list[dict[str, object]], list[dict[str, Any]]]] = []
    current_source = list(anchor)
    current_ast: list[dict[str, Any]] = []
    for kind, item in [
        *(("source", item) for item in usable_source),
        *(("ast", item) for item in usable_ast),
    ]:
        next_source = [*current_source, item] if kind == "source" else current_source
        next_ast = [*current_ast, item] if kind == "ast" else current_ast
        if len(canonical_bytes(payload(next_source, next_ast))) > budget_bytes:
            chunks.append((current_source, current_ast))
            current_source = [*anchor, item] if kind == "source" else list(anchor)
            current_ast = [item] if kind == "ast" else []
        else:
            current_source, current_ast = next_source, next_ast
    chunks.append((current_source, current_ast))
    contexts: list[SurfaceContext] = []
    for part_index, (sources, facts) in enumerate(chunks):
        record = payload(sources, facts, part_index=part_index, part_count=len(chunks))
        encoded = canonical_bytes(record)
        if len(encoded) > budget_bytes:
            raise SurfaceContextOverflow(surface.surface_id)
        ref = artifacts.put_json(record)
        context_id = hashlib.sha256(
            canonical_bytes(
                {
                    "kind": "simple_surface_context_id_v2",
                    "scope_fingerprint": index.scope_fingerprint,
                    "surface_id": surface.surface_id,
                    "part_index": part_index,
                    "context_hash": ref.content_hash,
                }
            )
        ).hexdigest()
        contexts.append(
            SurfaceContext(
                surface_id=surface.surface_id,
                context_id=context_id,
                context_hash=ref.content_hash,
                context_ref=ref,
                part_index=part_index,
                part_count=len(chunks),
                prompt_bytes=len(encoded),
                source_sha256=prepared.source_sha256,
                source_unavailable_reason=cast(
                    str | None, record["source_unavailable_reason"]
                ),
                ast_unavailable_reason=prepared.ast_unavailable_reason,
                omitted_source_line_count=cast(
                    int | None, record["omitted_source_line_count"]
                ),
                omitted_ast_fact_count=cast(
                    int | None, record["omitted_ast_fact_count"]
                ),
            )
        )
    return tuple(contexts)
