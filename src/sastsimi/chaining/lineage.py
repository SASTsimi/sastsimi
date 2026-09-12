"""Fail-closed Primitive lineage traversal and deepest-success exclusion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import LineageExclusion
from sastsimi.contracts.refs import StoredDataRef, require_record_ref


@dataclass(frozen=True)
class LineageNode:
    """Trusted projection of one Primitive's committed source-match lineage."""

    primitive_ref: StoredDataRef
    parent_primitive_refs: tuple[StoredDataRef, ...]
    analysis_id: str
    workspace_id: str
    commit_id: str
    committed: bool


@dataclass(frozen=True)
class Lineage:
    ancestors: tuple[StoredDataRef, ...]
    depth: int


class LineageResolver(Protocol):
    def __call__(self, primitive_ref: StoredDataRef) -> LineageNode: ...


def lineage(
    primitive_ref: StoredDataRef,
    resolve: LineageResolver,
    *,
    analysis_id: str,
) -> Lineage:
    """Return unique ancestors and fail on missing, foreign or cyclic lineage."""

    try:
        root = resolve(primitive_ref)
    except LookupError as error:
        raise ValueError("CHAINING_LINEAGE_MISSING") from error
    _validate_node(root, primitive_ref, root, analysis_id)
    ordered: list[StoredDataRef] = []
    seen: set[bytes] = set()

    def visit(current_ref: StoredDataRef, active: set[bytes]) -> None:
        key = canonical_bytes(current_ref)
        if key in active:
            raise ValueError("CHAINING_LINEAGE_CYCLE")
        if key in seen:
            return
        try:
            node = resolve(current_ref)
        except LookupError as error:
            raise ValueError("CHAINING_LINEAGE_MISSING") from error
        _validate_node(node, current_ref, root, analysis_id)
        next_active = active | {key}
        for parent_ref in node.parent_primitive_refs:
            if parent_ref == current_ref:
                raise ValueError("CHAINING_LINEAGE_CYCLE")
            parent_key = canonical_bytes(parent_ref)
            visit(parent_ref, next_active)
            if parent_key not in seen:
                seen.add(parent_key)
                ordered.append(parent_ref)

    visit(primitive_ref, set())
    root_key = canonical_bytes(primitive_ref)
    ancestors = tuple(item for item in ordered if canonical_bytes(item) != root_key)
    return Lineage(ancestors=ancestors, depth=len(ancestors))


def order_deepest_first(
    primitive_refs: tuple[StoredDataRef, ...],
    resolve: LineageResolver,
    *,
    analysis_id: str,
) -> tuple[StoredDataRef, ...]:
    """Order deterministically by ancestor count, deepest candidate first."""

    if len({canonical_bytes(ref) for ref in primitive_refs}) != len(primitive_refs):
        raise ValueError("CHAINING_LINEAGE_DUPLICATE")
    ranked = (
        (
            lineage(ref, resolve, analysis_id=analysis_id).depth,
            _record_id(ref),
            ref,
        )
        for ref in primitive_refs
    )
    return tuple(
        item[2] for item in sorted(ranked, key=lambda item: (-item[0], item[1]))
    )


def expected_lineage_exclusions(
    *,
    considered_refs: tuple[StoredDataRef, ...],
    trigger_ref: StoredDataRef,
    successful_candidate_refs: tuple[StoredDataRef, ...],
    resolve: LineageResolver,
    analysis_id: str,
) -> tuple[LineageExclusion, ...]:
    """Derive exclusions only after a deepest candidate actually matched."""

    considered = {canonical_bytes(ref): ref for ref in considered_refs}
    if (
        len(considered) != len(considered_refs)
        or canonical_bytes(trigger_ref) not in considered
    ):
        raise ValueError("CHAINING_LINEAGE_INPUT_MISMATCH")
    successful_keys = {canonical_bytes(ref) for ref in successful_candidate_refs}
    if len(successful_keys) != len(successful_candidate_refs) or not (
        successful_keys <= set(considered)
    ):
        raise ValueError("CHAINING_LINEAGE_INPUT_MISMATCH")
    excluded: set[bytes] = set()
    output: list[LineageExclusion] = []
    for candidate_ref in order_deepest_first(
        successful_candidate_refs, resolve, analysis_id=analysis_id
    ):
        candidate_key = canonical_bytes(candidate_ref)
        if candidate_key in excluded:
            raise ValueError("CHAINING_SUCCESSFUL_CANDIDATE_EXCLUDED")
        for ancestor_ref in lineage(
            candidate_ref, resolve, analysis_id=analysis_id
        ).ancestors:
            ancestor_key = canonical_bytes(ancestor_ref)
            if (
                ancestor_key not in considered
                or ancestor_ref == trigger_ref
                or ancestor_ref == candidate_ref
                or ancestor_key in successful_keys
                or ancestor_key in excluded
            ):
                continue
            excluded.add(ancestor_key)
            output.append(
                LineageExclusion(
                    excluded_primitive_ref=ancestor_ref,
                    excluded_by_ref=candidate_ref,
                    reason_code="ANCESTOR_REUSE",
                )
            )
    return tuple(output)


def _validate_node(
    node: LineageNode,
    expected_ref: StoredDataRef,
    root: LineageNode,
    analysis_id: str,
) -> None:
    require_record_ref(expected_ref, "primitive")
    if node.primitive_ref != expected_ref:
        raise ValueError("CHAINING_LINEAGE_REFERENCE_MISMATCH")
    if not node.committed:
        raise ValueError("CHAINING_LINEAGE_NOT_COMMITTED")
    if (
        node.analysis_id != analysis_id
        or root.analysis_id != analysis_id
        or node.workspace_id != root.workspace_id
        or node.commit_id != root.commit_id
        or str(expected_ref.workspace_id) != node.workspace_id
        or str(expected_ref.commit_id) != node.commit_id
    ):
        raise ValueError("CHAINING_LINEAGE_SCOPE_MISMATCH")


def _record_id(ref: StoredDataRef) -> str:
    require_record_ref(ref, "primitive")
    assert ref.record_id is not None
    return str(ref.record_id)


__all__ = [
    "Lineage",
    "LineageNode",
    "LineageResolver",
    "expected_lineage_exclusions",
    "lineage",
    "order_deepest_first",
]
