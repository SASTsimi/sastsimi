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


@dataclass(frozen=True)
class SuccessfulMatchPair:
    """The two Primitive records actually used by one successful match."""

    upstream_ref: StoredDataRef
    downstream_ref: StoredDataRef


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
    successful_match_pairs: tuple[SuccessfulMatchPair, ...],
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
    trigger_key = canonical_bytes(trigger_ref)
    pair_keys: list[tuple[bytes, bytes]] = []
    successful_keys: set[bytes] = set()
    pairs_by_candidate: dict[bytes, SuccessfulMatchPair] = {}
    for pair in successful_match_pairs:
        upstream_key = canonical_bytes(pair.upstream_ref)
        downstream_key = canonical_bytes(pair.downstream_ref)
        if (
            upstream_key == downstream_key
            or trigger_key not in {upstream_key, downstream_key}
            or not {upstream_key, downstream_key} <= set(considered)
        ):
            raise ValueError("CHAINING_LINEAGE_INPUT_MISMATCH")
        pair_key = (upstream_key, downstream_key)
        pair_keys.append(pair_key)
        candidate_key = downstream_key if upstream_key == trigger_key else upstream_key
        pairs_by_candidate[candidate_key] = pair
        successful_keys.update(pair_key)
    if len(set(pair_keys)) != len(pair_keys) or len(pairs_by_candidate) != len(
        pair_keys
    ):
        raise ValueError("CHAINING_LINEAGE_INPUT_MISMATCH")
    excluded: set[bytes] = set()
    output: list[LineageExclusion] = []
    for candidate_ref in order_deepest_first(
        tuple(considered[key] for key in pairs_by_candidate),
        resolve,
        analysis_id=analysis_id,
    ):
        candidate_key = canonical_bytes(candidate_ref)
        if candidate_key in excluded:
            raise ValueError("CHAINING_SUCCESSFUL_CANDIDATE_EXCLUDED")
        pair = pairs_by_candidate[candidate_key]
        for matched_ref in (pair.upstream_ref, pair.downstream_ref):
            for ancestor_ref in lineage(
                matched_ref, resolve, analysis_id=analysis_id
            ).ancestors:
                ancestor_key = canonical_bytes(ancestor_ref)
                if ancestor_key not in considered:
                    raise ValueError("CHAINING_LINEAGE_INPUT_MISMATCH")
                if ancestor_key in successful_keys:
                    raise ValueError("CHAINING_SUCCESSFUL_CANDIDATE_EXCLUDED")
                if ancestor_ref == matched_ref or ancestor_key in excluded:
                    continue
                excluded.add(ancestor_key)
                output.append(
                    LineageExclusion(
                        excluded_primitive_ref=ancestor_ref,
                        excluded_by_ref=matched_ref,
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
    "SuccessfulMatchPair",
    "expected_lineage_exclusions",
    "lineage",
    "order_deepest_first",
]
