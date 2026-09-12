from __future__ import annotations

import pytest

from sastsimi.chaining.lineage import (
    LineageNode,
    SuccessfulMatchPair,
    expected_lineage_exclusions,
    lineage,
    order_deepest_first,
    retain_deepest_successful_matches,
)
from sastsimi.contracts.refs import StoredDataRef
from tests.contract.domain.fixtures import ref, wire


def _ref(record_id: str) -> StoredDataRef:
    return wire(
        StoredDataRef,
        ref("primitive")
        | {
            "stored_data_id": f"stored-{record_id}",
            "record_id": record_id,
            "content_hash": (record_id[0] * 64),
        },
    )


def _resolver(
    graph: dict[StoredDataRef, tuple[StoredDataRef, ...]],
    *,
    committed: bool = True,
):
    def resolve(item: StoredDataRef) -> LineageNode:
        if item not in graph:
            raise LookupError("missing lineage")
        return LineageNode(
            primitive_ref=item,
            parent_primitive_refs=graph[item],
            analysis_id="a1",
            workspace_id="ws1",
            commit_id="c1",
            committed=committed,
        )

    return resolve


def test_deepest_success_excludes_only_its_ancestors() -> None:
    a, b, bc, bcd, bcde = map(_ref, ("a", "b", "c", "d", "e"))
    graph = {
        a: (),
        b: (),
        bc: (b,),
        bcd: (bc,),
        bcde: (bcd,),
    }
    resolve = _resolver(graph)

    assert order_deepest_first((b, bc, bcd, bcde), resolve, analysis_id="a1") == (
        bcde,
        bcd,
        bc,
        b,
    )
    exclusions = expected_lineage_exclusions(
        considered_refs=(a, b, bc, bcd, bcde),
        trigger_ref=a,
        successful_match_pairs=(SuccessfulMatchPair(a, bcde),),
        resolve=resolve,
        analysis_id="a1",
    )

    assert {
        (item.excluded_primitive_ref, item.excluded_by_ref) for item in exclusions
    } == {(b, bcde), (bc, bcde), (bcd, bcde)}
    assert (
        expected_lineage_exclusions(
            considered_refs=(a, b, bc, bcd, bcde),
            trigger_ref=a,
            successful_match_pairs=(),
            resolve=resolve,
            analysis_id="a1",
        )
        == ()
    )


def test_lineage_fails_closed_on_cycle_or_missing_parent() -> None:
    a, b = _ref("a"), _ref("b")
    with pytest.raises(ValueError, match="CHAINING_LINEAGE_CYCLE"):
        lineage(a, _resolver({a: (b,), b: (a,)}), analysis_id="a1")
    with pytest.raises(ValueError, match="CHAINING_LINEAGE_MISSING"):
        lineage(a, _resolver({a: (b,)}), analysis_id="a1")


def test_lineage_fails_closed_on_scope_or_commit_state() -> None:
    a = _ref("a")

    def foreign(_: StoredDataRef) -> LineageNode:
        return LineageNode(a, (), "a2", "ws1", "c1", True)

    def uncommitted(_: StoredDataRef) -> LineageNode:
        return LineageNode(a, (), "a1", "ws1", "c1", False)

    with pytest.raises(ValueError, match="CHAINING_LINEAGE_SCOPE_MISMATCH"):
        lineage(a, foreign, analysis_id="a1")
    with pytest.raises(ValueError, match="CHAINING_LINEAGE_NOT_COMMITTED"):
        lineage(a, uncommitted, analysis_id="a1")


def test_exclusion_rejects_ancestor_outside_pinned_universe() -> None:
    trigger, parent, child = _ref("a"), _ref("b"), _ref("c")
    resolve = _resolver({trigger: (), parent: (), child: (parent,)})

    with pytest.raises(ValueError, match="CHAINING_LINEAGE_INPUT_MISMATCH"):
        expected_lineage_exclusions(
            considered_refs=(trigger, child),
            trigger_ref=trigger,
            successful_match_pairs=(SuccessfulMatchPair(trigger, child),),
            resolve=resolve,
            analysis_id="a1",
        )


def test_successful_match_excludes_only_non_trigger_candidate_ancestors() -> None:
    trigger_parent, trigger, other_parent, other = map(_ref, ("a", "b", "c", "d"))
    resolve = _resolver(
        {
            trigger_parent: (),
            trigger: (trigger_parent,),
            other_parent: (),
            other: (other_parent,),
        }
    )

    exclusions = expected_lineage_exclusions(
        considered_refs=(trigger_parent, trigger, other_parent, other),
        trigger_ref=trigger,
        successful_match_pairs=(SuccessfulMatchPair(trigger, other),),
        resolve=resolve,
        analysis_id="a1",
    )

    assert {
        (item.excluded_primitive_ref, item.excluded_by_ref) for item in exclusions
    } == {(other_parent, other)}


def test_deepest_success_drops_a_provider_match_for_its_ancestor() -> None:
    trigger, root, child, deepest = map(_ref, ("a", "b", "c", "d"))
    resolve = _resolver({trigger: (), root: (), child: (root,), deepest: (child,)})
    deepest_pair = SuccessfulMatchPair(trigger, deepest)

    retained = retain_deepest_successful_matches(
        considered_refs=(trigger, root, child, deepest),
        trigger_ref=trigger,
        successful_match_pairs=(
            SuccessfulMatchPair(trigger, root),
            SuccessfulMatchPair(trigger, child),
            deepest_pair,
        ),
        resolve=resolve,
        analysis_id="a1",
    )

    assert retained == (deepest_pair,)
    exclusions = expected_lineage_exclusions(
        considered_refs=(trigger, root, child, deepest),
        trigger_ref=trigger,
        successful_match_pairs=(
            SuccessfulMatchPair(trigger, root),
            SuccessfulMatchPair(trigger, child),
            deepest_pair,
        ),
        resolve=resolve,
        analysis_id="a1",
    )
    assert {item.excluded_primitive_ref for item in exclusions} == {root, child}
