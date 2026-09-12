from __future__ import annotations

from sastsimi.chaining.matching import (
    PrimitiveEntry,
    directional_comparisons,
    owns_pair,
)
from sastsimi.contracts.chaining import Primitive
from sastsimi.contracts.refs import StoredDataRef, reference
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref, wire


def _draft(draft_id: str) -> dict[str, object]:
    return {
        "draft_id": draft_id,
        "entity_refs": [],
        "privilege_level": None,
        "evidence_refs": [ref("code", record=False)],
        "description": f"capability {draft_id}",
    }


def _primitive(
    record_id: str,
    hypothesis_id: str,
    *,
    inputs: tuple[str, ...] = (),
    result_id: str | None = None,
) -> tuple[StoredDataRef, Primitive]:
    value = make("Primitive") | {
        "meta": meta("primitive", hypothesis=hypothesis_id)
        | {
            "record_id": record_id,
            "logical_record_id": f"logical-{record_id}",
        },
        "primitive_id": f"primitive-{record_id}",
        "inputs": [_draft(item) for item in inputs],
        "result": _draft(result_id) if result_id is not None else None,
        "source_hypothesis_id": hypothesis_id,
        "source_verification_ref": ref("verification_result")
        | {"record_id": f"verification-{record_id}"},
        "technical_review_ref": (
            ref("technical_evidence_review") | {"record_id": f"technical-{record_id}"}
            if result_id is not None
            else None
        ),
        "admission_decision_ref": (
            ref("primitive_admission_decision")
            | {"record_id": f"admission-{record_id}"}
            if result_id is not None
            else None
        ),
        "evidence_refs": [ref("code", record=False)],
    }
    primitive = wire(Primitive, value)
    primitive_ref = reference(primitive)
    assert isinstance(primitive_ref, StoredDataRef)
    return primitive_ref, primitive


def test_directional_comparisons_cover_true_hold_and_true_true() -> None:
    trigger_ref, trigger = _primitive("p-z", "h1", result_id="provided")
    hold_ref, hold = _primitive("p-a", "h2", inputs=("needed",))
    chained_ref, chained = _primitive(
        "p-b", "h3", inputs=("needed-2",), result_id="provided-2"
    )
    entries = (
        PrimitiveEntry(trigger_ref, trigger),
        PrimitiveEntry(hold_ref, hold),
        PrimitiveEntry(chained_ref, chained),
    )

    comparisons = directional_comparisons(trigger_ref, entries)

    assert {
        (item.upstream_ref, item.downstream_ref, item.matched_input_id)
        for item in comparisons
    } == {
        (trigger_ref, hold_ref, "needed"),
        (trigger_ref, chained_ref, "needed-2"),
    }
    assert all(item.upstream_ref != item.downstream_ref for item in comparisons)


def test_result_bearing_trigger_can_be_downstream() -> None:
    trigger_ref, trigger = _primitive(
        "p-z", "h1", inputs=("needed",), result_id="provided"
    )
    other_ref, other = _primitive("p-a", "h2", result_id="other-result")

    comparisons = directional_comparisons(
        trigger_ref,
        (PrimitiveEntry(trigger_ref, trigger), PrimitiveEntry(other_ref, other)),
    )

    assert [
        (item.upstream_ref, item.downstream_ref, item.matched_input_id)
        for item in comparisons
    ] == [(other_ref, trigger_ref, "needed")]


def test_pair_owner_uses_only_pinned_pool_history() -> None:
    larger_ref, _ = _primitive("z-record", "h1", result_id="provided")
    smaller_ref, _ = _primitive("a-record", "h2", inputs=("needed",))

    assert owns_pair(
        larger_ref,
        smaller_ref,
        trigger_pool=(larger_ref, smaller_ref),
        other_trigger_pool=(smaller_ref, larger_ref),
    )
    assert not owns_pair(
        smaller_ref,
        larger_ref,
        trigger_pool=(smaller_ref, larger_ref),
        other_trigger_pool=(larger_ref, smaller_ref),
    )
    assert owns_pair(
        larger_ref,
        smaller_ref,
        trigger_pool=(larger_ref, smaller_ref),
        other_trigger_pool=(smaller_ref,),
    )


def test_pair_owner_rejects_incomplete_current_pool() -> None:
    trigger_ref, _ = _primitive("z-record", "h1", result_id="provided")
    other_ref, _ = _primitive("a-record", "h2", inputs=("needed",))

    try:
        owns_pair(
            trigger_ref,
            other_ref,
            trigger_pool=(trigger_ref,),
            other_trigger_pool=(other_ref,),
        )
    except ValueError as error:
        assert str(error) == "CHAINING_POOL_HISTORY_MISMATCH"
    else:
        raise AssertionError("incomplete pinned pool must fail closed")
