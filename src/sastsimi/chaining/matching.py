"""Pure directional comparison and immutable pool-ownership rules."""

from __future__ import annotations

from dataclasses import dataclass

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import Primitive
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference, require_record_ref


@dataclass(frozen=True)
class PrimitiveEntry:
    """One exact Primitive revision in the work's pinned universe."""

    ref: StoredDataRef
    primitive: Primitive


@dataclass(frozen=True)
class DirectionalComparison:
    """One prompt-local result-to-input question; it is not a domain record."""

    comparison_key: str
    upstream_ref: StoredDataRef
    downstream_ref: StoredDataRef
    matched_input_id: str


def directional_comparisons(
    trigger_ref: StoredDataRef,
    entries: tuple[PrimitiveEntry, ...],
) -> tuple[DirectionalComparison, ...]:
    """Enumerate every eligible direction involving the trigger, never self-pairs."""

    by_key = {_key(entry.ref): entry for entry in entries}
    if len(by_key) != len(entries) or _key(trigger_ref) not in by_key:
        raise ValueError("CHAINING_PINNED_UNIVERSE_MISMATCH")
    trigger = by_key[_key(trigger_ref)]
    if not isinstance(trigger.primitive.meta, RecordMeta):
        raise ValueError("CHAINING_PINNED_UNIVERSE_MISMATCH")
    for entry in entries:
        meta = entry.primitive.meta
        if (
            not isinstance(meta, RecordMeta)
            or reference(entry.primitive) != entry.ref
            or meta.analysis_id != trigger.primitive.meta.analysis_id
            or meta.workspace_id != trigger.primitive.meta.workspace_id
            or meta.commit_id != trigger.primitive.meta.commit_id
            or entry.primitive.workspace_id != meta.workspace_id
            or entry.primitive.commit_id != meta.commit_id
        ):
            raise ValueError("CHAINING_PINNED_UNIVERSE_MISMATCH")
    comparisons: list[DirectionalComparison] = []
    ordinal = 0
    for other in entries:
        if other.ref == trigger_ref:
            continue
        for upstream, downstream in ((trigger, other), (other, trigger)):
            if upstream.primitive.result is None:
                continue
            for required in downstream.primitive.inputs:
                ordinal += 1
                comparisons.append(
                    DirectionalComparison(
                        comparison_key=f"comparison-{ordinal}",
                        upstream_ref=upstream.ref,
                        downstream_ref=downstream.ref,
                        matched_input_id=str(required.draft_id),
                    )
                )
    return tuple(comparisons)


def owns_pair(
    trigger_ref: StoredDataRef,
    other_ref: StoredDataRef,
    *,
    trigger_pool: tuple[StoredDataRef, ...],
    other_trigger_pool: tuple[StoredDataRef, ...],
) -> bool:
    """Choose one owner using only the two immutable registration-time pools."""

    if trigger_ref == other_ref:
        raise ValueError("CHAINING_SELF_PAIR_FORBIDDEN")
    require_record_ref(trigger_ref, "primitive")
    require_record_ref(other_ref, "primitive")
    if (
        len({_key(ref) for ref in trigger_pool}) != len(trigger_pool)
        or len({_key(ref) for ref in other_trigger_pool}) != len(other_trigger_pool)
        or trigger_ref not in trigger_pool
        or other_ref not in trigger_pool
        or other_ref not in other_trigger_pool
    ):
        raise ValueError("CHAINING_POOL_HISTORY_MISMATCH")
    if trigger_ref not in other_trigger_pool:
        return True
    assert trigger_ref.record_id is not None and other_ref.record_id is not None
    return str(trigger_ref.record_id) > str(other_ref.record_id)


def _key(ref: StoredDataRef) -> bytes:
    return canonical_bytes(ref)


__all__ = [
    "DirectionalComparison",
    "PrimitiveEntry",
    "directional_comparisons",
    "owns_pair",
]
