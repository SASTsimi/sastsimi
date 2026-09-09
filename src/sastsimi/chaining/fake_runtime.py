"""Deterministic no-match chaining builder over an exact primitive snapshot."""

from typing import Any

from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.refs import StoredDataRef


def no_match_result(
    *,
    meta: dict[str, Any],
    primitive_ref: StoredDataRef | None = None,
    primitive_refs: tuple[StoredDataRef, ...] = (),
) -> ChainingResult:
    considered = primitive_refs or (
        (primitive_ref,) if primitive_ref is not None else ()
    )
    if not considered:
        raise ValueError("CHAINING_INPUT_SNAPSHOT_REQUIRED")
    return ChainingResult.model_validate(
        {
            "meta": meta,
            "source_result_refs": (),
            "considered_primitive_refs": considered,
            "input_primitive_refs": (),
            "primitive_match_candidates": (),
            "chained_hypothesis_proposals": (),
            "excluded_lineage_refs": (),
            "no_match_reasons": tuple(
                {
                    "upstream_result_ref": ref,
                    "downstream_input_ref": ref,
                    "checked_input_id": "fake-input",
                    "reason_code": "ENTITY_UNRELATED",
                    "detail": "No distinct downstream primitive exists",
                }
                for ref in considered
            ),
            "errors": (),
        }
    )
