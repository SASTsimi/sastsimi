"""Deterministic no-match chaining builder over an exact primitive snapshot."""

from typing import Any

from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.refs import StoredDataRef


def no_match_result(
    *, meta: dict[str, Any], primitive_ref: StoredDataRef
) -> ChainingResult:
    return ChainingResult.model_validate(
        {
            "meta": meta,
            "source_result_refs": (),
            "considered_primitive_refs": (primitive_ref,),
            "input_primitive_refs": (),
            "primitive_match_candidates": (),
            "chained_hypothesis_proposals": (),
            "excluded_lineage_refs": (),
            "no_match_reasons": (
                {
                    "upstream_result_ref": primitive_ref,
                    "downstream_input_ref": primitive_ref,
                    "checked_input_id": "fake-input",
                    "reason_code": "ENTITY_UNRELATED",
                    "detail": "No distinct downstream primitive exists",
                },
            ),
            "errors": (),
        }
    )
