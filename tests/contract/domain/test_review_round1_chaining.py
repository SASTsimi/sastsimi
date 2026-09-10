from typing import Any

import pytest

from sastsimi.contracts.chaining import (
    ChainingResult,
    Primitive,
    validate_chaining_closure,
)
from sastsimi.contracts.refs import StoredDataRef

from .canonical_fixtures import make
from .fixtures import location, meta, ref, wire
from .success_fixture import bound


@pytest.mark.parametrize(
    "patch",
    [
        {"assumptions": []},
        {"target_locations": [location() | {"file_path": "unrelated.py"}]},
        {"suspected_path": [location() | {"start_line": 10, "end_line": 11}]},
    ],
)
def test_r15_chained_proposal_derives_from_parent_capabilities(
    patch: dict[str, Any],
) -> None:
    symbol = dict(
        symbol_id="s1",
        symbol_kind="CALLABLE",
        native_kind=None,
        name="handler",
        location=location(),
    )
    draft = dict(
        draft_id="provided",
        entity_refs=[symbol],
        privilege_level=None,
        evidence_refs=[ref("code", record=False)],
        description="capability",
    )
    upstream = wire(
        Primitive,
        make("Primitive")
        | dict(
            result=draft,
            inputs=[],
            technical_review_ref=ref("technical_evidence_review"),
            admission_decision_ref=ref("primitive_admission_decision"),
        ),
    )
    downstream = wire(
        Primitive,
        make("Primitive")
        | dict(
            meta=meta("primitive", hypothesis="h2") | {"record_id": "down"},
            source_hypothesis_id="h2",
            source_verification_ref=ref("verification_result") | {"record_id": "v2"},
            inputs=[
                draft | dict(draft_id="matched"),
                draft | dict(draft_id="remaining", description="remaining condition"),
            ],
            result=None,
        ),
    )
    parent_refs = [bound(upstream), bound(downstream)]
    proposal = make("HypothesisProposal") | dict(
        origin="CHAINING",
        source_primitive_match_id="match1",
        parent_hypothesis_ids=["h1", "h2"],
        target_entities=[symbol],
        target_locations=[location()],
        suspected_path=[location()],
        assumptions=["remaining condition"],
        observed_facts=[],
    )
    value = make("ChainingResult") | dict(
        considered_primitive_refs=parent_refs,
        input_primitive_refs=parent_refs,
        source_result_refs=[
            upstream.source_verification_ref.model_dump(mode="json"),
            downstream.source_verification_ref.model_dump(mode="json"),
            ref("technical_evidence_review"),
        ],
        primitive_match_candidates=[
            dict(
                primitive_match_id="match1",
                upstream_result_ref=parent_refs[0],
                downstream_input_ref=parent_refs[1],
                matched_input_id="matched",
                parent_hypothesis_ids=["h1", "h2"],
                parent_verification_refs=[
                    upstream.source_verification_ref.model_dump(mode="json"),
                    downstream.source_verification_ref.model_dump(mode="json"),
                ],
                workspace_id="ws1",
                commit_id="c1",
                evidence_refs=[ref("code", record=False)],
                candidate_state="UNVALIDATED",
            )
        ],
        chained_hypothesis_proposals=[proposal],
    )
    references = tuple(wire(StoredDataRef, item) for item in parent_refs)
    validate_chaining_closure(
        wire(ChainingResult, value), (upstream, downstream), references, ()
    )
    with pytest.raises(ValueError, match="CHAINING_(DERIVATION|ASSUMPTION)_MISMATCH"):
        validate_chaining_closure(
            wire(
                ChainingResult,
                value | dict(chained_hypothesis_proposals=[proposal | patch]),
            ),
            (upstream, downstream),
            references,
            (),
        )
