"""Canonical non-Agent records must survive the persistent record boundary."""

import json

import pytest

from sastsimi.contracts.chaining import PrimitiveIndexState
from sastsimi.contracts.dynamic import DynamicReproductionState
from sastsimi.contracts.hypothesis import VulnerabilityHypothesis
from sastsimi.contracts.reporting import FindingIndexState
from sastsimi.contracts.verification import PlaybookApplication
from sastsimi.storage.codec import decode, encode
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta


@pytest.mark.parametrize(
    "model",
    [
        VulnerabilityHypothesis,
        PlaybookApplication,
        PrimitiveIndexState,
        FindingIndexState,
    ],
)
def test_canonical_workflow_state_round_trips_without_agent_result_owner(
    model: type[
        VulnerabilityHypothesis
        | PlaybookApplication
        | PrimitiveIndexState
        | FindingIndexState
    ],
) -> None:
    data = make(model.__name__)
    if model is VulnerabilityHypothesis:
        proposal = make("HypothesisProposal")
        data.update(
            {
                key: proposal[key]
                for key in (
                    "target_locations",
                    "falsification_questions",
                    "validation_checks",
                )
            }
        )
    if model is PlaybookApplication:
        data.update(selection="COMMON", selected_type=None, selection_reason="NO_TYPE")
    if model is FindingIndexState:
        data.update(
            meta=meta("finding_index_state", hypothesis="h1", attempt=None),
            status="EMPTY",
            finding_ref=None,
            stale_finding_ref=None,
            normalization_work_ref=None,
            last_transition_commit_ref=None,
        )
    record = model.model_validate_json(json.dumps(data))
    assert decode(record.meta.record_type, encode(record)) == record


def test_not_requested_dynamic_state_has_no_execution_or_elapsed_time() -> None:
    data = dict(
        meta=meta("dynamic_reproduction_state", hypothesis="h1", attempt=None),
        verification_generation=1,
        dynamic_work_ref=None,
        status="NOT_REQUESTED",
        request_ref=None,
        dynamic_result_ref=None,
        started_at=None,
        finished_at=None,
        elapsed_ms=0,
    )
    record = DynamicReproductionState.model_validate_json(json.dumps(data))
    assert decode(record.meta.record_type, encode(record)) == record
    with pytest.raises(ValueError, match="DYNAMIC_STATE"):
        DynamicReproductionState.model_validate_json(
            json.dumps(data | {"elapsed_ms": 1})
        )
