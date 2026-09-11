from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pytest

from sastsimi.contracts.chaining import PrimitiveIndexState
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    PoCBundle,
)
from sastsimi.contracts.gates import CWELabel, TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.policy import PolicyCollectionResult, RunPolicyState
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.orchestration.primitive_handoff import (
    PrimitiveHandoffRefs,
    PrimitiveUpdateHandoff,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import ref, wire
from tests.contract.domain.success_fixture import dynamic_success


def _exact(value: object) -> StoredDataRef:
    result = reference(value)  # type: ignore[arg-type]
    assert isinstance(result, StoredDataRef)
    return result


class _Records:
    def __init__(self, values: tuple[object, ...]) -> None:
        self.values = {_exact(value): value for value in values}

    def get_exact(self, value_ref: RecordRef) -> object:
        return self.values[value_ref]


class _Current:
    def __init__(self, values: tuple[object, ...]) -> None:
        self.values = values

    def current_records(self, analysis_id: str, kind: str) -> tuple[object, ...]:
        return tuple(
            value
            for value in self.values
            if value.meta.record_type == kind  # type: ignore[attr-defined]
            and str(value.meta.analysis_id) == analysis_id  # type: ignore[attr-defined]
        )

    def published_records(self, _analysis_id: str) -> tuple[object, ...]:
        return ()


@dataclass
class _Ready:
    calls: list[dict[str, object]]

    def enqueue(self, *args: object, **kwargs: object) -> object:
        self.calls.append({"args": args, **kwargs})
        return object()


def _fixture() -> tuple[PrimitiveUpdateHandoff, PrimitiveHandoffRefs, _Ready, object]:
    dynamic = dynamic_success()
    request = cast(DynamicReproductionRequest, dynamic["request"])
    request_ref = _exact(request)
    original_poc = cast(PoCBundle, dynamic["poc"])
    poc = PoCBundle.model_validate(
        original_poc.model_dump() | {"request_ref": request_ref}
    )
    poc_ref = _exact(poc)
    original_result = cast(DynamicReproductionResult, dynamic["result"])
    result = DynamicReproductionResult.model_validate(
        original_result.model_dump()
        | {
            "request_ref": request_ref,
            "poc_ref": poc_ref,
        }
    )
    result_ref = _exact(result)
    verification = wire(
        VerificationResult,
        make("VerificationResult")
        | {
            "initial_verdict": "TRUE",
            "verdict": "TRUE",
            "verdict_rationale": "Validated reproduction supports the hypothesis",
            "dynamic_request_ref": request_ref.model_dump(mode="json"),
            "dynamic_result_ref": result_ref.model_dump(mode="json"),
            "poc_ref": poc_ref.model_dump(mode="json"),
            "unresolved_conditions": [],
        },
    )
    verification_ref = _exact(verification)
    process = wire(
        HypothesisProcessState,
        make("HypothesisProcessState")
        | {
            "status": "TERMINAL",
            "verification_assignment_ref": ref("verification_assignment"),
            "verification_generation": 1,
            "verification_work_ref": None,
            "verification_result_ref": verification_ref.model_dump(mode="json"),
            "finished_at": "2026-09-08T00:00:01Z",
        },
    )
    index = wire(
        PrimitiveIndexState,
        make("PrimitiveIndexState")
        | {
            "current_verification_ref": verification_ref.model_dump(mode="json"),
            "primitive_refs": [],
        },
    )
    cwe = wire(
        CWELabel,
        make("CWELabel", "cwe_label")
        | {
            "verification_result_ref": verification_ref.model_dump(mode="json"),
            "verification_generation": 1,
        },
    )
    cwe_ref = _exact(cwe)
    technical = wire(
        TechnicalEvidenceReview,
        make("TechnicalEvidenceReview")
        | {
            "verification_result_ref": verification_ref.model_dump(mode="json"),
            "cwe_label_ref": cwe_ref.model_dump(mode="json"),
            "status": "ACCEPT",
            "handoff_readiness": "READY",
        },
    )
    collection = wire(
        PolicyCollectionResult,
        make("PolicyCollectionResult")
        | {
            "status": "COLLECTION_FAILED",
            "official_source_refs": [],
            "parser_result_refs": [],
            "policy_record_ref": None,
            "gap_ids": [],
            "error_ids": ["policy-fetch-failed"],
        },
    )
    collection_ref = _exact(collection)
    policy_state = wire(
        RunPolicyState,
        make("RunPolicyState")
        | {
            "status": "FAILED",
            "preparation_source": "COLLECTED",
            "policy_cache_ref": None,
            "collection_result_ref": collection_ref.model_dump(mode="json"),
            "policy_record_ref": None,
            "freshness_criterion_ref": None,
            "freshness_checked_at": None,
            "freshness_evidence_refs": [],
            "freshness_valid_until": None,
        },
    )
    refs = PrimitiveHandoffRefs(
        process_ref=_exact(process),
        verification_ref=verification_ref,
        dynamic_request_ref=request_ref,
        dynamic_result_ref=result_ref,
        poc_ref=poc_ref,
        cwe_label_ref=cwe_ref,
        technical_review_ref=_exact(technical),
        run_policy_state_ref=_exact(policy_state),
        collection_ref=collection_ref,
        primitive_index_ref=_exact(index),
    )
    values = (
        process,
        verification,
        request,
        result,
        poc,
        cwe,
        technical,
        policy_state,
        collection,
        index,
    )
    ready = _Ready([])
    service = PrimitiveUpdateHandoff(
        records=_Records(values),
        current=_Current((process, policy_state, index)),  # type: ignore[arg-type]
        ready_work=ready,  # type: ignore[arg-type]
    )
    return service, refs, ready, process.meta


def test_accepted_true_enqueues_exact_primitive_update_as_ready_only() -> None:
    service, refs, ready, metadata = _fixture()
    identity = StoredDataRef.model_validate(ref("agent_identity"))
    returned = service.enqueue_true(
        refs=refs,
        scope=identity,
        metadata=metadata,  # type: ignore[arg-type]
        identity=identity,
    )

    assert returned is not None
    assert len(ready.calls) == 1
    assert ready.calls[0]["args"][2] == "PRIMITIVE_UPDATE"  # type: ignore[index]
    assert ready.calls[0]["inputs"] == refs.work_inputs()
    assert "start" not in ready.calls[0]


def test_stale_primitive_index_stops_before_ready_handoff() -> None:
    service, refs, ready, metadata = _fixture()
    service._current = _Current(())  # type: ignore[assignment]
    identity = StoredDataRef.model_validate(ref("agent_identity"))

    with pytest.raises(ValueError, match="STALE_RESULT"):
        service.enqueue_true(
            refs=refs,
            scope=identity,
            metadata=metadata,  # type: ignore[arg-type]
            identity=identity,
        )

    assert ready.calls == []
