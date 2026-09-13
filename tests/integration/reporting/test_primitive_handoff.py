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
from sastsimi.contracts.records import RecordMetadata
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.primitive_handoff import (
    PrimitiveHandoffRefs,
    PrimitiveUpdateHandoff,
)
from sastsimi.ports.chaining import HoldPrimitiveAdmissionClosure
from sastsimi.ports.dto import Record
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import ref, wire
from tests.contract.domain.success_fixture import dynamic_success


def _exact(value: Record) -> StoredDataRef:
    result = reference(value)
    assert isinstance(result, StoredDataRef)
    return result


class _Records:
    def __init__(self, values: tuple[Record, ...]) -> None:
        self.values: dict[RecordRef, Record] = {
            _exact(value): value for value in values
        }

    def get_exact(self, value_ref: RecordRef) -> object:
        return self.values[value_ref]


class _Current:
    def __init__(self, values: tuple[Record, ...]) -> None:
        self.values = values

    def current_records(self, analysis_id: str, kind: str) -> tuple[Record, ...]:
        return tuple(
            value
            for value in self.values
            if value.meta.record_type == kind
            and str(getattr(value.meta, "analysis_id", "")) == analysis_id
        )

    def published_records(self, _analysis_id: str) -> tuple[Record, ...]:
        return ()


@dataclass
class _Ready:
    calls: list[dict[str, object]]

    def enqueue(
        self,
        scope: BudgetScopeRef,
        metadata: RecordMetadata,
        work_type: str,
        subject_type: str,
        subject_id: str,
        identity: BudgetScopeRef,
        *,
        role: str = "ORCHESTRATION",
        generation: int = 1,
        inputs: tuple[RecordRef, ...] = (),
        parent: RecordRef | None = None,
        trigger_primitive_ref: RecordRef | None = None,
    ) -> WorkExecutionState:
        self.calls.append(
            {
                "scope": scope,
                "metadata": metadata,
                "work_type": work_type,
                "subject_type": subject_type,
                "subject_id": subject_id,
                "identity": identity,
                "role": role,
                "generation": generation,
                "inputs": inputs,
                "parent": parent,
                "trigger_primitive_ref": trigger_primitive_ref,
            }
        )
        return WorkExecutionState.model_construct(meta=metadata, work_type=work_type)

    def enqueue_registered(
        self,
        registered: WorkExecutionState,
        scope: BudgetScopeRef,
        identity: BudgetScopeRef,
        *,
        role: str = "ORCHESTRATION",
    ) -> WorkExecutionState:
        del scope, identity, role
        return registered


def _fixture(
    *, current_empty: bool = False
) -> tuple[PrimitiveUpdateHandoff, PrimitiveHandoffRefs, _Ready, RecordMetadata]:
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
    current_values: tuple[Record, ...] = (
        () if current_empty else (process, policy_state, index)
    )
    service = PrimitiveUpdateHandoff(
        records=_Records(values),
        current=_Current(current_values),
        ready_work=ready,
    )
    return service, refs, ready, process.meta


def test_accepted_true_enqueues_exact_primitive_update_as_ready_only() -> None:
    service, refs, ready, metadata = _fixture()
    identity = StoredDataRef.model_validate(ref("agent_identity"))
    returned = service.enqueue_true(
        refs=refs,
        scope=identity,
        metadata=metadata,
        identity=identity,
    )

    assert returned is not None
    assert len(ready.calls) == 1
    assert ready.calls[0]["work_type"] == "PRIMITIVE_UPDATE"
    assert ready.calls[0]["inputs"] == refs.work_inputs()
    assert "start" not in ready.calls[0]


def test_stale_primitive_index_stops_before_ready_handoff() -> None:
    service, refs, ready, metadata = _fixture(current_empty=True)
    identity = StoredDataRef.model_validate(ref("agent_identity"))

    with pytest.raises(ValueError, match="STALE_RESULT"):
        service.enqueue_true(
            refs=refs,
            scope=identity,
            metadata=metadata,
            identity=identity,
        )

    assert ready.calls == []


def _hold_fixture(
    *, mismatched_index: bool = False
) -> tuple[
    PrimitiveUpdateHandoff,
    HoldPrimitiveAdmissionClosure,
    _Ready,
    RecordMetadata,
]:
    primitive_draft = make("PrimitiveDraft") | {
        "evidence_refs": [ref("code_fragment", record=False)]
    }
    verification = wire(
        VerificationResult,
        make("VerificationResult")
        | {
            "required_primitive_candidates": [primitive_draft],
            "unresolved_conditions": ["A reachable authenticated session is needed."],
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
    index_verification_ref = (
        _exact(
            wire(
                VerificationResult,
                make("VerificationResult")
                | {
                    "meta": make("VerificationResult")["meta"]
                    | {
                        "record_id": "verification-result-r2",
                        "logical_record_id": "verification-result-l2",
                    }
                },
            )
        )
        if mismatched_index
        else verification_ref
    )
    index = wire(
        PrimitiveIndexState,
        make("PrimitiveIndexState")
        | {
            "current_verification_ref": index_verification_ref.model_dump(mode="json"),
            "primitive_refs": [],
        },
    )
    closure = HoldPrimitiveAdmissionClosure(
        verification_ref=verification_ref,
        hypothesis_process_ref=_exact(process),
        expected_primitive_index_ref=_exact(index),
    )
    ready = _Ready([])
    service = PrimitiveUpdateHandoff(
        records=_Records((process, verification, index)),
        current=_Current((process, index)),
        ready_work=ready,
    )
    return service, closure, ready, process.meta


def test_non_empty_hold_enqueues_the_exact_three_ref_closure_as_ready_only() -> None:
    service, closure, ready, metadata = _hold_fixture()
    identity = StoredDataRef.model_validate(ref("agent_identity"))

    returned = service.enqueue_hold(
        closure=closure,
        scope=identity,
        metadata=metadata,
        identity=identity,
    )

    assert returned is not None
    assert ready.calls[0]["inputs"] == closure.input_refs()
    assert ready.calls[0]["work_type"] == "PRIMITIVE_UPDATE"
    assert "start" not in ready.calls[0]


def test_hold_with_a_mismatched_expected_index_never_reaches_ready() -> None:
    service, closure, ready, metadata = _hold_fixture(mismatched_index=True)
    identity = StoredDataRef.model_validate(ref("agent_identity"))

    with pytest.raises(ValueError, match="STALE_RESULT"):
        service.enqueue_hold(
            closure=closure,
            scope=identity,
            metadata=metadata,
            identity=identity,
        )

    assert ready.calls == []
