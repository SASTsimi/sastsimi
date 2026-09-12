from __future__ import annotations

import json
from dataclasses import dataclass
from typing import cast

import pytest

from sastsimi.contracts.chaining import (
    Primitive,
    PrimitiveAdmissionDecision,
    PrimitiveIndexState,
)
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    PoCBundle,
)
from sastsimi.contracts.gates import CWELabel, TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.ids import OpaqueId
from sastsimi.contracts.policy import PolicyCollectionResult, RunPolicyState
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState, WorkStatus
from sastsimi.ports.dto import Record
from sastsimi.reporting.primitive_admission import (
    PrimitiveAdmissionRuntime,
    decide_primitive_admission,
)
from sastsimi.storage.primitive_projection import validate_resolved_primitive_outputs
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref, wire
from tests.contract.domain.success_fixture import dynamic_success
from tests.unit.contracts.test_core_models import work


def _exact(value: Record) -> StoredDataRef:
    result = reference(value)
    assert isinstance(result, StoredDataRef)
    return result


class _Clock:
    def now(self):  # type: ignore[no-untyped-def]
        return wire(VerificationResult, make("VerificationResult")).meta.created_at

    def monotonic_ms(self) -> int:
        return 0


class _Ids:
    def __init__(self) -> None:
        self.index = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.index += 1
        return kind(f"admission-{kind.__name__.lower()}-{self.index}")


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


@dataclass
class _Publisher:
    calls: list[tuple[WorkExecutionState, tuple[Record, ...], tuple[RecordRef, ...]]]

    def complete(
        self,
        work_value: WorkExecutionState,
        identity: BudgetScopeRef,
        role: str,
        outputs: tuple[Record, ...],
        *,
        status: str = "SUCCEEDED",
        cause: str = "COMPLETED",
        error_ids: tuple[str, ...] = (),
        gap_ids: tuple[str, ...] = (),
        action_input_refs: tuple[RecordRef, ...] | None = None,
    ) -> WorkExecutionState:
        del identity, role, error_ids, gap_ids
        self.calls.append((work_value, outputs, action_input_refs or ()))
        return work_value.model_copy(
            update={
                "status": WorkStatus(status),
                "active_attempt_id": None,
                "last_transition_commit_ref": ref("transition_commit"),
                "finished_at": work_value.meta.created_at,
                "stop_reason": cause,
            }
        )


def _running_work(input_refs: tuple[StoredDataRef, ...]) -> WorkExecutionState:
    return WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=meta("work_execution_state", hypothesis="h1", attempt=None),
                work_id="primitive-update-work",
                work_type="PRIMITIVE_UPDATE",
                subject_type="HYPOTHESIS",
                subject_id="h1",
                status="RUNNING",
                state_version=2,
                last_transition_ref=ref("state_transition"),
                active_attempt_id="admission-attempt",
                started_at="2026-09-08T00:00:00Z",
                input_refs=[item.model_dump(mode="json") for item in input_refs],
            )
        )
    )


def _terminal(
    verification: VerificationResult,
) -> tuple[HypothesisProcessState, PrimitiveIndexState]:
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
    return process, index


def _hold_fixture(
    *, verdict: str = "HOLD", with_required_input: bool = True
) -> tuple[
    PrimitiveAdmissionRuntime,
    WorkExecutionState,
    _Publisher,
    VerificationResult,
]:
    draft = make("PrimitiveDraft")
    draft["evidence_refs"] = [ref("hold-evidence", record=False)]
    verification = wire(
        VerificationResult,
        make("VerificationResult")
        | {
            "initial_verdict": verdict,
            "verdict": verdict,
            "falsification_results": [
                {
                    "question_id": "q1",
                    "outcome": "DISPROVED" if verdict == "FALSE" else "INCONCLUSIVE",
                    "evidence_refs": [ref("hold-evidence", record=False)],
                    "rationale": "The exact hypothesis condition was checked",
                }
            ],
            "required_primitive_candidates": [draft]
            if verdict == "HOLD" and with_required_input
            else [],
            "unresolved_conditions": ["Authentication state is not known"]
            if verdict == "HOLD"
            else [],
        },
    )
    process, index = _terminal(verification)
    values: tuple[Record, ...] = (verification, process, index)
    input_refs = tuple(_exact(value) for value in values)
    publisher = _Publisher([])
    runtime = PrimitiveAdmissionRuntime(
        records=_Records(values),
        current=_Current((process, index)),
        publisher=publisher,
        identity_ref=input_refs[0],
        clock=_Clock(),
        ids=_Ids(),
    )
    return runtime, _running_work(input_refs), publisher, verification


def _true_fixture(
    *, technical_status: str = "ACCEPT", collection_available: bool = True
) -> tuple[
    PrimitiveAdmissionRuntime,
    WorkExecutionState,
    _Publisher,
    VerificationResult,
    tuple[Record, ...],
]:
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
        original_result.model_dump() | {"request_ref": request_ref, "poc_ref": poc_ref}
    )
    result_ref = _exact(result)
    first = make("PrimitiveDraft") | {
        "draft_id": "provided-1",
        "description": "The confirmed result provides user privileges",
        "evidence_refs": [ref("provided-1-evidence", record=False)],
    }
    second = make("PrimitiveDraft") | {
        "draft_id": "provided-2",
        "description": "The confirmed result provides an authenticated session",
        "evidence_refs": [ref("provided-2-evidence", record=False)],
    }
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
            "provided_primitive_candidates": [first, second],
            "unresolved_conditions": [],
        },
    )
    verification_ref = _exact(verification)
    process, index = _terminal(verification)
    cwe = wire(
        CWELabel,
        make("CWELabel", "cwe_label")
        | {
            "verification_result_ref": verification_ref.model_dump(mode="json"),
            "verification_generation": 1,
        },
    )
    technical = wire(
        TechnicalEvidenceReview,
        make("TechnicalEvidenceReview")
        | {
            "verification_result_ref": verification_ref.model_dump(mode="json"),
            "cwe_label_ref": _exact(cwe).model_dump(mode="json"),
            "status": technical_status,
            "handoff_readiness": "READY"
            if technical_status == "ACCEPT"
            else "NOT_READY",
            "revision_requests": ["Recheck evidence"]
            if technical_status == "REVISE"
            else [],
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
            "status": "FAILED" if collection_available else "PREPARING",
            "preparation_source": "COLLECTED" if collection_available else None,
            "policy_cache_ref": None,
            "collection_result_ref": collection_ref.model_dump(mode="json")
            if collection_available
            else None,
            "policy_record_ref": None,
            "freshness_criterion_ref": None,
            "freshness_checked_at": None,
            "freshness_evidence_refs": [],
            "freshness_valid_until": None,
        },
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
        *((collection,) if collection_available else ()),
        index,
    )
    input_refs = tuple(_exact(value) for value in values)
    publisher = _Publisher([])
    runtime = PrimitiveAdmissionRuntime(
        records=_Records(values),
        current=_Current((process, policy_state, index)),
        publisher=publisher,
        identity_ref=input_refs[0],
        clock=_Clock(),
        ids=_Ids(),
    )
    return runtime, _running_work(input_refs), publisher, verification, values


def test_non_empty_hold_commits_one_inputs_only_primitive() -> None:
    runtime, work_value, publisher, verification = _hold_fixture()

    completed = runtime.admit(work_value)

    assert completed.status == "SUCCEEDED"
    assert len(publisher.calls[0][1]) == 1
    primitive = publisher.calls[0][1][0]
    assert isinstance(primitive, Primitive)
    assert primitive.inputs == verification.required_primitive_candidates
    assert primitive.result is None
    assert primitive.technical_review_ref is None
    assert primitive.admission_decision_ref is None
    assert publisher.calls[0][1] == (primitive,)
    assert publisher.calls[0][2] == work_value.input_refs


def test_storage_boundary_accepts_the_exact_inputs_only_hold_batch() -> None:
    runtime, work_value, publisher, verification = _hold_fixture()
    runtime.admit(work_value)
    primitive = publisher.calls[0][1][0]
    assert isinstance(primitive, Primitive)
    process, index = _terminal(verification)

    primitives = validate_resolved_primitive_outputs(
        work=work_value,
        outputs=(primitive,),
        verification=verification,
        process=process,
        index=index,
    )

    assert primitives == (primitive,)


def test_storage_boundary_rejects_a_hold_with_an_unpinned_index() -> None:
    runtime, work_value, publisher, verification = _hold_fixture()
    runtime.admit(work_value)
    primitive = publisher.calls[0][1][0]
    assert isinstance(primitive, Primitive)
    process, index = _terminal(verification)
    unpinned = PrimitiveIndexState.model_validate(
        index.model_dump()
        | {
            "meta": index.meta.model_copy(
                update={"record_id": "different-index-record"}
            )
        }
    )

    with pytest.raises(ValueError, match="PRIMITIVE_EXACT_INPUT_REQUIRED"):
        validate_resolved_primitive_outputs(
            work=work_value,
            outputs=(primitive,),
            verification=verification,
            process=process,
            index=unpinned,
        )


@pytest.mark.parametrize(
    ("verdict", "with_required_input"),
    [("FALSE", False), ("HOLD", False)],
)
def test_unexpected_work_for_false_or_empty_hold_fails_closed_for_worker_owner(
    verdict: str, with_required_input: bool
) -> None:
    runtime, work_value, publisher, _ = _hold_fixture(
        verdict=verdict, with_required_input=with_required_input
    )

    with pytest.raises(ValueError, match="PRIMITIVE_UPDATE_NOT_REQUIRED"):
        runtime.admit(work_value)

    assert publisher.calls == []


def test_workflow_runner_cannot_complete_a_primitive_update_with_empty_outputs() -> (
    None
):
    from sastsimi.runtime.workflow_runner import WorkflowRunner

    _, work_value, _, _ = _hold_fixture(verdict="FALSE", with_required_input=False)
    runner = object.__new__(WorkflowRunner)

    with pytest.raises(ValueError, match="requires its exact output"):
        runner.complete(
            work_value,
            cast(BudgetScopeRef, work_value.input_refs[0]),
            "PRIMITIVE_ADMISSION_RUNTIME",
            (),
        )


def test_allowed_true_commits_one_decision_and_one_primitive_per_output() -> None:
    runtime, work_value, publisher, verification, values = _true_fixture()

    completed = runtime.admit(work_value)

    assert completed.status == "SUCCEEDED"
    decision, *primitives = publisher.calls[0][1]
    assert isinstance(decision, PrimitiveAdmissionDecision)
    assert all(isinstance(item, Primitive) for item in primitives)
    primitive_values = cast(tuple[Primitive, ...], tuple(primitives))
    assert decision.decision == "ALLOW"
    assert decision.testing_restriction_compliance == "NOT_EVALUATED"
    assert tuple(item.result for item in primitive_values) == (
        *verification.provided_primitive_candidates,
    )
    assert len(primitive_values) == 2

    by_type = {type(item): item for item in values}
    process = cast(HypothesisProcessState, by_type[HypothesisProcessState])
    index = cast(PrimitiveIndexState, by_type[PrimitiveIndexState])
    accepted = validate_resolved_primitive_outputs(
        work=work_value,
        outputs=publisher.calls[0][1],
        verification=verification,
        process=process,
        index=index,
        request=cast(DynamicReproductionRequest, by_type[DynamicReproductionRequest]),
        dynamic=cast(DynamicReproductionResult, by_type[DynamicReproductionResult]),
        poc=cast(PoCBundle, by_type[PoCBundle]),
        cwe=cast(CWELabel, by_type[CWELabel]),
        technical=cast(TechnicalEvidenceReview, by_type[TechnicalEvidenceReview]),
        admission=decision,
        collection=cast(PolicyCollectionResult, by_type[PolicyCollectionResult]),
        state=cast(RunPolicyState, by_type[RunPolicyState]),
    )
    assert accepted == primitive_values


@pytest.mark.parametrize("technical_status", ["REVISE", "REJECT"])
def test_non_accepted_technical_gate_publishes_nothing(
    technical_status: str,
) -> None:
    runtime, work_value, publisher, _, _ = _true_fixture(
        technical_status=technical_status
    )

    with pytest.raises(ValueError, match="TECHNICAL_GATE_NOT_ACCEPTED"):
        runtime.admit(work_value)

    assert publisher.calls == []


def test_unexpected_true_work_without_a_collection_result_fails_closed() -> None:
    runtime, work_value, publisher, _, _ = _true_fixture(collection_available=False)

    with pytest.raises(ValueError, match="PRIMITIVE_UPDATE_NOT_REQUIRED"):
        runtime.admit(work_value)

    assert publisher.calls == []


@pytest.mark.parametrize(
    ("collection_status", "testing", "expected"),
    [
        ("FOUND", "PASS", ("ALLOW", "TESTING_RESTRICTION_PASSED")),
        ("FOUND", "UNCERTAIN", ("ALLOW", "TESTING_RESTRICTION_UNCERTAIN")),
        ("FOUND", "FAIL", ("DENY", "TESTING_RESTRICTION_VIOLATION")),
        ("COLLECTION_FAILED", None, ("ALLOW", "POLICY_COLLECTION_FAILED")),
    ],
)
def test_only_confirmed_forbidden_testing_denies_primitive_admission(
    collection_status: str,
    testing: str | None,
    expected: tuple[str, str],
) -> None:
    decision = decide_primitive_admission(
        collection_status=collection_status,
        testing_restriction_compliance=testing,
    )

    assert decision == expected
