from __future__ import annotations

import inspect

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import DynamicReproductionRequest
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.verification.verdict_router import VerdictRouter
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.success_fixture import bound, dynamic_success


class _Records:
    def __init__(self, *values: object) -> None:
        self.values: dict[RecordRef, object] = {}
        for index, value in enumerate(values):
            ref = (
                reference(value)  # type: ignore[arg-type]
                if index == 0
                else StoredDataRef.model_validate(bound(value))  # type: ignore[arg-type]
            )
            assert isinstance(ref, StoredDataRef)
            self.values[ref] = value
        result = values[0]
        assert isinstance(result, VerificationResult)
        self.result = result
        self.ref = reference(result)
        assert isinstance(self.ref, StoredDataRef)

    def get_exact(self, ref: RecordRef) -> object:
        return self.values[ref]


def _result(
    verdict: str, *, with_required_primitive: bool = True
) -> tuple[_Records, StoredDataRef]:
    payload = make("VerificationResult")
    payload["verdict"] = verdict
    payload["initial_verdict"] = verdict
    if verdict == "FALSE":
        payload["falsification_results"][0]["outcome"] = "DISPROVED"
        payload["unresolved_conditions"] = []
    elif verdict == "HOLD":
        payload["falsification_results"][0]["outcome"] = "INCONCLUSIVE"
        payload["unresolved_conditions"] = ["Reachability remains unresolved"]
        payload["required_primitive_candidates"] = (
            [
                make("PrimitiveDraft")
                | {"evidence_refs": payload["validation_results"][0]["evidence_refs"]}
            ]
            if with_required_primitive
            else []
        )
    else:
        chain = dynamic_success()
        payload.update(
            dynamic_request_ref=bound(chain["request"]),
            dynamic_result_ref=bound(chain["result"]),
            poc_ref=bound(chain["poc"]),
        )
        result = VerificationResult.model_validate_json(canonical_bytes(payload))
        records = _Records(result, chain["request"], chain["result"], chain["poc"])
        return records, records.ref
    result = VerificationResult.model_validate_json(canonical_bytes(payload))
    records = _Records(result)
    return records, records.ref


def test_false_has_no_downstream_work() -> None:
    records, result_ref = _result("FALSE")

    assert VerdictRouter(records).route(result_ref) == ()


def test_hold_only_proposes_primitive_update_registration() -> None:
    records, result_ref = _result("HOLD")

    (route,) = VerdictRouter(records, current_process=lambda _: None).route(result_ref)

    assert route.work_type == "PRIMITIVE_UPDATE"
    assert route.input_refs == (result_ref,)


def test_hold_without_required_primitive_has_no_downstream_work() -> None:
    records, result_ref = _result("HOLD", with_required_primitive=False)

    assert VerdictRouter(records).route(result_ref) == ()


def test_committed_true_only_proposes_cwe_label_registration() -> None:
    records, result_ref = _result("TRUE")
    request = records.get_exact(records.result.dynamic_request_ref)
    assert isinstance(request, DynamicReproductionRequest)
    process = HypothesisProcessState.model_construct(
        meta=records.result.meta.model_copy(
            update={"record_type": "hypothesis_process_state", "attempt_id": None}
        ),
        proposal_ref=records.result.playbook_application_ref,
        status="TERMINAL",
        verification_assignment_ref=request.verification_assignment_ref,
        verification_generation=request.verification_generation,
        verification_work_ref=None,
        verification_result_ref=result_ref,
        started_at=records.result.meta.created_at,
        finished_at=records.result.meta.created_at,
        elapsed_ms=0,
    )

    (route,) = VerdictRouter(records, current_process=lambda _: process).route(
        result_ref
    )

    assert route.work_type == "CWE_LABEL"
    assert route.input_refs == (result_ref,)


def test_true_with_uncommitted_process_pointer_is_rejected() -> None:
    records, result_ref = _result("TRUE")

    with pytest.raises(ValueError, match="STALE_RESULT"):
        VerdictRouter(records, current_process=lambda _: None).route(result_ref)


def test_router_has_no_concrete_downstream_imports() -> None:
    source = inspect.getsource(
        __import__("sastsimi.verification.verdict_router", fromlist=["*"])
    )
    assert "sastsimi.reporting" not in source
    assert "sastsimi.chaining" not in source
    assert "sastsimi.gates" not in source
