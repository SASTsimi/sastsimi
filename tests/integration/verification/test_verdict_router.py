from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.bootstrap import build_t10_services
from sastsimi.contracts._domain import DomainRecord
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import DynamicReproductionRequest
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.refs import (
    RecordRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.verification import VerificationResult
from sastsimi.verification.verdict_router import VerdictRouter
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.success_fixture import bound, dynamic_success


class _Records:
    def __init__(self, *values: DomainRecord) -> None:
        self.values: dict[RecordRef, DomainRecord] = {}
        for index, value in enumerate(values):
            ref = (
                reference(value)
                if index == 0
                else StoredDataRef.model_validate(bound(value))
            )
            assert isinstance(ref, StoredDataRef)
            self.values[ref] = value
        result = values[0]
        assert isinstance(result, VerificationResult)
        self.result = result
        result_ref = reference(result)
        assert isinstance(result_ref, StoredDataRef)
        self.ref = result_ref

    def get_exact(self, ref: RecordRef) -> DomainRecord:
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
    dynamic_request_ref = records.result.dynamic_request_ref
    assert dynamic_request_ref is not None
    request = records.get_exact(dynamic_request_ref)
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


def test_production_t10_router_resolves_the_current_true_process() -> None:
    records, result_ref = _result("TRUE")
    request_ref = records.result.dynamic_request_ref
    assert request_ref is not None
    request = records.get_exact(request_ref)
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
    runtime = SimpleNamespace(
        unit_of_work=SimpleNamespace(records=records, artifacts=object()),
        llm_calls=object(),
        queries=SimpleNamespace(
            current_records=lambda _analysis, kind: (
                (process,) if kind == "hypothesis_process_state" else ()
            )
        ),
        budget_registry=SimpleNamespace(current_state=lambda _analysis: object()),
        work=SimpleNamespace(get=lambda _work_id: None),
        verification_registration=object(),
    )
    identity = records.ref.model_copy(update={"data_kind": "agent_identity"})

    services = build_t10_services(
        runtime=cast(Any, runtime),
        runner=cast(Any, object()),
        clock=cast(Any, object()),
        ids=cast(Any, object()),
        role_identity_refs={
            RequesterRole.VERIFICATION: identity,
            RequesterRole.ORCHESTRATION: identity,
        },
    )

    assert services.verdict_router.route(result_ref)[0].work_type == "CWE_LABEL"


def test_router_has_no_concrete_downstream_imports() -> None:
    source = inspect.getsource(
        __import__("sastsimi.verification.verdict_router", fromlist=["*"])
    )
    assert "sastsimi.reporting" not in source
    assert "sastsimi.chaining" not in source
    assert "sastsimi.gates" not in source
