from __future__ import annotations

import inspect

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.verification.verdict_router import VerdictRouter
from tests.contract.domain.canonical_fixtures import make


class _Records:
    def __init__(self, result: VerificationResult) -> None:
        ref = reference(result)
        assert isinstance(ref, StoredDataRef)
        self.ref = ref
        self.result = result

    def get_exact(self, ref: RecordRef) -> object:
        assert ref == self.ref
        return self.result


def _result(verdict: str) -> tuple[_Records, StoredDataRef]:
    payload = make("VerificationResult")
    payload["verdict"] = verdict
    payload["initial_verdict"] = verdict
    if verdict == "FALSE":
        payload["falsification_results"][0]["outcome"] = "DISPROVED"
        payload["unresolved_conditions"] = []
    elif verdict == "HOLD":
        payload["falsification_results"][0]["outcome"] = "INCONCLUSIVE"
        payload["unresolved_conditions"] = ["Reachability remains unresolved"]
    else:
        # This bypasses the T11 dynamic requirement only to test router fail-closed.
        payload["verdict"] = "HOLD"
        payload["initial_verdict"] = "HOLD"
        payload["unresolved_conditions"] = ["T11 output is not available"]
        result = VerificationResult.model_validate_json(
            canonical_bytes(payload)
        ).model_copy(update={"verdict": "TRUE"})
        records = _Records(result)
        return records, records.ref
    result = VerificationResult.model_validate_json(canonical_bytes(payload))
    records = _Records(result)
    return records, records.ref


def test_false_has_no_downstream_work() -> None:
    records, result_ref = _result("FALSE")

    assert VerdictRouter(records).route(result_ref) == ()


def test_hold_only_proposes_primitive_update_registration() -> None:
    records, result_ref = _result("HOLD")

    (route,) = VerdictRouter(records).route(result_ref)

    assert route.work_type == "PRIMITIVE_UPDATE"
    assert route.input_refs == (result_ref,)


def test_t10_router_rejects_true_and_has_no_concrete_downstream_imports() -> None:
    records, result_ref = _result("TRUE")

    with pytest.raises(ValueError, match="T11_OUTPUT_REQUIRED"):
        VerdictRouter(records).route(result_ref)
    source = inspect.getsource(
        __import__("sastsimi.verification.verdict_router", fromlist=["*"])
    )
    assert "sastsimi.reporting" not in source
    assert "sastsimi.chaining" not in source
    assert "sastsimi.gates" not in source
