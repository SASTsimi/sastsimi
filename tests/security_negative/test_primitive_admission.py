from __future__ import annotations

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import WorkContext
from tests.contract.domain.fixtures import ref
from tests.integration.chaining.test_primitive_admission_runtime import _hold_fixture


def test_caller_supplied_admission_record_is_not_accepted_as_source_input() -> None:
    runtime, context, publisher, _, _ = _hold_fixture()
    supplied = StoredDataRef.model_validate(ref("primitive_admission_decision"))
    inputs = (*context.work.input_refs, supplied)
    inputs_hash = content_hash(inputs)
    forged = WorkExecutionState.model_validate(
        context.work.model_dump() | {"input_refs": inputs, "input_hash": inputs_hash}
    )
    attempt = context.attempt.model_copy(update={"input_hash": inputs_hash})

    with pytest.raises(ValueError, match="PRIMITIVE_EXACT_INPUT_REQUIRED"):
        runtime.admit(WorkContext(forged, attempt))

    assert publisher.calls == []


def test_tampered_exact_reference_fails_as_revision_mismatch() -> None:
    runtime, context, publisher, _, _ = _hold_fixture()
    verification = next(
        item
        for item in context.work.input_refs
        if item.data_kind == "verification_result"
    )
    assert isinstance(verification, StoredDataRef)
    tampered = verification.model_copy(update={"content_hash": "f" * 64})
    inputs = tuple(
        tampered if item == verification else item for item in context.work.input_refs
    )
    inputs_hash = content_hash(inputs)
    forged = WorkExecutionState.model_validate(
        context.work.model_dump() | {"input_refs": inputs, "input_hash": inputs_hash}
    )
    attempt = context.attempt.model_copy(update={"input_hash": inputs_hash})

    with pytest.raises(ValueError, match="RECORD_REVISION_MISMATCH"):
        runtime.admit(WorkContext(forged, attempt))

    assert publisher.calls == []
