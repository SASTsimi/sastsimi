from __future__ import annotations

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from tests.contract.domain.fixtures import ref
from tests.integration.chaining.test_primitive_admission_runtime import _hold_fixture


def test_caller_supplied_admission_record_is_not_accepted_as_source_input() -> None:
    runtime, work, publisher, _ = _hold_fixture()
    supplied = StoredDataRef.model_validate(ref("primitive_admission_decision"))
    forged = WorkExecutionState.model_validate(
        work.model_dump() | {"input_refs": (*work.input_refs, supplied)}
    )

    with pytest.raises(ValueError, match="PRIMITIVE_EXACT_INPUT_REQUIRED"):
        runtime.admit(forged)

    assert publisher.calls == []


def test_tampered_exact_reference_fails_as_revision_mismatch() -> None:
    runtime, work, publisher, _ = _hold_fixture()
    verification = next(
        item for item in work.input_refs if item.data_kind == "verification_result"
    )
    assert isinstance(verification, StoredDataRef)
    tampered = verification.model_copy(update={"content_hash": "f" * 64})
    forged = WorkExecutionState.model_validate(
        work.model_dump()
        | {
            "input_refs": tuple(
                tampered if item == verification else item for item in work.input_refs
            )
        }
    )

    with pytest.raises(ValueError, match="RECORD_REVISION_MISMATCH"):
        runtime.admit(forged)

    assert publisher.calls == []
