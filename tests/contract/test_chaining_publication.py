from __future__ import annotations

from dataclasses import dataclass

import pytest

from sastsimi.chaining.publication import RuntimeChainingResultPublisher
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
from sastsimi.ports.dto import Record, WorkContext
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import ref, wire


@dataclass
class _Publisher:
    calls: list[tuple[object, ...]]

    def complete(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        role: str,
        outputs: tuple[Record, ...],
        *,
        action_input_refs: tuple[RecordRef, ...] | None = None,
        **_ignored: object,
    ) -> WorkExecutionState:
        self.calls.append((work, identity, role, outputs, action_input_refs))
        return work.model_copy(
            update={
                "status": "SUCCEEDED",
                "active_attempt_id": None,
                "output_refs": (),
            }
        )


def test_runtime_publisher_uses_chaining_authority_and_exact_save_inputs() -> None:
    meta = wire(
        RecordMeta,
        make("WorkExecutionState")["meta"]
        | {"attempt_id": None, "hypothesis_id": None},
    )
    input_hash = content_hash(())
    work = WorkExecutionState.model_construct(
        meta=meta,
        work_id="work-1",
        work_type="CHAINING",
        status="RUNNING",
        active_attempt_id="at-running",
        input_refs=(),
        input_hash=input_hash,
    )
    attempt = WorkAttempt.model_construct(
        meta=meta.model_copy(update={"attempt_id": "at-running"}),
        work_id="work-1",
        attempt_id="at-running",
        input_hash=input_hash,
        status="RUNNING",
    )
    context = WorkContext(work, attempt)
    result = wire(ChainingResult, make("ChainingResult")).model_copy(
        update={
            "meta": meta.model_copy(
                update={
                    "record_type": "chaining_result",
                    "attempt_id": "at-running",
                }
            )
        }
    )
    identity = wire(StoredDataRef, ref("identity"))
    action_inputs: tuple[RecordRef, ...] = (identity,)
    delegate = _Publisher([])
    publisher = RuntimeChainingResultPublisher(delegate, identity)

    publisher.publish(
        context=context,
        result=result,
        action_input_refs=action_inputs,
    )

    assert delegate.calls == [
        (context.work, identity, "CHAINING", (result,), action_inputs)
    ]

    forged = result.model_copy(
        update={"meta": result.meta.model_copy(update={"attempt_id": "late-attempt"})}
    )
    delegate.calls.clear()
    with pytest.raises(ValueError, match="CHAINING_RESULT_CONTEXT_MISMATCH"):
        publisher.publish(
            context=context,
            result=forged,
            action_input_refs=action_inputs,
        )
    assert delegate.calls == []
