from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.contracts.chaining import PrimitiveIndexState
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.chaining import HoldPrimitiveAdmissionClosure
from sastsimi.verification.completion import (
    NonDynamicVerificationCompletionCoordinator,
)
from tests.integration.verification.test_dynamic_completion import (
    _persist_final_invocation,
    _RecordingRunner,
)
from tests.integration.verification.test_verification_service import (
    _Fixture,
    _meta,
)


def _process(
    fixture: _Fixture,
    *,
    generation: int = 1,
    result_ref: StoredDataRef | None = None,
) -> HypothesisProcessState:
    terminal = result_ref is not None
    return HypothesisProcessState.model_construct(
        meta=_meta("hypothesis_process_state", suffix="process", attempt=None),
        proposal_ref=fixture.proposal_ref,
        status="TERMINAL" if terminal else "VERIFYING",
        verification_assignment_ref=fixture._opaque_record(
            "verification_assignment", "owner"
        ),
        verification_generation=generation,
        verification_work_ref=None if terminal else reference(fixture.work),
        verification_result_ref=result_ref,
        started_at=fixture.work.meta.created_at,
        finished_at=fixture.work.meta.created_at if terminal else None,
        elapsed_ms=0,
    )


async def _ready_hold() -> tuple[_Fixture, StoredDataRef]:
    fixture = _Fixture()
    assert isinstance(fixture.work.meta, RecordMeta)
    fixture.work = fixture.work.model_copy(
        update={
            "parent_work_ref": None,
            "subject_type": "HYPOTHESIS",
            "subject_id": fixture.work.meta.hypothesis_id,
            "state_version": 1,
            "last_transition_ref": None,
            "last_transition_commit_ref": None,
            "input_hash": "a" * 64,
            "dedupe_key": "b" * 64,
            "trigger_primitive_ref": None,
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "waiting_for": (),
            "stop_reason": None,
            "started_at": fixture.work.meta.created_at,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )
    fixture.queue(
        fixture.assessment_payload("HOLD", unresolved=("Need authenticated caller",)),
        task_kind="ASSESS_INITIAL",
        context_refs=fixture.assessment_context(),
    )
    assessment = await fixture.service.assess_initial(
        generation=fixture.generation,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )
    assessment_ref = reference(assessment)
    assert isinstance(assessment_ref, StoredDataRef)
    fixture.queue(
        fixture.final_payload(
            "HOLD",
            outcome="INCONCLUSIVE",
            unresolved=("Need authenticated caller",),
            required=(fixture.primitive_content("Authenticated caller required"),),
        ),
        task_kind="FINAL_VERDICT",
        context_refs=(*fixture.assessment_context(), assessment_ref),
    )
    _persist_final_invocation(fixture)
    return fixture, assessment_ref


@pytest.mark.asyncio
async def test_non_dynamic_hold_commits_before_ready_primitive_handoff() -> None:
    fixture, assessment_ref = await _ready_hold()
    runner = _RecordingRunner()
    scope = fixture._opaque_record("budget_profile_binding", "scope")
    verification_identity = fixture._opaque_record("agent_identity", "verification")
    orchestration_identity = fixture._opaque_record("agent_identity", "orchestration")
    routed: list[dict[str, Any]] = []

    def current_records(_analysis_id: str, kind: str) -> tuple[object, ...]:
        if not runner.calls:
            return (_process(fixture),) if kind == "hypothesis_process_state" else ()
        result = runner.calls[-1]["outputs"][0]
        result_ref = reference(result)
        assert isinstance(result_ref, StoredDataRef)
        if kind == "hypothesis_process_state":
            return (_process(fixture, result_ref=result_ref),)
        if kind == "primitive_index_state":
            return (
                PrimitiveIndexState.model_construct(
                    meta=_meta("primitive_index_state", suffix="current", attempt=None),
                    current_verification_ref=result_ref,
                    primitive_refs=(),
                    updated_at=fixture.work.meta.created_at,
                ),
            )
        return ()

    handed_work: list[WorkExecutionState] = []

    def enqueue_hold(**kwargs: object) -> WorkExecutionState:
        assert runner.calls, "HOLD handoff must happen after the result commit"
        routed.append(cast(dict[str, Any], kwargs))
        closure = kwargs["closure"]
        assert isinstance(closure, HoldPrimitiveAdmissionClosure)
        ready = fixture.work.model_copy(
            update={
                "work_type": WorkType.PRIMITIVE_UPDATE,
                "status": WorkStatus.READY,
                "active_attempt_id": None,
                "input_refs": closure.input_refs(),
            }
        )
        handed_work.append(ready)
        return ready

    coordinator = NonDynamicVerificationCompletionCoordinator(
        verification=fixture.service,
        runner=runner,
        records=fixture.records,
        work_resolver=lambda _: fixture.work,
        current=cast(Any, SimpleNamespace(current_records=current_records)),
        budget_scope=lambda _analysis_id: scope,
        hold_handoff=cast(Any, SimpleNamespace(enqueue_hold=enqueue_hold)),
        verification_identity_ref=verification_identity,
        orchestration_identity_ref=orchestration_identity,
    )

    completed = await coordinator.complete_without_dynamic(
        generation=fixture.generation,
        assessment_ref=assessment_ref,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )

    result_ref = reference(completed.outcome.record)
    assert isinstance(result_ref, StoredDataRef)
    assert completed.completed_work.output_refs == (result_ref,)
    assert completed.routed_work is handed_work[0]
    assert len(runner.calls) == 1
    assert len(routed) == 1
    closure = routed[0]["closure"]
    assert isinstance(closure, HoldPrimitiveAdmissionClosure)
    assert closure.verification_ref == result_ref
    assert closure.hypothesis_process_ref.data_kind == "hypothesis_process_state"
    assert closure.expected_primitive_index_ref.data_kind == "primitive_index_state"
    assert routed[0]["scope"] == scope
    assert routed[0]["identity"] == orchestration_identity


@pytest.mark.asyncio
async def test_non_dynamic_stale_generation_fails_before_final_verdict_call() -> None:
    fixture, assessment_ref = await _ready_hold()
    runner = _RecordingRunner()
    route_calls: list[object] = []
    coordinator = NonDynamicVerificationCompletionCoordinator(
        verification=fixture.service,
        runner=runner,
        records=fixture.records,
        work_resolver=lambda _: fixture.work,
        current=cast(
            Any,
            SimpleNamespace(
                current_records=lambda _analysis, kind: (
                    (_process(fixture, generation=2),)
                    if kind == "hypothesis_process_state"
                    else ()
                )
            ),
        ),
        budget_scope=lambda _analysis_id: fixture._opaque_record(
            "budget_profile_binding", "scope"
        ),
        hold_handoff=cast(
            Any,
            SimpleNamespace(enqueue_hold=lambda **kwargs: route_calls.append(kwargs)),
        ),
        verification_identity_ref=fixture._opaque_record(
            "agent_identity", "verification"
        ),
        orchestration_identity_ref=fixture._opaque_record(
            "agent_identity", "orchestration"
        ),
    )

    with pytest.raises(ValueError, match="STALE_RESULT"):
        await coordinator.complete_without_dynamic(
            generation=fixture.generation,
            assessment_ref=assessment_ref,
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )

    assert runner.calls == []
    assert route_calls == []
    assert len(fixture.llm.outcomes) == 1
