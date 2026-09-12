"""Focused generation and failure safety tests for the dynamic return hook."""

import json
from types import SimpleNamespace

import pytest

from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionState,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.orchestration.dynamic_verification_handoff import (
    DynamicParentResumeService,
)
from tests.contract.domain.canonical_fixtures import make
from tests.unit.orchestration.test_production_llm_work_handlers import _context


class _Records:
    def __init__(self, records: tuple[object, ...]) -> None:
        self.values = {reference(item): item for item in records}  # type: ignore[arg-type]

    def get_exact(self, ref: object) -> object:
        return self.values[ref]


class _Queries:
    def __init__(self, state: DynamicReproductionState) -> None:
        self.state = state

    def current_records(self, analysis_id: str, kind: str) -> tuple[object, ...]:
        if analysis_id == "a1" and kind == DynamicReproductionState.KIND:
            return (self.state,)
        return ()


class _WorkStore:
    def __init__(self, parent: WorkExecutionState, child: WorkExecutionState) -> None:
        self.parent = parent
        self.child = child

    def get(self, work_id: str) -> WorkExecutionState:
        return self.child if work_id == str(self.child.work_id) else self.parent

    def make_ready(self, transition: object) -> WorkExecutionState:
        self.parent = self.parent.model_copy(
            update={
                "status": WorkStatus.READY,
                "state_version": self.parent.state_version + 1,
                "waiting_for": (),
                "stop_reason": None,
            }
        )
        return self.parent


class _Runner:
    def __init__(self, work: _WorkStore) -> None:
        self.runtime = SimpleNamespace(work=work)
        self.actions = 0

    def action(self, *_args: object, **_kwargs: object) -> object:
        self.actions += 1
        return object()

    def authorize(self, *_args: object, **_kwargs: object) -> StoredDataRef:
        return StoredDataRef.model_validate(make("StoredDataRef"))

    def transition(self, *_args: object, **_kwargs: object) -> object:
        return object()


def _chain(*, current_parent_generation: int = 1) -> tuple[object, ...]:
    request = DynamicReproductionRequest.model_validate_json(
        json.dumps(make("DynamicReproductionRequest"))
    )
    request_ref = reference(request)
    assert isinstance(request_ref, StoredDataRef)
    result = DynamicReproductionResult.model_validate_json(
        json.dumps(
            make("DynamicReproductionResult")
            | {"request_ref": request_ref.model_dump(mode="json")}
        )
    ).model_copy(update={"status": "SUCCEEDED"})
    result_ref = reference(result)
    assert isinstance(result_ref, StoredDataRef)
    old_parent = _context(
        WorkType.VERIFICATION,
        (),
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
    ).work.model_copy(
        update={
            "status": WorkStatus.BLOCKED,
            "active_attempt_id": None,
            "waiting_for": ("DEPENDENCY",),
            "stop_reason": "WAITING_FOR_DYNAMIC_REPRO",
        }
    )
    old_parent_ref = reference(old_parent)
    assert isinstance(old_parent_ref, StoredDataRef)
    child = _context(
        WorkType.DYNAMIC_REPRO,
        (request_ref,),
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
        parent_ref=old_parent_ref,
    ).work.model_copy(
        update={
            "status": WorkStatus.SUCCEEDED,
            "active_attempt_id": None,
            "output_refs": (result_ref,),
        }
    )
    child_ref = reference(child)
    assert isinstance(child_ref, StoredDataRef)
    state = DynamicReproductionState.model_validate_json(
        json.dumps(
            make("DynamicReproductionState")
            | {
                "meta": make("DynamicReproductionState")["meta"]
                | {"attempt_id": None},
                "verification_generation": 1,
                "status": "SUCCEEDED",
                "dynamic_work_ref": child_ref.model_dump(mode="json"),
                "request_ref": request_ref.model_dump(mode="json"),
                "dynamic_result_ref": result_ref.model_dump(mode="json"),
                "started_at": result.started_at.isoformat(),
                "finished_at": result.finished_at.isoformat(),
            }
        )
    )
    current_parent = old_parent.model_copy(
        update={"work_generation": current_parent_generation}
    )
    return old_parent, current_parent, child, state, request, result


def test_successful_child_resumes_the_exact_same_generation_once() -> None:
    old_parent, parent, child, state, request, result = _chain()
    work = _WorkStore(parent, child)
    runner = _Runner(work)
    service = DynamicParentResumeService(
        records=_Records((old_parent, child, request, result)),  # type: ignore[arg-type]
        queries=_Queries(state),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        verification_identity_ref=StoredDataRef.model_validate(make("StoredDataRef")),
    )

    resumed = service.resume(str(child.work_id))
    replayed = service.resume(str(child.work_id))

    assert resumed.status == WorkStatus.READY
    assert resumed.work_id == old_parent.work_id
    assert resumed.work_generation == child.work_generation == 1
    assert replayed == resumed
    assert runner.actions == 1


def test_late_child_cannot_resume_a_newer_verification_generation() -> None:
    old_parent, parent, child, state, request, result = _chain(
        current_parent_generation=2
    )
    work = _WorkStore(parent, child)
    runner = _Runner(work)
    service = DynamicParentResumeService(
        records=_Records((old_parent, child, request, result)),  # type: ignore[arg-type]
        queries=_Queries(state),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        verification_identity_ref=StoredDataRef.model_validate(make("StoredDataRef")),
    )

    with pytest.raises(ValueError, match="STALE_DYNAMIC_RESULT"):
        service.resume(str(child.work_id))

    assert parent.status == WorkStatus.BLOCKED
    assert runner.actions == 0
