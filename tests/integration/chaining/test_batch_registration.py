"""Atomic sibling registration and immutable historical-pool coverage."""

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.chaining import (
    Primitive,
    PrimitiveIndexState,
)
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.chaining import PrimitiveUpdateOutcome
from sastsimi.storage import models
from sastsimi.storage.chaining_registration import (
    ChainingCohortStore,
    ChainingCommittedSourceStore,
)
from sastsimi.storage.codec import reference as stored_reference
from sastsimi.storage.work_service import WorkService


def _completed_update(
    tmp_path: Path,
) -> tuple[
    Any,
    WorkService,
    PrimitiveUpdateOutcome,
    StoredDataRef,
    StoredDataRef,
]:
    scenario = build_fake_pipeline(tmp_path)._scenario
    execution = scenario._verification("TRUE")
    scenario._post_true(execution, stop_after_chaining=True)
    assert scenario.runtime is not None
    works = scenario.runtime.work.store
    assert isinstance(works, WorkService)
    with works.records.database.engine.connect() as connection:
        updates = [
            WorkExecutionState.model_validate_json(payload)
            for payload in connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.analysis_id == "fake-analysis"
                )
            ).scalars()
            if WorkExecutionState.model_validate_json(payload).work_type
            == "PRIMITIVE_UPDATE"
        ]
    (source_work,) = updates
    source_work_ref = stored_reference(source_work)
    assert isinstance(source_work_ref, StoredDataRef)
    assert isinstance(source_work.last_transition_commit_ref, StoredDataRef)
    primitive_refs = tuple(
        ref for ref in source_work.output_refs if ref.data_kind == "primitive"
    )
    admission_refs = tuple(
        ref
        for ref in source_work.output_refs
        if ref.data_kind == "primitive_admission_decision"
    )
    assert all(isinstance(ref, StoredDataRef) for ref in primitive_refs)
    assert all(isinstance(ref, StoredDataRef) for ref in admission_refs)
    stored_primitives = tuple(
        ref for ref in primitive_refs if isinstance(ref, StoredDataRef)
    )
    stored_admissions = tuple(
        ref for ref in admission_refs if isinstance(ref, StoredDataRef)
    )
    (index,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )
    assert isinstance(index, PrimitiveIndexState)
    index_ref = reference(index)
    assert isinstance(index_ref, StoredDataRef)
    outcome = PrimitiveUpdateOutcome(
        source_work_ref=source_work_ref,
        transition_commit_ref=source_work.last_transition_commit_ref,
        admission_decision_ref=stored_admissions[0],
        primitive_refs=stored_primitives,
        primitive_index_ref=index_ref,
    )
    state = scenario.runtime.budget_registry.current_state("fake-analysis")
    assert isinstance(state.budget_binding_ref, StoredDataRef)
    identity = scenario.evidence.identity(RequesterRole.PRIMITIVE_ADMISSION_RUNTIME)
    assert isinstance(identity, StoredDataRef)
    return scenario, works, outcome, state.budget_binding_ref, identity


def test_cohort_is_pending_then_becomes_ready_as_one_visible_batch(
    tmp_path: Path,
) -> None:
    _scenario, works, outcome, scope, identity = _completed_update(tmp_path)
    service = ChainingCohortStore(works)
    source = works.records.get_exact(outcome.source_work_ref)
    assert isinstance(source, WorkExecutionState)

    pending = service.register_pending(
        outcome=outcome,
        scope=scope,
        requester_identity_ref=identity,
        metadata=source.meta,
        generation=source.work_generation,
    )
    assert pending.status == "PENDING"
    assert all(member.work.status == "PENDING" for member in pending.members)
    pinned = pending.members[0].pool.universe
    assert pinned.index_refs == (outcome.primitive_index_ref,)
    assert outcome.primitive_index_ref is not None
    index = works.records.get_exact(outcome.primitive_index_ref)
    assert isinstance(index, PrimitiveIndexState)
    assert pinned.considered_primitive_refs == index.primitive_refs

    ready = service.promote_ready(
        registration=pending,
        scope=scope,
        requester_identity_ref=identity,
    )
    assert ready.status == "READY"
    assert all(member.work.status == "READY" for member in ready.members)
    for member in ready.members:
        stored_pool = service.pools.get_for_trigger(member.pool.trigger_work_ref)
        assert stored_pool == member.pool
        assert (
            service.pools.get_for_primitive(member.pool.universe.trigger_primitive_ref)
            == member.pool
        )

    assert (
        ChainingCommittedSourceStore(works.records).primitive_update(
            outcome.transition_commit_ref
        )
        == outcome
    )

    replay = service.register_pending(
        outcome=outcome,
        scope=scope,
        requester_identity_ref=identity,
        metadata=source.meta,
        generation=source.work_generation,
    )
    assert replay == ready


def test_failure_after_multiple_siblings_rolls_back_the_entire_cohort(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario, works, outcome, scope, identity = _completed_update(tmp_path)
    source = works.records.get_exact(outcome.source_work_ref)
    assert outcome.primitive_index_ref is not None
    index = works.records.get_exact(outcome.primitive_index_ref)
    (original_ref,) = outcome.primitive_refs
    original = works.records.get_exact(original_ref)
    assert isinstance(source, WorkExecutionState)
    assert isinstance(index, PrimitiveIndexState)
    assert isinstance(original, Primitive)

    def clone_primitive(suffix: str) -> Primitive:
        record_id = scenario.ids.new(RecordId)
        return Primitive.model_validate(
            original.model_dump()
            | {
                "meta": original.meta.model_dump()
                | {
                    "record_id": record_id,
                    "logical_record_id": LogicalRecordId(str(record_id)),
                    "revision_number": 1,
                    "previous_record_id": None,
                },
                "primitive_id": f"rollback-{suffix}",
            }
        )

    first, second = clone_primitive("first"), clone_primitive("second")
    first_ref = works.records.stage_record(first)
    second_ref = works.records.stage_record(second)
    assert isinstance(first_ref, StoredDataRef)
    assert isinstance(second_ref, StoredDataRef)
    with works.records.database.write() as connection:
        works.records.publish(connection, first_ref)
        works.records.publish(connection, second_ref)
    fake_index = PrimitiveIndexState.model_validate(
        index.model_dump() | {"primitive_refs": (first_ref, second_ref)}
    )
    two = PrimitiveUpdateOutcome(
        source_work_ref=outcome.source_work_ref,
        transition_commit_ref=outcome.transition_commit_ref,
        admission_decision_ref=outcome.admission_decision_ref,
        primitive_refs=(first_ref, second_ref),
        primitive_index_ref=outcome.primitive_index_ref,
    )
    baseline = {}
    with works.records.database.engine.connect() as connection:
        for name, table in {
            "works": models.work_states,
            "reservations": models.budget_reservations,
            "cohorts": models.chaining_cohorts,
            "pools": models.chaining_work_pools,
        }.items():
            baseline[name] = connection.execute(
                select(func.count()).select_from(table)
            ).scalar_one()

    seen = 0

    def fail_after_second(stage: str) -> None:
        nonlocal seen
        if stage == "pending_member":
            seen += 1
            if seen == 2:
                raise RuntimeError("simulated crash")

    service = ChainingCohortStore(works, checkpoint=fail_after_second)
    monkeypatch.setattr(service, "_validate_outcome", lambda *_args: fake_index)
    with pytest.raises(RuntimeError, match="simulated crash"):
        service.register_pending(
            outcome=two,
            scope=scope,
            requester_identity_ref=identity,
            metadata=source.meta,
            generation=source.work_generation,
        )

    with works.records.database.engine.connect() as connection:
        for name, table in {
            "works": models.work_states,
            "reservations": models.budget_reservations,
            "cohorts": models.chaining_cohorts,
            "pools": models.chaining_work_pools,
        }.items():
            assert (
                connection.execute(select(func.count()).select_from(table)).scalar_one()
                == baseline[name]
            )
