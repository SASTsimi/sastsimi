"""Atomic sibling registration and immutable historical-pool coverage."""

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, insert, select, update

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.chaining import (
    Primitive,
    PrimitiveIndexState,
)
from sastsimi.contracts.ids import (
    HypothesisId,
    LogicalRecordId,
    RecordId,
    TransitionCommitId,
    WorkId,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import TransitionCommit, WorkExecutionState
from sastsimi.ports.chaining import PrimitiveUpdateOutcome
from sastsimi.storage import models
from sastsimi.storage.chaining_registration import (
    ChainingCohortStore,
    ChainingCommittedSourceStore,
)
from sastsimi.storage.codec import encode
from sastsimi.storage.codec import reference as stored_reference
from sastsimi.storage.records import fresh_meta, next_meta
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


def test_registered_cohort_replay_uses_its_pinned_historical_universe(
    tmp_path: Path,
) -> None:
    scenario, works, outcome, scope, identity = _completed_update(tmp_path)
    service = ChainingCohortStore(works)
    source = works.records.get_exact(outcome.source_work_ref)
    assert isinstance(source, WorkExecutionState)
    assert outcome.primitive_index_ref is not None

    pending = service.register_pending(
        outcome=outcome,
        scope=scope,
        requester_identity_ref=identity,
        metadata=source.meta,
        generation=source.work_generation,
    )
    ready = service.promote_ready(
        registration=pending,
        scope=scope,
        requester_identity_ref=identity,
    )

    original_index = works.records.get_exact(outcome.primitive_index_ref)
    assert isinstance(original_index, PrimitiveIndexState)
    later_index = PrimitiveIndexState.model_validate(
        original_index.model_dump()
        | {
            "meta": next_meta(original_index.meta, scenario.clock, scenario.ids),
        }
    )
    later_index_ref = works.records.stage_record(later_index)
    assert isinstance(later_index_ref, StoredDataRef)
    with works.records.database.write() as connection:
        works.records.publish(connection, later_index_ref)
        connection.execute(
            update(models.current_records)
            .where(
                models.current_records.c.logical_record_id
                == str(original_index.meta.logical_record_id)
            )
            .values(
                record_id=str(later_index.meta.record_id),
                state_version=later_index.meta.revision_number,
            )
        )

    replay = service.register_pending(
        outcome=outcome,
        scope=scope,
        requester_identity_ref=identity,
        metadata=source.meta,
        generation=source.work_generation,
    )

    assert replay == ready
    assert all(
        member.pool.universe.index_refs == ready.members[0].pool.universe.index_refs
        for member in replay.members
    )


def test_cohort_generation_must_equal_its_committed_source_work(
    tmp_path: Path,
) -> None:
    _scenario, works, outcome, scope, identity = _completed_update(tmp_path)
    source = works.records.get_exact(outcome.source_work_ref)
    assert isinstance(source, WorkExecutionState)

    with pytest.raises(ValueError, match="CHAINING_UPDATE_GENERATION_MISMATCH"):
        ChainingCohortStore(works).register_pending(
            outcome=outcome,
            scope=scope,
            requester_identity_ref=identity,
            metadata=source.meta,
            generation=source.work_generation + 1,
        )


def test_committed_hold_update_reconstructs_without_an_admission_decision(
    tmp_path: Path,
) -> None:
    scenario, works, outcome, _scope_ref, _identity = _completed_update(tmp_path)
    assert outcome.primitive_index_ref is not None
    original_work = works.records.get_exact(outcome.source_work_ref)
    original_commit = works.records.get_exact(outcome.transition_commit_ref)
    original_index = works.records.get_exact(outcome.primitive_index_ref)
    original = works.records.get_exact(outcome.primitive_refs[0])
    assert isinstance(original_work, WorkExecutionState)
    assert isinstance(original_commit, TransitionCommit)
    assert isinstance(original_index, PrimitiveIndexState)
    assert isinstance(original, Primitive)
    hold = Primitive.model_validate(
        original.model_dump()
        | {
            "meta": fresh_meta(
                original.meta,
                "primitive",
                scenario.clock,
                scenario.ids,
            ),
            "primitive_id": "hold-primitive",
            "result": None,
            "technical_review_ref": None,
            "admission_decision_ref": None,
        }
    )
    hold_ref = works.records.stage_record(hold)
    assert isinstance(hold_ref, StoredDataRef)
    hold_index = PrimitiveIndexState.model_validate(
        original_index.model_dump()
        | {
            "meta": next_meta(original_index.meta, scenario.clock, scenario.ids),
            "primitive_refs": (*original_index.primitive_refs, hold_ref),
        }
    )
    hold_index_ref = works.records.stage_record(hold_index)
    assert isinstance(hold_index_ref, StoredDataRef)
    work_id = scenario.ids.new(WorkId)
    commit = TransitionCommit.model_validate(
        original_commit.model_dump()
        | {
            "meta": fresh_meta(
                original_commit.meta,
                "transition_commit",
                scenario.clock,
                scenario.ids,
                attempt_id=original_commit.attempt_id,
            ),
            "transition_commit_id": scenario.ids.new(TransitionCommitId),
            "work_id": work_id,
            "output_refs": (hold_ref,),
        }
    )
    commit_ref = works.records.stage_record(commit)
    assert isinstance(commit_ref, StoredDataRef)
    work = WorkExecutionState.model_validate(
        original_work.model_dump()
        | {
            "meta": fresh_meta(
                original_work.meta,
                "work_execution_state",
                scenario.clock,
                scenario.ids,
                attempt_id=None,
            ),
            "work_id": work_id,
            "work_generation": original_work.work_generation + 1,
            "last_transition_commit_ref": commit_ref,
            "output_refs": (hold_ref,),
        }
    )
    work_ref = works.records.stage_record(work)
    assert isinstance(work_ref, StoredDataRef)
    with works.records.database.write() as connection:
        for ref in (hold_ref, hold_index_ref, commit_ref, work_ref):
            works.records.publish(connection, ref)
        connection.execute(
            insert(models.work_states).values(
                work_id=str(work_id),
                analysis_id=str(work.meta.analysis_id),
                registration_key=content_hash([work_id, "hold-source"]),
                status=work.status.value,
                state_version=work.state_version,
                active_attempt_id=None,
                payload=encode(work),
            )
        )

    reconstructed = ChainingCommittedSourceStore(works.records).primitive_update(
        commit_ref
    )

    assert reconstructed.admission_decision_ref is None
    assert reconstructed.primitive_refs == (hold_ref,)
    assert reconstructed.primitive_index_ref == hold_index_ref


def test_claimed_running_work_reads_its_exact_ready_time_pool(
    tmp_path: Path,
) -> None:
    scenario, works, outcome, scope, identity = _completed_update(tmp_path)
    service = ChainingCohortStore(works)
    source = works.records.get_exact(outcome.source_work_ref)
    assert isinstance(source, WorkExecutionState)
    assert outcome.primitive_index_ref is not None
    pending = service.register_pending(
        outcome=outcome,
        scope=scope,
        requester_identity_ref=identity,
        metadata=source.meta,
        generation=source.work_generation,
    )
    ready = service.promote_ready(
        registration=pending,
        scope=scope,
        requester_identity_ref=identity,
    )
    chaining_identity = scenario.evidence.stored_identity(RequesterRole.CHAINING)
    assert scenario.runner is not None

    running = scenario.runner.activate(
        ready.members[0].work,
        scope,
        chaining_identity,
        role="CHAINING",
    )
    running_ref = reference(running)
    assert isinstance(running_ref, StoredDataRef)

    history = service.pools.get_for_trigger(running_ref)

    assert history.trigger_work_ref == running_ref
    assert history.universe == ready.members[0].pool.universe

    with works.records.database.write() as connection:
        connection.execute(
            update(models.chaining_work_pools)
            .where(models.chaining_work_pools.c.work_id == str(running.work_id))
            .values(input_hash="f" * 64)
        )
    with pytest.raises(ValueError, match="CHAINING_POOL_WORK_MISMATCH"):
        service.pools.get_for_trigger(running_ref)


def test_new_true_trigger_pins_current_true_and_hold_cross_hypothesis_pool(
    tmp_path: Path,
) -> None:
    scenario, works, outcome, scope, identity = _completed_update(tmp_path)
    source = works.records.get_exact(outcome.source_work_ref)
    assert isinstance(source, WorkExecutionState)
    assert outcome.primitive_index_ref is not None
    (original_ref,) = outcome.primitive_refs
    original = works.records.get_exact(original_ref)
    assert isinstance(original, Primitive)
    other_hypothesis = HypothesisId("other-hypothesis")
    other_meta = fresh_meta(
        original.meta.model_copy(update={"hypothesis_id": other_hypothesis}),
        "primitive",
        scenario.clock,
        scenario.ids,
    )
    other = Primitive.model_validate(
        original.model_dump()
        | {
            "meta": other_meta,
            "primitive_id": "other-hold-primitive",
            "source_hypothesis_id": other_hypothesis,
            "result": None,
            "technical_review_ref": None,
            "admission_decision_ref": None,
        }
    )
    other_ref = works.records.stage_record(other)
    assert isinstance(other_ref, StoredDataRef)
    source_index = works.records.get_exact(outcome.primitive_index_ref)
    assert isinstance(source_index, PrimitiveIndexState)
    other_index = PrimitiveIndexState.model_validate(
        source_index.model_dump()
        | {
            "meta": fresh_meta(
                source_index.meta.model_copy(
                    update={"hypothesis_id": other_hypothesis}
                ),
                "primitive_index_state",
                scenario.clock,
                scenario.ids,
                attempt_id=None,
            ),
            "primitive_refs": (other_ref,),
        }
    )
    other_index_ref = works.records.stage_record(other_index)
    assert isinstance(other_index_ref, StoredDataRef)
    with works.records.database.write() as connection:
        works.records.publish(connection, other_ref)
        works.records.publish(connection, other_index_ref)
        connection.execute(
            insert(models.current_records).values(
                logical_record_id=str(other_index.meta.logical_record_id),
                record_id=str(other_index.meta.record_id),
                state_version=1,
            )
        )

    pending = ChainingCohortStore(works).register_pending(
        outcome=outcome,
        scope=scope,
        requester_identity_ref=identity,
        metadata=source.meta,
        generation=source.work_generation,
    )

    universe = pending.members[0].pool.universe
    assert set(universe.index_refs) == {
        outcome.primitive_index_ref,
        other_index_ref,
    }
    assert set(universe.considered_primitive_refs) == {original_ref, other_ref}
    assert original.result is not None
    assert other.result is None


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
