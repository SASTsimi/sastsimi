"""Pinned Chaining input remains valid independently of work generation."""

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy import Connection, insert

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.chaining import no_match_result
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.chaining import ChainingResult, Primitive, PrimitiveIndexState
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import TransitionCommit, WorkAttempt, WorkExecutionState
from sastsimi.storage import models
from sastsimi.storage.chaining_projection import validate_chaining_output
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade
from sastsimi.storage.repositories import SQLiteRecordStore
from sastsimi.storage.work_service import WorkService
from tests.contract.domain.canonical_fixtures import NOW, make
from tests.contract.domain.fixtures import meta, ref, wire


def test_chaining_work_generation_is_not_compared_to_parent_generation(
    tmp_path: Path,
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    execution = scenario._verification("TRUE")
    verification = execution.result
    scenario._post_true(execution, stop_after_chaining=True)
    assert scenario.runtime is not None and scenario.runner is not None
    state = scenario.runtime.budget_registry.current_state("fake-analysis")
    assert state.budget_binding_ref is not None
    orchestrator = next(
        ref
        for ref, role in scenario.evidence.identities.items()
        if role == RequesterRole.ORCHESTRATION and isinstance(ref, StoredDataRef)
    )
    (index,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )
    (primitive,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive"
    )
    assert isinstance(index, PrimitiveIndexState)
    assert isinstance(primitive, Primitive)
    index_ref = reference(index)
    primitive_ref = reference(primitive)
    assert isinstance(index_ref, StoredDataRef)
    assert isinstance(primitive_ref, StoredDataRef)

    work = scenario.runner.start(
        state.budget_binding_ref,
        verification.meta,
        "CHAINING",
        "ANALYSIS",
        "fake-analysis",
        orchestrator,
        inputs=(index_ref, primitive_ref),
        trigger_primitive_ref=primitive_ref,
        generation=99,
    )
    (process,) = scenario.runtime.queries.current_records(
        "fake-analysis", "hypothesis_process_state"
    )
    assert isinstance(process, HypothesisProcessState)
    assert work.work_generation != process.verification_generation
    chaining_identity = reference(
        scenario.runtime.queries.current_records(
            "fake-analysis", "rule_scope_impact_review"
        )[0]
    )
    assert isinstance(chaining_identity, StoredDataRef)
    scenario.evidence.identities[chaining_identity] = RequesterRole.CHAINING
    result = no_match_result(
        meta=scenario.runner.metadata(
            work.meta,
            "chaining_result",
            attempt_id=work.active_attempt_id,
        ),
        primitive_ref=primitive_ref,
    )

    completed = scenario.runner.complete(
        work,
        chaining_identity,
        "CHAINING",
        (result,),
    )

    assert completed.status == "SUCCEEDED"


def _scoped_meta(
    kind: str,
    suffix: str,
    *,
    hypothesis_id: str | None,
    attempt_id: str | None,
) -> dict[str, object]:
    return meta(kind, hypothesis=hypothesis_id, attempt=attempt_id) | {
        "record_id": f"{kind}-{suffix}-r1",
        "logical_record_id": f"{kind}-{suffix}-l1",
    }


def _verification(suffix: str, hypothesis_id: str) -> VerificationResult:
    data = make("VerificationResult")
    data["meta"] = _scoped_meta(
        "verification_result",
        suffix,
        hypothesis_id=hypothesis_id,
        attempt_id=f"verification-{suffix}-attempt",
    )
    return wire(VerificationResult, data)


def _publish_committed_verification(
    records: SQLiteRecordStore,
    connection: Connection,
    verification: VerificationResult,
    *,
    suffix: str,
    generation: int,
) -> StoredDataRef:
    verification_ref = reference(verification)
    assert isinstance(verification_ref, StoredDataRef)
    hypothesis_id = str(verification.meta.hypothesis_id)
    work_id = f"verification-{suffix}-work"
    attempt_id = f"verification-{suffix}-attempt"
    transition_ref = ref("state_transition") | {
        "stored_data_id": f"state-transition-{suffix}-s1",
        "record_id": f"state-transition-{suffix}-r1",
        "content_hash": str(generation) * 64,
    }
    commit = wire(
        TransitionCommit,
        make("TransitionCommit")
        | {
            "meta": _scoped_meta(
                "transition_commit",
                suffix,
                hypothesis_id=hypothesis_id,
                attempt_id=attempt_id,
            ),
            "transition_commit_id": f"verification-{suffix}-commit",
            "work_id": work_id,
            "transition_ref": transition_ref,
            "expected_state_version": 1,
            "target_state_version": 2,
            "attempt_id": attempt_id,
            "target_status": "SUCCEEDED",
            "output_refs": [verification_ref.model_dump(mode="json")],
            "state": "COMMITTED",
            "committed_at": NOW,
        },
    )
    commit_ref = reference(commit)
    assert isinstance(commit_ref, StoredDataRef)
    input_hash = str(generation) * 64
    work = wire(
        WorkExecutionState,
        make("WorkExecutionState")
        | {
            "meta": _scoped_meta(
                "work_execution_state",
                suffix,
                hypothesis_id=hypothesis_id,
                attempt_id=None,
            ),
            "work_id": work_id,
            "work_type": "VERIFICATION",
            "subject_type": "HYPOTHESIS",
            "subject_id": hypothesis_id,
            "work_generation": generation,
            "status": "SUCCEEDED",
            "state_version": 2,
            "last_transition_ref": transition_ref,
            "last_transition_commit_ref": commit_ref.model_dump(mode="json"),
            "input_hash": input_hash,
            "dedupe_key": ("a" if generation == 1 else "b") * 64,
            "output_refs": [verification_ref.model_dump(mode="json")],
            "stop_reason": "COMPLETED",
            "started_at": NOW,
            "finished_at": NOW,
        },
    )
    attempt = wire(
        WorkAttempt,
        make("WorkAttempt")
        | {
            "meta": _scoped_meta(
                "work_attempt",
                suffix,
                hypothesis_id=hypothesis_id,
                attempt_id=attempt_id,
            ),
            "work_id": work_id,
            "attempt_id": attempt_id,
            "input_hash": input_hash,
            "status": "SUCCEEDED",
            "output_refs": [verification_ref.model_dump(mode="json")],
            "finished_at": NOW,
        },
    )
    staged_ref = records.stage(connection, verification)
    records.publish(connection, staged_ref)
    connection.execute(
        insert(models.work_states).values(
            work_id=work_id,
            analysis_id="a1",
            registration_key=f"verification-{suffix}-registration",
            status="SUCCEEDED",
            state_version=2,
            active_attempt_id=None,
            payload=work.model_dump_json(),
        )
    )
    connection.execute(
        insert(models.work_attempts).values(
            attempt_id=attempt_id,
            work_id=work_id,
            attempt_number=1,
            status="SUCCEEDED",
            payload=attempt.model_dump_json(),
        )
    )
    connection.execute(
        insert(models.transition_commits).values(
            transition_commit_id=str(commit.transition_commit_id),
            work_id=work_id,
            expected_state_version=1,
            candidate_binding=f"verification-{suffix}-binding",
            state="COMMITTED",
            payload=commit.model_dump_json(),
            request="{}",
        )
    )
    return verification_ref


def _terminal_process(
    hypothesis_id: str,
    verification_ref: StoredDataRef,
    *,
    generation: int,
) -> HypothesisProcessState:
    data = make("HypothesisProcessState")
    data["meta"] = _scoped_meta(
        "hypothesis_process_state",
        f"{hypothesis_id}-{generation}",
        hypothesis_id=hypothesis_id,
        attempt_id=None,
    ) | {
        "logical_record_id": f"hypothesis-process-{hypothesis_id}",
        "revision_number": generation,
        "previous_record_id": (
            None
            if generation == 1
            else f"hypothesis_process_state-{hypothesis_id}-{generation - 1}-r1"
        ),
    }
    data |= {
        "status": "TERMINAL",
        "verification_assignment_ref": ref("verification_assignment"),
        "verification_generation": generation,
        "verification_result_ref": verification_ref.model_dump(mode="json"),
        "finished_at": NOW,
    }
    return wire(HypothesisProcessState, data)


def _primitive(
    hypothesis_id: str,
    source_ref: StoredDataRef,
    suffix: str,
) -> Primitive:
    data = make("Primitive")
    data["meta"] = _scoped_meta(
        "primitive",
        suffix,
        hypothesis_id=hypothesis_id,
        attempt_id=f"primitive-{suffix}-attempt",
    )
    data |= {
        "primitive_id": f"primitive-{suffix}",
        "source_hypothesis_id": hypothesis_id,
        "source_verification_ref": source_ref.model_dump(mode="json"),
    }
    data["inputs"][0]["draft_id"] = "fake-input"
    return wire(Primitive, data)


def _index(
    hypothesis_id: str,
    current_verification_ref: StoredDataRef,
    primitive_refs: tuple[StoredDataRef, ...],
    *,
    suffix: str,
    revision: int = 1,
) -> PrimitiveIndexState:
    data = make("PrimitiveIndexState")
    data["meta"] = _scoped_meta(
        "primitive_index_state",
        suffix,
        hypothesis_id=hypothesis_id,
        attempt_id=None,
    ) | {
        "logical_record_id": f"primitive-index-{suffix}",
        "revision_number": revision,
        "previous_record_id": (
            None if revision == 1 else f"primitive_index_state-{suffix}-r{revision - 1}"
        ),
        "record_id": f"primitive_index_state-{suffix}-r{revision}",
    }
    data |= {
        "current_verification_ref": current_verification_ref.model_dump(mode="json"),
        "primitive_refs": [item.model_dump(mode="json") for item in primitive_refs],
    }
    return wire(PrimitiveIndexState, data)


def _chaining_case(
    indexes: tuple[PrimitiveIndexState, ...],
    primitives: tuple[Primitive, ...],
) -> tuple[WorkExecutionState, ChainingResult]:
    index_refs = tuple(reference(index) for index in indexes)
    primitive_refs = tuple(reference(primitive) for primitive in primitives)
    assert all(isinstance(item, StoredDataRef) for item in index_refs)
    assert all(isinstance(item, StoredDataRef) for item in primitive_refs)
    stored_indexes = cast(tuple[StoredDataRef, ...], index_refs)
    stored_primitives = cast(tuple[StoredDataRef, ...], primitive_refs)
    inputs = (*stored_indexes, *stored_primitives)
    work_data = make("WorkExecutionState")
    work_data["meta"] = _scoped_meta(
        "work_execution_state",
        "chaining",
        hypothesis_id=None,
        attempt_id=None,
    )
    work_data |= {
        "work_id": "chaining-work",
        "work_type": "CHAINING",
        "subject_type": "ANALYSIS",
        "subject_id": "a1",
        "input_hash": content_hash(inputs),
        "dedupe_key": "d" * 64,
        "trigger_primitive_ref": stored_primitives[0].model_dump(mode="json"),
        "input_refs": [item.model_dump(mode="json") for item in inputs],
    }
    work = wire(WorkExecutionState, work_data)
    result_meta = wire(ChainingResult, make("ChainingResult")).meta.model_dump()
    result_meta |= {
        "record_id": "chaining_result-chaining-r1",
        "logical_record_id": "chaining_result-chaining-l1",
        "attempt_id": "chaining-attempt",
    }
    result = no_match_result(
        meta=result_meta,
        primitive_refs=stored_primitives,
    )
    return work, result


def _publish(
    records: SQLiteRecordStore,
    connection: Connection,
    *values: HypothesisProcessState | Primitive | PrimitiveIndexState,
) -> None:
    for value in values:
        value_ref = records.stage(connection, value)
        records.publish(connection, value_ref)


def test_second_generation_mixed_pool_remains_valid_after_later_index_revision(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "runtime.db")
    upgrade(database)
    records = SQLiteRecordStore(database)
    with database.write() as connection:
        first_ref = _publish_committed_verification(
            records,
            connection,
            _verification("h1-g1", "h1"),
            suffix="h1-g1",
            generation=1,
        )
        second_ref = _publish_committed_verification(
            records,
            connection,
            _verification("h1-g2", "h1"),
            suffix="h1-g2",
            generation=2,
        )
        first_process = _terminal_process("h1", first_ref, generation=1)
        second_process = _terminal_process("h1", second_ref, generation=2)
        first = _primitive("h1", first_ref, "h1-g1")
        second = _primitive("h1", second_ref, "h1-g2")
        later = _primitive("h1", second_ref, "h1-later")
        first_primitive_ref = reference(first)
        second_primitive_ref = reference(second)
        later_primitive_ref = reference(later)
        assert isinstance(first_primitive_ref, StoredDataRef)
        assert isinstance(second_primitive_ref, StoredDataRef)
        assert isinstance(later_primitive_ref, StoredDataRef)
        pinned = _index(
            "h1",
            second_ref,
            (first_primitive_ref, second_primitive_ref),
            suffix="h1",
        )
        advanced = _index(
            "h1",
            second_ref,
            (first_primitive_ref, second_primitive_ref, later_primitive_ref),
            suffix="h1",
            revision=2,
        )
        _publish(
            records,
            connection,
            first_process,
            second_process,
            first,
            second,
            later,
            pinned,
            advanced,
        )
        connection.execute(
            insert(models.current_records).values(
                logical_record_id=str(second_process.meta.logical_record_id),
                record_id=str(second_process.meta.record_id),
                state_version=2,
            )
        )
        connection.execute(
            insert(models.current_records).values(
                logical_record_id=str(advanced.meta.logical_record_id),
                record_id=str(advanced.meta.record_id),
                state_version=2,
            )
        )
    work, result = _chaining_case((pinned,), (first, second))
    works = cast(WorkService, SimpleNamespace(records=records))
    with database.engine.connect() as connection:
        validate_chaining_output(works, connection, work, (result,))


def test_index_current_verification_requires_its_own_terminal_process(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "runtime.db")
    upgrade(database)
    records = SQLiteRecordStore(database)
    with database.write() as connection:
        first_ref = _publish_committed_verification(
            records,
            connection,
            _verification("h1-g1", "h1"),
            suffix="h1-g1",
            generation=1,
        )
        orphan_ref = _publish_committed_verification(
            records,
            connection,
            _verification("h1-orphan", "h1"),
            suffix="h1-orphan",
            generation=2,
        )
        process = _terminal_process("h1", first_ref, generation=1)
        primitive = _primitive("h1", first_ref, "h1-g1")
        primitive_ref = reference(primitive)
        assert isinstance(primitive_ref, StoredDataRef)
        index = _index("h1", orphan_ref, (primitive_ref,), suffix="h1")
        _publish(records, connection, process, primitive, index)
    work, result = _chaining_case((index,), (primitive,))
    works = cast(WorkService, SimpleNamespace(records=records))
    with database.engine.connect() as connection:
        with pytest.raises(ValueError, match="CHAINING_PINNED_VERIFICATION_MISMATCH"):
            validate_chaining_output(works, connection, work, (result,))


def test_primitive_must_belong_to_its_hypothesis_index(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "runtime.db")
    upgrade(database)
    records = SQLiteRecordStore(database)
    with database.write() as connection:
        h1_ref = _publish_committed_verification(
            records,
            connection,
            _verification("h1-g1", "h1"),
            suffix="h1-g1",
            generation=1,
        )
        h2_ref = _publish_committed_verification(
            records,
            connection,
            _verification("h2-g1", "h2"),
            suffix="h2-g1",
            generation=1,
        )
        h1_process = _terminal_process("h1", h1_ref, generation=1)
        h2_process = _terminal_process("h2", h2_ref, generation=1)
        h1_primitive = _primitive("h1", h1_ref, "h1-g1")
        h2_primitive = _primitive("h2", h2_ref, "h2-g1")
        h1_primitive_ref = reference(h1_primitive)
        h2_primitive_ref = reference(h2_primitive)
        assert isinstance(h1_primitive_ref, StoredDataRef)
        assert isinstance(h2_primitive_ref, StoredDataRef)
        h1_index = _index("h1", h1_ref, (h2_primitive_ref,), suffix="h1")
        h2_index = _index("h2", h2_ref, (h1_primitive_ref,), suffix="h2")
        _publish(
            records,
            connection,
            h1_process,
            h2_process,
            h1_primitive,
            h2_primitive,
            h1_index,
            h2_index,
        )
    work, result = _chaining_case(
        (h1_index, h2_index),
        (h1_primitive, h2_primitive),
    )
    works = cast(WorkService, SimpleNamespace(records=records))
    with database.engine.connect() as connection:
        with pytest.raises(ValueError, match="CHAINING_PINNED_INDEX_MISMATCH"):
            validate_chaining_output(works, connection, work, (result,))
