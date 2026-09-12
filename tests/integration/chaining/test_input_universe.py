"""Pinned Chaining input remains valid independently of work generation."""

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy import insert

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.chaining import no_match_result
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.chaining import ChainingResult, Primitive, PrimitiveIndexState
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.storage import models
from sastsimi.storage.chaining_projection import validate_chaining_output
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade
from sastsimi.storage.repositories import SQLiteRecordStore
from sastsimi.storage.work_service import WorkService
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import wire


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


def test_later_verification_generation_does_not_invalidate_pinned_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "runtime.db")
    upgrade(database)
    records = SQLiteRecordStore(database)
    verification = wire(VerificationResult, make("VerificationResult"))
    verification_ref = reference(verification)
    assert isinstance(verification_ref, StoredDataRef)
    primitive = wire(
        Primitive,
        make("Primitive")
        | {"source_verification_ref": verification_ref.model_dump(mode="json")},
    )
    primitive_ref = reference(primitive)
    assert isinstance(primitive_ref, StoredDataRef)
    index = wire(
        PrimitiveIndexState,
        make("PrimitiveIndexState")
        | {
            "current_verification_ref": verification_ref.model_dump(mode="json"),
            "primitive_refs": [primitive_ref.model_dump(mode="json")],
        },
    )
    index_ref = reference(index)
    assert isinstance(index_ref, StoredDataRef)
    terminal_wire = make("HypothesisProcessState")
    terminal_wire |= {
        "status": "TERMINAL",
        "verification_assignment_ref": make("VerificationResult")[
            "playbook_application_ref"
        ]
        | {"data_kind": "verification_assignment"},
        "verification_generation": 1,
        "verification_result_ref": verification_ref.model_dump(mode="json"),
        "finished_at": "2026-09-08T00:00:01Z",
    }
    terminal = wire(HypothesisProcessState, terminal_wire)
    later_result_ref = StoredDataRef.model_validate(
        verification_ref.model_dump()
        | {
            "stored_data_id": "later-verification",
            "record_id": "later-verification",
            "content_hash": "f" * 64,
        }
    )
    later_wire = terminal.model_dump(mode="json")
    later_wire["meta"] |= {
        "record_id": "hypothesis-process-r2",
        "previous_record_id": str(terminal.meta.record_id),
        "revision_number": 2,
    }
    later_wire |= {
        "verification_generation": 2,
        "verification_result_ref": later_result_ref.model_dump(mode="json"),
    }
    later = wire(HypothesisProcessState, later_wire)
    inputs = (index_ref, primitive_ref)
    work_wire = make("WorkExecutionState")
    work_wire["meta"] |= {"hypothesis_id": None, "attempt_id": None}
    work_wire |= {
        "work_type": "CHAINING",
        "subject_type": "ANALYSIS",
        "subject_id": "a1",
        "input_hash": content_hash(inputs),
        "dedupe_key": "d" * 64,
        "trigger_primitive_ref": primitive_ref.model_dump(mode="json"),
        "input_refs": [ref.model_dump(mode="json") for ref in inputs],
    }
    work = wire(WorkExecutionState, work_wire)
    result_wire = make("ChainingResult")
    result_wire |= {
        "considered_primitive_refs": [primitive_ref.model_dump(mode="json")],
    }
    result = wire(ChainingResult, result_wire)
    with database.write() as connection:
        for value in (verification, primitive, index, terminal, later):
            value_ref = records.stage(connection, value)
            records.publish(connection, value_ref)
        connection.execute(
            insert(models.current_records).values(
                logical_record_id=str(later.meta.logical_record_id),
                record_id=str(later.meta.record_id),
                state_version=2,
            )
        )
    import sastsimi.storage.chaining_projection as projection

    monkeypatch.setattr(projection, "require_committed", lambda *_args: None)
    works = cast(WorkService, SimpleNamespace(records=records))
    with database.engine.connect() as connection:
        validate_chaining_output(works, connection, work, (result,))
