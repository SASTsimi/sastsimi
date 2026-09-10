"""The optional child flow closes deterministically at a no-match result."""

from pathlib import Path

import pytest

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.chaining import no_match_result
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.chaining import (
    ChainingResult,
    Primitive,
    PrimitiveAdmissionDecision,
    PrimitiveIndexState,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.ids import AnalysisId, WorkspaceId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.verification import register_verification_children


def test_chaining_no_match_uses_the_current_primitive_snapshot(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    result = pipeline.analyze(scenario="CHAINING")
    assert result.status == "COMPLETE"
    assert pipeline.runtime is not None
    (chaining,) = pipeline.runtime.queries.current_records(
        "fake-analysis", "chaining_result"
    )
    (index,) = pipeline.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )
    assert isinstance(chaining, ChainingResult)
    assert isinstance(index, PrimitiveIndexState)
    assert chaining.considered_primitive_refs == index.primitive_refs
    assert chaining.primitive_match_candidates == ()
    assert chaining.chained_hypothesis_proposals == ()
    assert chaining.no_match_reasons[0].reason_code == "ENTITY_UNRELATED"


def test_material_verification_child_registers_through_runtime_work(
    tmp_path: Path,
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    execution = scenario._verification("TRUE", material_child=True)
    verification = execution.result
    assert scenario.runtime is not None and scenario.runner is not None
    assert execution.work_ref is not None
    state = scenario.runtime.budget_registry.current_state("fake-analysis")
    assert isinstance(state.budget_binding_ref, StoredDataRef)
    identity = scenario.evidence.stored_identity(RequesterRole.ORCHESTRATION)

    registered = register_verification_children(
        runtime=scenario.runtime,
        runner=scenario.runner,
        scope=state.budget_binding_ref,
        orchestration_identity=identity,
        source=verification,
    )

    assert len(registered) == 1
    processes = tuple(
        item
        for item in scenario.runtime.queries.current_records(
            "fake-analysis", "hypothesis_process_state"
        )
        if isinstance(item, HypothesisProcessState)
    )
    assert len(processes) == 2
    child = next(item for item in processes if item.status == "REGISTERED")
    assert child.proposal_ref == registered[0]


def test_denied_admission_commits_without_changing_primitive_index(
    tmp_path: Path,
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    execution = scenario._verification("TRUE")
    assert scenario.runtime is not None
    (before,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )

    scenario._post_true(
        execution,
        admission_decision="DENY",
    )

    (after,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )
    (admission,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive_admission_decision"
    )
    assert isinstance(admission, PrimitiveAdmissionDecision)
    assert admission.decision == "DENY"
    assert after == before
    assert not any(
        isinstance(item, Primitive)
        for item in scenario.runtime.queries.published_records("fake-analysis")
    )


def test_denied_admission_with_primitive_rolls_back_every_output(
    tmp_path: Path,
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    execution = scenario._verification("TRUE")
    assert scenario.runtime is not None
    (before,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )

    with pytest.raises(ValueError, match="PRIMITIVE_DENY_MUST_NOT_PUBLISH"):
        scenario._post_true(
            execution,
            admission_decision="DENY",
            publish_denied_primitive=True,
        )

    (after,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )
    assert after == before
    assert (
        scenario.runtime.queries.current_records(
            "fake-analysis", "primitive_admission_decision"
        )
        == ()
    )
    assert scenario.runtime.queries.current_records("fake-analysis", "primitive") == ()


def test_chaining_rejects_stale_index_and_cross_generation_atomically(
    tmp_path: Path,
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    execution = scenario._verification("TRUE")
    verification = execution.result
    scenario._post_true(execution)
    assert scenario.runtime is not None and scenario.runner is not None
    state = scenario.runtime.budget_registry.current_state("fake-analysis")
    assert state.budget_binding_ref is not None
    identity = next(
        ref
        for ref, role in scenario.evidence.identities.items()
        if role == RequesterRole.ORCHESTRATION and isinstance(ref, StoredDataRef)
    )
    indexes = tuple(
        item
        for item in scenario.runtime.queries.published_records("fake-analysis")
        if isinstance(item, PrimitiveIndexState)
    )
    stale = min(indexes, key=lambda item: item.meta.revision_number)
    (current,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )
    (primitive,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive"
    )
    stale_ref = reference(stale)
    current_ref = reference(current)
    primitive_ref = reference(primitive)
    assert isinstance(stale_ref, StoredDataRef)
    assert isinstance(current_ref, StoredDataRef)
    assert isinstance(primitive_ref, StoredDataRef)

    foreign_primitive_ref = StoredDataRef.model_validate(
        primitive_ref.model_dump() | {"workspace_id": WorkspaceId("foreign")}
    )
    with pytest.raises(ValueError, match="WORKSPACE_MISMATCH"):
        scenario.runner.start(
            state.budget_binding_ref,
            verification.meta,
            "CHAINING",
            "ANALYSIS",
            "fake-analysis",
            identity,
            inputs=(current_ref, foreign_primitive_ref),
            trigger_primitive_ref=foreign_primitive_ref,
        )
    assert isinstance(verification.meta, RecordMeta)
    foreign_analysis_meta = verification.meta.model_copy(
        update={"analysis_id": AnalysisId("foreign-analysis")}
    )
    with pytest.raises(ValueError, match="ANALYSIS_SCOPE_MISMATCH"):
        scenario.runner.start(
            state.budget_binding_ref,
            foreign_analysis_meta,
            "CHAINING",
            "ANALYSIS",
            "foreign-analysis",
            identity,
            inputs=(current_ref, primitive_ref),
            trigger_primitive_ref=primitive_ref,
        )

    with pytest.raises(ValueError, match="STALE_RESULT"):
        scenario.runner.start(
            state.budget_binding_ref,
            verification.meta,
            "CHAINING",
            "ANALYSIS",
            "fake-analysis",
            identity,
            inputs=(stale_ref, primitive_ref),
            trigger_primitive_ref=primitive_ref,
        )

    work = scenario.runner.start(
        state.budget_binding_ref,
        verification.meta,
        "CHAINING",
        "ANALYSIS",
        "fake-analysis",
        identity,
        inputs=(current_ref, primitive_ref),
        trigger_primitive_ref=primitive_ref,
        generation=2,
    )
    chaining_identity = reference(
        scenario.runtime.queries.current_records(
            "fake-analysis", "rule_scope_impact_review"
        )[0]
    )
    assert isinstance(chaining_identity, StoredDataRef)
    scenario.evidence.identities[chaining_identity] = RequesterRole.CHAINING
    before = scenario.runtime.queries.current_records(
        "fake-analysis", "chaining_result"
    )

    candidate = no_match_result(
        meta=scenario.runner.metadata(
            work.meta,
            "chaining_result",
            attempt_id=work.active_attempt_id,
        ),
        primitive_ref=primitive_ref,
    )
    with pytest.raises(ValueError, match="CHAINING_CURRENT_VERIFICATION_MISMATCH"):
        scenario.runner.complete(work, chaining_identity, "CHAINING", (candidate,))

    assert (
        scenario.runtime.queries.current_records("fake-analysis", "chaining_result")
        == before
    )


def test_chaining_accepts_the_pinned_index_after_an_unrelated_append(
    tmp_path: Path,
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    execution = scenario._verification("TRUE")
    verification = execution.result
    scenario._post_true(
        execution,
        stop_after_chaining=True,
    )
    assert scenario.runtime is not None and scenario.runner is not None
    state = scenario.runtime.budget_registry.current_state("fake-analysis")
    assert state.budget_binding_ref is not None
    identity = next(
        ref
        for ref, role in scenario.evidence.identities.items()
        if role == RequesterRole.ORCHESTRATION and isinstance(ref, StoredDataRef)
    )
    (pinned_index,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )
    (primitive,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive"
    )
    pinned_ref = reference(pinned_index)
    primitive_ref = reference(primitive)
    assert isinstance(pinned_ref, StoredDataRef)
    assert isinstance(primitive_ref, StoredDataRef)
    work = scenario.runner.start(
        state.budget_binding_ref,
        verification.meta,
        "CHAINING",
        "ANALYSIS",
        "fake-analysis",
        identity,
        inputs=(pinned_ref, primitive_ref),
        trigger_primitive_ref=primitive_ref,
    )

    # A later admission appends to the current index while this work retains its
    # exact immutable start snapshot.
    scenario._post_true(
        execution,
        stop_after_chaining=True,
    )
    (advanced_index,) = scenario.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )
    assert reference(advanced_index) != pinned_ref

    chaining_identity = reference(
        scenario.runtime.queries.current_records(
            "fake-analysis", "rule_scope_impact_review"
        )[0]
    )
    assert isinstance(chaining_identity, StoredDataRef)
    scenario.evidence.identities[chaining_identity] = RequesterRole.CHAINING
    candidate = no_match_result(
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
        (candidate,),
    )
    assert completed.status == "SUCCEEDED"
