"""Pinned Chaining input remains valid independently of work generation."""

from pathlib import Path

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.chaining import no_match_result
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.chaining import Primitive, PrimitiveIndexState
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.refs import StoredDataRef, reference


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
