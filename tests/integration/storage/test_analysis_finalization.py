"""Trusted exact terminal analysis projection."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionDecision, ActionRequest, RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.ids import AnalysisId
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import AnalysisError
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.storage.analysis_finalization import AnalysisFinalizationService
from sastsimi.storage.run_states import get_run
from tests.contract.domain.canonical_fixtures import make
from tests.integration.recovery.test_transitions import SimulatedCrash, completion
from tests.integration.runtime_support import Harness
from tests.integration.storage.test_work import start_fixture


def _result(artifacts: ArtifactStore) -> AnalysisRunResult:
    value = make("AnalysisRunResult") | {
        "program_id": "program",
        "started_at": "2026-09-07T00:00:00Z",
        "finished_at": "2026-09-07T00:00:00Z",
        "elapsed_ms": 0,
    }
    value["resources"] = value["resources"] | {
        "elapsed_ms": 0,
        "work_count": 0,
        "attempt_count": 0,
        "retry_count": 0,
        "llm_call_count": 0,
        "dynamic_attempt_count": 0,
    }
    staged = artifacts.stage_bytes(b"deterministic finalization trace\n", "text/plain")
    value["debug_trace_ref"] = artifacts.commit_run(
        staged, AnalysisId("a1")
    ).model_dump()
    return AnalysisRunResult.model_validate_json(canonical_bytes(value))


def test_finalization_validates_inventory_and_closes_run_atomically(
    tmp_path: Path,
) -> None:
    h = Harness(tmp_path)
    profile = h.execution()
    identity_ref = reference(profile)
    assert isinstance(identity_ref, (RunStoredDataRef, StoredDataRef))
    h.evidence.identities[identity_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(
        tmp_path,
        None,
        None,
        h.clock,
        h.ids,
        evidence=h.evidence,
        analysis_finalization_identity_ref=identity_ref,
    )
    h.pin_execution(runtime.budget_registry, profile)
    result = _result(runtime.unit_of_work.artifacts)

    result_ref = runtime.finalization.finalize(result)

    state = runtime.budget_registry.current_state("a1")
    assert state.status == "FAILED"
    assert state.analysis_result_ref == result_ref
    assert state in runtime.queries.published_records("a1")
    published = runtime.queries.published_records("a1")
    (action,) = tuple(
        item
        for item in published
        if isinstance(item, ActionRequest) and item.result_kind == "analysis_run_result"
    )
    decisions = tuple(
        item
        for item in published
        if isinstance(item, ActionDecision) and item.action_ref == reference(action)
    )
    final_decision = max(decisions, key=lambda item: item.meta.revision_number)
    assert final_decision.use_status == "USED"
    assert final_decision.outcome_refs == (result_ref,)
    assert runtime.finalization.finalize(result) == result_ref


def test_finalization_rejects_fabricated_resource_summary_atomically(
    tmp_path: Path,
) -> None:
    h = Harness(tmp_path)
    profile = h.execution()
    identity_ref = reference(profile)
    assert isinstance(identity_ref, (RunStoredDataRef, StoredDataRef))
    h.evidence.identities[identity_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(
        tmp_path,
        None,
        None,
        h.clock,
        h.ids,
        evidence=h.evidence,
        analysis_finalization_identity_ref=identity_ref,
    )
    h.pin_execution(runtime.budget_registry, profile)
    result = _result(runtime.unit_of_work.artifacts)
    invalid = result.model_copy(
        update={"resources": result.resources.model_copy(update={"work_count": 1})}
    )

    with pytest.raises(ValueError, match="ANALYSIS_RESOURCE_SUMMARY_MISMATCH"):
        runtime.finalization.finalize(invalid)

    state = runtime.budget_registry.current_state("a1")
    assert state.status == "RUNNING"
    assert not any(
        isinstance(item, AnalysisRunResult)
        for item in runtime.queries.published_records("a1")
    )


def test_finalization_rejects_count_usage_and_error_fabrication(
    tmp_path: Path,
) -> None:
    h = Harness(tmp_path)
    profile = h.execution()
    identity_ref = reference(profile)
    assert isinstance(identity_ref, (RunStoredDataRef, StoredDataRef))
    h.evidence.identities[identity_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(
        tmp_path,
        None,
        None,
        h.clock,
        h.ids,
        evidence=h.evidence,
        analysis_finalization_identity_ref=identity_ref,
    )
    h.pin_execution(runtime.budget_registry, profile)
    result = _result(runtime.unit_of_work.artifacts)
    fabricated_error = AnalysisError.model_validate_json(
        canonical_bytes(make("AnalysisError"))
    )
    invalid_candidates = (
        (
            result.model_copy(update={"hypothesis_counts": {"TOTAL": 1}}),
            "HYPOTHESIS_COUNTS_MISMATCH",
        ),
        (
            result.model_copy(
                update={
                    "resources": result.resources.model_copy(
                        update={"usage_complete": True, "unavailable_reasons": ()}
                    )
                }
            ),
            "ANALYSIS_RESOURCE_SUMMARY_MISMATCH",
        ),
        (
            result.model_copy(update={"errors": (fabricated_error,)}),
            "ANALYSIS_ERROR_CLOSURE_MISMATCH",
        ),
    )

    for candidate, expected_error in invalid_candidates:
        with pytest.raises(ValueError, match=expected_error):
            runtime.finalization.finalize(candidate)
        assert runtime.budget_registry.current_state("a1").status == "RUNNING"
        assert not any(
            isinstance(item, AnalysisRunResult)
            for item in runtime.queries.published_records("a1")
        )


def test_finalization_denies_untrusted_callers(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    profile = h.execution()
    h.pin_execution(runtime.budget_registry, profile)
    result = _result(runtime.unit_of_work.artifacts)

    with pytest.raises(ValueError, match="trusted finalization identity"):
        runtime.finalization.finalize(result)


def test_finalization_rejects_a_nonterminal_work(tmp_path: Path) -> None:
    h, _works, _attempts, _transition, _attempt, _reservation = start_fixture(tmp_path)
    with h.database.engine.connect() as connection:
        identity_ref = get_run(connection, "a1").execution_budget_profile_ref
    h.evidence.identities[identity_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(
        tmp_path,
        None,
        None,
        h.clock,
        h.ids,
        evidence=h.evidence,
        analysis_finalization_identity_ref=identity_ref,
    )

    with pytest.raises(ValueError, match="ANALYSIS_WORK_NOT_QUIESCENT"):
        runtime.finalization.finalize(_result(runtime.unit_of_work.artifacts))

    assert runtime.budget_registry.current_state("a1").status == "RUNNING"


def test_finalization_crash_rolls_back_result_action_and_run_pointer(
    tmp_path: Path,
) -> None:
    h = Harness(tmp_path)
    profile = h.execution()
    identity_ref = reference(profile)
    assert isinstance(identity_ref, (RunStoredDataRef, StoredDataRef))
    h.evidence.identities[identity_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(
        tmp_path,
        None,
        None,
        h.clock,
        h.ids,
        evidence=h.evidence,
        analysis_finalization_identity_ref=identity_ref,
    )
    h.pin_execution(runtime.budget_registry, profile)
    result = _result(runtime.unit_of_work.artifacts)

    def crash(_name: str) -> None:
        raise RuntimeError("simulated finalization crash")

    finalization = cast(AnalysisFinalizationService, runtime.finalization.store)
    finalization.checkpoint = crash
    with pytest.raises(RuntimeError, match="simulated finalization crash"):
        runtime.finalization.finalize(result)

    assert runtime.budget_registry.current_state("a1").status == "RUNNING"
    assert not any(
        isinstance(item, (AnalysisRunResult, ActionDecision))
        for item in runtime.queries.published_records("a1")
    )
    finalization.checkpoint = lambda _name: None
    assert runtime.finalization.finalize(result) == reference(result)


def test_finalization_rejects_an_unresolved_transition_journal(
    tmp_path: Path,
) -> None:
    h, transitions, request = completion(tmp_path)

    def crash(name: str) -> None:
        if name == "PREPARED":
            raise SimulatedCrash(name)

    transitions.checkpoint = crash
    with pytest.raises(SimulatedCrash):
        transitions.commit(request)
    with h.database.engine.connect() as connection:
        identity_ref = get_run(connection, "a1").execution_budget_profile_ref
    h.evidence.identities[identity_ref] = RequesterRole.ORCHESTRATION
    finalization = AnalysisFinalizationService(
        h.records,
        h.clock,
        h.ids,
        identity_ref,
        transitions.works.validator,
        transitions.artifacts,
    )

    with pytest.raises(ValueError, match="ANALYSIS_TRANSITION_UNRESOLVED"):
        finalization.finalize(_result(transitions.artifacts))

    with h.database.engine.connect() as connection:
        assert get_run(connection, "a1").status == "RUNNING"


def test_finalization_uses_one_sample_despite_moving_wall_clock(tmp_path: Path) -> None:
    class MovingClock:
        calls = 0
        tick = 0

        def now(self) -> datetime:
            self.calls += 1
            return datetime(2026, 9, 7, tzinfo=UTC) + timedelta(milliseconds=self.calls)

        def monotonic_ms(self) -> int:
            return self.tick

    h = Harness(tmp_path)
    profile = h.execution()
    identity_ref = reference(profile)
    assert isinstance(identity_ref, (RunStoredDataRef, StoredDataRef))
    h.evidence.identities[identity_ref] = RequesterRole.ORCHESTRATION
    clock = MovingClock()
    runtime = build_runtime(
        tmp_path,
        None,
        None,
        clock,
        h.ids,
        evidence=h.evidence,
        analysis_finalization_identity_ref=identity_ref,
    )
    h.pin_execution(runtime.budget_registry, profile)
    state = runtime.budget_registry.current_state("a1")
    candidate = _result(runtime.unit_of_work.artifacts).model_copy(
        update={"started_at": state.started_at}
    )
    clock.tick = 77
    final_ref = runtime.finalization.finalize(candidate)
    final = runtime.unit_of_work.records.get_exact(final_ref)
    assert isinstance(final, AnalysisRunResult)
    assert final.elapsed_ms == 77
    assert final.finished_at != clock.now()
    state = runtime.budget_registry.current_state("a1")
    assert state.elapsed_ms == 77
    assert state.finished_at == final.finished_at
    assert runtime.finalization.finalize(candidate) == final_ref


@pytest.mark.parametrize("assigned", [False, True])
def test_registered_hypothesis_cancellation_is_not_proposal_cancellation(
    tmp_path: Path, assigned: bool
) -> None:
    from sastsimi.contracts.evaluation import ResolvedAnalysisInventory
    from sastsimi.contracts.hypothesis import (
        HypothesisProcessState,
        ProposalProcessState,
        VerificationAssignment,
    )

    h = Harness(tmp_path)
    profile = h.execution()
    identity = reference(profile)
    assert isinstance(identity, (RunStoredDataRef, StoredDataRef))
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(
        tmp_path,
        None,
        None,
        h.clock,
        h.ids,
        evidence=h.evidence,
        analysis_finalization_identity_ref=identity,
    )
    h.pin_execution(runtime.budget_registry, profile)
    assignment = VerificationAssignment.model_validate_json(
        canonical_bytes(make("VerificationAssignment"))
    )
    h.publish(assignment)
    process = HypothesisProcessState.model_validate_json(
        canonical_bytes(
            make("HypothesisProcessState")
            | {
                "status": "CANCELLED",
                "verification_generation": 1 if assigned else 0,
                "verification_assignment_ref": reference(assignment)
                if assigned
                else None,
                "finished_at": "2026-09-08T00:00:00Z",
            }
        )
    )
    proposal_state = ProposalProcessState.model_validate_json(
        canonical_bytes(
            make("ProposalProcessState")
            | {
                "status": "SCHEMA_VALID",
                "registration_reason": "NO_CANDIDATES",
                "duplicate_review_ref": None,
                "duplicate_of_hypothesis_ref": None,
                "finished_at": "2026-09-08T00:00:00Z",
            }
        )
    )
    candidate = _result(runtime.unit_of_work.artifacts).model_copy(
        update={
            "hypothesis_counts": {
                "TOTAL": 1,
                "PROPOSAL_TOTAL": 1,
                "REGISTERED": 1,
                "DUPLICATE": 0,
                "INVALID_OUTPUT": 0,
                "CANCELLED": 0,
                "DUPLICATE_UNIQUE": 0,
                "DUPLICATE_UNCERTAIN": 0,
                "CHECK_FAILED": 0,
                "INVALID_DUPLICATE_TARGET": 0,
            }
        }
    )
    finalization = cast(AnalysisFinalizationService, runtime.finalization.store)
    inventory = ResolvedAnalysisInventory(
        records={},
        expected_refs={"work_attempt_refs": ()},
        current_verification_refs={},
        verification_generations={},
    )
    state = runtime.budget_registry.current_state("a1")
    with h.database.engine.connect() as connection:
        if assigned:
            with pytest.raises(
                ValueError, match="ANALYSIS_ASSIGNMENT_CLOSURE_MISMATCH"
            ):
                finalization._validate_readiness_and_summaries(
                    connection, candidate, (process, proposal_state), inventory, state
                )
        finalization._validate_readiness_and_summaries(
            connection,
            candidate,
            (process, proposal_state, assignment)
            if assigned
            else (process, proposal_state),
            inventory,
            state,
        )
