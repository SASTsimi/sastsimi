from __future__ import annotations

import dataclasses
import inspect
from typing import get_type_hints

import pytest

import sastsimi.ports as public_ports
from sastsimi.contracts.llm import LLMInvocationRequest, LLMInvocationResult
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.chaining import (
    ChainedHypothesisContent,
    ChainingAgentInput,
    ChainingAgentOutcome,
    ChainingAgentOutput,
    ChainingAgentPort,
    ChainingChildHandoffPort,
    ChainingCohortPort,
    ChainingComparison,
    ChainingDecision,
    ChainingEvidence,
    ChainingLineagePort,
    ChainingMatchIdentity,
    ChainingMatchReservationPort,
    ChainingPoolHistory,
    ChainingPoolHistoryPort,
    ChainingPrimitive,
    ChainingPrimitiveInput,
    ChainingPrimitiveResult,
    ChainingReconciliationPort,
    HoldPrimitiveAdmissionClosure,
    PinnedChainingUniverse,
    PrimitiveAdmissionSourcePort,
    PrimitiveUpdateReconciliationRequest,
    TruePrimitiveAdmissionClosure,
)
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from tests.contract.domain.fixtures import ref


def _ref(kind: str, *, suffix: str = "1") -> StoredDataRef:
    value = ref(kind) | {
        "stored_data_id": f"{kind}-s{suffix}",
        "record_id": f"{kind}-r{suffix}",
    }
    return StoredDataRef.model_validate(value)


def test_exact_admission_closures_are_frozen_and_kind_checked() -> None:
    hold = HoldPrimitiveAdmissionClosure(
        verification_ref=_ref("verification_result"),
        hypothesis_process_ref=_ref("hypothesis_process_state"),
        expected_primitive_index_ref=_ref("primitive_index_state"),
    )

    assert hold.input_refs() == (
        hold.verification_ref,
        hold.hypothesis_process_ref,
        hold.expected_primitive_index_ref,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        hold.verification_ref = _ref("verification_result", suffix="2")  # type: ignore[misc]
    with pytest.raises(ValueError, match="PRIMITIVE_ADMISSION_REF_KIND"):
        HoldPrimitiveAdmissionClosure(
            verification_ref=_ref("cwe_label"),
            hypothesis_process_ref=hold.hypothesis_process_ref,
            expected_primitive_index_ref=hold.expected_primitive_index_ref,
        )


def test_pinned_universe_requires_one_exact_trigger_and_no_duplicate_refs() -> None:
    trigger = _ref("primitive", suffix="trigger")
    other = _ref("primitive", suffix="other")
    universe = PinnedChainingUniverse(
        trigger_primitive_ref=trigger,
        index_refs=(_ref("primitive_index_state"),),
        considered_primitive_refs=(trigger, other),
    )

    assert universe.considered_primitive_refs == (trigger, other)
    with pytest.raises(ValueError, match="CHAINING_TRIGGER_NOT_PINNED"):
        PinnedChainingUniverse(
            trigger_primitive_ref=trigger,
            index_refs=(_ref("primitive_index_state"),),
            considered_primitive_refs=(other,),
        )
    with pytest.raises(ValueError, match="CHAINING_PINNED_REF_DUPLICATE"):
        PinnedChainingUniverse(
            trigger_primitive_ref=trigger,
            index_refs=(_ref("primitive_index_state"),),
            considered_primitive_refs=(trigger, trigger),
        )


def test_pool_history_preserves_the_exact_work_time_universe() -> None:
    trigger = _ref("primitive", suffix="trigger")
    universe = PinnedChainingUniverse(
        trigger_primitive_ref=trigger,
        index_refs=(_ref("primitive_index_state"),),
        considered_primitive_refs=(trigger, _ref("primitive", suffix="other")),
    )

    history = ChainingPoolHistory(
        trigger_work_ref=_ref("work_execution_state"),
        universe=universe,
    )

    assert history.universe is universe
    assert (
        "current"
        not in inspect.signature(ChainingPoolHistoryPort.get_for_trigger).parameters
    )


def test_agent_boundary_is_content_only_and_uses_prompt_local_keys() -> None:
    evidence = ChainingEvidence(
        evidence_key="ev-1",
        kind="CODE_FLOW",
        summary="Validated call path reaches the authorization boundary.",
    )
    upstream = ChainingPrimitive(
        primitive_key="p-up",
        description="Attacker-controlled account can invoke the endpoint.",
        inputs=(),
        result=ChainingPrimitiveResult(
            description="Endpoint can be invoked as the victim.",
            entity_keys=("entity-login",),
            privilege_level="victim",
            evidence_keys=("ev-1",),
        ),
        restrictions=("Requires a valid victim session.",),
    )
    downstream = ChainingPrimitive(
        primitive_key="p-down",
        description="Sensitive update requires victim-level invocation.",
        inputs=(
            ChainingPrimitiveInput(
                input_key="input-victim",
                description="Invoke update as the victim.",
                entity_keys=("entity-update",),
                privilege_level="victim",
                evidence_keys=("ev-1",),
            ),
        ),
        result=None,
        restrictions=(),
    )
    agent_input = ChainingAgentInput(
        evidence=(evidence,),
        primitives=(upstream, downstream),
        comparisons=(
            ChainingComparison(
                comparison_key="cmp-1",
                upstream_key="p-up",
                downstream_key="p-down",
                input_key="input-victim",
            ),
        ),
    )
    output = ChainingAgentOutput(
        decisions=(
            ChainingDecision(
                comparison_key="cmp-1",
                outcome="MATCH",
                reason_code=None,
                detail="The proven victim invocation supplies the required input.",
                evidence_keys=("ev-1",),
                child=ChainedHypothesisContent(
                    statement="Victim invocation may permit the sensitive update.",
                    vulnerability_type_candidates=("CWE-639",),
                    falsification_questions=(
                        "Does the chained call reach the update with victim identity?",
                    ),
                    validation_checks=("Revalidate the full chained path.",),
                ),
            ),
        )
    )

    assert agent_input.comparisons[0].comparison_key == "cmp-1"
    assert output.decisions[0].child is not None
    content_types = (
        ChainedHypothesisContent,
        ChainingAgentInput,
        ChainingAgentOutput,
        ChainingComparison,
        ChainingDecision,
        ChainingEvidence,
        ChainingPrimitive,
        ChainingPrimitiveInput,
        ChainingPrimitiveResult,
    )
    for model in content_types:
        assert dataclasses.is_dataclass(model)
        for field in dataclasses.fields(model):
            assert field.name != "meta"
            assert not field.name.endswith(("_ref", "_refs", "_id", "_ids"))
        assert "StoredDataRef" not in repr(get_type_hints(model))


def test_content_output_rejects_runtime_owned_or_incomplete_decisions() -> None:
    with pytest.raises(TypeError):
        ChainingDecision(  # type: ignore[call-arg]
            comparison_key="cmp-1",
            primitive_match_id="provider-owned-id",
            outcome="MATCH",
            reason_code=None,
            detail="Invalid provider authority.",
            evidence_keys=("ev-1",),
            child=None,
        )


def _invocation(status: str) -> PersistedLLMInvocation:
    return PersistedLLMInvocation(
        request=LLMInvocationRequest.model_construct(),
        result=LLMInvocationResult.model_construct(status=status),
        log_ref=_ref("llm_invocation_log"),
        dispatch_state="RETURNED",
    )


def test_provider_failure_cannot_become_empty_success_or_no_match() -> None:
    failure = _invocation("AUTH_REQUIRED")
    empty_success = ChainingAgentOutput(decisions=())

    with pytest.raises(ValueError, match="CHAINING_INVOCATION_OUTCOME_MISMATCH"):
        ChainingAgentOutcome(invocation=failure, content=empty_success)
    assert ChainingAgentOutcome(invocation=failure, content=None).content is None

    success = _invocation("SUCCEEDED")
    with pytest.raises(ValueError, match="CHAINING_INVOCATION_OUTCOME_MISMATCH"):
        ChainingAgentOutcome(invocation=success, content=None)
    with pytest.raises(ValueError, match="CHAINING_MATCH_CHILD_REQUIRED"):
        ChainingDecision(
            comparison_key="cmp-1",
            outcome="MATCH",
            reason_code=None,
            detail="Missing child.",
            evidence_keys=("ev-1",),
            child=None,
        )


def test_ports_expose_only_exact_ready_or_transactional_boundaries() -> None:
    expected_protocols = (
        PrimitiveAdmissionSourcePort,
        ChainingPoolHistoryPort,
        ChainingCohortPort,
        ChainingAgentPort,
        ChainingLineagePort,
        ChainingMatchReservationPort,
        ChainingReconciliationPort,
        ChainingChildHandoffPort,
    )
    for protocol in expected_protocols:
        source = inspect.getsource(protocol)
        assert "Connection" not in source
        assert "Session" not in source
        assert "execute(" not in source

    assert "promote_ready" in ChainingCohortPort.__dict__
    assert "enqueue_ready" in ChainingChildHandoffPort.__dict__
    assert "start" not in ChainingChildHandoffPort.__dict__
    assert "claim" not in ChainingChildHandoffPort.__dict__
    assert "reserve_for_result" in ChainingMatchReservationPort.__dict__


def test_chaining_seams_are_available_from_the_public_ports_package() -> None:
    assert public_ports.ChainingAgentPort is ChainingAgentPort
    assert public_ports.ChainingCohortPort is ChainingCohortPort
    assert public_ports.ChainingPoolHistoryPort is ChainingPoolHistoryPort
    assert public_ports.ChainingChildHandoffPort is ChainingChildHandoffPort


def test_reconciliation_request_requires_an_exact_committed_source_kind() -> None:
    request = PrimitiveUpdateReconciliationRequest(
        source_update_ref=_ref("transition_commit")
    )
    assert request.source_update_ref.data_kind == "transition_commit"

    with pytest.raises(ValueError, match="RECONCILIATION_SOURCE_KIND"):
        PrimitiveUpdateReconciliationRequest(
            source_update_ref=_ref("primitive_index_state")
        )


def test_match_identity_requires_exact_primitive_refs() -> None:
    identity = ChainingMatchIdentity(
        primitive_match_id="trusted-match-1",
        upstream_result_ref=_ref("primitive", suffix="up"),
        downstream_input_ref=_ref("primitive", suffix="down"),
        matched_input_id="required-capability-1",
    )
    assert identity.upstream_result_ref != identity.downstream_input_ref

    with pytest.raises(ValueError, match="CHAINING_SELF_MATCH"):
        ChainingMatchIdentity(
            primitive_match_id="trusted-match-2",
            upstream_result_ref=identity.upstream_result_ref,
            downstream_input_ref=identity.upstream_result_ref,
            matched_input_id="required-capability-1",
        )


def test_true_closure_keeps_all_gate_inputs_exact_and_ordered() -> None:
    closure = TruePrimitiveAdmissionClosure(
        hypothesis_process_ref=_ref("hypothesis_process_state"),
        verification_ref=_ref("verification_result"),
        dynamic_request_ref=_ref("dynamic_reproduction_request"),
        dynamic_result_ref=_ref("dynamic_reproduction_result"),
        poc_ref=_ref("poc_bundle"),
        cwe_label_ref=_ref("cwe_label"),
        technical_review_ref=_ref("technical_evidence_review"),
        run_policy_state_ref=_ref("run_policy_state"),
        collection_ref=_ref("policy_collection_result"),
        expected_primitive_index_ref=_ref("primitive_index_state"),
    )

    assert closure.input_refs()[0] == closure.hypothesis_process_ref
    assert closure.input_refs()[-1] == closure.expected_primitive_index_ref
