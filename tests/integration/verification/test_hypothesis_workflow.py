from __future__ import annotations

from dataclasses import dataclass

import pytest

from sastsimi.agents.hypothesis import HypothesisAgentOutcome
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import LLMInvocationLog
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.hypothesis_workflow import HypothesisWorkflow
from tests.contract.domain.canonical_fixtures import make
from tests.integration.verification.test_hypothesis_agent import (
    MemoryArtifacts,
    _bundle,
    _invocation,
    _work,
    metadata,
    stored_ref,
)


@dataclass
class _Agent:
    outcome: HypothesisAgentOutcome

    async def propose(self, **_: object) -> HypothesisAgentOutcome:
        return self.outcome


class _Records:
    def __init__(self, values: dict[RecordRef, object]) -> None:
        self.values = values

    def get_exact(self, ref: RecordRef) -> object:
        return self.values[ref]


class _Runner:
    def __init__(self, completed: WorkExecutionState) -> None:
        self.completed = completed
        self.action_input_refs: tuple[RecordRef, ...] | None = None

    def complete(self, *args: object, **kwargs: object) -> WorkExecutionState:
        self.action_input_refs = kwargs.get("action_input_refs")  # type: ignore[assignment]
        return self.completed


def _successful_outcome() -> tuple[
    HypothesisAgentOutcome, StoredDataRef, LLMInvocationLog
]:
    artifacts = MemoryArtifacts()
    bundle = _bundle()
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    work = _work(bundle_ref)
    invocation = _invocation(artifacts, work, bundle_ref, [])
    request, result = invocation.request, invocation.result
    data = make("LLMInvocationLog")
    data.update(
        meta=metadata(
            "llm_invocation_log",
            "hypothesis-log",
            hypothesis_id=None,
            attempt_id=work.active_attempt_id,
        ),
        llm_call_id=request.llm_call_id,
        action_decision_ref=request.action_decision_ref,
        call_spec_ref=request.call_spec_ref,
        agent_role=request.agent_role,
        task_kind=request.task_kind,
        purpose=request.purpose,
        provider_profile_ref=request.provider_profile_ref,
        provider=result.provider,
        model=request.model,
        session_policy=request.session_policy,
        session_ref=result.session_ref,
        parent_session_ref=request.parent_session_ref,
        prompt_registry_entry_ref=request.prompt_registry_entry_ref,
        prompt_key=request.prompt_key,
        prompt_template_ref=request.prompt_template_ref,
        prompt_template_version=request.prompt_template_version,
        prompt_payload_ref=request.prompt_payload_ref,
        execution_limits_ref=request.execution_limits_ref,
        retry_policy_ref=request.retry_policy_ref,
        tool_policy_ref=request.tool_policy_ref,
        redaction_policy_ref=request.redaction_policy_ref,
        semantic_validator_ref=request.semantic_validator_ref,
        output_schema_ref=request.output_schema_ref,
        context_refs=request.context_refs,
        exposed_request_ref=stored_ref("artifact", "exposed-request").model_copy(
            update={"record_id": None}
        ),
        exposed_response_ref=result.response_ref,
        parsed_output_ref=result.parsed_output_ref,
        status=result.status,
        safe_error=result.safe_error,
        started_at=result.started_at,
        finished_at=result.finished_at,
        elapsed_ms=result.elapsed_ms,
    )
    log = LLMInvocationLog.model_validate_json(canonical_bytes(data))
    log_ref = reference(log)
    assert isinstance(log_ref, StoredDataRef)
    invocation = type(invocation)(request, result, log_ref, "RETURNED")
    return HypothesisAgentOutcome(invocation, ()), bundle_ref, log


@pytest.mark.asyncio
async def test_success_pins_exact_invocation_and_artifact_before_completion() -> None:
    outcome, bundle_ref, log = _successful_outcome()
    work = _work(bundle_ref)
    request_ref = reference(outcome.invocation.request)
    result_ref = reference(outcome.invocation.result)
    log_ref = reference(log)
    assert isinstance(request_ref, StoredDataRef)
    assert isinstance(result_ref, StoredDataRef)
    assert isinstance(log_ref, StoredDataRef)
    runner = _Runner(work)
    records = _Records(
        {
            request_ref: outcome.invocation.request,
            result_ref: outcome.invocation.result,
            log_ref: log,
        }
    )
    workflow = HypothesisWorkflow(
        agent=_Agent(outcome),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        records=records,  # type: ignore[arg-type]
    )

    result = await workflow.run(
        work=work,
        orchestration_identity_ref=stored_ref("action_request", "orchestration"),
        decision_ref=outcome.invocation.request.action_decision_ref,
        reservation_ref=stored_ref("budget_reservation", "reservation"),
        call_spec_ref=outcome.invocation.request.call_spec_ref,
        static_bundle=_bundle(),
        static_bundle_ref=bundle_ref,
    )

    assert result.completed_work == work
    assert runner.action_input_refs == (
        bundle_ref,
        request_ref,
        result_ref,
        log_ref,
        outcome.invocation.result.parsed_output_ref,
    )


@pytest.mark.asyncio
async def test_missing_persisted_log_stops_storage() -> None:
    outcome, bundle_ref, _log = _successful_outcome()
    work = _work(bundle_ref)
    runner = _Runner(work)
    workflow = HypothesisWorkflow(
        agent=_Agent(outcome),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        records=_Records({}),  # type: ignore[arg-type]
    )

    with pytest.raises(KeyError):
        await workflow.run(
            work=work,
            orchestration_identity_ref=stored_ref("action_request", "orchestration"),
            decision_ref=outcome.invocation.request.action_decision_ref,
            reservation_ref=stored_ref("budget_reservation", "reservation"),
            call_spec_ref=outcome.invocation.request.call_spec_ref,
            static_bundle=_bundle(),
            static_bundle_ref=bundle_ref,
        )

    assert runner.action_input_refs is None
