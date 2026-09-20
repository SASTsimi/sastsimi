import asyncio
import json
import threading
from dataclasses import dataclass

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    LLMInvocationRequest,
    ProviderValidationEvidence,
    ProviderValidationTest,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import CapabilityProbeResult
from sastsimi.providers.base import (
    CodexProcessRequest,
    CodexProcessResult,
    CodexProcessRunner,
)
from sastsimi.providers.codex_subscription import CodexSubscriptionAdapter
from tests.contract.domain.canonical_fixtures import make
from tests.integration.providers.test_openai_api import (
    _ARRAY_SCHEMA_BYTES,
    ArrayOutputSchemaValidator,
    FixedClock,
    OutputSchemaValidator,
    PromptResolver,
    ResultBuilder,
    SchemaPromptResolver,
    SessionStore,
    output_schema_record,
    prompt_payload_record,
    request,
    request_for_schema,
    resolved_prompt,
    validated_output_ref,
)


@dataclass
class FakeCodexProcessRunner:
    result: CodexProcessResult

    def __post_init__(self) -> None:
        self.requests: list[CodexProcessRequest] = []

    async def execute(self, value: CodexProcessRequest) -> CodexProcessResult:
        self.requests.append(value)
        return self.result


class SerialObservationRunner:
    def __init__(self) -> None:
        self.requests: list[CodexProcessRequest] = []
        self.first_started = asyncio.Event()
        self.release_first = asyncio.Event()
        self.active = 0
        self.max_active = 0

    async def execute(self, value: CodexProcessRequest) -> CodexProcessResult:
        self.requests.append(value)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if len(self.requests) == 1:
                self.first_started.set()
                await self.release_first.wait()
            return CodexProcessResult(
                status="SUCCEEDED",
                final_message=b'{"decision":"accept"}',
                provider_session_id=f"provider-{value.invocation_id}",
            )
        finally:
            self.active -= 1


class CrossThreadSerialObservationRunner:
    def __init__(self) -> None:
        self.requests: list[CodexProcessRequest] = []
        self.first_started = threading.Event()
        self.release_first = threading.Event()
        self.guard = threading.Lock()
        self.active = 0
        self.max_active = 0

    async def execute(self, value: CodexProcessRequest) -> CodexProcessResult:
        with self.guard:
            self.requests.append(value)
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            first = len(self.requests) == 1
        try:
            if first:
                self.first_started.set()
                await asyncio.to_thread(self.release_first.wait)
            return CodexProcessResult(
                status="SUCCEEDED",
                final_message=b'{"decision":"accept"}',
                provider_session_id=f"provider-{value.invocation_id}",
            )
        finally:
            with self.guard:
                self.active -= 1


class PassingProbeRunner:
    async def run(
        self, candidate: ProviderValidationEvidence, _adapter: object
    ) -> CapabilityProbeResult:
        return CapabilityProbeResult(candidate)


class PoCContentRepairValidator(OutputSchemaValidator):
    def validate(self, raw: bytes, **_kwargs: object) -> object:
        value = json.loads(raw)
        assert value == {"decision": "contains-sensitive-placeholder"}
        return {"decision": "accept"}


def adapter(
    invocation: LLMInvocationRequest,
    runner: CodexProcessRunner,
) -> tuple[CodexSubscriptionAdapter, SessionStore]:
    sessions = SessionStore()
    return (
        CodexSubscriptionAdapter(
            provider_profile_ref=invocation.provider_profile_ref,
            model=invocation.model,
            prompt_resolver=PromptResolver(),
            process_runner=runner,
            session_store=sessions,
            output_schema_validator=OutputSchemaValidator(),
            result_builder=ResultBuilder(),
            clock=FixedClock(),
        ),
        sessions,
    )


@pytest.mark.asyncio
async def test_subscription_processes_are_serialized_per_adapter() -> None:
    first = request()
    second = first.model_copy(update={"llm_call_id": "llm-call-serial-second"})
    runner = SerialObservationRunner()
    provider, _sessions = adapter(first, runner)

    first_task = asyncio.create_task(provider.invoke(first))
    await asyncio.wait_for(runner.first_started.wait(), timeout=1)
    second_task = asyncio.create_task(provider.invoke(second))
    await asyncio.sleep(0.05)

    assert len(runner.requests) == 1
    runner.release_first.set()
    first_result, second_result = await asyncio.gather(first_task, second_task)

    assert first_result.status == second_result.status == "SUCCEEDED"
    assert len(runner.requests) == 2
    assert runner.max_active == 1


@pytest.mark.asyncio
async def test_subscription_processes_are_serialized_across_adapters() -> None:
    first = request()
    second = first.model_copy(update={"llm_call_id": "llm-call-other-adapter"})
    runner = SerialObservationRunner()
    first_provider, _first_sessions = adapter(first, runner)
    second_provider, _second_sessions = adapter(second, runner)

    first_task = asyncio.create_task(first_provider.invoke(first))
    await asyncio.wait_for(runner.first_started.wait(), timeout=1)
    second_task = asyncio.create_task(second_provider.invoke(second))
    await asyncio.sleep(0.05)

    assert len(runner.requests) == 1
    runner.release_first.set()
    first_result, second_result = await asyncio.gather(first_task, second_task)

    assert first_result.status == second_result.status == "SUCCEEDED"
    assert len(runner.requests) == 2
    assert runner.max_active == 1


@pytest.mark.asyncio
async def test_subscription_processes_are_serialized_across_worker_threads() -> None:
    first = request()
    second = first.model_copy(update={"llm_call_id": "llm-call-worker-thread"})
    runner = CrossThreadSerialObservationRunner()
    first_provider, _first_sessions = adapter(first, runner)
    second_provider, _second_sessions = adapter(second, runner)

    first_task = asyncio.create_task(
        asyncio.to_thread(asyncio.run, first_provider.invoke(first))
    )
    assert await asyncio.to_thread(runner.first_started.wait, 1)
    second_task = asyncio.create_task(
        asyncio.to_thread(asyncio.run, second_provider.invoke(second))
    )
    await asyncio.sleep(0.05)

    try:
        assert len(runner.requests) == 1
    finally:
        runner.release_first.set()
    first_result, second_result = await asyncio.gather(first_task, second_task)

    assert first_result.status == second_result.status == "SUCCEEDED"
    assert len(runner.requests) == 2
    assert runner.max_active == 1


@pytest.mark.asyncio
async def test_poc_content_may_use_the_validator_redacted_field_value() -> None:
    seed = request().model_copy(
        update={
            "agent_role": "DYNAMIC_REPRODUCTION",
            "task_kind": "CREATE_POC_CANDIDATE",
        }
    )
    schema_ref = reference(output_schema_record(seed))
    payload_ref = reference(prompt_payload_record(seed))
    assert isinstance(schema_ref, StoredDataRef)
    assert isinstance(payload_ref, StoredDataRef)
    invocation = seed.model_copy(
        update={"output_schema_ref": schema_ref, "prompt_payload_ref": payload_ref}
    )
    runner = FakeCodexProcessRunner(
        CodexProcessResult(
            status="SUCCEEDED",
            final_message=b'{"decision":"contains-sensitive-placeholder"}',
            provider_session_id="provider-poc-repair",
        )
    )
    provider, _sessions = adapter(invocation, runner)
    provider.output_schema_validator = PoCContentRepairValidator()

    result = await provider.invoke(invocation)

    assert result.status == "SUCCEEDED"
    assert result.parsed_output_ref == validated_output_ref(
        invocation, {"decision": "accept"}
    )


@pytest.mark.asyncio
async def test_non_poc_output_cannot_be_rewritten_by_the_validator() -> None:
    invocation = request()
    runner = FakeCodexProcessRunner(
        CodexProcessResult(
            status="SUCCEEDED",
            final_message=b'{"decision":"contains-sensitive-placeholder"}',
            provider_session_id="provider-non-poc-repair",
        )
    )
    provider, sessions = adapter(invocation, runner)
    provider.output_schema_validator = PoCContentRepairValidator()

    result = await provider.invoke(invocation)

    assert result.status == "INVALID_OUTPUT"
    assert result.parsed_output_ref is None
    assert sessions.registered == []


@pytest.mark.asyncio
async def test_codex_uses_exact_rendered_prompt_schema_model_and_new_session() -> None:
    """Changing the authorized prompt, schema, model, or session must fail this."""
    invocation = request()
    runner = FakeCodexProcessRunner(
        CodexProcessResult(
            status="SUCCEEDED",
            final_message=b'{"decision":"accept"}',
            provider_session_id="provider-thread-1",
        )
    )
    provider, sessions = adapter(invocation, runner)

    result = await provider.invoke(invocation)

    assert result.status == "SUCCEEDED"
    assert result.provider == "OPENAI"
    assert result.model == invocation.model
    assert result.actual_session_mode == "NEW"
    assert result.session_ref == f"local-session-{invocation.llm_call_id}"
    assert sessions.registered == [("provider-thread-1", invocation.llm_call_id)]
    resolved = resolved_prompt(invocation)
    assert runner.requests == [
        CodexProcessRequest(
            invocation_id=invocation.llm_call_id,
            provider_profile_ref=invocation.provider_profile_ref,
            model=invocation.model,
            prompt=resolved.rendered_prompt_bytes,
            output_schema=resolved.output_schema_bytes,
            timeout_ms=invocation.timeout_ms,
        )
    ]


@pytest.mark.asyncio
async def test_probe_cannot_claim_pvd_02_without_observed_server_model() -> None:
    invocation = request()
    runner = FakeCodexProcessRunner(CodexProcessResult("FAILED", None, None))
    provider, _sessions = adapter(invocation, runner)
    provider.probe_runner = PassingProbeRunner()
    candidate = ProviderValidationEvidence.model_validate_json(
        canonical_bytes(make("ProviderValidationEvidence"))
    ).model_copy(
        update={
            "product": "CODEX",
            "transport": "CODEX_CLIENT",
            "auth_mode": "SUBSCRIPTION_LOGIN",
            "tests": (
                ProviderValidationTest(
                    test_id="PVD-02",
                    result="PASS",
                    evidence_refs=(invocation.provider_profile_ref,),
                    safe_summary="requested model was accepted",
                ),
            ),
        }
    )

    result = await provider.probe(candidate)

    assert result.evidence.tests[0].result == "FAIL"
    assert result.evidence.tests[0].safe_summary == (
        "Codex exec did not expose provider-reported model identity"
    )


@pytest.mark.asyncio
async def test_codex_auth_failure_stays_a_provider_status_without_output() -> None:
    """An expired ChatGPT login must not become content or a domain verdict."""
    invocation = request()
    runner = FakeCodexProcessRunner(
        CodexProcessResult(
            status="AUTH_REQUIRED",
            final_message=b'{"decision":"accept"}',
            provider_session_id="must-not-be-registered",
        )
    )
    provider, sessions = adapter(invocation, runner)

    result = await provider.invoke(invocation)

    assert result.status == "AUTH_REQUIRED"
    assert result.safe_error == "AUTH_REQUIRED: Codex ChatGPT login is required"
    assert result.response_ref is None
    assert result.parsed_output_ref is None
    assert result.session_ref is None
    assert sessions.registered == []
    assert "must-not-be-registered" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_codex_rate_limit_stays_a_provider_status_without_output() -> None:
    invocation = request()
    runner = FakeCodexProcessRunner(
        CodexProcessResult(
            status="RATE_LIMITED",
            final_message=None,
            provider_session_id=None,
        )
    )
    provider, sessions = adapter(invocation, runner)

    result = await provider.invoke(invocation)

    assert result.status == "RATE_LIMITED"
    assert result.safe_error == (
        "RATE_LIMITED: Codex subscription usage limit was reached"
    )
    assert result.response_ref is None
    assert result.parsed_output_ref is None
    assert result.session_ref is None
    assert sessions.registered == []


@pytest.mark.asyncio
async def test_codex_rejects_a_model_outside_the_bound_profile() -> None:
    invocation = request()
    runner = FakeCodexProcessRunner(
        CodexProcessResult(
            status="SUCCEEDED",
            final_message=b'{"decision":"accept"}',
            provider_session_id="provider-thread-mismatch",
        )
    )
    provider, sessions = adapter(invocation, runner)

    result = await provider.invoke(
        invocation.model_copy(update={"model": "another-profile-model"})
    )

    assert result.status == "FAILED"
    assert result.safe_error == (
        "FAILED: authorized Codex request inputs did not match"
    )
    assert runner.requests == []
    assert sessions.registered == []


class BlockingCodexProcessRunner:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.tree_terminated = False

    async def execute(self, value: CodexProcessRequest) -> CodexProcessResult:
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.tree_terminated = True
            raise
        raise AssertionError("unreachable")


class UnconfirmedCleanupProcessRunner:
    async def execute(self, value: CodexProcessRequest) -> CodexProcessResult:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            raise RuntimeError("secret cleanup diagnostic") from None
        raise AssertionError("unreachable")


@pytest.mark.asyncio
async def test_codex_timeout_terminates_process_tree_and_returns_status() -> None:
    """Removing the adapter deadline would leave the Codex process tree alive."""
    invocation = request().model_copy(update={"timeout_ms": 10})
    runner = BlockingCodexProcessRunner()
    provider, _sessions = adapter(invocation, runner)

    result = await asyncio.wait_for(provider.invoke(invocation), timeout=0.5)

    assert result.status == "TIMED_OUT"
    assert result.safe_error == (
        "TIMED_OUT: Codex subscription request exceeded its deadline"
    )
    assert runner.tree_terminated


@pytest.mark.asyncio
async def test_unconfirmed_tree_cleanup_never_claims_timeout_success() -> None:
    invocation = request().model_copy(update={"timeout_ms": 10})
    provider, _sessions = adapter(invocation, UnconfirmedCleanupProcessRunner())

    result = await asyncio.wait_for(provider.invoke(invocation), timeout=0.5)

    assert result.status == "FAILED"
    assert result.safe_error == "FAILED: Codex subscription request failed"
    assert "secret cleanup diagnostic" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_codex_cancel_terminates_process_tree_and_returns_status() -> None:
    """Cancellation must not return until the child process tree is gone."""
    invocation = request()
    runner = BlockingCodexProcessRunner()
    provider, _sessions = adapter(invocation, runner)
    invocation_task = asyncio.create_task(provider.invoke(invocation))
    await asyncio.wait_for(runner.started.wait(), timeout=0.5)

    cancellation = await asyncio.wait_for(
        provider.cancel(invocation.llm_call_id), timeout=0.5
    )
    result = await asyncio.wait_for(invocation_task, timeout=0.5)

    assert cancellation.cancelled
    assert cancellation.reason is None
    assert result.status == "CANCELLED"
    assert result.safe_error == "CANCELLED: Codex subscription request was cancelled"
    assert runner.tree_terminated


@pytest.mark.asyncio
async def test_codex_invalid_schema_output_is_a_status_without_artifacts() -> None:
    """Malformed structured output must never escape as a verdict artifact."""
    invocation = request()
    runner = FakeCodexProcessRunner(
        CodexProcessResult(
            status="SUCCEEDED",
            final_message=b'{"decision":"test-secret-never-persist"}',
            provider_session_id="provider-thread-invalid",
        )
    )
    provider, sessions = adapter(invocation, runner)

    result = await provider.invoke(invocation)

    assert result.status == "INVALID_OUTPUT"
    assert result.safe_error == (
        "INVALID_OUTPUT: Codex returned invalid structured output"
    )
    assert result.response_ref is None
    assert result.parsed_output_ref is None
    assert result.session_ref is None
    assert sessions.registered == []
    assert "test-secret-never-persist" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_codex_unwraps_array_transport_before_validation_and_storage() -> None:
    invocation = request_for_schema(_ARRAY_SCHEMA_BYTES)
    runner = FakeCodexProcessRunner(
        CodexProcessResult(
            status="SUCCEEDED",
            final_message=(b'{"items":[{"decision":"accept"},{"decision":"reject"}]}'),
            provider_session_id="provider-thread-array",
        )
    )
    provider, _sessions = adapter(invocation, runner)
    validator = ArrayOutputSchemaValidator()
    provider.prompt_resolver = SchemaPromptResolver(_ARRAY_SCHEMA_BYTES)
    provider.output_schema_validator = validator

    result = await provider.invoke(invocation)

    expected = [{"decision": "accept"}, {"decision": "reject"}]
    assert result.status == "SUCCEEDED"
    assert validator.values == [expected]


# mypy: disable-error-code="assignment,override"
