import asyncio
from dataclasses import dataclass

import pytest

from sastsimi.contracts.llm import LLMInvocationRequest
from sastsimi.providers.base import (
    CodexProcessRequest,
    CodexProcessResult,
    CodexProcessRunner,
)
from sastsimi.providers.codex_subscription import CodexSubscriptionAdapter
from tests.integration.providers.test_openai_api import (
    _ARRAY_SCHEMA_BYTES,
    ArrayOutputSchemaValidator,
    FixedClock,
    OutputSchemaValidator,
    PromptResolver,
    ResultBuilder,
    SchemaPromptResolver,
    SessionStore,
    request,
    request_for_schema,
    resolved_prompt,
)


@dataclass
class FakeCodexProcessRunner:
    result: CodexProcessResult

    def __post_init__(self) -> None:
        self.requests: list[CodexProcessRequest] = []

    async def execute(self, value: CodexProcessRequest) -> CodexProcessResult:
        self.requests.append(value)
        return self.result


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
            model=invocation.model,
            prompt=resolved.rendered_prompt_bytes,
            output_schema=resolved.output_schema_bytes,
            timeout_ms=invocation.timeout_ms,
        )
    ]


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
