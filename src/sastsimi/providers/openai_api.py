"""OpenAI Responses API adapter with injected official async client boundary."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Literal, cast

from pydantic import JsonValue

from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.evaluation import UsageMeasurement
from sastsimi.contracts.llm import (
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.dto import CancellationResult, CapabilityProbeResult

from .base import (
    Clock,
    CredentialUnavailableError,
    InvocationResultBuilder,
    NormalizedProviderResult,
    OpenAIResponsesClientFactory,
    OutputSchemaValidator,
    PromptInputResolver,
    ProviderInputMismatchError,
    ProviderInvalidOutputError,
    ProviderProbeRunner,
    ProviderSessionStore,
    ResolvedPromptInput,
    SecretResolver,
)
from .normalization import (
    NormalizedFailure,
    failure,
    normalize_exception,
    normalize_response_failure,
)


class OpenAIResponsesApiAdapter:
    """One exact API profile/model path; no tools, persistence or silent fallback.

    The dependency-injected factory must wrap the official ``AsyncOpenAI`` client,
    create it with ``max_retries=0`` and close it after this invocation.  The optional
    SDK dependency and concrete factory are intentionally deferred to the Task 16
    composition root.
    """

    def __init__(
        self,
        *,
        provider_profile_ref: StoredDataRef,
        model: str,
        credential_ref: SecretReference,
        prompt_resolver: PromptInputResolver,
        secret_resolver: SecretResolver,
        client_factory: OpenAIResponsesClientFactory,
        session_store: ProviderSessionStore,
        output_schema_validator: OutputSchemaValidator,
        result_builder: InvocationResultBuilder,
        clock: Clock,
        probe_runner: ProviderProbeRunner | None = None,
    ) -> None:
        self.provider_profile_ref = provider_profile_ref
        self.model = model
        self.credential_ref = credential_ref
        self.prompt_resolver = prompt_resolver
        self.secret_resolver = secret_resolver
        self.client_factory = client_factory
        self.session_store = session_store
        self.output_schema_validator = output_schema_validator
        self.result_builder = result_builder
        self.clock = clock
        self.probe_runner = probe_runner
        self._active: dict[str, asyncio.Task[LLMInvocationResult]] = {}
        self._active_lock = asyncio.Lock()

    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult:
        if self.probe_runner is not None:
            return await self.probe_runner.run(candidate, self)
        evidence = candidate.model_copy(
            update={
                "tests": tuple(
                    test.model_copy(
                        update={
                            "result": "FAIL",
                            "safe_summary": (
                                "OpenAI API probe runner is not configured"
                            ),
                        }
                    )
                    for test in candidate.tests
                )
            }
        )
        return CapabilityProbeResult(evidence=evidence)

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        current = asyncio.current_task()
        if current is None:
            raise RuntimeError("FAILED: OpenAI invocation requires an asyncio task")
        async with self._active_lock:
            if request.llm_call_id in self._active:
                return self._failed_before_call(
                    request,
                    NormalizedFailure(
                        "FAILED", "FAILED: duplicate OpenAI invocation is active"
                    ),
                )
            self._active[request.llm_call_id] = current
        try:
            return await self._invoke_active(request)
        finally:
            async with self._active_lock:
                if self._active.get(request.llm_call_id) is current:
                    del self._active[request.llm_call_id]

    async def _invoke_active(
        self, request: LLMInvocationRequest
    ) -> LLMInvocationResult:
        started_at = self.clock.now()
        started_ms = self.clock.monotonic_ms()
        session_mode: Literal["NEW", "RESUMED"] = (
            "RESUMED" if request.session_policy == "RESUME" else "NEW"
        )
        try:
            resolved, schema, previous_response_id = await self._prepare(request)
            kwargs = self._request_arguments(
                request, resolved, schema, previous_response_id
            )
            credential = await self.secret_resolver.resolve(self.credential_ref)
            if not credential.strip():
                raise CredentialUnavailableError
            client_context = self.client_factory.open(credential, max_retries=0)
            del credential
            async with client_context as client:
                async with asyncio.timeout(request.timeout_ms / 1_000):
                    response = await client.responses.create(**kwargs)
            outcome = await self._success_outcome(
                request,
                response,
                started_at=started_at,
                started_ms=started_ms,
                session_mode=session_mode,
                schema=schema,
            )
        except asyncio.CancelledError:
            outcome = self._failure_outcome(
                request,
                failure("CANCELLED"),
                started_at=started_at,
                started_ms=started_ms,
                session_mode=session_mode,
            )
        except Exception as error:
            outcome = self._failure_outcome(
                request,
                normalize_exception(error),
                started_at=started_at,
                started_ms=started_ms,
                session_mode=session_mode,
            )
        return self._build_checked(request, outcome)

    async def _prepare(
        self, request: LLMInvocationRequest
    ) -> tuple[ResolvedPromptInput, dict[str, JsonValue], str | None]:
        if (
            request.provider_profile_ref != self.provider_profile_ref
            or request.model != self.model
        ):
            raise ProviderInputMismatchError
        if request.session_policy == "AUTO":
            raise ProviderInputMismatchError
        if (request.session_policy == "NEW") != (request.parent_session_ref is None):
            raise ProviderInputMismatchError
        resolved = await self.prompt_resolver.resolve(request)
        if (
            resolved.prompt_payload_ref != request.prompt_payload_ref
            or resolved.prompt_registry_entry_ref != request.prompt_registry_entry_ref
            or resolved.prompt_template_ref != request.prompt_template_ref
            or resolved.output_schema_ref != request.output_schema_ref
            or not resolved.instructions.strip()
            or not resolved.untrusted_input.strip()
        ):
            raise ProviderInputMismatchError
        try:
            parsed_schema = json.loads(request.output_schema)
        except (TypeError, ValueError) as error:
            raise ProviderInputMismatchError from error
        if not isinstance(parsed_schema, dict):
            raise ProviderInputMismatchError
        schema = cast(dict[str, JsonValue], parsed_schema)
        previous_response_id = None
        if request.session_policy == "RESUME":
            assert request.parent_session_ref is not None
            previous_response_id = (
                await self.session_store.resolve_previous_response_id(
                    request.parent_session_ref
                )
            )
            if not previous_response_id.strip():
                raise ProviderInputMismatchError
        return resolved, schema, previous_response_id

    @staticmethod
    def _request_arguments(
        request: LLMInvocationRequest,
        resolved: ResolvedPromptInput,
        schema: dict[str, JsonValue],
        previous_response_id: str | None,
    ) -> dict[str, object]:
        arguments: dict[str, object] = {
            "model": request.model,
            "instructions": resolved.instructions,
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": resolved.untrusted_input}
                    ],
                }
            ],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "sastsimi_output",
                    "strict": True,
                    "schema": schema,
                }
            },
            "tools": [],
            "tool_choice": "none",
            "parallel_tool_calls": False,
            "store": False,
            "stream": False,
            "background": False,
            "truncation": "disabled",
            "timeout": request.timeout_ms / 1_000,
        }
        if request.token_budget is not None:
            arguments["max_output_tokens"] = request.token_budget
        if previous_response_id is not None:
            arguments["previous_response_id"] = previous_response_id
        return arguments

    async def _success_outcome(
        self,
        request: LLMInvocationRequest,
        response: object,
        *,
        started_at: datetime,
        started_ms: int,
        session_mode: Literal["NEW", "RESUMED"],
        schema: dict[str, JsonValue],
    ) -> NormalizedProviderResult:
        status = getattr(response, "status", None)
        if status != "completed":
            provider_error = getattr(response, "error", None)
            code = getattr(provider_error, "code", None)
            normalized = normalize_response_failure(
                status if isinstance(status, str) else "unknown",
                code if isinstance(code, str) else None,
            )
            return self._failure_outcome(
                request,
                normalized,
                started_at=started_at,
                started_ms=started_ms,
                session_mode=session_mode,
            )
        response_model = getattr(response, "model", None)
        response_id = getattr(response, "id", None)
        output_text = getattr(response, "output_text", None)
        if (
            response_model != request.model
            or not isinstance(response_id, str)
            or not response_id.strip()
            or not isinstance(output_text, str)
        ):
            raise ProviderInvalidOutputError
        try:
            parsed = json.loads(output_text)
        except ValueError as error:
            raise ProviderInvalidOutputError from error
        if not isinstance(parsed, dict):
            raise ProviderInvalidOutputError
        parsed_output = cast(dict[str, JsonValue], parsed)
        try:
            self.output_schema_validator.validate(
                parsed_output,
                schema,
            )
        except ProviderInvalidOutputError:
            raise
        except Exception as error:
            raise ProviderInvalidOutputError from error
        session_ref = await self.session_store.register_response(
            response_id, request.llm_call_id
        )
        if not session_ref.strip():
            raise ProviderInvalidOutputError
        finished_at = self.clock.now()
        elapsed_ms = max(0, self.clock.monotonic_ms() - started_ms)
        return NormalizedProviderResult(
            status="SUCCEEDED",
            provider="OPENAI",
            model=request.model,
            actual_session_mode=session_mode,
            session_ref=session_ref,
            response_text=output_text,
            parsed_output=parsed_output,
            usage=_usage(response),
            started_at=started_at,
            finished_at=finished_at,
            elapsed_ms=elapsed_ms,
            safe_error=None,
        )

    def _failure_outcome(
        self,
        request: LLMInvocationRequest,
        normalized: NormalizedFailure,
        *,
        started_at: datetime,
        started_ms: int,
        session_mode: Literal["NEW", "RESUMED"],
    ) -> NormalizedProviderResult:
        return NormalizedProviderResult(
            status=normalized.status,
            provider="OPENAI",
            model=request.model,
            actual_session_mode=session_mode,
            session_ref=None,
            response_text=None,
            parsed_output=None,
            usage=None,
            started_at=started_at,
            finished_at=self.clock.now(),
            elapsed_ms=max(0, self.clock.monotonic_ms() - started_ms),
            safe_error=normalized.safe_error,
        )

    def _failed_before_call(
        self, request: LLMInvocationRequest, normalized: NormalizedFailure
    ) -> LLMInvocationResult:
        now = self.clock.now()
        outcome = NormalizedProviderResult(
            status=normalized.status,
            provider="OPENAI",
            model=request.model,
            actual_session_mode=(
                "RESUMED" if request.session_policy == "RESUME" else "NEW"
            ),
            session_ref=None,
            response_text=None,
            parsed_output=None,
            usage=None,
            started_at=now,
            finished_at=now,
            elapsed_ms=0,
            safe_error=normalized.safe_error,
        )
        return self._build_checked(request, outcome)

    def _build_checked(
        self, request: LLMInvocationRequest, outcome: NormalizedProviderResult
    ) -> LLMInvocationResult:
        result = LLMInvocationResult.model_validate(
            self.result_builder.build(request, outcome)
        )
        expected_success = outcome.status == "SUCCEEDED"
        if (
            result.meta.record_type != "llm_invocation_result"
            or any(
                getattr(result.meta, field) != getattr(request.meta, field)
                for field in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                    "attempt_id",
                )
            )
            or result.llm_call_id != request.llm_call_id
            or result.purpose != request.purpose
            or result.status != outcome.status
            or result.provider != "OPENAI"
            or result.model != request.model
            or result.actual_session_mode != outcome.actual_session_mode
            or result.session_ref != outcome.session_ref
            or result.usage != outcome.usage
            or result.started_at != outcome.started_at
            or result.finished_at != outcome.finished_at
            or result.elapsed_ms != outcome.elapsed_ms
            or result.safe_error != outcome.safe_error
            or expected_success
            != (
                result.response_ref is not None and result.parsed_output_ref is not None
            )
        ):
            raise ValueError("PROVIDER_RESULT_BUILDER_MISMATCH")
        return result

    async def cancel(self, invocation_id: str) -> CancellationResult:
        async with self._active_lock:
            task = self._active.get(invocation_id)
        if task is None:
            return CancellationResult(False, "No matching active invocation")
        if task is asyncio.current_task():
            return CancellationResult(False, "Invocation cannot cancel itself")
        task.cancel()
        try:
            result = await task
        except asyncio.CancelledError:
            return CancellationResult(True, None)
        return CancellationResult(result.status == "CANCELLED", None)


def _usage(response: object) -> UsageMeasurement:
    observed = getattr(response, "usage", None)
    input_tokens = getattr(observed, "input_tokens", None)
    output_tokens = getattr(observed, "output_tokens", None)
    total_tokens = getattr(observed, "total_tokens", None)
    if (
        isinstance(input_tokens, int)
        and not isinstance(input_tokens, bool)
        and input_tokens >= 0
        and isinstance(output_tokens, int)
        and not isinstance(output_tokens, bool)
        and output_tokens >= 0
        and isinstance(total_tokens, int)
        and not isinstance(total_tokens, bool)
        and total_tokens == input_tokens + output_tokens
    ):
        return UsageMeasurement(
            token_source="PROVIDER_REPORTED",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            token_unavailable_reason=None,
            provider_units={"requests": 1},
            cost_source="UNAVAILABLE",
            cost_minor_units=None,
            currency=None,
            pricing_revision_ref=None,
            cost_unavailable_reason="Provider response did not include trusted cost",
        )
    return UsageMeasurement(
        token_source="UNAVAILABLE",
        input_tokens=None,
        output_tokens=None,
        total_tokens=None,
        token_unavailable_reason="Provider response did not include valid token usage",
        provider_units={"requests": 1},
        cost_source="UNAVAILABLE",
        cost_minor_units=None,
        currency=None,
        pricing_revision_ref=None,
        cost_unavailable_reason="Provider response did not include trusted cost",
    )


__all__ = ["OpenAIResponsesApiAdapter"]
