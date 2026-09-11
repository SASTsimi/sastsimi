"""OpenAI Responses API adapter with injected official async client boundary."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime
from typing import Literal, cast

from pydantic import JsonValue

from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.evaluation import UsageMeasurement
from sastsimi.contracts.llm import (
    LLMInvocationRequest,
    LLMInvocationResult,
    OutputSchemaSpec,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef, reference
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

_WORK_CLEANUP_TIMEOUT_SECONDS = 0.1
_CANCEL_CONFIRM_TIMEOUT_SECONDS = 0.5


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
        self._cancel_events: dict[str, asyncio.Event] = {}
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
        cancel_event = asyncio.Event()
        async with self._active_lock:
            if request.llm_call_id in self._active:
                return self._failed_before_call(
                    request,
                    NormalizedFailure(
                        "FAILED", "FAILED: duplicate OpenAI invocation is active"
                    ),
                )
            self._active[request.llm_call_id] = current
            self._cancel_events[request.llm_call_id] = cancel_event
        try:
            return await self._invoke_active(request, cancel_event)
        finally:
            async with self._active_lock:
                if self._active.get(request.llm_call_id) is current:
                    del self._active[request.llm_call_id]
                    self._cancel_events.pop(request.llm_call_id, None)

    async def _invoke_active(
        self, request: LLMInvocationRequest, cancel_event: asyncio.Event
    ) -> LLMInvocationResult:
        started_at = self.clock.now()
        started_ms = self.clock.monotonic_ms()
        session_mode: Literal["NEW", "RESUMED"] = "NEW"

        async def within_deadline() -> LLMInvocationResult:
            try:
                resolved, schema, instructions, untrusted_input = await self._prepare(
                    request
                )
                self._raise_if_cancel_requested(cancel_event)
                kwargs = self._request_arguments(
                    request, instructions, untrusted_input, schema
                )
                credential = await self.secret_resolver.resolve(self.credential_ref)
                self._raise_if_cancel_requested(cancel_event)
                if not credential.strip():
                    raise CredentialUnavailableError
                client_context = self.client_factory.open(credential, max_retries=0)
                del credential
                async with client_context as client:
                    self._raise_if_cancel_requested(cancel_event)
                    response = await client.responses.create(**kwargs)
                    self._raise_if_cancel_requested(cancel_event)
                outcome = await self._success_outcome(
                    request,
                    response,
                    started_at=started_at,
                    started_ms=started_ms,
                    session_mode=session_mode,
                    schema=schema,
                    output_schema=resolved.output_schema,
                    cancel_event=cancel_event,
                )
            except Exception as error:
                outcome = self._failure_outcome(
                    request,
                    normalize_exception(error),
                    started_at=started_at,
                    started_ms=started_ms,
                    session_mode=session_mode,
                )
            self._raise_if_cancel_requested(cancel_event)
            return self._build_checked(request, outcome)

        work_task = asyncio.create_task(within_deadline())
        try:
            done, _pending = await asyncio.wait(
                (work_task,), timeout=request.timeout_ms / 1_000
            )
            if done:
                return await work_task
            cancel_event.set()
            work_task.cancel()
            await _bounded_cleanup(work_task)
            outcome = self._failure_outcome(
                request,
                failure("TIMED_OUT"),
                started_at=started_at,
                started_ms=started_ms,
                session_mode=session_mode,
            )
        except asyncio.CancelledError:
            cancel_event.set()
            work_task.cancel()
            await _bounded_cleanup(work_task)
            outcome = self._failure_outcome(
                request,
                failure("CANCELLED"),
                started_at=started_at,
                started_ms=started_ms,
                session_mode=session_mode,
            )
        return self._build_checked(request, outcome)

    async def _prepare(
        self, request: LLMInvocationRequest
    ) -> tuple[ResolvedPromptInput, dict[str, JsonValue], str, str]:
        if (
            request.provider_profile_ref != self.provider_profile_ref
            or request.model != self.model
        ):
            raise ProviderInputMismatchError
        if request.session_policy != "NEW" or request.parent_session_ref is not None:
            raise ProviderInputMismatchError
        resolved = await self.prompt_resolver.resolve(request)
        try:
            payload_ref = reference(resolved.payload)
            output_schema_ref = reference(resolved.output_schema)
        except (TypeError, ValueError) as error:
            raise ProviderInputMismatchError from error
        payload = resolved.payload
        if (
            not isinstance(payload_ref, StoredDataRef)
            or payload_ref != request.prompt_payload_ref
            or not isinstance(output_schema_ref, StoredDataRef)
            or output_schema_ref != request.output_schema_ref
            or payload.registry_entry_ref != request.prompt_registry_entry_ref
            or payload.prompt_key != request.prompt_key
            or payload.agent_role != request.agent_role
            or payload.task_kind != request.task_kind
            or payload.purpose != request.purpose
            or payload.template_ref != request.prompt_template_ref
            or payload.template_version != request.prompt_template_version
            or payload.output_schema_ref != request.output_schema_ref
            or tuple(binding.source_ref for binding in payload.context_bindings)
            != request.context_refs
            or request.output_schema_ref.data_kind != "output_schema_spec"
            or any(
                getattr(payload.meta, field) != getattr(request.meta, field)
                for field in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                    "attempt_id",
                )
            )
        ):
            raise ProviderInputMismatchError

        if (
            _sha256(resolved.template_bytes) != payload.template_ref.content_hash
            or _sha256(resolved.output_schema_bytes)
            != resolved.output_schema.schema_artifact_ref.content_hash
            or _sha256(resolved.rendered_prompt_bytes)
            != payload.rendered_prompt_ref.content_hash
        ):
            raise ProviderInputMismatchError

        if len(resolved.projected_contexts) != len(payload.context_bindings):
            raise ProviderInputMismatchError
        rendered_bindings: list[dict[str, JsonValue]] = []
        for binding, context in zip(
            payload.context_bindings, resolved.projected_contexts, strict=True
        ):
            if (
                binding.trust_class != "UNTRUSTED_DATA"
                or context.slot != binding.slot
                or context.projected_data_ref != binding.projected_data_ref
                or _sha256(context.data) != binding.projected_data_ref.content_hash
            ):
                raise ProviderInputMismatchError
            value = _strict_json(context.data, ProviderInputMismatchError)
            if canonical_bytes(value) != context.data:
                raise ProviderInputMismatchError
            rendered_bindings.append(
                cast(
                    dict[str, JsonValue],
                    {
                        "slot": binding.slot,
                        "trust_class": "UNTRUSTED_DATA",
                        "sha256": _sha256(context.data),
                        "data": value,
                    },
                )
            )

        data_section = canonical_bytes({"bindings": rendered_bindings})
        data_section = data_section.replace(b"<", b"\\u003c").replace(
            b">", b"\\u003e"
        )
        untrusted_bytes = (
            b"<UNTRUSTED_DATA>\n" + data_section + b"\n</UNTRUSTED_DATA>\n"
        )
        expected_rendered = resolved.template_bytes + b"\n" + untrusted_bytes
        if expected_rendered != resolved.rendered_prompt_bytes:
            raise ProviderInputMismatchError

        schema_value = _strict_json(
            resolved.output_schema_bytes, ProviderInputMismatchError
        )
        if not isinstance(schema_value, dict):
            raise ProviderInputMismatchError
        try:
            request_schema_bytes = request.output_schema.encode("utf-8")
            instructions = resolved.template_bytes.decode("utf-8")
            untrusted_input = untrusted_bytes.decode("utf-8")
        except UnicodeError as error:
            raise ProviderInputMismatchError from error
        if (
            canonical_bytes(schema_value) != resolved.output_schema_bytes
            or request_schema_bytes != resolved.output_schema_bytes
            or not instructions.strip()
        ):
            raise ProviderInputMismatchError
        return resolved, schema_value, instructions, untrusted_input

    @staticmethod
    def _request_arguments(
        request: LLMInvocationRequest,
        instructions: str,
        untrusted_input: str,
        schema: dict[str, JsonValue],
    ) -> dict[str, object]:
        return {
            "model": request.model,
            "instructions": instructions,
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": untrusted_input}
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

    async def _success_outcome(
        self,
        request: LLMInvocationRequest,
        response: object,
        *,
        started_at: datetime,
        started_ms: int,
        session_mode: Literal["NEW", "RESUMED"],
        schema: dict[str, JsonValue],
        output_schema: OutputSchemaSpec,
        cancel_event: asyncio.Event,
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
        raw_output = output_text.encode("utf-8")
        parsed = _strict_json(raw_output, ProviderInvalidOutputError)
        if not isinstance(parsed, dict):
            raise ProviderInvalidOutputError
        parsed_output = parsed
        try:
            validated_output = self.output_schema_validator.validate(
                raw_output,
                schema=schema,
                output_schema=output_schema,
                request=request,
            )
            validated_ref = reference(validated_output)
            validated_meta = validated_output.meta
            if (
                not isinstance(validated_ref, StoredDataRef)
                or validated_meta.record_type != output_schema.result_kind
                or canonical_bytes(validated_output) != canonical_bytes(parsed_output)
                or any(
                    getattr(validated_meta, field) != getattr(request.meta, field)
                    for field in (
                        "analysis_id",
                        "workspace_id",
                        "commit_id",
                        "hypothesis_id",
                        "attempt_id",
                    )
                )
            ):
                raise ProviderInvalidOutputError
        except ProviderInvalidOutputError:
            raise
        except Exception as error:
            raise ProviderInvalidOutputError from error
        self._raise_if_cancel_requested(cancel_event)
        session_ref = await self.session_store.register_response(
            response_id, request.llm_call_id
        )
        self._raise_if_cancel_requested(cancel_event)
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
            validated_output=validated_output,
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
            validated_output=None,
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
            actual_session_mode="NEW",
            session_ref=None,
            response_text=None,
            parsed_output=None,
            validated_output=None,
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
        expected_success = outcome.status == "SUCCEEDED"
        expected_output_ref = (
            reference(outcome.validated_output)
            if outcome.validated_output is not None
            else None
        )
        if (
            expected_success
            != (
                outcome.response_text is not None
                and outcome.parsed_output is not None
                and isinstance(expected_output_ref, StoredDataRef)
                and outcome.session_ref is not None
            )
            or (not expected_success and outcome.validated_output is not None)
        ):
            raise ValueError("PROVIDER_RESULT_BUILDER_MISMATCH")
        result = LLMInvocationResult.model_validate(
            self.result_builder.build(request, outcome)
        )
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
            or (result.response_ref is not None) != expected_success
            or result.parsed_output_ref != expected_output_ref
        ):
            raise ValueError("PROVIDER_RESULT_BUILDER_MISMATCH")
        return result

    async def cancel(self, invocation_id: str) -> CancellationResult:
        async with self._active_lock:
            task = self._active.get(invocation_id)
            cancel_event = self._cancel_events.get(invocation_id)
        if task is None:
            return CancellationResult(False, "No matching active invocation")
        if task is asyncio.current_task():
            return CancellationResult(False, "Invocation cannot cancel itself")
        if cancel_event is not None:
            cancel_event.set()
        task.cancel()
        try:
            result = await asyncio.wait_for(
                asyncio.shield(task), timeout=_CANCEL_CONFIRM_TIMEOUT_SECONDS
            )
        except TimeoutError:
            return CancellationResult(
                False, "Invocation cancellation was not confirmed before deadline"
            )
        except asyncio.CancelledError:
            return CancellationResult(True, None)
        cancelled = result.status == "CANCELLED"
        return CancellationResult(
            cancelled,
            None if cancelled else "Invocation cancellation was not confirmed",
        )

    @staticmethod
    def _raise_if_cancel_requested(cancel_event: asyncio.Event) -> None:
        if cancel_event.is_set():
            raise asyncio.CancelledError


async def _bounded_cleanup(task: asyncio.Task[object]) -> None:
    try:
        await asyncio.wait_for(
            asyncio.shield(task), timeout=_WORK_CLEANUP_TIMEOUT_SECONDS
        )
    except (TimeoutError, asyncio.CancelledError):
        pass
    if not task.done():
        task.add_done_callback(_consume_task_result)


def _consume_task_result(task: asyncio.Task[object]) -> None:
    try:
        task.result()
    except BaseException:
        pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_json(
    data: bytes, error_type: type[RuntimeError]
) -> JsonValue:
    def reject_duplicates(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        output: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate JSON member")
            output[key] = value
        return output

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        decoded = data.decode("utf-8")
        return cast(
            JsonValue,
            json.loads(
                decoded,
                object_pairs_hook=reject_duplicates,
                parse_constant=reject_constant,
            ),
        )
    except (UnicodeError, TypeError, ValueError) as error:
        raise error_type from error


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
