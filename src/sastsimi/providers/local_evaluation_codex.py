"""Purpose-safe official Codex subscription calls for local evaluation.

This module deliberately does not create Provider validation evidence, a quality
recommendation, or Production approval.  It only narrows an already exact Codex
binding to ``LOCAL_EVALUATION`` requests whose session policy is ``NEW``.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from typing import Final, Literal

from sastsimi.contracts.llm import LLMInvocationRequest, LLMInvocationResult
from sastsimi.contracts.refs import StoredDataRef, reference

from .base import (
    Clock,
    InvocationResultBuilder,
    OutputSchemaValidator,
    PromptInputResolver,
    ProviderSessionStore,
)
from .codex_subscription import (
    ApprovedCodexExecutionBinding,
    CodexCliProcessRunner,
    CodexSubscriptionAdapter,
)

_SAFE_REASON: Final = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")


class LocalEvaluationCodexUnavailable(RuntimeError):
    """A safe reason why the local Codex call must not run or be accepted."""

    def __init__(self, reason_code: str) -> None:
        if _SAFE_REASON.fullmatch(reason_code) is None:
            reason_code = "LOCAL_EVALUATION_CODEX_UNAVAILABLE"
        self.reason_code = reason_code
        super().__init__(reason_code)


class LocalEvaluationCodexCallService:
    """Allow one exact local-evaluation call per fresh official-client session."""

    purpose: Literal["LOCAL_EVALUATION"] = "LOCAL_EVALUATION"

    def __init__(
        self,
        *,
        binding: ApprovedCodexExecutionBinding,
        adapter: CodexSubscriptionAdapter,
    ) -> None:
        provider_profile_ref = reference(binding.provider_profile)
        if (
            not isinstance(provider_profile_ref, StoredDataRef)
            or adapter.provider_profile_ref != provider_profile_ref
            or adapter.model != binding.provider_profile.model
        ):
            raise LocalEvaluationCodexUnavailable(
                "LOCAL_EVALUATION_CODEX_ROUTE_MISMATCH"
            )
        self.binding = binding
        self.adapter = adapter
        self._provider_profile_ref = provider_profile_ref
        self._model = binding.provider_profile.model
        self._seen_call_ids: set[str] = set()
        self._seen_session_refs: set[str] = set()
        self._identity_lock = asyncio.Lock()

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        """Invoke the exact route, preserving every fail-closed provider status."""
        self._require_request(request)
        async with self._identity_lock:
            if request.llm_call_id in self._seen_call_ids:
                raise LocalEvaluationCodexUnavailable(
                    "LOCAL_EVALUATION_CODEX_CALL_ID_REUSED"
                )
            self._seen_call_ids.add(request.llm_call_id)
        try:
            result = await self.adapter.invoke(request)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise LocalEvaluationCodexUnavailable(
                "LOCAL_EVALUATION_CODEX_CALL_FAILED"
            ) from None
        self._require_result(request, result)
        if result.status == "SUCCEEDED":
            assert result.session_ref is not None
            async with self._identity_lock:
                if result.session_ref in self._seen_session_refs:
                    raise LocalEvaluationCodexUnavailable(
                        "LOCAL_EVALUATION_CODEX_SESSION_REUSED"
                    )
                self._seen_session_refs.add(result.session_ref)
        return result

    def _require_request(self, request: LLMInvocationRequest) -> None:
        if request.purpose != self.purpose:
            raise LocalEvaluationCodexUnavailable(
                "LOCAL_EVALUATION_CODEX_PURPOSE_MISMATCH"
            )
        if (
            request.provider_profile_ref != self._provider_profile_ref
            or request.model != self._model
        ):
            raise LocalEvaluationCodexUnavailable(
                "LOCAL_EVALUATION_CODEX_ROUTE_MISMATCH"
            )
        if request.session_policy != "NEW" or request.parent_session_ref is not None:
            reason = (
                "LOCAL_EVALUATION_CODEX_DYNAMIC_RESUME_UNSUPPORTED"
                if request.agent_role == "DYNAMIC_REPRODUCTION"
                else "LOCAL_EVALUATION_CODEX_SESSION_RESUME_UNSUPPORTED"
            )
            raise LocalEvaluationCodexUnavailable(reason)

    def _require_result(
        self,
        request: LLMInvocationRequest,
        result: LLMInvocationResult,
    ) -> None:
        scope_fields = (
            "analysis_id",
            "workspace_id",
            "commit_id",
            "hypothesis_id",
            "attempt_id",
        )
        if (
            result.llm_call_id != request.llm_call_id
            or result.purpose != self.purpose
            or result.provider != "OPENAI"
            or result.model != self._model
            or result.actual_session_mode != "NEW"
            or any(
                getattr(result.meta, field) != getattr(request.meta, field)
                for field in scope_fields
            )
        ):
            raise LocalEvaluationCodexUnavailable(
                "LOCAL_EVALUATION_CODEX_RESULT_MISMATCH"
            )


def build_local_evaluation_codex_call_service(
    *,
    binding: ApprovedCodexExecutionBinding,
    prompt_resolver: PromptInputResolver,
    session_store: ProviderSessionStore,
    output_schema_validator: OutputSchemaValidator,
    result_builder: InvocationResultBuilder,
    clock: Clock,
    binding_validator: Callable[[ApprovedCodexExecutionBinding], None] | None = None,
) -> LocalEvaluationCodexCallService:
    """Compose the exact official CLI adapter without Production approval objects."""
    provider_profile_ref = reference(binding.provider_profile)
    if not isinstance(provider_profile_ref, StoredDataRef):
        raise LocalEvaluationCodexUnavailable("LOCAL_EVALUATION_CODEX_ROUTE_MISMATCH")
    runner = CodexCliProcessRunner(
        binding=binding,
        binding_validator=binding_validator,
    )
    adapter = CodexSubscriptionAdapter(
        provider_profile_ref=provider_profile_ref,
        model=binding.provider_profile.model,
        prompt_resolver=prompt_resolver,
        process_runner=runner,
        session_store=session_store,
        output_schema_validator=output_schema_validator,
        result_builder=result_builder,
        clock=clock,
    )
    return LocalEvaluationCodexCallService(binding=binding, adapter=adapter)


__all__ = [
    "LocalEvaluationCodexCallService",
    "LocalEvaluationCodexUnavailable",
    "build_local_evaluation_codex_call_service",
]
