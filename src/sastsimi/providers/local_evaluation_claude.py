"""Purpose-safe official Claude Code subscription calls for local evaluation.

This module deliberately does not create Provider validation evidence, a quality
recommendation, or Production approval.  It only narrows an already exact Claude
Code binding to ``LOCAL_EVALUATION`` requests whose session policy is ``NEW``.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from typing import Final, Literal

from sastsimi.contracts.llm import (
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import CancellationResult, CapabilityProbeResult

from .base import (
    Clock,
    InvocationResultBuilder,
    OutputSchemaValidator,
    PromptInputResolver,
    ProviderSessionStore,
    SubscriptionProcessRunner,
)
from .claude_subscription import (
    ApprovedClaudeExecutionBinding,
    ClaudeCliProcessRunner,
    ClaudeSubscriptionAdapter,
)
from .local_claude_validation import (
    LocalEvaluationClaudeProcessRunner,
    LocalValidatedClaudeExecutionBinding,
)

type LocalClaudeBinding = (
    ApprovedClaudeExecutionBinding | LocalValidatedClaudeExecutionBinding
)

_SAFE_REASON: Final = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")


class LocalEvaluationClaudeUnavailable(RuntimeError):
    """A safe reason why the local Claude Code call must not run or be accepted."""

    def __init__(self, reason_code: str) -> None:
        if _SAFE_REASON.fullmatch(reason_code) is None:
            reason_code = "LOCAL_EVALUATION_CLAUDE_UNAVAILABLE"
        self.reason_code = reason_code
        super().__init__(reason_code)


class LocalEvaluationClaudeCallService:
    """Allow one exact local-evaluation call per fresh official-client session."""

    purpose: Literal["LOCAL_EVALUATION"] = "LOCAL_EVALUATION"

    def __init__(
        self,
        *,
        binding: LocalClaudeBinding,
        adapter: ClaudeSubscriptionAdapter,
    ) -> None:
        provider_profile_ref = reference(binding.provider_profile)
        if (
            not isinstance(provider_profile_ref, StoredDataRef)
            or adapter.provider_profile_ref != provider_profile_ref
            or adapter.model != binding.provider_profile.model
        ):
            raise LocalEvaluationClaudeUnavailable(
                "LOCAL_EVALUATION_CLAUDE_ROUTE_MISMATCH"
            )
        self.binding = binding
        self.adapter = adapter
        self.provider_profile_ref = provider_profile_ref
        self.model = binding.provider_profile.model
        self._seen_call_ids: set[str] = set()
        self._seen_session_refs: set[str] = set()
        self._identity_lock = asyncio.Lock()

    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult:
        """Probe only the exact Provider identity bound to this local route."""
        self._require_probe_identity(candidate)
        try:
            result = await self.adapter.probe(candidate)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise LocalEvaluationClaudeUnavailable(
                "LOCAL_EVALUATION_CLAUDE_PROBE_FAILED"
            ) from None
        self._require_probe_identity(result.evidence)
        return result

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        """Invoke the exact route, preserving every fail-closed provider status."""
        self._require_request(request)
        async with self._identity_lock:
            if request.llm_call_id in self._seen_call_ids:
                raise LocalEvaluationClaudeUnavailable(
                    "LOCAL_EVALUATION_CLAUDE_CALL_ID_REUSED"
                )
            self._seen_call_ids.add(request.llm_call_id)
        try:
            result = await self.adapter.invoke(request)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise LocalEvaluationClaudeUnavailable(
                "LOCAL_EVALUATION_CLAUDE_CALL_FAILED"
            ) from None
        self._require_result(request, result)
        if result.status == "SUCCEEDED":
            assert result.session_ref is not None
            async with self._identity_lock:
                if result.session_ref in self._seen_session_refs:
                    raise LocalEvaluationClaudeUnavailable(
                        "LOCAL_EVALUATION_CLAUDE_SESSION_REUSED"
                    )
                self._seen_session_refs.add(result.session_ref)
        return result

    async def cancel(self, invocation_id: str) -> CancellationResult:
        """Cancel only a call identifier previously admitted by this wrapper."""
        async with self._identity_lock:
            owned = invocation_id in self._seen_call_ids
        if not owned:
            return CancellationResult(False, "No matching local evaluation invocation")
        try:
            return await self.adapter.cancel(invocation_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise LocalEvaluationClaudeUnavailable(
                "LOCAL_EVALUATION_CLAUDE_CANCEL_FAILED"
            ) from None

    def _require_probe_identity(self, candidate: ProviderValidationEvidence) -> None:
        profile = self.binding.provider_profile
        fields = (
            "profile_key",
            "provider",
            "product",
            "transport",
            "model",
            "environment",
            "auth_mode",
            "client_name",
            "client_version",
        )
        if any(
            getattr(candidate, field) != getattr(profile, field) for field in fields
        ):
            raise LocalEvaluationClaudeUnavailable(
                "LOCAL_EVALUATION_CLAUDE_ROUTE_MISMATCH"
            )

    def _require_request(self, request: LLMInvocationRequest) -> None:
        if request.purpose != self.purpose:
            raise LocalEvaluationClaudeUnavailable(
                "LOCAL_EVALUATION_CLAUDE_PURPOSE_MISMATCH"
            )
        if (
            request.provider_profile_ref != self.provider_profile_ref
            or request.model != self.model
        ):
            raise LocalEvaluationClaudeUnavailable(
                "LOCAL_EVALUATION_CLAUDE_ROUTE_MISMATCH"
            )
        if request.session_policy != "NEW" or request.parent_session_ref is not None:
            reason = (
                "LOCAL_EVALUATION_CLAUDE_DYNAMIC_RESUME_UNSUPPORTED"
                if request.agent_role == "DYNAMIC_REPRODUCTION"
                else "LOCAL_EVALUATION_CLAUDE_SESSION_RESUME_UNSUPPORTED"
            )
            raise LocalEvaluationClaudeUnavailable(reason)

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
            or result.provider != "ANTHROPIC"
            or result.model != self.model
            or result.actual_session_mode != "NEW"
            or any(
                getattr(result.meta, field) != getattr(request.meta, field)
                for field in scope_fields
            )
        ):
            raise LocalEvaluationClaudeUnavailable(
                "LOCAL_EVALUATION_CLAUDE_RESULT_MISMATCH"
            )


def build_local_evaluation_claude_call_service(
    *,
    binding: LocalClaudeBinding,
    prompt_resolver: PromptInputResolver,
    session_store: ProviderSessionStore,
    output_schema_validator: OutputSchemaValidator,
    result_builder: InvocationResultBuilder,
    clock: Clock,
    binding_validator: Callable[[ApprovedClaudeExecutionBinding], None] | None = None,
) -> LocalEvaluationClaudeCallService:
    """Compose the exact official CLI adapter without Production approval objects."""
    provider_profile_ref = reference(binding.provider_profile)
    if not isinstance(provider_profile_ref, StoredDataRef):
        raise LocalEvaluationClaudeUnavailable("LOCAL_EVALUATION_CLAUDE_ROUTE_MISMATCH")
    runner: SubscriptionProcessRunner
    if isinstance(binding, LocalValidatedClaudeExecutionBinding):
        if binding_validator is not None:
            binding_validator(binding.experimental_binding)
        runner = LocalEvaluationClaudeProcessRunner(binding=binding)
    else:
        runner = ClaudeCliProcessRunner(
            binding=binding,
            binding_validator=binding_validator,
        )
    adapter = ClaudeSubscriptionAdapter(
        provider_profile_ref=provider_profile_ref,
        model=binding.provider_profile.model,
        prompt_resolver=prompt_resolver,
        process_runner=runner,
        session_store=session_store,
        output_schema_validator=output_schema_validator,
        result_builder=result_builder,
        clock=clock,
    )
    return LocalEvaluationClaudeCallService(binding=binding, adapter=adapter)


__all__ = [
    "LocalClaudeBinding",
    "LocalEvaluationClaudeCallService",
    "LocalEvaluationClaudeUnavailable",
    "build_local_evaluation_claude_call_service",
]
