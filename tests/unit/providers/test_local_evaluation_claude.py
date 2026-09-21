from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import CancellationResult, CapabilityProbeResult
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.providers.claude_subscription import (
    ApprovedClaudeExecutable,
    ApprovedClaudeExecutionBinding,
    ClaudeSubscriptionAdapter,
)
from sastsimi.providers.local_evaluation_claude import (
    LocalEvaluationClaudeCallService,
    LocalEvaluationClaudeUnavailable,
    build_local_evaluation_claude_call_service,
)
from tests.contract.domain.canonical_fixtures import make

_MODEL = "claude-haiku-4-5-20251001"


class _RecordingAdapter:
    def __init__(
        self,
        *,
        provider_profile_ref: StoredDataRef,
        model: str,
        result_factory: Callable[[LLMInvocationRequest], LLMInvocationResult],
    ) -> None:
        self.provider_profile_ref = provider_profile_ref
        self.model = model
        self._result_factory = result_factory
        self.requests: list[LLMInvocationRequest] = []
        self.probes: list[ProviderValidationEvidence] = []
        self.cancelled: list[str] = []

    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult:
        self.probes.append(candidate)
        return CapabilityProbeResult(evidence=candidate)

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        self.requests.append(request)
        return self._result_factory(request)

    async def cancel(self, invocation_id: str) -> CancellationResult:
        self.cancelled.append(invocation_id)
        return CancellationResult(True, None)


def _stored_ref(data_kind: str, digest: str = "b") -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": f"{data_kind}-stored",
            "data_kind": data_kind,
            "record_id": f"{data_kind}-record",
            "content_hash": digest * 64,
            "workspace_id": "ws1",
            "commit_id": "c1",
        }
    )


def _binding() -> ApprovedClaudeExecutionBinding:
    validation_ref = _stored_ref("provider_validation_evidence", "c")
    client = ClientExecutionProfile.model_validate_json(
        canonical_bytes(
            make("ClientExecutionProfile")
            | {
                "environment_variable_allowlist": (
                    "CLAUDE_CONFIG_DIR",
                    "SYSTEMROOT",
                    "WINDIR",
                    "COMSPEC",
                    "TEMP",
                    "TMP",
                ),
                "verification_evidence_ref": validation_ref.model_dump(mode="json"),
            }
        )
    )
    client_ref = reference(client)
    assert isinstance(client_ref, StoredDataRef)
    profile = ProviderProfile.model_validate_json(
        canonical_bytes(
            make("ProviderProfile")
            | {
                "provider": "ANTHROPIC",
                "product": "CLAUDE_CODE",
                "transport": "CLAUDE_CODE_CLIENT",
                "model": _MODEL,
                "auth_mode": "SUBSCRIPTION_LOGIN",
                "credential_source": "OFFICIAL_CLIENT_SESSION",
                "client_name": "claude-code",
                "client_version": "2.1.197",
                "support_status": "EXPERIMENTAL",
                "validation_evidence_ref": validation_ref.model_dump(mode="json"),
                "client_execution_profile_ref": client_ref.model_dump(mode="json"),
            }
        )
    )
    executable = Path(__file__).resolve()
    return ApprovedClaudeExecutionBinding(
        provider_profile=profile,
        client_execution_profile=client,
        executable=ApprovedClaudeExecutable(
            path=executable,
            sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        ),
        claude_config_dir=executable.parent,
        runtime_environment="PERSONAL_LOCAL",
    )


def _request(
    binding: ApprovedClaudeExecutionBinding,
    *,
    call_id: str = "call-1",
    role: str = "HYPOTHESIS",
    task_kind: str = "PROPOSE",
    purpose: str = "LOCAL_EVALUATION",
    session_policy: str = "NEW",
    parent_session_ref: str | None = None,
) -> LLMInvocationRequest:
    provider_ref = reference(binding.provider_profile)
    assert isinstance(provider_ref, StoredDataRef)
    raw = make("LLMInvocationRequest")
    raw["meta"]["record_type"] = "llm_invocation_request"
    raw.update(
        {
            "llm_call_id": call_id,
            "agent_role": role,
            "task_kind": task_kind,
            "purpose": purpose,
            "provider_profile_ref": provider_ref.model_dump(mode="json"),
            "model": binding.provider_profile.model,
            "session_policy": session_policy,
            "parent_session_ref": parent_session_ref,
        }
    )
    return LLMInvocationRequest.model_validate_json(canonical_bytes(raw))


def _validation_evidence(
    binding: ApprovedClaudeExecutionBinding,
) -> ProviderValidationEvidence:
    raw = make("ProviderValidationEvidence")
    profile = binding.provider_profile
    raw.update(
        {
            "profile_key": profile.profile_key,
            "provider": profile.provider,
            "product": profile.product,
            "transport": profile.transport,
            "model": profile.model,
            "environment": profile.environment,
            "auth_mode": profile.auth_mode,
            "client_name": profile.client_name,
            "client_version": profile.client_version,
        }
    )
    return ProviderValidationEvidence.model_validate_json(canonical_bytes(raw))


def _result(
    request: LLMInvocationRequest,
    *,
    status: str = "SUCCEEDED",
    session_ref: str | None = "local-session-1",
) -> LLMInvocationResult:
    raw = make("LLMInvocationResult")
    raw["meta"] = request.meta.model_copy(
        update={"record_type": "llm_invocation_result"}
    ).model_dump(mode="json")
    raw.update(
        {
            "llm_call_id": request.llm_call_id,
            "purpose": request.purpose,
            "provider": "ANTHROPIC",
            "model": request.model,
            "actual_session_mode": "NEW",
            "status": status,
            "session_ref": session_ref if status == "SUCCEEDED" else None,
            "response_ref": (
                _stored_ref("artifact", "d").model_dump(mode="json")
                if status == "SUCCEEDED"
                else None
            ),
            "parsed_output_ref": (
                _stored_ref("artifact", "e").model_dump(mode="json")
                if status == "SUCCEEDED"
                else None
            ),
            "safe_error": None if status == "SUCCEEDED" else f"{status}: blocked",
        }
    )
    return LLMInvocationResult.model_validate_json(canonical_bytes(raw))


def _service(
    binding: ApprovedClaudeExecutionBinding,
    result_factory: Callable[[LLMInvocationRequest], LLMInvocationResult],
) -> tuple[LocalEvaluationClaudeCallService, _RecordingAdapter]:
    provider_ref = reference(binding.provider_profile)
    assert isinstance(provider_ref, StoredDataRef)
    adapter = _RecordingAdapter(
        provider_profile_ref=provider_ref,
        model=binding.provider_profile.model,
        result_factory=result_factory,
    )
    return (
        LocalEvaluationClaudeCallService(
            binding=binding,
            adapter=cast(ClaudeSubscriptionAdapter, adapter),
        ),
        adapter,
    )


@pytest.mark.asyncio
async def test_local_call_accepts_only_exact_local_evaluation_route() -> None:
    binding = _binding()
    service, adapter = _service(binding, lambda request: _result(request))

    result = await service.invoke(_request(binding))

    assert result.status == "SUCCEEDED"
    assert result.purpose == "LOCAL_EVALUATION"
    assert result.provider == "ANTHROPIC"
    assert result.actual_session_mode == "NEW"
    assert len(adapter.requests) == 1


@pytest.mark.asyncio
async def test_local_call_service_implements_full_provider_adapter_boundary() -> None:
    binding = _binding()
    service, adapter = _service(binding, lambda request: _result(request))
    candidate = _validation_evidence(binding)

    assert isinstance(service, LLMProviderAdapter)
    assert (await service.probe(candidate)).evidence == candidate
    await service.invoke(_request(binding, call_id="owned-call"))
    assert (await service.cancel("owned-call")).cancelled is True
    assert adapter.probes == [candidate]
    assert adapter.cancelled == ["owned-call"]


@pytest.mark.asyncio
async def test_local_call_rejects_probe_and_cancel_outside_exact_route() -> None:
    binding = _binding()
    service, adapter = _service(binding, lambda request: _result(request))
    wrong = _validation_evidence(binding).model_copy(update={"model": "other-model"})

    with pytest.raises(
        LocalEvaluationClaudeUnavailable,
        match="LOCAL_EVALUATION_CLAUDE_ROUTE_MISMATCH",
    ):
        await service.probe(wrong)
    cancellation = await service.cancel("not-owned")

    assert cancellation.cancelled is False
    assert adapter.probes == []
    assert adapter.cancelled == []


@pytest.mark.asyncio
@pytest.mark.parametrize("purpose", ["PRODUCTION", "EVALUATION"])
async def test_non_local_purpose_is_rejected_before_the_claude_call(
    purpose: str,
) -> None:
    binding = _binding()
    service, adapter = _service(binding, lambda request: _result(request))

    with pytest.raises(
        LocalEvaluationClaudeUnavailable,
        match="LOCAL_EVALUATION_CLAUDE_PURPOSE_MISMATCH",
    ):
        await service.invoke(_request(binding, purpose=purpose))

    assert adapter.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("session_policy", "parent_session_ref"),
    [("AUTO", None), ("RESUME", "previous-session")],
)
async def test_resume_dependent_dynamic_reproduction_is_blocked_before_call(
    session_policy: str,
    parent_session_ref: str | None,
) -> None:
    binding = _binding()
    service, adapter = _service(binding, lambda request: _result(request))

    with pytest.raises(
        LocalEvaluationClaudeUnavailable,
        match="LOCAL_EVALUATION_CLAUDE_DYNAMIC_RESUME_UNSUPPORTED",
    ):
        await service.invoke(
            _request(
                binding,
                role="DYNAMIC_REPRODUCTION",
                task_kind="EXECUTE_REPRODUCTION",
                session_policy=session_policy,
                parent_session_ref=parent_session_ref,
            )
        )

    assert adapter.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status", ["AUTH_REQUIRED", "RATE_LIMITED", "INVALID_OUTPUT", "FAILED"]
)
async def test_claude_failure_is_preserved_and_never_becomes_success(
    status: str,
) -> None:
    binding = _binding()
    service, _adapter = _service(
        binding, lambda request: _result(request, status=status, session_ref=None)
    )

    result = await service.invoke(_request(binding))

    assert result.status == status
    assert result.session_ref is None
    assert result.parsed_output_ref is None
    assert result.safe_error == f"{status}: blocked"


@pytest.mark.asyncio
async def test_each_successful_agent_call_requires_a_distinct_new_session() -> None:
    binding = _binding()
    service, _adapter = _service(
        binding,
        lambda request: _result(request, session_ref="reused-session"),
    )

    await service.invoke(_request(binding, call_id="pro-1", role="PRO"))
    with pytest.raises(
        LocalEvaluationClaudeUnavailable,
        match="LOCAL_EVALUATION_CLAUDE_SESSION_REUSED",
    ):
        await service.invoke(_request(binding, call_id="con-1", role="CON"))


@pytest.mark.asyncio
async def test_one_call_identifier_cannot_be_replayed() -> None:
    binding = _binding()
    service, _adapter = _service(binding, lambda request: _result(request))

    await service.invoke(_request(binding, call_id="call-1"))
    with pytest.raises(
        LocalEvaluationClaudeUnavailable,
        match="LOCAL_EVALUATION_CLAUDE_CALL_ID_REUSED",
    ):
        await service.invoke(_request(binding, call_id="call-1"))


@pytest.mark.asyncio
async def test_exact_provider_profile_and_model_are_required_before_call() -> None:
    binding = _binding()
    service, adapter = _service(binding, lambda request: _result(request))
    request = _request(binding).model_copy(update={"model": "claude-opus-4-8"})

    with pytest.raises(
        LocalEvaluationClaudeUnavailable,
        match="LOCAL_EVALUATION_CLAUDE_ROUTE_MISMATCH",
    ):
        await service.invoke(request)

    assert adapter.requests == []


def test_builder_uses_exact_official_binding_without_production_approval() -> None:
    binding = _binding()
    checked: list[ApprovedClaudeExecutionBinding] = []

    service = build_local_evaluation_claude_call_service(
        binding=binding,
        prompt_resolver=cast(object, None),  # type: ignore[arg-type]
        session_store=cast(object, None),  # type: ignore[arg-type]
        output_schema_validator=cast(object, None),  # type: ignore[arg-type]
        result_builder=cast(object, None),  # type: ignore[arg-type]
        clock=cast(object, None),  # type: ignore[arg-type]
        binding_validator=checked.append,
    )

    assert service.model == _MODEL
    assert service.provider_profile_ref == reference(binding.provider_profile)
    assert checked == [binding]
    assert binding.provider_profile.support_status == "EXPERIMENTAL"
    assert binding.provider_validation_evidence is None
