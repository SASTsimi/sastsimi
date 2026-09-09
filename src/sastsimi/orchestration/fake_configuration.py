"""Deterministic, host-approved configuration graph for fake LLM stages."""

from collections.abc import Callable
from datetime import datetime

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.llm import (
    ExecutionLimits,
    LLMCallSpec,
    LLMRetryPolicy,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptPayload,
    PromptRedactionPolicy,
    PromptRegistryEntry,
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.orchestration.fake_support import FakeEvidence
from sastsimi.runtime.services import RuntimeServices


def _approved(evidence: FakeEvidence, record: object) -> None:
    evidence.llm_approvals.add(content_hash(record))


def register_fake_llm_call(
    runtime: RuntimeServices,
    evidence: FakeEvidence,
    metadata: Callable[[str], RecordMeta],
    artifact: Callable[[str], RecordRef],
    now: datetime,
    *,
    role: str,
    result_kind: str,
) -> tuple[StoredDataRef, StoredDataRef]:
    """Publish one exact typed configuration closure and return call/provider refs."""

    validation = ProviderValidationEvidence.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("provider_validation_evidence"),
                profile_key="fake-provider",
                provider="OPENAI",
                product="OPENAI_API",
                transport="RESPONSES_API",
                model="fake-model",
                environment="PRIVATE_CI",
                auth_mode="API_KEY",
                client_name="sastsimi-fake",
                client_version="1",
                tests=(),
                checked_at=now,
                checked_by="fixture-r8",
            )
        )
    )
    _approved(evidence, validation)
    validation_ref = runtime.configuration.register_provider_validation(validation)
    capabilities = {
        name: "SUPPORTED"
        for name in (
            "non_interactive",
            "structured_output",
            "new_session",
            "resume_session",
            "parallel_calls",
            "cancellation",
            "timeout_detection",
            "auth_expiry_detection",
            "rate_limit_detection",
            "request_id",
            "token_usage",
            "session_metadata",
            "runtime_tool_loop",
        )
    }
    provider = ProviderProfile.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("provider_profile"),
                profile_key="fake-provider",
                provider="OPENAI",
                product="OPENAI_API",
                transport="RESPONSES_API",
                model="fake-model",
                environment="PRIVATE_CI",
                auth_mode="API_KEY",
                client_name="sastsimi-fake",
                client_version="1",
                credential_source="ENVIRONMENT",
                capabilities=capabilities,
                support_status="SUPPORTED",
                validation_evidence_ref=validation_ref,
                client_execution_profile_ref=None,
                limitations=("Deterministic fake only",),
                checked_at=now,
                evidence_urls=("https://example.invalid/fake-provider",),
            )
        )
    )
    _approved(evidence, provider)
    provider_ref = runtime.configuration.register_provider_profile(provider)

    limits = ExecutionLimits(
        meta=metadata("execution_limits"),
        limits_key=f"fake-{role.lower()}",
        token_budget=100,
        timeout_ms=10_000,
        max_parallel_calls=1,
        max_calls_per_work=1,
    )
    retry = LLMRetryPolicy(
        meta=metadata("llm_retry_policy"),
        policy_key=f"fake-{role.lower()}",
        max_schema_repairs=0,
        max_semantic_repairs=0,
        max_retries=0,
        max_failovers=0,
        retryable_statuses=(),
        backoff_policy_ref=None,
    )
    tools = LLMToolPolicy(
        meta=metadata("llm_tool_policy"),
        policy_key=f"fake-{role.lower()}",
        allowed_tools=(),
        forbidden_actions=("external-network",),
        sandbox_only=True,
    )
    redaction = PromptRedactionPolicy(
        meta=metadata("prompt_redaction_policy"),
        policy_key=f"fake-{role.lower()}",
        remove_categories=(
            "CREDENTIAL",
            "COOKIE",
            "TOKEN",
            "BROWSER_PROFILE",
            "HOST_ABSOLUTE_PATH",
            "HIDDEN_REASONING",
        ),
        fail_closed=True,
    )
    schema = OutputSchemaSpec(
        meta=metadata("output_schema_spec"),
        schema_key=f"fake-{result_kind}",
        schema_artifact_ref=_stored(artifact(f"schema-{result_kind}")),
        result_kind=result_kind,
    )
    semantic = SemanticValidatorSpec(
        meta=metadata("semantic_validator_spec"),
        validator_key=f"fake-{result_kind}",
        implementation_ref=_stored(artifact(f"validator-{result_kind}")),
        test_refs=(_stored(artifact(f"validator-test-{result_kind}")),),
    )
    leaves = (limits, retry, tools, redaction, schema, semantic)
    for item in leaves:
        _approved(evidence, item)
    limits_ref = runtime.configuration.register_execution_limits(limits)
    retry_ref = runtime.configuration.register_retry_policy(retry)
    tools_ref = runtime.configuration.register_tool_policy(tools)
    redaction_ref = runtime.configuration.register_redaction_policy(redaction)
    schema_ref = runtime.configuration.register_output_schema(schema)
    semantic_ref = runtime.configuration.register_semantic_validator(semantic)

    prompt = PromptRegistryEntry.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("prompt_registry_entry"),
                prompt_key=f"fake-{role.lower()}",
                agent_role=role,
                task_kind=result_kind,
                purpose="PRODUCTION",
                template_ref=_stored(artifact(f"template-{role.lower()}")),
                template_version="1",
                input_slots=(),
                forbidden_context_kinds=("credential",),
                output_schema_ref=schema_ref,
                session_policy="NEW",
                provider_profile_refs=(provider_ref,),
                execution_limits_ref=limits_ref,
                retry_policy_ref=retry_ref,
                semantic_validator_ref=semantic_ref,
                tool_policy_ref=tools_ref,
                redaction_policy_ref=redaction_ref,
                result_kind=result_kind,
                status="ACTIVE",
                quality_evaluation_ref=_stored(artifact("evaluation_recommendation")),
                owner_role=role,
                reviewer_roles=("fixture-r8",),
            )
        )
    )
    _approved(evidence, prompt)
    prompt_ref = runtime.configuration.register_prompt_entry(prompt)
    payload = PromptPayload.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("prompt_payload"),
                registry_entry_ref=prompt_ref,
                prompt_key=prompt.prompt_key,
                agent_role=role,
                task_kind=result_kind,
                purpose="PRODUCTION",
                template_ref=prompt.template_ref,
                template_version=prompt.template_version,
                context_bindings=(),
                rendered_prompt_ref=_stored(artifact(f"rendered-{role.lower()}")),
                output_schema_ref=schema_ref,
            )
        )
    )
    _approved(evidence, payload)
    payload_ref = runtime.configuration.register_prompt_payload(payload)
    call = LLMCallSpec.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("llm_call_spec"),
                llm_call_id=f"fake-{role.lower()}-call",
                agent_role=role,
                task_kind=result_kind,
                purpose="PRODUCTION",
                provider_profile_ref=provider_ref,
                model=provider.model,
                session_policy="NEW",
                parent_session_ref=None,
                context_refs=(),
                prompt_registry_entry_ref=prompt_ref,
                prompt_key=prompt.prompt_key,
                prompt_template_ref=prompt.template_ref,
                prompt_template_version=prompt.template_version,
                prompt_payload_ref=payload_ref,
                execution_limits_ref=limits_ref,
                retry_policy_ref=retry_ref,
                tool_policy_ref=tools_ref,
                redaction_policy_ref=redaction_ref,
                semantic_validator_ref=semantic_ref,
                output_schema_ref=schema_ref,
                output_schema="{}",
                token_budget=limits.token_budget,
                timeout_ms=limits.timeout_ms,
            )
        )
    )
    _approved(evidence, call)
    return runtime.configuration.register_call_spec(call), provider_ref


def _stored(ref: RecordRef) -> StoredDataRef:
    if not isinstance(ref, StoredDataRef):
        raise ValueError("FAKE_CONFIGURATION_SCOPE_MISMATCH")
    return ref
