"""Deterministic, host-approved configuration graph for fake LLM stages."""

import asyncio
from collections.abc import Callable
from datetime import datetime

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.evaluation import (
    EvaluationRecommendation,
    EvaluationRunConfig,
    EvaluationRunResult,
)
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
from sastsimi.contracts.prompt_projection import project_prompt_value
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef
from sastsimi.ports.dto import CapabilityProbeResult
from sastsimi.ports.fake_workflow import ProviderProber
from sastsimi.prompts.redaction import redact_projected_json, render_provider_prompt
from sastsimi.runtime.fake_support import FakeEvidence
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner


def _approved(evidence: FakeEvidence, record: object) -> None:
    evidence.llm_approvals.add(content_hash(record))


def _artifact_bytes(
    runtime: RuntimeServices, data: bytes, media_type: str = "application/json"
) -> StoredDataRef:
    staged = runtime.unit_of_work.artifacts.stage_bytes(data, media_type)
    return runtime.unit_of_work.artifacts.commit(staged)


def _source_projection(runtime: RuntimeServices, ref: StoredDataRef) -> bytes:
    """Resolve `$` to the actual immutable source value used by the provider."""
    if ref.record_id is not None:
        return project_prompt_value(runtime.unit_of_work.records.get_exact(ref), ("$",))
    with runtime.unit_of_work.artifacts.open_verified(ref) as source:
        return project_prompt_value(source.read().decode("utf-8"), ("$",))


def register_fake_llm_call(
    runtime: RuntimeServices,
    evidence: FakeEvidence,
    metadata: Callable[[str], RecordMeta],
    artifact: Callable[[str], RecordRef],
    now: datetime,
    provider_probe: ProviderProber,
    *,
    runner: WorkflowRunner,
    scope: StoredDataRef,
    orchestration_identity: BudgetScopeRef,
    role: str,
    result_kind: str,
    task_kind: str | None = None,
    context_refs: tuple[StoredDataRef, ...] = (),
) -> tuple[StoredDataRef, StoredDataRef]:
    """Publish one exact typed configuration closure and return call/provider refs."""
    if orchestration_identity != evidence.identity(RequesterRole.ORCHESTRATION):
        raise ValueError("FAKE_ORCHESTRATION_IDENTITY_MISMATCH")
    evaluation_identity = evidence.identity(RequesterRole.R8_EVALUATION_RUNTIME)

    probe_candidate = ProviderValidationEvidence.model_validate_json(
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
                tests=tuple(
                    dict(
                        test_id=f"PVD-{index:02d}",
                        result="NOT_APPLICABLE",
                        evidence_refs=(_stored(artifact(f"pvd-{index:02d}")),),
                        safe_summary="Pending deterministic adapter probe",
                    )
                    for index in range(1, 17)
                ),
                checked_at=now,
                checked_by="fixture-r8",
            )
        )
    )

    async def execute_probe() -> CapabilityProbeResult:
        return await provider_probe(probe_candidate)

    probe = asyncio.run(execute_probe())
    validation = probe.evidence
    _approved(evidence, validation)
    validation_ref = runtime.configuration.register_provider_validation(validation)
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
                capabilities=runtime.configuration.derive_provider_capabilities(
                    validation
                ),
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
    provider_ref = runtime.configuration.register_provider_profile(provider, probe)

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

    exact_task_kind = task_kind or result_kind
    input_slots = tuple(
        dict(
            slot=f"context-{index}",
            data_kind=ref.data_kind,
            field_paths=("$",),
            cardinality="REQUIRED_ONE",
            trust_class="UNTRUSTED_DATA",
        )
        for index, ref in enumerate(context_refs, 1)
    )
    template_ref = _artifact_bytes(
        runtime,
        (
            f"role={role}\ntask={exact_task_kind}\n"
            "Use each ordered context binding exactly once and return the "
            "configured schema.\n"
        ).encode(),
        "text/plain",
    )
    prompt_fields = dict(
        agent_role=role,
        task_kind=exact_task_kind,
        template_ref=template_ref,
        template_version="1",
        input_slots=input_slots,
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
        owner_role=role,
        reviewer_roles=("fixture-r8",),
    )
    evaluation_prompt = PromptRegistryEntry.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("prompt_registry_entry"),
                prompt_key=f"fake-{role.lower()}-evaluation",
                purpose="EVALUATION",
                status="ACTIVE",
                quality_evaluation_ref=None,
                **prompt_fields,
            )
        )
    )
    _approved(evidence, evaluation_prompt)
    evaluation_prompt_ref = runtime.configuration.register_prompt_entry(
        evaluation_prompt
    )
    state = runtime.budget_registry.current_state(
        str(evaluation_prompt.meta.analysis_id)
    )
    evaluation_config = EvaluationRunConfig.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("evaluation_run_config"),
                evaluation_config_id=f"fake-{role.lower()}-evaluation",
                comparison_group_id=f"fake-{role.lower()}-quality",
                corpus_refs=(_stored(artifact(f"corpus-{role.lower()}")),),
                ground_truth_refs=(_stored(artifact(f"ground-truth-{role.lower()}")),),
                grader_refs=(_stored(artifact(f"grader-{role.lower()}")),),
                provider_profile_ref=provider_ref,
                model=provider.model,
                session_policy="NEW",
                prompt_registry_entry_ref=evaluation_prompt_ref,
                execution_budget_profile_ref=state.execution_budget_profile_ref,
                output_schema_ref=schema_ref,
            )
        )
    )
    _approved(evidence, evaluation_config)
    evaluation_config_ref = runtime.configuration.register_evaluation_config(
        evaluation_config
    )

    evaluation_work = runner.start(
        scope,
        metadata("evaluation_stage"),
        "REPORT_DRAFT",
        "ANALYSIS",
        str(evaluation_prompt.meta.analysis_id),
        orchestration_identity,
    )
    evaluation_result = EvaluationRunResult.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("evaluation_run_result"),
                evaluation_run_id=f"fake-{role.lower()}-evaluation-result",
                config_ref=evaluation_config_ref,
                analysis_result_refs=(),
                grader_result_refs=(),
                metrics=(),
                usage=dict(
                    elapsed_ms=1,
                    work_count=1,
                    attempt_count=1,
                    retry_count=0,
                    llm_call_count=1,
                    dynamic_attempt_count=0,
                    cost_minor_units=0,
                    currency="USD",
                    pricing_revision_refs=(),
                    usage_measurement_refs=(),
                    usage_complete=True,
                    unavailable_reasons=(),
                ),
                status="SUCCEEDED",
                error_ids=(),
                started_at=now,
                finished_at=now,
            )
        )
    )
    runner.complete(
        evaluation_work,
        evaluation_identity,
        "R8_EVALUATION_RUNTIME",
        (evaluation_result,),
    )
    evaluation_result_ref = _stored(
        runtime.unit_of_work.records.stage_record(evaluation_result)
    )

    production_draft = PromptRegistryEntry.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("prompt_registry_entry"),
                prompt_key=f"fake-{role.lower()}-production",
                purpose="PRODUCTION",
                status="DRAFT",
                quality_evaluation_ref=None,
                **prompt_fields,
            )
        )
    )
    _approved(evidence, production_draft)
    runtime.configuration.register_prompt_entry(production_draft)
    recommendation_work = runner.start(
        scope,
        metadata("evaluation_stage"),
        "REPORT_DRAFT",
        "ANALYSIS",
        str(evaluation_prompt.meta.analysis_id),
        orchestration_identity,
    )
    recommendation = EvaluationRecommendation.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("evaluation_recommendation"),
                recommendation_id=f"fake-{role.lower()}-recommendation",
                evaluation_result_ref=evaluation_result_ref,
                target_provider_profile_ref=provider_ref,
                target_model=provider.model,
                target_session_policy="NEW",
                target_prompt_registry_entry_ref=evaluation_prompt_ref,
                decision="ACCEPT_FOR_PRODUCTION",
                rationale="Deterministic quality evaluation accepted",
                decided_by="R8_EVALUATION_RUNTIME",
                decided_at=now,
            )
        )
    )
    runner.complete(
        recommendation_work,
        evaluation_identity,
        "R8_EVALUATION_RUNTIME",
        (recommendation,),
    )
    recommendation_ref = _stored(
        runtime.unit_of_work.records.stage_record(recommendation)
    )
    active_metadata = runner.revision_metadata(production_draft.meta)
    prompt = PromptRegistryEntry.model_validate_json(
        canonical_bytes(
            production_draft.model_dump()
            | dict(
                meta=active_metadata,
                status="ACTIVE",
                quality_evaluation_ref=recommendation_ref,
            )
        )
    )
    _approved(evidence, prompt)
    prompt_ref = runtime.configuration.register_prompt_entry(prompt)
    projected_bytes = tuple(
        redact_projected_json(_source_projection(runtime, ref)).data
        for ref in context_refs
    )
    projected_refs = tuple(_artifact_bytes(runtime, data) for data in projected_bytes)
    with runtime.unit_of_work.artifacts.open_verified(template_ref) as template:
        template_bytes = template.read()
    rendered_bytes = render_provider_prompt(
        template_bytes,
        tuple(
            (f"context-{index}", data) for index, data in enumerate(projected_bytes, 1)
        ),
    )
    rendered_prompt_ref = _artifact_bytes(
        runtime,
        rendered_bytes,
        "text/plain",
    )
    payload = PromptPayload.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("prompt_payload"),
                registry_entry_ref=prompt_ref,
                prompt_key=prompt.prompt_key,
                agent_role=role,
                task_kind=exact_task_kind,
                purpose="PRODUCTION",
                template_ref=prompt.template_ref,
                template_version=prompt.template_version,
                context_bindings=tuple(
                    dict(
                        slot=f"context-{index}",
                        data_kind=ref.data_kind,
                        source_ref=ref,
                        projected_data_ref=projected_refs[index - 1],
                        field_paths=("$",),
                        trust_class="UNTRUSTED_DATA",
                    )
                    for index, ref in enumerate(context_refs, 1)
                ),
                rendered_prompt_ref=rendered_prompt_ref,
                output_schema_ref=schema_ref,
            )
        )
    )
    _approved(evidence, payload)
    payload_ref = runtime.configuration.register_prompt_payload(payload)
    call_meta = metadata("llm_call_spec")
    call = LLMCallSpec.model_validate_json(
        canonical_bytes(
            dict(
                meta=call_meta,
                llm_call_id=f"fake-{role.lower()}-{call_meta.record_id}",
                agent_role=role,
                task_kind=exact_task_kind,
                purpose="PRODUCTION",
                provider_profile_ref=provider_ref,
                model=provider.model,
                session_policy="NEW",
                parent_session_ref=None,
                context_refs=context_refs,
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
