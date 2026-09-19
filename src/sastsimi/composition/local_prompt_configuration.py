"""Materialize and publish the LOCAL_EVALUATION Codex prompt graph.

The two-phase API lets composition approve the exact immutable records before
the runtime registry publishes them.  No Evaluation recommendation, Production
PVD, or Production prompt entry is created here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from sastsimi.composition.local_codex_binding import LocalCodexBindingRecords
from sastsimi.config.package_resources import resolve_builtin_resource
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    ExecutionLimits,
    LLMRetryPolicy,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptRedactionPolicy,
    PromptRegistryEntry,
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.configuration_registry import ConfigurationRegistryPort
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.prompts.local_calls import LocalEvaluationRouteBinding
from sastsimi.prompts.local_catalog import (
    LOCAL_EVALUATION_PROMPT_SPECS,
    LocalEvaluationPromptSpec,
    local_output_schema,
    validate_local_output,
)
from sastsimi.prompts.local_evaluation import (
    ApprovedLocalEvaluationRoute,
    LocalEvaluationRoute,
)
from sastsimi.providers.local_codex_validation import LocalCodexValidationResult

type SemanticValidator = Callable[[object], None]

_REDACTIONS: tuple[
    Literal[
        "CREDENTIAL",
        "COOKIE",
        "TOKEN",
        "BROWSER_PROFILE",
        "HOST_ABSOLUTE_PATH",
        "HIDDEN_REASONING",
    ],
    ...,
] = (
    "CREDENTIAL",
    "COOKIE",
    "TOKEN",
    "BROWSER_PROFILE",
    "HOST_ABSOLUTE_PATH",
    "HIDDEN_REASONING",
)


class LocalPromptConfigurationPublisher(ConfigurationRegistryPort, Protocol):
    """Configuration seam including explicit local-provider publication."""


@dataclass(frozen=True, slots=True)
class LocalPromptConfigurationPlan:
    validation_evidence: ProviderValidationEvidence
    client_execution: ClientExecutionProfile
    experimental_provider: ProviderProfile
    supported_provider: ProviderProfile
    local_evidence_ref: StoredDataRef
    execution_limits: ExecutionLimits
    retry_policy: LLMRetryPolicy
    tool_policy: LLMToolPolicy
    redaction_policy: PromptRedactionPolicy
    output_schemas: tuple[OutputSchemaSpec, ...]
    semantic_validators: tuple[SemanticValidatorSpec, ...]
    prompt_entries: tuple[PromptRegistryEntry, ...]
    routes: tuple[LocalEvaluationRoute, ...]

    @property
    def approval_records(self) -> tuple[object, ...]:
        """Exact values an injected LOCAL configuration authority must approve."""

        return (
            self.validation_evidence,
            self.client_execution,
            self.experimental_provider,
            self.supported_provider,
            self.execution_limits,
            self.retry_policy,
            self.tool_policy,
            self.redaction_policy,
            *self.output_schemas,
            *self.semantic_validators,
            *self.prompt_entries,
        )


@dataclass(frozen=True, slots=True)
class PublishedLocalPromptConfiguration:
    provider_profile_ref: StoredDataRef
    bindings: tuple[LocalEvaluationRouteBinding, ...]
    semantic_validators: dict[StoredDataRef, SemanticValidator]


def _meta(
    source: RecordMeta,
    kind: str,
    *,
    ids: IdGenerator,
    clock: Clock,
) -> RecordMeta:
    record_id = ids.new(RecordId)
    return RecordMeta(
        record_id=record_id,
        logical_record_id=LogicalRecordId(str(record_id)),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=clock.now(),
        analysis_id=source.analysis_id,
        workspace_id=source.workspace_id,
        commit_id=source.commit_id,
        hypothesis_id=None,
        attempt_id=None,
    )


def _artifact(artifacts: ArtifactStore, data: bytes, media_type: str) -> StoredDataRef:
    return artifacts.commit(artifacts.stage_bytes(data, media_type))


def _ref(record: object) -> StoredDataRef:
    value = reference(record)  # type: ignore[arg-type]
    if not isinstance(value, StoredDataRef):
        raise ValueError("LOCAL_PROMPT_CONFIGURATION_SCOPE_MISMATCH")
    return value


def _route(
    spec: LocalEvaluationPromptSpec, provider: ProviderProfile
) -> LocalEvaluationRoute:
    role = str(spec.role).lower().replace("_", "-")
    task = spec.task_kind.lower().replace("_", "-")
    slug = f"{role}.{task}"
    return LocalEvaluationRoute(
        role=spec.role,
        task_kind=spec.task_kind,
        provider_profile_key=str(provider.profile_key),
        model=str(provider.model),
        prompt_key=f"{slug}.local-v1",
    )


def build_local_prompt_configuration_plan(
    *,
    repository_root: Path,
    binding_records: LocalCodexBindingRecords,
    validation: LocalCodexValidationResult,
    artifacts: ArtifactStore,
    ids: IdGenerator,
    clock: Clock,
    timeout_ms: int,
    max_parallel_calls: int,
    max_calls_per_work: int,
    max_retries: int,
) -> LocalPromptConfigurationPlan:
    """Create the exact local graph after the bounded live Codex probe succeeds."""

    experimental = binding_records.provider
    supported = validation.provider
    if (
        validation.binding.provider_profile != supported
        or validation.binding.experimental_binding != binding_records.binding
        or validation.binding.local_evidence_ref != validation.evidence_ref
        or supported.meta.logical_record_id != experimental.meta.logical_record_id
        or supported.meta.previous_record_id != experimental.meta.record_id
        or supported.model != experimental.model
        or supported.profile_key != experimental.profile_key
        or supported.support_status != "SUPPORTED"
        or experimental.support_status != "EXPERIMENTAL"
        or supported.capabilities.resume_session != "UNSUPPORTED"
        or supported.capabilities.runtime_tool_loop != "UNSUPPORTED"
    ):
        raise ValueError("LOCAL_PROMPT_PROVIDER_BINDING_MISMATCH")
    if (
        isinstance(timeout_ms, bool)
        or timeout_ms < 1
        or isinstance(max_parallel_calls, bool)
        or max_parallel_calls < 1
        or isinstance(max_calls_per_work, bool)
        or max_calls_per_work < 1
        or isinstance(max_retries, bool)
        or max_retries < 0
    ):
        raise ValueError("LOCAL_PROMPT_LIMITS_INVALID")
    source = supported.meta
    limits = ExecutionLimits(
        meta=_meta(source, ExecutionLimits.KIND, ids=ids, clock=clock),
        limits_key="local-evaluation-codex-v1",
        token_budget=None,
        timeout_ms=timeout_ms,
        max_parallel_calls=max_parallel_calls,
        max_calls_per_work=max_calls_per_work,
    )
    retry = LLMRetryPolicy(
        meta=_meta(source, LLMRetryPolicy.KIND, ids=ids, clock=clock),
        policy_key="local-evaluation-codex-v1",
        max_schema_repairs=1,
        max_semantic_repairs=0,
        max_retries=max_retries,
        max_failovers=0,
        retryable_statuses=("TIMED_OUT", "RATE_LIMITED"),
        backoff_policy_ref=None,
    )
    tools = LLMToolPolicy(
        meta=_meta(source, LLMToolPolicy.KIND, ids=ids, clock=clock),
        policy_key="tools.none.local-evaluation-v1",
        allowed_tools=(),
        forbidden_actions=(
            "provider-tool-use",
            "repository-access",
            "sandbox-control",
            "external-disclosure",
        ),
        sandbox_only=True,
    )
    redaction = PromptRedactionPolicy(
        meta=_meta(source, PromptRedactionPolicy.KIND, ids=ids, clock=clock),
        policy_key="local-evaluation-redaction-v1",
        remove_categories=_REDACTIONS,
        fail_closed=True,
    )
    provider_ref = _ref(supported)
    limits_ref = _ref(limits)
    retry_ref = _ref(retry)
    tools_ref = _ref(tools)
    redaction_ref = _ref(redaction)
    schemas: list[OutputSchemaSpec] = []
    validators: list[SemanticValidatorSpec] = []
    entries: list[PromptRegistryEntry] = []
    routes: list[LocalEvaluationRoute] = []
    for spec in LOCAL_EVALUATION_PROMPT_SPECS:
        route = _route(spec, supported)
        schema_ref = _artifact(
            artifacts,
            local_output_schema(str(spec.role), spec.task_kind).encode("utf-8"),
            "application/schema+json",
        )
        schema = OutputSchemaSpec(
            meta=_meta(source, OutputSchemaSpec.KIND, ids=ids, clock=clock),
            schema_key=f"{route.prompt_key}.content-schema",
            schema_artifact_ref=schema_ref,
            result_kind=spec.result_kind,
        )
        implementation_ref = _artifact(
            artifacts,
            canonical_bytes(
                {
                    "schema_version": 1,
                    "purpose": "LOCAL_EVALUATION",
                    "implementation": "AGENT_CONTENT_MODEL_V1",
                    "role": spec.role,
                    "task_kind": spec.task_kind,
                }
            ),
            "application/json",
        )
        test_ref = _artifact(
            artifacts,
            canonical_bytes(
                {
                    "schema_version": 1,
                    "purpose": "LOCAL_EVALUATION",
                    "test": "RUNTIME_OWNED_FIELDS_REJECTED",
                    "role": spec.role,
                    "task_kind": spec.task_kind,
                }
            ),
            "application/json",
        )
        semantic = SemanticValidatorSpec(
            meta=_meta(source, SemanticValidatorSpec.KIND, ids=ids, clock=clock),
            validator_key=f"{route.prompt_key}.content-validator",
            implementation_ref=implementation_ref,
            test_refs=(test_ref,),
        )
        try:
            template_path = resolve_builtin_resource(
                repository_root, Path(spec.template_path)
            )
        except ValueError:
            raise ValueError("LOCAL_PROMPT_TEMPLATE_MISSING") from None
        try:
            template_bytes = template_path.read_bytes()
        except OSError:
            raise ValueError("LOCAL_PROMPT_TEMPLATE_MISSING") from None
        template_ref = _artifact(artifacts, template_bytes, "text/markdown")
        entry = PromptRegistryEntry(
            meta=_meta(source, PromptRegistryEntry.KIND, ids=ids, clock=clock),
            prompt_key=route.prompt_key,
            agent_role=spec.role,
            task_kind=spec.task_kind,
            purpose="LOCAL_EVALUATION",
            template_ref=template_ref,
            template_version=Path(spec.template_path).stem,
            input_slots=spec.input_slots,
            forbidden_context_kinds=(
                "credential",
                "provider_profile",
                "llm_invocation_log",
            ),
            output_schema_ref=_ref(schema),
            session_policy="NEW",
            provider_profile_refs=(provider_ref,),
            execution_limits_ref=limits_ref,
            retry_policy_ref=retry_ref,
            semantic_validator_ref=_ref(semantic),
            tool_policy_ref=tools_ref,
            redaction_policy_ref=redaction_ref,
            result_kind=spec.result_kind,
            status="ACTIVE",
            quality_evaluation_ref=None,
            owner_role="R3",
            reviewer_roles=("R4", "R8"),
        )
        schemas.append(schema)
        validators.append(semantic)
        entries.append(entry)
        routes.append(route)
    return LocalPromptConfigurationPlan(
        validation_evidence=binding_records.validation,
        client_execution=binding_records.client,
        experimental_provider=experimental,
        supported_provider=supported,
        local_evidence_ref=validation.evidence_ref,
        execution_limits=limits,
        retry_policy=retry,
        tool_policy=tools,
        redaction_policy=redaction,
        output_schemas=tuple(schemas),
        semantic_validators=tuple(validators),
        prompt_entries=tuple(entries),
        routes=tuple(routes),
    )


def publish_local_prompt_configuration(
    *,
    plan: LocalPromptConfigurationPlan,
    configuration: LocalPromptConfigurationPublisher,
) -> PublishedLocalPromptConfiguration:
    """Publish one pre-approved local plan in exact dependency order."""

    evidence_ref = plan.local_evidence_ref
    if configuration.register_local_provider_validation(
        plan.validation_evidence, local_evidence_ref=evidence_ref
    ) != _ref(plan.validation_evidence):
        raise ValueError("LOCAL_PROMPT_PUBLICATION_MISMATCH")
    if configuration.register_local_client_execution(
        plan.client_execution, local_evidence_ref=evidence_ref
    ) != _ref(plan.client_execution):
        raise ValueError("LOCAL_PROMPT_PUBLICATION_MISMATCH")
    for provider in (plan.experimental_provider, plan.supported_provider):
        if configuration.register_local_provider_profile(
            provider, local_evidence_ref=evidence_ref
        ) != _ref(provider):
            raise ValueError("LOCAL_PROMPT_PUBLICATION_MISMATCH")
    if configuration.register_execution_limits(plan.execution_limits) != _ref(
        plan.execution_limits
    ):
        raise ValueError("LOCAL_PROMPT_PUBLICATION_MISMATCH")
    if configuration.register_retry_policy(plan.retry_policy) != _ref(
        plan.retry_policy
    ):
        raise ValueError("LOCAL_PROMPT_PUBLICATION_MISMATCH")
    if configuration.register_tool_policy(plan.tool_policy) != _ref(plan.tool_policy):
        raise ValueError("LOCAL_PROMPT_PUBLICATION_MISMATCH")
    if configuration.register_redaction_policy(plan.redaction_policy) != _ref(
        plan.redaction_policy
    ):
        raise ValueError("LOCAL_PROMPT_PUBLICATION_MISMATCH")
    for output_schema in plan.output_schemas:
        if configuration.register_output_schema(output_schema) != _ref(output_schema):
            raise ValueError("LOCAL_PROMPT_PUBLICATION_MISMATCH")
    semantic_bindings: dict[StoredDataRef, SemanticValidator] = {}
    for spec, validator_record in zip(
        LOCAL_EVALUATION_PROMPT_SPECS, plan.semantic_validators, strict=True
    ):
        exact_ref = configuration.register_semantic_validator(validator_record)
        if exact_ref != _ref(validator_record):
            raise ValueError("LOCAL_PROMPT_PUBLICATION_MISMATCH")

        def validate(
            value: object,
            *,
            role: str = str(spec.role),
            task: str = spec.task_kind,
        ) -> None:
            validate_local_output(role, task, value)

        semantic_bindings[exact_ref] = validate
    bindings: list[LocalEvaluationRouteBinding] = []
    provider_ref = _ref(plan.supported_provider)
    for route, entry in zip(plan.routes, plan.prompt_entries, strict=True):
        entry_ref = configuration.register_prompt_entry(entry)
        if entry_ref != _ref(entry):
            raise ValueError("LOCAL_PROMPT_PUBLICATION_MISMATCH")
        bindings.append(
            LocalEvaluationRouteBinding(
                analysis_id=str(entry.meta.analysis_id),
                route=route,
                approval=ApprovedLocalEvaluationRoute(
                    active_prompt_ref=entry_ref,
                    provider_profile_ref=provider_ref,
                ),
            )
        )
    return PublishedLocalPromptConfiguration(
        provider_profile_ref=provider_ref,
        bindings=tuple(bindings),
        semantic_validators=semantic_bindings,
    )


__all__ = [
    "LocalPromptConfigurationPlan",
    "LocalPromptConfigurationPublisher",
    "PublishedLocalPromptConfiguration",
    "build_local_prompt_configuration_plan",
    "publish_local_prompt_configuration",
]
