"""Fail-closed production prompt activation and per-attempt call preparation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.evaluation import EvaluationRecommendation
from sastsimi.contracts.ids import AttemptId, LogicalRecordId, RecordId
from sastsimi.contracts.llm import (
    ExecutionLimits,
    LLMCallSpec,
    LLMRetryPolicy,
    LLMRole,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptPayload,
    PromptRedactionPolicy,
    PromptRegistryEntry,
    ProviderProfile,
    SemanticValidatorSpec,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.configuration_registry import ConfigurationRegistryPort
from sastsimi.ports.dto import Record
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.runtime.prompt_registry import PromptRegistry

from .builder import PromptBuilder, PromptSource
from .loader import PromptLoader
from .registry import LoadedPromptDefinition


class ProductionRoute(Protocol):
    """Structural view of one ``ProductionProfile.llm_routes`` item."""

    role: LLMRole
    task_kind: str
    provider_profile_key: str
    model: str
    prompt_key: str


@dataclass(frozen=True)
class RequiredProductionPromptRoute:
    role: LLMRole
    task_kind: str
    result_kind: str
    template_path: Path


def _required(
    role: LLMRole, task: str, result: str, path: str
) -> RequiredProductionPromptRoute:
    return RequiredProductionPromptRoute(role, task, result, Path(path))


REQUIRED_PRODUCTION_PROMPT_ROUTES = (
    _required(
        "HYPOTHESIS",
        "GENERATE_INITIAL",
        "hypothesis_proposal",
        "src/sastsimi/prompts/templates/hypothesis/generate-initial/1.0.0.md",
    ),
    _required(
        "PRO",
        "COLLECT_SUPPORT",
        "pro_evidence_result",
        "src/sastsimi/prompts/templates/pro/collect-support/1.0.0.md",
    ),
    _required(
        "CON",
        "COLLECT_COUNTEREVIDENCE",
        "con_evidence_result",
        "src/sastsimi/prompts/templates/con-agent/collect-counterevidence/1.0.0.md",
    ),
    _required(
        "VERIFICATION",
        "ASSESS_INITIAL",
        "verification_initial_assessment",
        "src/sastsimi/prompts/templates/verification/assess-initial/1.0.0.md",
    ),
    _required(
        "VERIFICATION",
        "FINAL_VERDICT",
        "verification_result",
        "src/sastsimi/prompts/templates/verification/final-verdict/1.0.0.md",
    ),
    _required(
        "DYNAMIC_REPRODUCTION",
        "DERIVE_ENVIRONMENT",
        "environment_requirements",
        "src/sastsimi/prompts/templates/dynamic-reproduction/derive-environment/1.0.0.md",
    ),
    _required(
        "DYNAMIC_REPRODUCTION",
        "PLAN_REPRODUCTION",
        "reproduction_plan",
        "src/sastsimi/prompts/templates/dynamic-reproduction/plan-reproduction/1.0.0.md",
    ),
    _required(
        "DYNAMIC_REPRODUCTION",
        "CREATE_POC_CANDIDATE",
        "poc_candidate",
        "src/sastsimi/prompts/templates/dynamic-reproduction/create-poc-candidate/1.0.1.md",
    ),
    _required(
        "DYNAMIC_REPRODUCTION",
        "EXECUTE_REPRODUCTION",
        "dynamic_reproduction_tool_request",
        "src/sastsimi/prompts/templates/dynamic-reproduction/execute-reproduction/1.0.1.md",
    ),
    _required(
        "DYNAMIC_REPRODUCTION",
        "INTERPRET_ATTEMPT",
        "dynamic_reproduction_conclusion",
        "src/sastsimi/prompts/templates/dynamic-reproduction/interpret-attempt/1.0.0.md",
    ),
    _required(
        "CWE_LABELING",
        "CLASSIFY_CWE",
        "cwe_label",
        "src/sastsimi/prompts/templates/cwe-labeling/classify/1.0.0.md",
    ),
    _required(
        "TECHNICAL_GATE",
        "REVIEW_TECHNICAL",
        "technical_evidence_review",
        "src/sastsimi/prompts/templates/technical-gate/review/1.0.0.md",
    ),
    _required(
        "RULE_SCOPE_GATE",
        "REVIEW",
        "rule_scope_impact_review",
        "src/sastsimi/prompts/templates/rule-scope-gate/review/1.0.0.md",
    ),
    _required(
        "REPORTER",
        "CREATE_DRAFT",
        "report_draft",
        "src/sastsimi/prompts/templates/reporter/create-draft/1.0.0.md",
    ),
    _required(
        "POLICY_PARSER",
        "PARSE_POLICY",
        "policy_parser_result",
        "src/sastsimi/prompts/templates/policy-parser/parse-policy/1.0.0.md",
    ),
    _required(
        "CHAINING",
        "MATCH_PRIMITIVES",
        "chaining_result",
        "src/sastsimi/prompts/templates/chaining/match-primitives/1.0.0.md",
    ),
)
_ROUTES = {
    (route.role, route.task_kind): route for route in REQUIRED_PRODUCTION_PROMPT_ROUTES
}
_REQUIRED_REDACTIONS = frozenset(
    {
        "CREDENTIAL",
        "COOKIE",
        "TOKEN",
        "BROWSER_PROFILE",
        "HOST_ABSOLUTE_PATH",
        "HIDDEN_REASONING",
    }
)
_FORBIDDEN_CONTEXT = frozenset({"credential", "provider_profile", "llm_invocation_log"})


class ProductionPromptApproval(ContractModel):
    """Operator-provided exact R8 quality approval; never a credential value."""

    evaluation_prompt_ref: StoredDataRef
    quality_evaluation_ref: StoredDataRef
    provider_profile_ref: StoredDataRef


class ApprovedProductionRoute(ProductionPromptApproval):
    active_prompt_ref: StoredDataRef


@dataclass(frozen=True)
class PromptActivation:
    route: ProductionRoute
    draft: PromptRegistryEntry
    active: PromptRegistryEntry
    definition: LoadedPromptDefinition
    approval: ProductionPromptApproval


@dataclass(frozen=True)
class ResolvedProductionRoute:
    route: ProductionRoute
    entry: PromptRegistryEntry
    entry_ref: StoredDataRef
    provider: ProviderProfile
    provider_ref: StoredDataRef
    limits: ExecutionLimits
    output_schema: OutputSchemaSpec
    definition: LoadedPromptDefinition


@dataclass(frozen=True)
class PreparedProductionCall:
    payload: PromptPayload
    payload_ref: StoredDataRef
    call_spec: LLMCallSpec
    call_spec_ref: StoredDataRef


class ProductionLLMConfigurationService:
    """Provision approved routes and bind exact per-attempt LLM calls.

    Provider credentials are intentionally absent from this API. Adapters inject
    a credential only after the resulting call spec is authorized.
    """

    def __init__(
        self,
        *,
        repository_root: Path,
        records: RecordStore,
        queries: RuntimeQueryPort,
        configuration: ConfigurationRegistryPort,
        prompt_registry: PromptRegistry,
        artifacts: ArtifactStore,
        ids: IdGenerator,
        clock: Clock,
    ) -> None:
        self._loader = PromptLoader(repository_root)
        self._records = records
        self._queries = queries
        self._configuration = configuration
        self._prompt_registry = prompt_registry
        self._builder = PromptBuilder(artifacts)
        self._ids = ids
        self._clock = clock

    @staticmethod
    def require_complete_profile(routes: tuple[ProductionRoute, ...]) -> None:
        keys = tuple((route.role, route.task_kind) for route in routes)
        if len(keys) != len(set(keys)) or set(keys) != set(_ROUTES):
            raise ValueError("PRODUCTION_PROMPT_ROUTE_SET_INCOMPLETE")

    def plan_activation(
        self,
        *,
        scope: RecordMeta,
        route: ProductionRoute,
        approval: ProductionPromptApproval,
    ) -> PromptActivation:
        required, evaluation, provider, recommendation = self._approval_graph(
            route, approval
        )
        self._require_same_scope(scope, evaluation, provider, recommendation)
        definition = self._definition(required, evaluation)
        if scope.hypothesis_id is not None or scope.attempt_id is not None:
            raise ValueError("PRODUCTION_PROMPT_SCOPE_MISMATCH")
        draft_meta = self._fresh_meta(scope, PromptRegistryEntry.KIND)
        draft = PromptRegistryEntry.model_validate(
            evaluation.model_dump()
            | {
                "meta": draft_meta,
                "prompt_key": route.prompt_key,
                "purpose": "PRODUCTION",
                "status": "DRAFT",
                "quality_evaluation_ref": None,
            }
        )
        active = PromptRegistryEntry.model_validate(
            draft.model_dump()
            | {
                "meta": self._next_meta(draft.meta),
                "status": "ACTIVE",
                "quality_evaluation_ref": approval.quality_evaluation_ref,
            }
        )
        return PromptActivation(route, draft, active, definition, approval)

    def publish_activation(
        self, activation: PromptActivation
    ) -> ApprovedProductionRoute:
        self._prompt_registry.publish(activation.draft)
        active_ref = self._prompt_registry.publish(activation.active)
        return ApprovedProductionRoute(
            active_prompt_ref=active_ref,
            evaluation_prompt_ref=activation.approval.evaluation_prompt_ref,
            quality_evaluation_ref=activation.approval.quality_evaluation_ref,
            provider_profile_ref=activation.approval.provider_profile_ref,
        )

    def resolve_route(
        self,
        *,
        route: ProductionRoute,
        approval: ApprovedProductionRoute,
    ) -> ResolvedProductionRoute:
        if not isinstance(approval.quality_evaluation_ref, StoredDataRef):
            raise ValueError("PRODUCTION_PROMPT_APPROVAL_REQUIRED")
        required = self._required(route)
        entry = self._prompt_registry.require_active(
            approval.active_prompt_ref,
            agent_role=route.role,
            task_kind=route.task_kind,
            purpose="PRODUCTION",
        )
        _, evaluation, provider, recommendation = self._approval_graph(route, approval)
        if (
            entry.prompt_key != route.prompt_key
            or entry.result_kind != required.result_kind
            or entry.quality_evaluation_ref != approval.quality_evaluation_ref
            or entry.provider_profile_refs != evaluation.provider_profile_refs
        ):
            raise ValueError("PRODUCTION_PROMPT_ROUTE_MISMATCH")
        self._require_same_scope(entry.meta, evaluation, provider, recommendation)
        self._require_current(entry, approval.active_prompt_ref)
        support = self._support_records(entry)
        definition = self._definition(required, entry)
        return ResolvedProductionRoute(
            route=route,
            entry=entry,
            entry_ref=approval.active_prompt_ref,
            provider=provider,
            provider_ref=approval.provider_profile_ref,
            limits=support[0],
            output_schema=support[4],
            definition=definition,
        )

    def prepare_call(
        self,
        *,
        route: ProductionRoute,
        approval: ApprovedProductionRoute,
        work: WorkExecutionState,
        sources: tuple[PromptSource, ...],
        parent_session_ref: str | None = None,
    ) -> PreparedProductionCall:
        if (
            work.status != "RUNNING"
            or work.active_attempt_id is None
            or not isinstance(work.meta, RecordMeta)
        ):
            raise ValueError("PRODUCTION_LLM_ACTIVE_ATTEMPT_REQUIRED")
        resolved = self.resolve_route(route=route, approval=approval)
        self._require_same_scope(work.meta, resolved.entry, resolved.provider)
        payload = self._builder.build_payload(
            definition=resolved.definition,
            registry_entry_ref=resolved.entry_ref,
            metadata=self._fresh_meta(
                work.meta,
                PromptPayload.KIND,
                attempt_id=work.active_attempt_id,
            ),
            sources=sources,
        )
        payload_ref = self._configuration.register_prompt_payload(payload)
        call_spec = self._builder.build_call_spec(
            entry=resolved.entry,
            registry_entry_ref=resolved.entry_ref,
            payload=payload,
            prompt_payload_ref=payload_ref,
            provider=resolved.provider,
            provider_profile_ref=resolved.provider_ref,
            limits=resolved.limits,
            output_schema=resolved.output_schema,
            metadata=self._fresh_meta(
                work.meta,
                LLMCallSpec.KIND,
                attempt_id=work.active_attempt_id,
            ),
            llm_call_id=f"llm-{self._ids.new(RecordId)}",
            model=route.model,
            parent_session_ref=parent_session_ref,
        )
        call_spec_ref = self._configuration.register_call_spec(call_spec)
        return PreparedProductionCall(payload, payload_ref, call_spec, call_spec_ref)

    def _approval_graph(
        self,
        route: ProductionRoute,
        approval: ProductionPromptApproval,
    ) -> tuple[
        RequiredProductionPromptRoute,
        PromptRegistryEntry,
        ProviderProfile,
        EvaluationRecommendation,
    ]:
        if not isinstance(approval.quality_evaluation_ref, StoredDataRef):
            raise ValueError("PRODUCTION_PROMPT_APPROVAL_REQUIRED")
        required = self._required(route)
        try:
            evaluation = self._prompt_registry.require_active(
                approval.evaluation_prompt_ref,
                agent_role=route.role,
                task_kind=route.task_kind,
                purpose="EVALUATION",
            )
            provider = self._records.get_exact(approval.provider_profile_ref)
            recommendation = self._records.get_exact(approval.quality_evaluation_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("PRODUCTION_PROMPT_APPROVAL_REQUIRED") from error
        if not isinstance(provider, ProviderProfile):
            raise ValueError("PRODUCTION_PROVIDER_ROUTE_MISMATCH")
        if (
            provider.support_status != "SUPPORTED"
            or provider.profile_key != route.provider_profile_key
            or provider.model != route.model
            or approval.provider_profile_ref not in evaluation.provider_profile_refs
        ):
            raise ValueError("PRODUCTION_PROVIDER_ROUTE_MISMATCH")
        if (
            not isinstance(recommendation, EvaluationRecommendation)
            or recommendation.decision != "ACCEPT_FOR_PRODUCTION"
            or recommendation.target_prompt_registry_entry_ref
            != approval.evaluation_prompt_ref
            or recommendation.target_provider_profile_ref
            != approval.provider_profile_ref
            or recommendation.target_model != route.model
            or recommendation.target_session_policy != evaluation.session_policy
        ):
            raise ValueError("PRODUCTION_PROMPT_APPROVAL_REQUIRED")
        if (
            evaluation.result_kind != required.result_kind
            or evaluation.template_ref.record_id is not None
            or evaluation.template_ref.data_kind != "artifact"
        ):
            raise ValueError("PRODUCTION_PROMPT_ROUTE_MISMATCH")
        self._require_current(provider, approval.provider_profile_ref)
        self._require_current(recommendation, approval.quality_evaluation_ref)
        self._support_records(evaluation)
        return required, evaluation, provider, recommendation

    def _support_records(
        self, entry: PromptRegistryEntry
    ) -> tuple[
        ExecutionLimits,
        LLMRetryPolicy,
        LLMToolPolicy,
        PromptRedactionPolicy,
        OutputSchemaSpec,
        SemanticValidatorSpec,
    ]:
        refs = (
            entry.execution_limits_ref,
            entry.retry_policy_ref,
            entry.tool_policy_ref,
            entry.redaction_policy_ref,
            entry.output_schema_ref,
            entry.semantic_validator_ref,
        )
        types = (
            ExecutionLimits,
            LLMRetryPolicy,
            LLMToolPolicy,
            PromptRedactionPolicy,
            OutputSchemaSpec,
            SemanticValidatorSpec,
        )
        values: list[Record] = []
        for exact_ref, expected in zip(refs, types, strict=True):
            try:
                value = self._records.get_exact(exact_ref)
            except (LookupError, ValueError) as error:
                raise ValueError("PRODUCTION_PROMPT_SUPPORT_MISSING") from error
            if not isinstance(value, expected):
                raise ValueError("PRODUCTION_PROMPT_SUPPORT_MISSING")
            self._require_same_scope(entry.meta, value)
            self._require_current(value, exact_ref)
            values.append(value)
        limits, retry, tools, redaction, schema, semantic = values
        if (
            not isinstance(limits, ExecutionLimits)
            or not isinstance(retry, LLMRetryPolicy)
            or not isinstance(tools, LLMToolPolicy)
            or not isinstance(redaction, PromptRedactionPolicy)
            or not isinstance(schema, OutputSchemaSpec)
            or not isinstance(semantic, SemanticValidatorSpec)
        ):
            raise ValueError("PRODUCTION_PROMPT_SUPPORT_MISSING")
        if (
            tools.allowed_tools
            or not tools.sandbox_only
            or not _REQUIRED_REDACTIONS.issubset(redaction.remove_categories)
            or redaction.fail_closed is not True
            or not _FORBIDDEN_CONTEXT.issubset(entry.forbidden_context_kinds)
            or schema.result_kind != entry.result_kind
        ):
            raise ValueError("PRODUCTION_PROMPT_SECURITY_POLICY_MISMATCH")
        return limits, retry, tools, redaction, schema, semantic

    def _definition(
        self,
        required: RequiredProductionPromptRoute,
        entry: PromptRegistryEntry,
    ) -> LoadedPromptDefinition:
        if entry.template_version != required.template_path.stem:
            raise ValueError("PRODUCTION_PROMPT_ROUTE_MISMATCH")
        template = self._loader.load_template(
            required.template_path, entry.template_ref.content_hash
        )
        return LoadedPromptDefinition.from_bytes(
            entry=entry,
            template_path=required.template_path,
            template=template,
        )

    def _required(self, route: ProductionRoute) -> RequiredProductionPromptRoute:
        required = _ROUTES.get((route.role, route.task_kind))
        if required is None or not all(
            isinstance(value, str) and value.strip()
            for value in (
                route.provider_profile_key,
                route.model,
                route.prompt_key,
            )
        ):
            raise ValueError("PRODUCTION_PROMPT_ROUTE_UNSUPPORTED")
        return required

    def _require_current(self, record: Record, exact_ref: StoredDataRef) -> None:
        meta = record.meta
        if not isinstance(meta, RecordMeta):
            raise ValueError("PRODUCTION_PROMPT_SCOPE_MISMATCH")
        current = tuple(
            candidate
            for candidate in self._queries.current_records(
                str(meta.analysis_id), str(meta.record_type)
            )
            if candidate.meta.logical_record_id == meta.logical_record_id
        )
        if len(current) != 1 or reference(current[0]) != exact_ref:
            raise ValueError("PRODUCTION_PROMPT_CONFIGURATION_STALE")

    @staticmethod
    def _require_same_scope(scope: RecordMeta, *records: Record) -> None:
        expected = (scope.analysis_id, scope.workspace_id, scope.commit_id)
        for record in records:
            meta = record.meta
            if (
                not isinstance(meta, RecordMeta)
                or (
                    meta.analysis_id,
                    meta.workspace_id,
                    meta.commit_id,
                )
                != expected
            ):
                raise ValueError("PRODUCTION_PROMPT_SCOPE_MISMATCH")

    def _fresh_meta(
        self,
        source: RecordMeta,
        kind: str,
        *,
        attempt_id: AttemptId | None = None,
    ) -> RecordMeta:
        record_id = self._ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            schema_version=source.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=self._clock.now(),
            analysis_id=source.analysis_id,
            workspace_id=source.workspace_id,
            commit_id=source.commit_id,
            hypothesis_id=source.hypothesis_id if attempt_id is not None else None,
            attempt_id=attempt_id,
        )

    def _next_meta(self, previous: RecordMeta) -> RecordMeta:
        return previous.model_copy(
            update={
                "record_id": self._ids.new(RecordId),
                "previous_record_id": previous.record_id,
                "revision_number": previous.revision_number + 1,
                "created_at": self._clock.now(),
            }
        )


__all__ = [
    "ApprovedProductionRoute",
    "PreparedProductionCall",
    "ProductionLLMConfigurationService",
    "ProductionPromptApproval",
    "ProductionRoute",
    "PromptActivation",
    "REQUIRED_PRODUCTION_PROMPT_ROUTES",
    "RequiredProductionPromptRoute",
    "ResolvedProductionRoute",
]
