"""Exact LOCAL_EVALUATION prompt routes without Production authority.

The service reuses the reviewed prompt templates and ordinary prompt storage
contracts, but it never consumes or creates an ``EvaluationRecommendation`` or
any Production approval object.  Every call is bound to one exact provider
record, one model, and a fresh session.  The runtime-tool-loop stage is absent
until the official Codex client can safely resume an isolated session.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sastsimi.contracts.ids import AttemptId, LogicalRecordId, RecordId
from sastsimi.contracts.llm import (
    ExecutionLimits,
    LLMCallSpec,
    LLMRetryPolicy,
    LLMRole,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptInputSlot,
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
from sastsimi.ports.prompt_registry import PromptRegistryPort
from sastsimi.ports.record_store import RecordStore

from .builder import ArtifactPromptSource, PromptBuilder, PromptSource
from .loader import PromptLoader
from .production import REQUIRED_PRODUCTION_PROMPT_ROUTES
from .registry import LoadedPromptDefinition

LOCAL_EVALUATION_EXECUTE_UNAVAILABLE = (
    "LOCAL_EVALUATION_CODEX_DYNAMIC_RESUME_UNSUPPORTED"
)

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
_CANDIDATE_TASK = "CREATE_POC_CANDIDATE"
_CANDIDATE_ARTIFACT_SLOT = (
    "code_fragments",
    "artifact",
    ("/redacted_body",),
    "REQUIRED_MANY",
    "UNTRUSTED_DATA",
)


@dataclass(frozen=True, slots=True)
class RequiredLocalEvaluationPromptRoute:
    role: LLMRole
    task_kind: str
    result_kind: str
    template_path: Path


REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES = tuple(
    RequiredLocalEvaluationPromptRoute(
        route.role, route.task_kind, route.result_kind, route.template_path
    )
    for route in REQUIRED_PRODUCTION_PROMPT_ROUTES
    if not (
        route.role == "DYNAMIC_REPRODUCTION"
        and route.task_kind == "EXECUTE_REPRODUCTION"
    )
)
_ROUTES = {
    (route.role, route.task_kind): route
    for route in REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES
}


@dataclass(frozen=True, slots=True)
class LocalEvaluationRoute:
    role: LLMRole
    task_kind: str
    provider_profile_key: str
    model: str
    prompt_key: str


@dataclass(frozen=True, slots=True)
class LocalEvaluationPromptSupport:
    template_ref: StoredDataRef
    provider_profile_ref: StoredDataRef
    execution_limits_ref: StoredDataRef
    retry_policy_ref: StoredDataRef
    tool_policy_ref: StoredDataRef
    redaction_policy_ref: StoredDataRef
    output_schema_ref: StoredDataRef
    semantic_validator_ref: StoredDataRef


@dataclass(frozen=True, slots=True)
class ApprovedLocalEvaluationRoute:
    """Exact active prompt and provider refs; deliberately not an approval graph."""

    active_prompt_ref: StoredDataRef
    provider_profile_ref: StoredDataRef


@dataclass(frozen=True, slots=True)
class PreparedLocalEvaluationCall:
    payload: PromptPayload
    payload_ref: StoredDataRef
    call_spec: LLMCallSpec
    call_spec_ref: StoredDataRef


@dataclass(frozen=True, slots=True)
class _ResolvedLocalEvaluationRoute:
    entry: PromptRegistryEntry
    entry_ref: StoredDataRef
    provider: ProviderProfile
    provider_ref: StoredDataRef
    limits: ExecutionLimits
    output_schema: OutputSchemaSpec
    definition: LoadedPromptDefinition


class LocalEvaluationLLMConfigurationService:
    """Publish and prepare exact, fresh-session local evaluation prompt calls."""

    purpose = "LOCAL_EVALUATION"

    def __init__(
        self,
        *,
        repository_root: Path,
        records: RecordStore,
        configuration: ConfigurationRegistryPort,
        prompt_registry: PromptRegistryPort,
        artifacts: ArtifactStore,
        ids: IdGenerator,
        clock: Clock,
    ) -> None:
        self._loader = PromptLoader(repository_root)
        self._records = records
        self._configuration = configuration
        self._prompt_registry = prompt_registry
        self._builder = PromptBuilder(artifacts)
        self._ids = ids
        self._clock = clock

    @staticmethod
    def require_complete_routes(routes: tuple[LocalEvaluationRoute, ...]) -> None:
        keys = tuple((route.role, route.task_kind) for route in routes)
        if len(keys) != len(set(keys)) or set(keys) != set(_ROUTES):
            raise ValueError("LOCAL_EVALUATION_PROMPT_ROUTE_SET_INCOMPLETE")

    def activate_route(
        self,
        *,
        scope: RecordMeta,
        route: LocalEvaluationRoute,
        support: LocalEvaluationPromptSupport,
        input_slots: tuple[PromptInputSlot, ...],
        owner_role: str = "R3",
        reviewer_roles: tuple[str, ...] = ("R4", "R8"),
    ) -> ApprovedLocalEvaluationRoute:
        """Publish one LOCAL_EVALUATION route directly, without R8 recommendation."""

        required = self._required(route)
        provider, values = self._support_records(scope, support, required.result_kind)
        if (
            provider.profile_key != route.provider_profile_key
            or provider.model != route.model
            or provider.support_status != "SUPPORTED"
            or provider.capabilities.non_interactive != "SUPPORTED"
            or provider.capabilities.structured_output != "SUPPORTED"
            or provider.capabilities.new_session != "SUPPORTED"
        ):
            raise ValueError("LOCAL_EVALUATION_PROVIDER_ROUTE_MISMATCH")
        if scope.hypothesis_id is not None or scope.attempt_id is not None:
            raise ValueError("LOCAL_EVALUATION_PROMPT_SCOPE_MISMATCH")
        entry = PromptRegistryEntry(
            meta=self._fresh_meta(scope, PromptRegistryEntry.KIND),
            prompt_key=route.prompt_key,
            agent_role=route.role,
            task_kind=route.task_kind,
            purpose="LOCAL_EVALUATION",
            template_ref=support.template_ref,
            template_version=required.template_path.stem,
            input_slots=input_slots,
            forbidden_context_kinds=tuple(sorted(_FORBIDDEN_CONTEXT)),
            output_schema_ref=support.output_schema_ref,
            session_policy="NEW",
            provider_profile_refs=(support.provider_profile_ref,),
            execution_limits_ref=support.execution_limits_ref,
            retry_policy_ref=support.retry_policy_ref,
            semantic_validator_ref=support.semantic_validator_ref,
            tool_policy_ref=support.tool_policy_ref,
            redaction_policy_ref=support.redaction_policy_ref,
            result_kind=required.result_kind,
            status="ACTIVE",
            quality_evaluation_ref=None,
            owner_role=owner_role,
            reviewer_roles=reviewer_roles,
        )
        self._definition(required, entry)
        self._require_route_input_contract(required, entry)
        # Keep the resolved values live through publication so type/closure checks
        # cannot accidentally be reduced to merely matching reference strings.
        if not values:
            raise ValueError("LOCAL_EVALUATION_PROMPT_SUPPORT_MISSING")
        active_ref = self._prompt_registry.publish(entry)
        return ApprovedLocalEvaluationRoute(
            active_prompt_ref=active_ref,
            provider_profile_ref=support.provider_profile_ref,
        )

    def prepare_call(
        self,
        *,
        route: LocalEvaluationRoute,
        approved: ApprovedLocalEvaluationRoute,
        work: WorkExecutionState,
        sources: tuple[PromptSource | ArtifactPromptSource, ...],
    ) -> PreparedLocalEvaluationCall:
        if (
            work.status != "RUNNING"
            or work.active_attempt_id is None
            or not isinstance(work.meta, RecordMeta)
        ):
            raise ValueError("LOCAL_EVALUATION_LLM_ACTIVE_ATTEMPT_REQUIRED")
        resolved = self._resolve(route, approved)
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
            parent_session_ref=None,
        )
        call_spec_ref = self._configuration.register_call_spec(call_spec)
        return PreparedLocalEvaluationCall(
            payload=payload,
            payload_ref=payload_ref,
            call_spec=call_spec,
            call_spec_ref=call_spec_ref,
        )

    def bind_artifact_source(
        self, slot: str, ref: StoredDataRef
    ) -> ArtifactPromptSource:
        return self._builder.bind_artifact(slot, ref)

    def _resolve(
        self,
        route: LocalEvaluationRoute,
        approved: ApprovedLocalEvaluationRoute,
    ) -> _ResolvedLocalEvaluationRoute:
        required = self._required(route)
        entry = self._prompt_registry.require_active(
            approved.active_prompt_ref,
            agent_role=route.role,
            task_kind=route.task_kind,
            purpose="LOCAL_EVALUATION",
        )
        support = LocalEvaluationPromptSupport(
            template_ref=entry.template_ref,
            provider_profile_ref=approved.provider_profile_ref,
            execution_limits_ref=entry.execution_limits_ref,
            retry_policy_ref=entry.retry_policy_ref,
            tool_policy_ref=entry.tool_policy_ref,
            redaction_policy_ref=entry.redaction_policy_ref,
            output_schema_ref=entry.output_schema_ref,
            semantic_validator_ref=entry.semantic_validator_ref,
        )
        provider, values = self._support_records(
            entry.meta, support, required.result_kind
        )
        if (
            entry.prompt_key != route.prompt_key
            or entry.provider_profile_refs != (approved.provider_profile_ref,)
            or provider.profile_key != route.provider_profile_key
            or provider.model != route.model
            or provider.support_status != "SUPPORTED"
        ):
            raise ValueError("LOCAL_EVALUATION_PROVIDER_ROUTE_MISMATCH")
        limits, _retry, _tools, _redaction, schema, _semantic = values
        return _ResolvedLocalEvaluationRoute(
            entry=entry,
            entry_ref=approved.active_prompt_ref,
            provider=provider,
            provider_ref=approved.provider_profile_ref,
            limits=limits,
            output_schema=schema,
            definition=self._definition(required, entry),
        )

    def _support_records(
        self,
        scope: RecordMeta,
        support: LocalEvaluationPromptSupport,
        result_kind: str,
    ) -> tuple[
        ProviderProfile,
        tuple[
            ExecutionLimits,
            LLMRetryPolicy,
            LLMToolPolicy,
            PromptRedactionPolicy,
            OutputSchemaSpec,
            SemanticValidatorSpec,
        ],
    ]:
        refs = (
            support.provider_profile_ref,
            support.execution_limits_ref,
            support.retry_policy_ref,
            support.tool_policy_ref,
            support.redaction_policy_ref,
            support.output_schema_ref,
            support.semantic_validator_ref,
        )
        types = (
            ProviderProfile,
            ExecutionLimits,
            LLMRetryPolicy,
            LLMToolPolicy,
            PromptRedactionPolicy,
            OutputSchemaSpec,
            SemanticValidatorSpec,
        )
        loaded: list[Record] = []
        try:
            for exact_ref, expected_type in zip(refs, types, strict=True):
                value = self._records.get_exact(exact_ref)
                if (
                    not isinstance(value, expected_type)
                    or reference(value) != exact_ref
                ):
                    raise ValueError("LOCAL_EVALUATION_PROMPT_SUPPORT_MISSING")
                self._require_same_scope(scope, value)
                loaded.append(value)
        except (LookupError, ValueError) as error:
            if isinstance(error, ValueError) and str(error).startswith(
                "LOCAL_EVALUATION_PROMPT_SCOPE_MISMATCH"
            ):
                raise
            raise ValueError("LOCAL_EVALUATION_PROMPT_SUPPORT_MISSING") from error
        provider, limits, retry, tools, redaction, schema, semantic = loaded
        assert isinstance(provider, ProviderProfile)
        assert isinstance(limits, ExecutionLimits)
        assert isinstance(retry, LLMRetryPolicy)
        assert isinstance(tools, LLMToolPolicy)
        assert isinstance(redaction, PromptRedactionPolicy)
        assert isinstance(schema, OutputSchemaSpec)
        assert isinstance(semantic, SemanticValidatorSpec)
        if (
            tools.allowed_tools
            or not tools.sandbox_only
            or not _REQUIRED_REDACTIONS.issubset(redaction.remove_categories)
            or redaction.fail_closed is not True
            or schema.result_kind != result_kind
        ):
            raise ValueError("LOCAL_EVALUATION_PROMPT_SECURITY_POLICY_MISMATCH")
        return provider, (limits, retry, tools, redaction, schema, semantic)

    def _definition(
        self,
        required: RequiredLocalEvaluationPromptRoute,
        entry: PromptRegistryEntry,
    ) -> LoadedPromptDefinition:
        if (
            entry.template_version != required.template_path.stem
            or entry.template_ref.record_id is not None
            or entry.template_ref.data_kind != "artifact"
        ):
            raise ValueError("LOCAL_EVALUATION_PROMPT_ROUTE_MISMATCH")
        template = self._loader.load_template(
            required.template_path, entry.template_ref.content_hash
        )
        try:
            persisted = self._builder.read_artifact(entry.template_ref)
        except (OSError, ValueError) as error:
            raise ValueError("LOCAL_EVALUATION_PROMPT_ROUTE_MISMATCH") from error
        if persisted != template:
            raise ValueError("LOCAL_EVALUATION_PROMPT_ROUTE_MISMATCH")
        return LoadedPromptDefinition.from_bytes(
            entry=entry,
            template_path=required.template_path,
            template=template,
        )

    def _required(
        self, route: LocalEvaluationRoute
    ) -> RequiredLocalEvaluationPromptRoute:
        if (
            route.role == "DYNAMIC_REPRODUCTION"
            and route.task_kind == "EXECUTE_REPRODUCTION"
        ):
            raise ValueError(LOCAL_EVALUATION_EXECUTE_UNAVAILABLE)
        required = _ROUTES.get((route.role, route.task_kind))
        if required is None or not all(
            isinstance(value, str) and value.strip()
            for value in (
                route.provider_profile_key,
                route.model,
                route.prompt_key,
            )
        ):
            raise ValueError("LOCAL_EVALUATION_PROMPT_ROUTE_UNSUPPORTED")
        return required

    @staticmethod
    def _require_route_input_contract(
        required: RequiredLocalEvaluationPromptRoute,
        entry: PromptRegistryEntry,
    ) -> None:
        if required.task_kind != _CANDIDATE_TASK:
            return
        artifact_slots = tuple(
            slot for slot in entry.input_slots if slot.data_kind == "artifact"
        )
        if len(artifact_slots) != 1:
            raise ValueError("LOCAL_EVALUATION_PROMPT_ROUTE_MISMATCH")
        slot = artifact_slots[0]
        if (
            slot.slot,
            slot.data_kind,
            slot.field_paths,
            slot.cardinality,
            slot.trust_class,
        ) != _CANDIDATE_ARTIFACT_SLOT:
            raise ValueError("LOCAL_EVALUATION_PROMPT_ROUTE_MISMATCH")

    @staticmethod
    def _require_same_scope(scope: RecordMeta, *records: Record) -> None:
        expected = (scope.analysis_id, scope.workspace_id, scope.commit_id)
        for record in records:
            if (
                not isinstance(record.meta, RecordMeta)
                or (
                    record.meta.analysis_id,
                    record.meta.workspace_id,
                    record.meta.commit_id,
                )
                != expected
            ):
                raise ValueError("LOCAL_EVALUATION_PROMPT_SCOPE_MISMATCH")

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


__all__ = [
    "ApprovedLocalEvaluationRoute",
    "LOCAL_EVALUATION_EXECUTE_UNAVAILABLE",
    "LocalEvaluationLLMConfigurationService",
    "LocalEvaluationPromptSupport",
    "LocalEvaluationRoute",
    "PreparedLocalEvaluationCall",
    "REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES",
    "RequiredLocalEvaluationPromptRoute",
]
