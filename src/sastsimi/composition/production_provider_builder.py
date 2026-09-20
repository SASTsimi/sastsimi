"""Build production Provider adapters from exact run-scoped provisioning only."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import model_validator

from sastsimi.config.production_profile import ProductionProfile, ProviderConnection
from sastsimi.contracts.base import ContractModel, NonEmptyStr, Sha256
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.evaluation import EvaluationRecommendation
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    LLMRole,
    PromptRegistryEntry,
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.orchestration.production_call_authority import (
    AnalysisApprovedRoute,
    ExactAnalysisProductionRouteLookup,
    ProductionPreparedCallAuthorizer,
)
from sastsimi.orchestration.production_capabilities import production_profile_hash
from sastsimi.orchestration.production_provisioning import (
    PromptRoutesProvisioning,
    ProviderConfigurationProvisioning,
)
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.configuration_registry import ConfigurationRegistryPort
from sastsimi.ports.dto import Record
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.production_prompt import ApprovedProductionRoute
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.prompts.production import ProductionLLMConfigurationService
from sastsimi.prompts.production_calls import ConfiguredProductionCallResolver
from sastsimi.prompts.validation import validate_output
from sastsimi.providers.codex_pvd import build_fail_closed_codex_pvd_runner
from sastsimi.providers.codex_subscription import (
    ApprovedCodexExecutable,
    ApprovedCodexExecutionBinding,
    CodexCliProcessRunner,
    CodexSubscriptionAdapter,
)
from sastsimi.providers.openai_composition import (
    StoredProviderSessionStore,
    build_openai_responses_api_adapter,
)
from sastsimi.providers.storage_io import (
    InvocationMetadataFactory,
    RequestSemanticValidator,
    SemanticValidator,
    StoredInvocationResultBuilder,
    StoredOutputValidator,
    StoredPromptInputResolver,
)
from sastsimi.reporting.content_validation import ReporterOutputSemanticValidator
from sastsimi.runtime.prompt_registry import PromptRegistry
from sastsimi.runtime.workflow_runner import WorkflowRunner

_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_SUPPORTED_IMPLEMENTATIONS = {
    "OPENAI_API": "OPENAI_RESPONSES_API_V1",
    "CODEX": "CODEX_OFFICIAL_CLIENT_V1",
}


class ProductionProviderBuildUnavailable(RuntimeError):
    """A safe reason why an approved Provider route cannot be built."""

    def __init__(self, reason_code: str) -> None:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", reason_code) is None:
            reason_code = "PRODUCTION_PROVIDER_BUILD_UNAVAILABLE"
        self.reason_code = reason_code
        super().__init__(reason_code)


class CodexHostBindingEvidence(ContractModel):
    """Secret-free names that resolve one approved local Codex executable."""

    schema_version: Literal[1]
    kind: Literal["CODEX_OFFICIAL_CLIENT_HOST_BINDING"]
    provider_profile_key: NonEmptyStr
    executable_path_env: NonEmptyStr
    executable_sha256: Sha256
    codex_home_env: NonEmptyStr

    @model_validator(mode="after")
    def environment_names_only(self) -> CodexHostBindingEvidence:
        if (
            _ENV_NAME.fullmatch(self.executable_path_env) is None
            or _ENV_NAME.fullmatch(self.codex_home_env) is None
            or self.executable_path_env == self.codex_home_env
        ):
            raise ValueError("CODEX_HOST_BINDING_ENVIRONMENT_INVALID")
        return self


@dataclass(frozen=True, slots=True)
class ProductionProviderAdapterFeature:
    """Exact adapters and semantic validators for one analysis."""

    adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter]
    semantic_validators: Mapping[StoredDataRef, SemanticValidator]
    request_semantic_validators: Mapping[tuple[LLMRole, str], RequestSemanticValidator]


@dataclass(frozen=True, slots=True)
class ProductionProviderPromptFeature:
    """Pre-runtime Provider adapters plus exact route configuration."""

    adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter]
    approved_routes: tuple[AnalysisApprovedRoute, ...]
    configuration: ProductionLLMConfigurationService
    route_lookup: ExactAnalysisProductionRouteLookup


@dataclass(frozen=True, slots=True)
class ProductionCallFeature:
    """Post-runtime call resolver with budget and action authorization."""

    authorizer: ProductionPreparedCallAuthorizer
    calls: ConfiguredProductionCallResolver


type AdapterFactory = Callable[..., object]


def build_production_adapter_feature(
    *,
    profile: ProductionProfile,
    provider_provisioning: ProviderConfigurationProvisioning,
    prompt_provisioning: PromptRoutesProvisioning,
    provisioned_records: Mapping[StoredDataRef, Record],
    provisioned_evidence: Mapping[str, bytes],
    queries: RuntimeQueryPort,
    records: RecordStore,
    artifacts: ArtifactStore,
    metadata_factory: InvocationMetadataFactory,
    clock: Clock,
    environment: Mapping[str, str] | None = None,
    openai_factory: AdapterFactory = build_openai_responses_api_adapter,
    codex_factory: AdapterFactory | None = None,
) -> ProductionProviderAdapterFeature:
    """Bind approved records to real adapters without discovery or fallback."""

    try:
        _require_document_scope(profile, provider_provisioning, prompt_provisioning)
        providers = _provider_records(provider_provisioning, provisioned_records)
        validators = _semantic_validators(
            prompt_provisioning, provisioned_records, queries
        )
        request_validators: dict[tuple[LLMRole, str], RequestSemanticValidator] = {
            ("REPORTER", "CREATE_DRAFT"): cast(
                RequestSemanticValidator, ReporterOutputSemanticValidator(records)
            )
        }
        connections = {item.provider_profile_key: item for item in profile.providers}
        used = {item.provider_profile_key for item in profile.llm_routes}
        bindings = {
            item.provider_profile_key: item.implementation_key
            for item in provider_provisioning.provider_implementation_bindings
        }
        if (
            set(providers) != set(bindings)
            or used != set(bindings)
            or not used <= set(connections)
        ):
            raise ProductionProviderBuildUnavailable(
                "PRODUCTION_PROVIDER_BINDING_SET_MISMATCH"
            )

        adapters: dict[tuple[StoredDataRef, str], LLMProviderAdapter] = {}
        runtime_environment = os.environ if environment is None else environment
        for profile_key in sorted(used):
            provider, validation, provider_ref = providers[profile_key]
            connection = connections[profile_key]
            implementation = bindings[profile_key]
            _require_provider_identity(provider, validation, connection, queries)
            expected_implementation = _SUPPORTED_IMPLEMENTATIONS.get(connection.product)
            if expected_implementation is None:
                raise ProductionProviderBuildUnavailable(
                    "PRODUCTION_PROVIDER_IMPLEMENTATION_UNSUPPORTED"
                )
            if implementation != expected_implementation:
                raise ProductionProviderBuildUnavailable(
                    "PRODUCTION_PROVIDER_IMPLEMENTATION_MISMATCH"
                )
            key = (provider_ref, provider.model)
            if key in adapters:
                raise ProductionProviderBuildUnavailable(
                    "PRODUCTION_PROVIDER_ADAPTER_AMBIGUOUS"
                )
            common: dict[str, object] = {
                "provider_profile_ref": provider_ref,
                "model": provider.model,
                "records": records,
                "artifacts": artifacts,
                "semantic_validators": validators,
                "metadata_factory": metadata_factory,
                "clock": clock,
                "request_semantic_validators": request_validators,
            }
            if connection.product == "OPENAI_API":
                if (
                    provider.credential_source != "ENVIRONMENT"
                    or not connection.credential_ref.reference.startswith("env:")
                ):
                    raise ProductionProviderBuildUnavailable(
                        "PRODUCTION_PROVIDER_CREDENTIAL_SOURCE_UNSUPPORTED"
                    )
                adapter = openai_factory(
                    validate_output=validate_output,
                    credential_ref=connection.credential_ref,
                    **common,
                )
            else:
                host_binding = _codex_host_binding(
                    profile_key,
                    provider_provisioning,
                    provisioned_evidence,
                    runtime_environment,
                )
                client = _client_execution(
                    provider,
                    provider_provisioning,
                    provisioned_records,
                    queries,
                )
                binding = ApprovedCodexExecutionBinding(
                    provider_profile=provider,
                    client_execution_profile=client,
                    executable=ApprovedCodexExecutable(
                        path=host_binding[0],
                        sha256=host_binding[1],
                    ),
                    codex_home=host_binding[2],
                    runtime_environment=provider.environment,
                    provider_validation_evidence=validation,
                )
                if codex_factory is not None:
                    adapter = codex_factory(binding=binding, **common)
                else:
                    adapter = _build_codex_adapter(
                        binding=binding,
                        provider_profile_ref=provider_ref,
                        model=str(provider.model),
                        records=records,
                        artifacts=artifacts,
                        semantic_validators=validators,
                        metadata_factory=metadata_factory,
                        clock=clock,
                        request_semantic_validators=request_validators,
                        queries=queries,
                    )
            if not isinstance(adapter, LLMProviderAdapter):
                raise ProductionProviderBuildUnavailable(
                    "PRODUCTION_PROVIDER_ADAPTER_INVALID"
                )
            adapters[key] = adapter
        return ProductionProviderAdapterFeature(
            adapters=adapters,
            semantic_validators=validators,
            request_semantic_validators=request_validators,
        )
    except ProductionProviderBuildUnavailable:
        raise
    except Exception:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROVIDER_BUILD_FAILED"
        ) from None


def build_production_provider_prompt_feature(
    *,
    repository_root: Path,
    profile: ProductionProfile,
    provider_provisioning: ProviderConfigurationProvisioning,
    prompt_provisioning: PromptRoutesProvisioning,
    provisioned_records: Mapping[StoredDataRef, Record],
    provisioned_evidence: Mapping[str, bytes],
    queries: RuntimeQueryPort,
    records: RecordStore,
    configuration: ConfigurationRegistryPort,
    artifacts: ArtifactStore,
    ids: IdGenerator,
    metadata_factory: InvocationMetadataFactory,
    clock: Clock,
    environment: Mapping[str, str] | None = None,
    openai_factory: AdapterFactory = build_openai_responses_api_adapter,
    codex_factory: AdapterFactory | None = None,
) -> ProductionProviderPromptFeature:
    """Build the complete pre-runtime LLM closure for one production run."""

    adapters = build_production_adapter_feature(
        profile=profile,
        provider_provisioning=provider_provisioning,
        prompt_provisioning=prompt_provisioning,
        provisioned_records=provisioned_records,
        provisioned_evidence=provisioned_evidence,
        queries=queries,
        records=records,
        artifacts=artifacts,
        metadata_factory=metadata_factory,
        clock=clock,
        environment=environment,
        openai_factory=openai_factory,
        codex_factory=codex_factory,
    )
    try:
        ProductionLLMConfigurationService.require_complete_profile(profile.llm_routes)
        approved = _approved_routes(
            profile,
            provider_provisioning,
            prompt_provisioning,
            provisioned_records,
            queries,
        )
        prompt_registry = PromptRegistry(configuration, records, queries)
        service = ProductionLLMConfigurationService(
            repository_root=repository_root,
            records=records,
            queries=queries,
            configuration=configuration,
            prompt_registry=prompt_registry,
            artifacts=artifacts,
            ids=ids,
            clock=clock,
        )
        lookup = ExactAnalysisProductionRouteLookup(
            records=records,
            queries=queries,
            approvals=approved,
        )
        for item in approved:
            lookup(item.analysis_id, item.route.role, item.route.task_kind)
        return ProductionProviderPromptFeature(
            adapters=adapters.adapters,
            approved_routes=approved,
            configuration=service,
            route_lookup=lookup,
        )
    except ProductionProviderBuildUnavailable:
        raise
    except Exception:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROMPT_ROUTE_GRAPH_INCOMPLETE"
        ) from None


def build_production_call_feature(
    *,
    provider_prompt: ProductionProviderPromptFeature,
    runner: WorkflowRunner,
    records: RecordStore,
    requester_identities: Mapping[tuple[str, str], BudgetScopeRef],
    reserved_cost_minor_units: int,
) -> ProductionCallFeature:
    """Attach exact per-attempt action and budget authority after runtime creation."""

    authorizer = ProductionPreparedCallAuthorizer(
        runner=runner,
        records=records,
        requester_identities=requester_identities,
        reserved_cost_minor_units=reserved_cost_minor_units,
    )
    calls = ConfiguredProductionCallResolver(
        configuration=provider_prompt.configuration,
        records=records,
        route_lookup=provider_prompt.route_lookup,
        authorizer=authorizer,
    )
    return ProductionCallFeature(authorizer=authorizer, calls=calls)


def _build_codex_adapter(
    *,
    binding: ApprovedCodexExecutionBinding,
    provider_profile_ref: StoredDataRef,
    model: str,
    records: RecordStore,
    artifacts: ArtifactStore,
    semantic_validators: Mapping[StoredDataRef, SemanticValidator],
    metadata_factory: InvocationMetadataFactory,
    clock: Clock,
    request_semantic_validators: Mapping[tuple[LLMRole, str], RequestSemanticValidator],
    queries: RuntimeQueryPort,
) -> CodexSubscriptionAdapter:
    process_runner = CodexCliProcessRunner(
        binding=binding,
        binding_validator=lambda current: _require_codex_binding_current(
            current, queries
        ),
    )
    return CodexSubscriptionAdapter(
        provider_profile_ref=provider_profile_ref,
        model=model,
        prompt_resolver=StoredPromptInputResolver(records, artifacts),
        process_runner=process_runner,
        session_store=StoredProviderSessionStore(artifacts),
        output_schema_validator=StoredOutputValidator(
            records,
            semantic_validators,
            validate_output,
            request_semantic_validators=request_semantic_validators,
        ),
        result_builder=StoredInvocationResultBuilder(
            records, artifacts, metadata_factory
        ),
        clock=clock,
        probe_runner=build_fail_closed_codex_pvd_runner(
            artifacts=artifacts,
            clock=clock,
            executable_sha256=binding.executable.sha256,
        ),
    )


def _require_document_scope(
    profile: ProductionProfile,
    provider: ProviderConfigurationProvisioning,
    prompts: PromptRoutesProvisioning,
) -> None:
    provider_scope = (
        provider.profile_hash,
        provider.analysis_id,
        provider.workspace_id,
        provider.commit_id,
    )
    prompt_scope = (
        prompts.profile_hash,
        prompts.analysis_id,
        prompts.workspace_id,
        prompts.commit_id,
    )
    if (
        provider_scope != prompt_scope
        or provider.profile_hash != production_profile_hash(profile)
    ):
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROVISIONING_SCOPE_MISMATCH"
        )


def _require_codex_binding_current(
    binding: ApprovedCodexExecutionBinding,
    queries: RuntimeQueryPort,
) -> None:
    validation = binding.provider_validation_evidence
    if validation is None:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROVIDER_EVIDENCE_MISMATCH"
        )
    for record in (
        binding.provider_profile,
        binding.client_execution_profile,
        validation,
    ):
        exact_ref = reference(record)
        if not isinstance(exact_ref, StoredDataRef):
            raise ProductionProviderBuildUnavailable(
                "PRODUCTION_PROVIDER_EVIDENCE_MISMATCH"
            )
        _require_current(exact_ref, record, queries)


def _approved_routes(
    profile: ProductionProfile,
    provider_document: ProviderConfigurationProvisioning,
    prompt_document: PromptRoutesProvisioning,
    provisioned: Mapping[StoredDataRef, Record],
    queries: RuntimeQueryPort,
) -> tuple[AnalysisApprovedRoute, ...]:
    providers = _provider_records(provider_document, provisioned)
    prompt_records = tuple(
        (ref, provisioned.get(ref)) for ref in prompt_document.record_refs
    )
    entries = tuple(
        (ref, value)
        for ref, value in prompt_records
        if isinstance(value, PromptRegistryEntry) and reference(value) == ref
    )
    recommendations = tuple(
        (ref, value)
        for ref, value in prompt_records
        if isinstance(value, EvaluationRecommendation) and reference(value) == ref
    )
    for ref, value in (*entries, *recommendations):
        _require_record_scope(prompt_document, ref, value)
    approved: list[AnalysisApprovedRoute] = []
    for route in profile.llm_routes:
        try:
            provider_ref = providers[str(route.provider_profile_key)][2]
        except KeyError:
            raise ProductionProviderBuildUnavailable(
                "PRODUCTION_PROMPT_ROUTE_GRAPH_INCOMPLETE"
            ) from None
        production = tuple(
            (ref, entry)
            for ref, entry in entries
            if entry.status == "ACTIVE"
            and entry.purpose == "PRODUCTION"
            and entry.agent_role == route.role
            and entry.task_kind == route.task_kind
            and entry.prompt_key == route.prompt_key
            and entry.provider_profile_refs == (provider_ref,)
        )
        evaluation = tuple(
            (ref, entry)
            for ref, entry in entries
            if entry.status == "ACTIVE"
            and entry.purpose == "EVALUATION"
            and entry.agent_role == route.role
            and entry.task_kind == route.task_kind
            and entry.provider_profile_refs == (provider_ref,)
        )
        if len(production) != 1 or len(evaluation) != 1:
            raise ProductionProviderBuildUnavailable(
                "PRODUCTION_PROMPT_ROUTE_GRAPH_INCOMPLETE"
            )
        production_ref, production_entry = production[0]
        evaluation_ref, evaluation_entry = evaluation[0]
        recommendation = tuple(
            (ref, item)
            for ref, item in recommendations
            if item.decision == "ACCEPT_FOR_PRODUCTION"
            and item.target_prompt_registry_entry_ref == evaluation_ref
            and item.target_provider_profile_ref == provider_ref
            and item.target_model == route.model
            and item.target_session_policy == evaluation_entry.session_policy
        )
        if len(recommendation) != 1:
            raise ProductionProviderBuildUnavailable(
                "PRODUCTION_PROMPT_ROUTE_GRAPH_INCOMPLETE"
            )
        recommendation_ref, _recommendation = recommendation[0]
        if production_entry.quality_evaluation_ref != recommendation_ref:
            raise ProductionProviderBuildUnavailable(
                "PRODUCTION_PROMPT_ROUTE_GRAPH_INCOMPLETE"
            )
        for exact_ref, value in (
            (production_ref, production_entry),
            (evaluation_ref, evaluation_entry),
            recommendation[0],
        ):
            _require_current(exact_ref, value, queries)
        approved.append(
            AnalysisApprovedRoute(
                analysis_id=str(production_entry.meta.analysis_id),
                route=route,
                approval=ApprovedProductionRoute(
                    active_prompt_ref=production_ref,
                    evaluation_prompt_ref=evaluation_ref,
                    quality_evaluation_ref=recommendation_ref,
                    provider_profile_ref=provider_ref,
                ),
            )
        )
    if len(approved) != len(profile.llm_routes):
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROMPT_ROUTE_GRAPH_INCOMPLETE"
        )
    return tuple(approved)


def _provider_records(
    document: ProviderConfigurationProvisioning,
    provisioned: Mapping[StoredDataRef, Record],
) -> dict[str, tuple[ProviderProfile, ProviderValidationEvidence, StoredDataRef]]:
    validations: dict[StoredDataRef, ProviderValidationEvidence] = {}
    output: dict[
        str, tuple[ProviderProfile, ProviderValidationEvidence, StoredDataRef]
    ] = {}
    for ref in document.record_refs:
        value = provisioned.get(ref)
        if isinstance(value, ProviderValidationEvidence) and reference(value) == ref:
            _require_record_scope(document, ref, value)
            validations[ref] = value
    for ref in document.record_refs:
        value = provisioned.get(ref)
        if not isinstance(value, ProviderProfile) or reference(value) != ref:
            continue
        _require_record_scope(document, ref, value)
        validation = validations.get(value.validation_evidence_ref)
        if validation is None or value.profile_key in output:
            raise ProductionProviderBuildUnavailable(
                "PRODUCTION_PROVIDER_EVIDENCE_MISMATCH"
            )
        output[str(value.profile_key)] = (value, validation, ref)
    if not output:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROVIDER_EVIDENCE_MISMATCH"
        )
    return output


def _semantic_validators(
    document: PromptRoutesProvisioning,
    provisioned: Mapping[StoredDataRef, Record],
    queries: RuntimeQueryPort,
) -> dict[StoredDataRef, SemanticValidator]:
    specs: dict[str, tuple[StoredDataRef, SemanticValidatorSpec]] = {}
    for ref in document.record_refs:
        value = provisioned.get(ref)
        if not isinstance(value, SemanticValidatorSpec) or reference(value) != ref:
            continue
        _require_record_scope(document, ref, value)
        if value.validator_key in specs:
            raise ProductionProviderBuildUnavailable(
                "PRODUCTION_SEMANTIC_VALIDATOR_AMBIGUOUS"
            )
        _require_current(ref, value, queries)
        specs[str(value.validator_key)] = (ref, value)
    bindings = {
        str(item.validator_key): item.implementation_key
        for item in document.semantic_validator_bindings
    }
    if set(specs) != set(bindings) or any(
        implementation != "JSON_SCHEMA_AND_AUTHORITY_V1"
        for implementation in bindings.values()
    ):
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_SEMANTIC_VALIDATOR_BINDING_MISMATCH"
        )
    return {ref: _json_schema_and_authority for ref, _spec in specs.values()}


def _json_schema_and_authority(_value: object) -> None:
    """Marker implementation; schema, role and runtime fields are checked upstream."""


def _require_provider_identity(
    provider: ProviderProfile,
    validation: ProviderValidationEvidence,
    connection: ProviderConnection,
    queries: RuntimeQueryPort,
) -> None:
    provider_ref = reference(provider)
    validation_ref = reference(validation)
    if not isinstance(provider_ref, StoredDataRef) or not isinstance(
        validation_ref, StoredDataRef
    ):
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROVIDER_EVIDENCE_MISMATCH"
        )
    _require_current(provider_ref, provider, queries)
    _require_current(validation_ref, validation, queries)
    identity = (
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
    expected_credential_source = (
        "OFFICIAL_CLIENT_SESSION"
        if connection.product == "CODEX"
        else (
            "ENVIRONMENT"
            if connection.credential_ref.reference.startswith("env:")
            else "SECRET_STORE"
        )
    )
    if (
        provider.support_status != "SUPPORTED"
        or provider.validation_evidence_ref != validation_ref
        or any(
            getattr(provider, field) != getattr(validation, field) for field in identity
        )
        or (
            str(provider.profile_key),
            provider.product,
            provider.environment,
            str(provider.client_name),
            str(provider.client_version),
            provider.credential_source,
        )
        != (
            str(connection.provider_profile_key),
            connection.product,
            connection.environment,
            str(connection.client_name),
            str(connection.client_version),
            expected_credential_source,
        )
    ):
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROVIDER_EVIDENCE_MISMATCH"
        )


def _require_current(
    exact_ref: StoredDataRef, record: Record, queries: RuntimeQueryPort
) -> None:
    meta = getattr(record, "meta", None)
    if not isinstance(meta, RecordMeta):
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROVIDER_CONFIGURATION_STALE"
        )
    current = tuple(
        candidate
        for candidate in queries.current_records(
            str(meta.analysis_id), str(meta.record_type)
        )
        if isinstance(getattr(candidate, "meta", None), RecordMeta)
        and candidate.meta.logical_record_id == meta.logical_record_id
    )
    if len(current) != 1 or reference(current[0]) != exact_ref:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROVIDER_CONFIGURATION_STALE"
        )


def _client_execution(
    provider: ProviderProfile,
    document: ProviderConfigurationProvisioning,
    provisioned: Mapping[StoredDataRef, Record],
    queries: RuntimeQueryPort,
) -> ClientExecutionProfile:
    ref = provider.client_execution_profile_ref
    value = provisioned.get(ref) if isinstance(ref, StoredDataRef) else None
    if not isinstance(value, ClientExecutionProfile) or reference(value) != ref:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_CODEX_CLIENT_PROFILE_MISSING"
        )
    _require_record_scope(document, ref, value)
    _require_current(ref, value, queries)
    return value


def _require_record_scope(
    document: ProviderConfigurationProvisioning | PromptRoutesProvisioning,
    exact_ref: StoredDataRef,
    record: Record,
) -> None:
    meta = getattr(record, "meta", None)
    if (
        not isinstance(meta, RecordMeta)
        or reference(record) != exact_ref
        or (
            str(meta.analysis_id),
            str(meta.workspace_id),
            str(meta.commit_id),
        )
        != (
            str(document.analysis_id),
            str(document.workspace_id),
            str(document.commit_id),
        )
    ):
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_PROVISIONED_RECORD_SCOPE_MISMATCH"
        )


def _codex_host_binding(
    profile_key: str,
    document: ProviderConfigurationProvisioning,
    evidence: Mapping[str, bytes],
    environment: Mapping[str, str],
) -> tuple[Path, str, Path]:
    matches: list[CodexHostBindingEvidence] = []
    for digest in document.evidence_sha256:
        payload = evidence.get(digest)
        if payload is None or hashlib.sha256(payload).hexdigest() != digest:
            raise ProductionProviderBuildUnavailable(
                "PRODUCTION_CODEX_HOST_BINDING_MISSING"
            )
        try:
            parsed = CodexHostBindingEvidence.model_validate_json(payload)
        except ValueError:
            continue
        if canonical_bytes(parsed) != payload:
            raise ProductionProviderBuildUnavailable(
                "PRODUCTION_CODEX_HOST_BINDING_INVALID"
            )
        if str(parsed.provider_profile_key) == profile_key:
            matches.append(parsed)
    if len(matches) != 1:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_CODEX_HOST_BINDING_MISSING"
        )
    binding = matches[0]
    executable_value = environment.get(str(binding.executable_path_env))
    home_value = environment.get(str(binding.codex_home_env))
    if not executable_value or not home_value:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_CODEX_RUNTIME_ENVIRONMENT_MISSING"
        )
    try:
        executable = Path(executable_value)
        codex_home = Path(home_value)
        if (
            not executable.is_absolute()
            or not codex_home.is_absolute()
            or executable.is_symlink()
            or codex_home.is_symlink()
        ):
            raise OSError
        executable = executable.resolve(strict=True)
        codex_home = codex_home.resolve(strict=True)
        if not executable.is_file() or not codex_home.is_dir():
            raise OSError
    except OSError:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_CODEX_RUNTIME_PATH_INVALID"
        ) from None
    try:
        executable_digest = _file_sha256(executable)
    except OSError:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_CODEX_RUNTIME_PATH_INVALID"
        ) from None
    if executable_digest != binding.executable_sha256:
        raise ProductionProviderBuildUnavailable(
            "PRODUCTION_CODEX_EXECUTABLE_DIGEST_MISMATCH"
        )
    return executable, str(binding.executable_sha256), codex_home


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "CodexHostBindingEvidence",
    "ProductionProviderAdapterFeature",
    "ProductionProviderBuildUnavailable",
    "ProductionCallFeature",
    "build_production_adapter_feature",
    "build_production_call_feature",
    "ProductionProviderPromptFeature",
    "build_production_provider_prompt_feature",
]
