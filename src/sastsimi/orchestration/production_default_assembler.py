"""Compose the built-in production features from exact approved inputs.

The filesystem provisioner resolves immutable configuration before this module
runs.  This assembler binds those records to the existing production builders;
it does not discover tools, choose fallback records, or provide a fake dynamic
implementation.  R7 dynamic construction and cancellation remain explicit
ports so bootstrap can supply their real implementations when they are ready.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.ids import AttemptId, LogicalRecordId, RecordId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.orchestration.production_composition import (
    InstalledProductionServices,
    ProductionCapabilityUnavailable,
    ProductionInstallationContext,
)
from sastsimi.orchestration.production_feature_installer import (
    DynamicProductionFeature,
    ProductionFeatureInputs,
    ProductionFeatureInstaller,
    ReadinessCheck,
    T08ProductionFeature,
)
from sastsimi.orchestration.production_filesystem_provisioner import (
    ProductionBundleAssembly,
    ProductionBundleAssemblyContext,
    ProductionBundleAssemblyPort,
    ProductionBundleAssemblyRegistry,
    ProductionImplementationSet,
)
from sastsimi.orchestration.production_policy_builder import (
    build_production_policy_feature_factory,
)
from sastsimi.orchestration.production_provider_builder import (
    build_production_call_feature,
    build_production_provider_prompt_feature,
)
from sastsimi.orchestration.production_provisioning import (
    PolicyCatalogProvisioning,
    PromptRoutesProvisioning,
    ProviderConfigurationProvisioning,
    SandboxProfileProvisioning,
    StaticAnalysisProvisioning,
    VerificationPlaybooksProvisioning,
    WorkspaceStorageProvisioning,
)
from sastsimi.orchestration.production_static_adapters import (
    ProductionStaticAdapterFactory,
    ProductionStaticOutputQuotaPort,
    StaticAttemptDispatchReader,
)
from sastsimi.orchestration.production_t08_builder import (
    ApprovedStaticRuleClosure,
    ProductionT08Inputs,
    build_production_t08_feature,
)
from sastsimi.orchestration.static_external_runner import (
    StaticCancellationObservationReader,
    StaticDispatchStateReader,
    StaticProcessReceiptReader,
)
from sastsimi.ports.dto import StaticRuleMapping
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.scheduler import ExternalCancellationPort
from sastsimi.providers.storage_io import InvocationMetadataFactory
from sastsimi.runtime.system_support import SystemClock, UUIDIds
from sastsimi.storage.context_lineage import ContextLineageReader

_STATIC_IMPLEMENTATIONS = frozenset(
    {
        "AST:PYTHON_AST:PYTHON_AST_JSON_V1",
        "CODEQL:CODEQL:CODEQL_SARIF_V1",
        "OPENGREP:OPENGREP:OPENGREP_JSON_V1",
    }
)
_PROVIDER_IMPLEMENTATIONS = frozenset(
    {"OPENAI_RESPONSES_API_V1", "CODEX_OFFICIAL_CLIENT_V1"}
)


@dataclass(frozen=True, slots=True)
class ProductionStaticRuntimePorts:
    """Durable T08 readers and optional hard CodeQL output quota."""

    process_receipts: StaticProcessReceiptReader
    cancellation_observation: StaticCancellationObservationReader
    dispatch_state: StaticDispatchStateReader
    attempt_dispatch: StaticAttemptDispatchReader
    output_quota: ProductionStaticOutputQuotaPort | None = None
    codeql_database_limit_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class BuiltProductionDynamicFeature:
    """Real R7 feature plus its exact external readiness checks."""

    feature: DynamicProductionFeature
    readiness_checks: tuple[ReadinessCheck, ...] = ()


class StaticRuntimeFactory(Protocol):
    def __call__(
        self, context: ProductionInstallationContext
    ) -> ProductionStaticRuntimePorts: ...


class DynamicFeatureFactory(Protocol):
    def __call__(
        self,
        assembly: ProductionBundleAssemblyContext,
        context: ProductionInstallationContext,
        static: T08ProductionFeature,
    ) -> BuiltProductionDynamicFeature: ...


class CancellationFactory(Protocol):
    def __call__(
        self,
        context: ProductionInstallationContext,
        static: T08ProductionFeature,
        provider_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter],
        dynamic: DynamicProductionFeature,
    ) -> ExternalCancellationPort: ...


type ExecutableResolver = Callable[[str], Path]


def build_default_production_bundle_assembler(
    *,
    repository_root: Path,
    static_runtime_factory: StaticRuntimeFactory,
    dynamic_feature_factory: DynamicFeatureFactory,
    cancellation_factory: CancellationFactory,
    executable_resolver: ExecutableResolver | None = None,
) -> ProductionBundleAssemblyPort:
    """Build the non-R7 defaults while requiring real R7 boundary factories."""

    if not callable(static_runtime_factory):
        raise ProductionCapabilityUnavailable("PRODUCTION_STATIC_RUNTIME_REQUIRED")
    if not callable(dynamic_feature_factory):
        raise ProductionCapabilityUnavailable("PRODUCTION_DYNAMIC_FACTORY_REQUIRED")
    if not callable(cancellation_factory):
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_CANCELLATION_FACTORY_REQUIRED"
        )
    root = _require_directory(repository_root)
    return _DefaultProductionBundleAssembler(
        repository_root=root,
        static_runtime_factory=static_runtime_factory,
        dynamic_feature_factory=dynamic_feature_factory,
        cancellation_factory=cancellation_factory,
        executable_resolver=executable_resolver or _resolve_executable,
    )


def build_default_production_bundle_registry(
    *,
    implementation_set: ProductionImplementationSet,
    repository_root: Path,
    static_runtime_factory: StaticRuntimeFactory,
    dynamic_feature_factory: DynamicFeatureFactory,
    cancellation_factory: CancellationFactory,
    executable_resolver: ExecutableResolver | None = None,
) -> ProductionBundleAssemblyRegistry:
    """Create a non-empty exact-key registry for production bootstrap."""

    builder = build_default_production_bundle_assembler(
        repository_root=repository_root,
        static_runtime_factory=static_runtime_factory,
        dynamic_feature_factory=dynamic_feature_factory,
        cancellation_factory=cancellation_factory,
        executable_resolver=executable_resolver,
    )
    registry = ProductionBundleAssemblyRegistry()
    registry.register(implementation_set, builder)
    return registry


@dataclass(frozen=True, slots=True)
class _PlaybookClosure:
    policy_ref: StoredDataRef
    common_ref: StoredDataRef


@dataclass(frozen=True, slots=True)
class _DefaultProductionBundleAssembler:
    repository_root: Path
    static_runtime_factory: StaticRuntimeFactory
    dynamic_feature_factory: DynamicFeatureFactory
    cancellation_factory: CancellationFactory
    executable_resolver: ExecutableResolver

    def __call__(
        self, context: ProductionBundleAssemblyContext
    ) -> ProductionBundleAssembly:
        try:
            _require_implementation_set(context.implementation_set)
            workspace = _document(
                context, "WORKSPACE_STORAGE", WorkspaceStorageProvisioning
            )
            static = _document(context, "STATIC_ANALYSIS", StaticAnalysisProvisioning)
            verification = _document(
                context,
                "VERIFICATION_PLAYBOOKS",
                VerificationPlaybooksProvisioning,
            )
            provider = _document(
                context,
                "PROVIDER_CONFIGURATION",
                ProviderConfigurationProvisioning,
            )
            prompts = _document(context, "PROMPT_ROUTES", PromptRoutesProvisioning)
            policy_document = _document(
                context, "POLICY_CATALOG", PolicyCatalogProvisioning
            )
            sandbox_document = _document(
                context, "SANDBOX_PROFILE", SandboxProfileProvisioning
            )
            _require_document_implementations(
                context.implementation_set,
                static=static,
                provider=provider,
                prompts=prompts,
                policy=policy_document,
                sandbox=sandbox_document,
            )
            playbooks = _resolve_playbooks(context, verification)
            clock = SystemClock()
            ids = UUIDIds()
            provider_prompt = build_production_provider_prompt_feature(
                repository_root=self.repository_root,
                profile=context.profile,
                provider_provisioning=provider,
                prompt_provisioning=prompts,
                provisioned_records=context.materialized.records,
                provisioned_evidence=context.materialized.evidence,
                queries=context.queries,
                records=context.records,
                configuration=context.configuration,
                artifacts=context.artifacts,
                ids=ids,
                metadata_factory=_metadata_factory(clock, ids),
                clock=clock,
            )
            policy_factory = build_production_policy_feature_factory(context)
        except ProductionCapabilityUnavailable:
            raise
        except Exception:
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_DEFAULT_ASSEMBLY_INVALID"
            ) from None

        def install(
            installation: ProductionInstallationContext,
        ) -> InstalledProductionServices:
            try:
                _require_installation(
                    context, provider_prompt.approved_routes, installation
                )
                calls = build_production_call_feature(
                    provider_prompt=provider_prompt,
                    runner=installation.runner,
                    records=installation.runtime.unit_of_work.records,
                    requester_identities=_requester_identities(installation),
                    reserved_cost_minor_units=_reserved_cost(installation),
                )
                static_ports = self.static_runtime_factory(installation)
                _require_static_runtime_ports(static_ports, static)
                t08 = build_production_t08_feature(
                    installation,
                    _t08_inputs(
                        context=context,
                        installation=installation,
                        workspace=workspace,
                        static=static,
                        ports=static_ports,
                        repository_root=self.repository_root,
                        executable_resolver=self.executable_resolver,
                    ),
                )
                policy = policy_factory(installation, calls.calls)
                dynamic = self.dynamic_feature_factory(context, installation, t08)
                _require_dynamic_result(dynamic)
                cancellation = self.cancellation_factory(
                    installation,
                    t08,
                    provider_prompt.adapters,
                    dynamic.feature,
                )
                if not callable(getattr(cancellation, "cancel", None)):
                    raise ValueError("PRODUCTION_CANCELLATION_INVALID")
                inputs = ProductionFeatureInputs(
                    t08=t08,
                    policy=policy,
                    dynamic=dynamic.feature,
                    calls=calls.calls,
                    verification_policy_ref=playbooks.policy_ref,
                    verification_playbook_ref=playbooks.common_ref,
                    taxonomy_version=context.profile.taxonomy_version,
                    external_cancellation=cancellation,
                    readiness_checks=dynamic.readiness_checks,
                )
                return ProductionFeatureInstaller(inputs)(installation)
            except ProductionCapabilityUnavailable:
                raise
            except Exception:
                raise ProductionCapabilityUnavailable(
                    "PRODUCTION_DEFAULT_INSTALLATION_INVALID"
                ) from None

        return ProductionBundleAssembly(
            llm_adapters=provider_prompt.adapters,
            approved_llm_routes=provider_prompt.approved_routes,
            install=install,
        )


def _document[T](
    context: ProductionBundleAssemblyContext,
    slot: str,
    expected: type[T],
) -> T:
    value = context.materialized.documents.get(slot)
    if not isinstance(value, expected):
        raise ProductionCapabilityUnavailable(
            f"PRODUCTION_{slot}_CONFIGURATION_MISSING"
        )
    return value


def _require_implementation_set(value: ProductionImplementationSet) -> None:
    routes = value.static_routes
    providers = value.provider_adapters
    if (
        not routes
        or "AST:PYTHON_AST:PYTHON_AST_JSON_V1" not in routes
        or len(routes) != len(set(routes))
        or not set(routes) <= _STATIC_IMPLEMENTATIONS
        or not providers
        or not set(providers) <= _PROVIDER_IMPLEMENTATIONS
        or value.policy_parser != "OFFICIAL_HTTP_POLICY_V1"
        or value.sandbox_authorization != "RUNTIME_DYNAMIC_AUTHORIZATION_V1"
        or value.sandbox_setup != "DOCKER_REPRODUCTION_SETUP_V1"
        or not value.semantic_validators
        or set(value.semantic_validators) != {"JSON_SCHEMA_AND_AUTHORITY_V1"}
    ):
        raise ProductionCapabilityUnavailable("PRODUCTION_FEATURE_SET_UNSUPPORTED")


def _require_document_implementations(
    value: ProductionImplementationSet,
    *,
    static: StaticAnalysisProvisioning,
    provider: ProviderConfigurationProvisioning,
    prompts: PromptRoutesProvisioning,
    policy: PolicyCatalogProvisioning,
    sandbox: SandboxProfileProvisioning,
) -> None:
    expected = ProductionImplementationSet(
        static_routes=tuple(
            f"{item.tool}:{item.adapter_key}:{item.decoder_key}"
            for item in static.routes
        ),
        provider_adapters=tuple(
            item.implementation_key
            for item in provider.provider_implementation_bindings
        ),
        policy_parser=policy.parser_implementation_key,
        sandbox_authorization=sandbox.authorization_implementation_key,
        sandbox_setup=sandbox.setup_implementation_key,
        semantic_validators=tuple(
            item.implementation_key for item in prompts.semantic_validator_bindings
        ),
    )
    if value != expected:
        raise ProductionCapabilityUnavailable("PRODUCTION_IMPLEMENTATION_SET_MISMATCH")


def _resolve_playbooks(
    context: ProductionBundleAssemblyContext,
    document: VerificationPlaybooksProvisioning,
) -> _PlaybookClosure:
    values: list[VerificationPlaybook | PlaybookPolicy] = []
    for expected_ref in document.record_refs:
        try:
            value = context.materialized.records[expected_ref]
        except KeyError:
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_PLAYBOOK_RECORD_MISSING"
            ) from None
        if not isinstance(value, (VerificationPlaybook, PlaybookPolicy)):
            raise ProductionCapabilityUnavailable("PRODUCTION_PLAYBOOK_RECORD_INVALID")
        actual_ref = reference(value)
        meta = value.meta
        if (
            actual_ref != expected_ref
            or not isinstance(actual_ref, StoredDataRef)
            or (
                meta.analysis_id,
                meta.workspace_id,
                meta.commit_id,
            )
            != (
                context.scope.analysis_id,
                context.scope.workspace_id,
                context.scope.commit_id,
            )
        ):
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_PLAYBOOK_RECORD_NOT_EXACT"
            )
        current = tuple(
            candidate
            for candidate in context.queries.current_records(
                str(context.scope.analysis_id), meta.record_type
            )
            if getattr(candidate, "meta", None) is not None
            and candidate.meta.logical_record_id == meta.logical_record_id
        )
        if len(current) != 1 or reference(current[0]) != expected_ref:
            raise ProductionCapabilityUnavailable("PRODUCTION_PLAYBOOK_RECORD_STALE")
        values.append(value)
    policies = tuple(value for value in values if isinstance(value, PlaybookPolicy))
    if len(policies) != 1:
        raise ProductionCapabilityUnavailable("PRODUCTION_PLAYBOOK_POLICY_AMBIGUOUS")
    policy = policies[0]
    playbook_by_ref = {
        cast(StoredDataRef, reference(value)): value
        for value in values
        if isinstance(value, VerificationPlaybook)
    }
    expected_playbooks = {
        policy.common_playbook_ref,
        *(item.playbook_ref for item in policy.type_playbooks),
    }
    common = playbook_by_ref.get(policy.common_playbook_ref)
    if (
        set(playbook_by_ref) != expected_playbooks
        or common is None
        or common.scope != "COMMON"
    ):
        raise ProductionCapabilityUnavailable("PRODUCTION_PLAYBOOK_CLOSURE_INCOMPLETE")
    for item in policy.type_playbooks:
        selected = playbook_by_ref[item.playbook_ref]
        if (
            selected.scope != "TYPE_SPECIFIC"
            or selected.vulnerability_type != item.vulnerability_type
        ):
            raise ProductionCapabilityUnavailable("PRODUCTION_PLAYBOOK_CLOSURE_INVALID")
    policy_ref = reference(policy)
    if not isinstance(policy_ref, StoredDataRef):
        raise ProductionCapabilityUnavailable("PRODUCTION_PLAYBOOK_RECORD_NOT_EXACT")
    return _PlaybookClosure(policy_ref, policy.common_playbook_ref)


@dataclass(frozen=True, slots=True)
class _ProductionInvocationMetadataFactory:
    clock: SystemClock
    ids: UUIDIds

    def __call__(
        self, source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta:
        record_id = self.ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=record_type,
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=self.clock.now(),
            analysis_id=source.analysis_id,
            workspace_id=source.workspace_id,
            commit_id=source.commit_id,
            hypothesis_id=source.hypothesis_id,
            attempt_id=attempt_id,
        )


def _metadata_factory(clock: SystemClock, ids: UUIDIds) -> InvocationMetadataFactory:
    return _ProductionInvocationMetadataFactory(clock, ids)


def _require_installation(
    assembled: ProductionBundleAssemblyContext,
    approved_routes: Sequence[object],
    installation: ProductionInstallationContext,
) -> None:
    if (
        installation.data_dir.resolve() != assembled.data_dir.resolve()
        or installation.request != assembled.request
        or installation.profile != assembled.profile
        or installation.scope != assembled.scope
        or tuple(installation.approved_llm_routes) != tuple(approved_routes)
        or installation.runtime.unit_of_work.records is not assembled.records
    ):
        raise ProductionCapabilityUnavailable("PRODUCTION_ASSEMBLY_CONTEXT_CHANGED")


def _requester_identities(
    context: ProductionInstallationContext,
) -> Mapping[tuple[str, str], BudgetScopeRef]:
    analysis_id = str(context.scope.analysis_id)
    try:
        return {
            (analysis_id, role.value): context.role_identity_refs[role]
            for role in RequesterRole
        }
    except KeyError:
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_REQUESTER_IDENTITY_MISSING"
        ) from None


def _reserved_cost(context: ProductionInstallationContext) -> int:
    budget = context.profile.budget
    return max(1, budget.max_total_cost_minor_units // budget.max_total_llm_calls)


def _require_static_runtime_ports(
    ports: ProductionStaticRuntimePorts, static: StaticAnalysisProvisioning
) -> None:
    if any(
        not callable(value)
        for value in (
            ports.process_receipts,
            ports.cancellation_observation,
            ports.dispatch_state,
            ports.attempt_dispatch,
        )
    ):
        raise ValueError("PRODUCTION_STATIC_RUNTIME_INVALID")
    if "CODEQL" in static.enabled_tools and (
        ports.output_quota is None
        or ports.codeql_database_limit_bytes is None
        or isinstance(ports.codeql_database_limit_bytes, bool)
        or ports.codeql_database_limit_bytes <= 0
    ):
        raise ValueError("PRODUCTION_CODEQL_HARD_QUOTA_REQUIRED")


def _t08_inputs(
    *,
    context: ProductionBundleAssemblyContext,
    installation: ProductionInstallationContext,
    workspace: WorkspaceStorageProvisioning,
    static: StaticAnalysisProvisioning,
    ports: ProductionStaticRuntimePorts,
    repository_root: Path,
    executable_resolver: ExecutableResolver,
) -> ProductionT08Inputs:
    bindings: dict[str, HostConfigurationRef] = {}
    for binding in context.provisioning.capabilities:
        if binding.slot in bindings:
            raise ValueError("PRODUCTION_CAPABILITY_SLOT_DUPLICATED")
        bindings[binding.slot] = binding.profile_ref
    required = {"GIT_CLONE", "GIT_CHECKOUT", *static.enabled_tools}
    if not required <= set(bindings):
        raise ValueError("PRODUCTION_T08_CAPABILITY_MISSING")

    executable_names = {
        "PYTHON_AST": installation.profile.tools.python,
        "CODEQL": installation.profile.tools.codeql,
        "OPENGREP": installation.profile.tools.opengrep,
    }
    executables: dict[str, Path] = {
        route.adapter_key: executable_resolver(executable_names[route.adapter_key])
        for route in static.routes
    }
    git_executable = executable_resolver(installation.profile.tools.git)
    worker = (
        repository_root
        / "src"
        / "sastsimi"
        / "static_analysis"
        / "python_ast_worker.py"
    )
    worker = worker.resolve(strict=True)
    if not worker.is_file():
        raise ValueError("PRODUCTION_PYTHON_AST_WORKER_MISSING")
    adapter_factory = ProductionStaticAdapterFactory(
        executables=executables,
        python_ast_worker=worker,
        python_ast_worker_sha256=_sha256_file(worker),
        output_quota=ports.output_quota,
        codeql_database_limit_bytes=ports.codeql_database_limit_bytes,
    )
    return ProductionT08Inputs(
        workspace=workspace,
        static=static,
        git_clone_profile_ref=bindings["GIT_CLONE"],
        git_checkout_profile_ref=bindings["GIT_CHECKOUT"],
        static_profile_refs={tool: bindings[tool] for tool in static.enabled_tools},
        evidence=context.materialized.evidence,
        rule_closures=_rule_closures(static, context.materialized.evidence),
        git_executable=git_executable,
        build_static_adapters=adapter_factory,
        static_process_receipts=ports.process_receipts,
        static_cancellation_observation=ports.cancellation_observation,
        static_dispatch_state=ports.dispatch_state,
        static_attempt_dispatch=ports.attempt_dispatch,
        workspace_timeout_ms=installation.profile.timeouts.workspace_ms,
        repository_profile_timeout_ms=installation.profile.timeouts.static_tool_ms,
        allow_local_repository=installation.profile.allow_local_repository,
        lineage_reader=ContextLineageReader(context.records),
    )


def _rule_closures(
    static: StaticAnalysisProvisioning, evidence: Mapping[str, bytes]
) -> Mapping[str, ApprovedStaticRuleClosure]:
    result: dict[str, ApprovedStaticRuleClosure] = {}
    for route in static.routes:
        if route.tool == "AST":
            continue
        if (
            route.rule_catalog_sha256 is None
            or route.rule_selection_sha256 is None
            or route.rule_mapping_sha256 is None
        ):
            raise ValueError("PRODUCTION_STATIC_RULE_CLOSURE_MISSING")
        catalog = _json_evidence(evidence, route.rule_catalog_sha256)
        selection = _json_evidence(evidence, route.rule_selection_sha256)
        mapping = _json_evidence(evidence, route.rule_mapping_sha256)
        if (
            not isinstance(catalog, dict)
            or catalog.get("schema_version") != 1
            or set(catalog) != {"schema_version", "rule_ids"}
            or not isinstance(catalog.get("rule_ids"), list)
            or not all(isinstance(item, str) for item in catalog["rule_ids"])
            or not isinstance(selection, dict)
            or selection.get("schema_version") != 1
            or set(selection) != {"schema_version", "rule_ids", "rule_packs"}
            or not isinstance(selection.get("rule_ids"), list)
            or not all(isinstance(item, str) for item in selection["rule_ids"])
            or not isinstance(mapping, dict)
            or mapping.get("schema_version") != 1
            or set(mapping) != {"schema_version", "mappings"}
            or not isinstance(mapping.get("mappings"), list)
        ):
            raise ValueError("PRODUCTION_STATIC_RULE_CLOSURE_INVALID")
        try:
            mappings = tuple(
                StaticRuleMapping(
                    rule_id=str(item["rule_id"]),
                    result_fact_kind=str(item["result_fact_kind"]),
                    flow_start_fact_kind=(
                        None
                        if item["flow_start_fact_kind"] is None
                        else str(item["flow_start_fact_kind"])
                    ),
                    requires_code_flow=item["requires_code_flow"],
                )
                for item in mapping["mappings"]
                if isinstance(item, dict)
                and set(item)
                == {
                    "rule_id",
                    "result_fact_kind",
                    "flow_start_fact_kind",
                    "requires_code_flow",
                }
                and isinstance(item["requires_code_flow"], bool)
            )
        except (KeyError, TypeError):
            raise ValueError("PRODUCTION_STATIC_RULE_CLOSURE_INVALID") from None
        if len(mappings) != len(mapping["mappings"]):
            raise ValueError("PRODUCTION_STATIC_RULE_CLOSURE_INVALID")
        closure = ApprovedStaticRuleClosure(
            catalog_sha256=route.rule_catalog_sha256,
            selection_sha256=route.rule_selection_sha256,
            mapping_sha256=route.rule_mapping_sha256,
            catalog_rule_ids=tuple(cast(list[str], catalog["rule_ids"])),
            selected_rule_ids=tuple(cast(list[str], selection["rule_ids"])),
            mappings=mappings,
        )
        closure.validate_for(route)
        result[route.tool] = closure
    return result


def _json_evidence(evidence: Mapping[str, bytes], digest: str) -> object:
    try:
        raw = evidence[digest]
    except KeyError:
        raise ValueError("PRODUCTION_STATIC_RULE_EVIDENCE_MISSING") from None
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("PRODUCTION_STATIC_RULE_EVIDENCE_STALE")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("PRODUCTION_STATIC_RULE_EVIDENCE_INVALID") from None


def _require_dynamic_result(value: BuiltProductionDynamicFeature) -> None:
    if not isinstance(value, BuiltProductionDynamicFeature) or any(
        not callable(check) for check in value.readiness_checks
    ):
        raise ValueError("PRODUCTION_DYNAMIC_FACTORY_INVALID")


def _require_directory(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_REPOSITORY_ROOT_INVALID"
        ) from None
    if not resolved.is_dir():
        raise ProductionCapabilityUnavailable("PRODUCTION_REPOSITORY_ROOT_INVALID")
    return resolved


def _resolve_executable(value: str) -> Path:
    candidate = Path(value)
    discovered = (
        str(candidate)
        if candidate.is_absolute() or candidate.parent != Path(".")
        else shutil.which(value)
    )
    if discovered is None:
        raise ValueError("PRODUCTION_EXECUTABLE_UNAVAILABLE")
    try:
        resolved = Path(discovered).resolve(strict=True)
    except OSError:
        raise ValueError("PRODUCTION_EXECUTABLE_UNAVAILABLE") from None
    if not resolved.is_file():
        raise ValueError("PRODUCTION_EXECUTABLE_UNAVAILABLE")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "BuiltProductionDynamicFeature",
    "CancellationFactory",
    "DynamicFeatureFactory",
    "ProductionStaticRuntimePorts",
    "StaticRuntimeFactory",
    "build_default_production_bundle_assembler",
    "build_default_production_bundle_registry",
]
