"""Concrete, fail-closed filesystem provisioning for one production run."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from sqlalchemy import insert, select, update

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.evaluation import (
    EvaluationRecommendation,
    EvaluationRunConfig,
    EvaluationRunResult,
)
from sastsimi.contracts.ids import StoredDataId
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    ExecutionLimits,
    LLMRecord,
    LLMRetryPolicy,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptRedactionPolicy,
    PromptRegistryEntry,
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from sastsimi.contracts.policy import (
    OfficialPolicySourceConfig,
    PolicyFreshnessCriterion,
)
from sastsimi.contracts.refs import (
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.orchestration.production_call_authority import AnalysisApprovedRoute
from sastsimi.orchestration.production_capabilities import (
    ProfileBackedProductionCapabilityBundle,
    production_profile_hash,
)
from sastsimi.orchestration.production_context import (
    ProductionCapabilityUnavailable,
    ProductionFeatureInstaller,
)
from sastsimi.orchestration.production_onboarding import (
    ProductionOnboardingManifest,
    ProductionProvisioningManifest,
)
from sastsimi.orchestration.production_provisioning import (
    ExactProductionProvisioningResolver,
    ExactProvisioningArtifactMaterializer,
    MaterializedProvisioningArtifacts,
    ParsedProvisioningTemplate,
    PolicyCatalogProvisioningTemplate,
    PromptRoutesProvisioningTemplate,
    ProviderConfigurationProvisioningTemplate,
    ProvisioningRecordEnvelopeMaterializer,
    ProvisioningTemplateMaterializer,
    ResolvedProductionProvisioning,
    SandboxProfileProvisioningTemplate,
    StaticAnalysisProvisioningTemplate,
)
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.dto import CapabilityProbeResult, Record
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.trusted_evidence import UnprovenEvidence
from sastsimi.storage import models
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.configuration_registry import ConfigurationRegistry
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade
from sastsimi.storage.queries import RuntimeQueries
from sastsimi.storage.repositories import SQLiteRecordStore


@dataclass(frozen=True, slots=True)
class ProductionImplementationSet:
    """Exact compiled-in implementation keys requested by approved templates."""

    static_routes: tuple[str, ...]
    provider_adapters: tuple[str, ...]
    policy_parser: str
    sandbox_authorization: str
    sandbox_setup: str
    semantic_validators: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProductionBundleAssemblyContext:
    """Typed input supplied to feature-specific builders, never guessed values."""

    data_dir: Path
    request: AnalysisStartRequest
    profile: ProductionProfile
    scope: PlannedRunScope
    onboarding: ProductionOnboardingManifest
    provisioning: ProductionProvisioningManifest
    implementation_set: ProductionImplementationSet
    resolved: ResolvedProductionProvisioning
    materialized: MaterializedProvisioningArtifacts
    template_record_refs: Mapping[str, StoredDataRef]
    records: SQLiteRecordStore
    queries: RuntimeQueries
    artifacts: LocalArtifactStore
    configuration: ConfigurationRegistry


@dataclass(frozen=True, slots=True)
class ProductionBundleAssembly:
    """Feature-specific values required to finish the generic capability bundle."""

    llm_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter]
    approved_llm_routes: tuple[AnalysisApprovedRoute, ...]
    install: ProductionFeatureInstaller


class ProductionBundleAssemblyPort(Protocol):
    def __call__(
        self, context: ProductionBundleAssemblyContext
    ) -> ProductionBundleAssembly: ...


class ProductionBundleAssemblyRegistry:
    """Allowlist feature builders by the complete approved implementation set."""

    def __init__(
        self,
        builders: Mapping[ProductionImplementationSet, ProductionBundleAssemblyPort]
        | None = None,
    ) -> None:
        self._builders = dict(builders or {})

    def register(
        self,
        key: ProductionImplementationSet,
        builder: ProductionBundleAssemblyPort,
    ) -> None:
        if key in self._builders:
            raise ValueError("PRODUCTION_FEATURE_SET_DUPLICATED")
        self._builders[key] = builder

    def __call__(
        self, context: ProductionBundleAssemblyContext
    ) -> ProductionBundleAssembly:
        try:
            builder = self._builders[context.implementation_set]
        except KeyError:
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_FEATURE_SET_UNSUPPORTED"
            ) from None
        return builder(context)


class ExactProvisioningTrustedEvidence(UnprovenEvidence):
    """Approve only exact records materialized from hashed operator templates."""

    def __init__(self, records: Mapping[str, Record]) -> None:
        self._playbooks = frozenset(
            content_hash(item)
            for item in records.values()
            if isinstance(item, (VerificationPlaybook, PlaybookPolicy))
        )
        self._llm = frozenset(
            content_hash(item)
            for item in records.values()
            if isinstance(item, (LLMRecord, EvaluationRunConfig))
        )
        self._sandbox = frozenset(
            content_hash(item)
            for item in records.values()
            if isinstance(item, SandboxProfile)
        )

    def playbook_configuration_approved(
        self, record: VerificationPlaybook | PlaybookPolicy
    ) -> bool:
        return content_hash(record) in self._playbooks

    def llm_configuration_approved(self, record: LLMRecord) -> bool:
        return content_hash(record) in self._llm

    def sandbox_configuration_approved(self, profile: SandboxProfile) -> bool:
        return content_hash(profile) in self._sandbox


class FilesystemAnalysisCapabilityProvisioner:
    """Materialize exact approvals in SQLite and assemble one scoped bundle."""

    def __init__(self, assemble: ProductionBundleAssemblyPort) -> None:
        self._assemble = assemble

    def __call__(
        self,
        *,
        data_dir: Path,
        request: object,
        profile: ProductionProfile,
        scope: object,
        manifest: ProductionOnboardingManifest,
        provisioning: ProductionProvisioningManifest,
        evidence: Callable[[str], bytes],
    ) -> ProfileBackedProductionCapabilityBundle:
        if not isinstance(request, AnalysisStartRequest) or not isinstance(
            scope, PlannedRunScope
        ):
            raise ProductionCapabilityUnavailable("PRODUCTION_SCOPE_INVALID")
        if manifest.profile_hash != production_profile_hash(profile):
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_PROFILE_CAPABILITY_MISMATCH"
            )

        paths = RuntimePaths(data_dir)
        database = Database(paths.database)
        upgrade(database)
        database.check_ready()
        artifacts = LocalArtifactStore(
            paths.artifacts, scope.workspace_id, scope.commit_id
        )

        templates_raw: dict[str, bytes] = {
            item.slot: self._verified_bytes(evidence, item.content_sha256)
            for item in provisioning.artifacts
        }
        templates = ProvisioningTemplateMaterializer.parse(
            templates_raw,
            profile_hash=manifest.profile_hash,
            host_id=profile.host_id,
        )
        record_templates = tuple(
            item
            for document in templates.values()
            for item in document.record_templates
        )
        payloads = {
            item.content_sha256: self._verified_bytes(evidence, item.content_sha256)
            for item in record_templates
        }
        evidence_digests = self._evidence_digests(manifest, templates)
        workspace_evidence, run_evidence = self._import_evidence(
            artifacts=artifacts,
            evidence=evidence,
            digests=evidence_digests,
            scope=scope,
        )
        records_by_key = ProvisioningRecordEnvelopeMaterializer.materialize(
            templates=record_templates,
            payloads=payloads,
            evidence_refs=workspace_evidence,
            run_evidence_refs=run_evidence,
            analysis_id=str(scope.analysis_id),
            workspace_id=str(scope.workspace_id),
            commit_id=str(scope.commit_id),
        )
        trusted = ExactProvisioningTrustedEvidence(records_by_key)
        records = SQLiteRecordStore(database, trusted)
        queries = RuntimeQueries(records)
        configuration = ConfigurationRegistry(records, artifacts, profile.host_id)

        try:
            resolved = ExactProductionProvisioningResolver(
                configuration=configuration,
                evidence=evidence,
            ).resolve(provisioning)
        except (LookupError, OSError, TypeError, ValueError):
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_APPROVED_CAPABILITY_MISSING"
            ) from None

        self._publish_records(records_by_key, records, configuration)
        record_refs = {
            key: cast(StoredDataRef, reference(record))
            for key, record in records_by_key.items()
        }
        run_artifacts = ProvisioningTemplateMaterializer.bind_run(
            templates,
            analysis_id=str(scope.analysis_id),
            workspace_id=str(scope.workspace_id),
            commit_id=str(scope.commit_id),
            record_refs=record_refs,
        )
        materialized = ExactProvisioningArtifactMaterializer(
            records=records,
            queries=queries,
            evidence=evidence,
        ).materialize(
            run_artifacts,
            profile_hash=manifest.profile_hash,
            analysis_id=str(scope.analysis_id),
            workspace_id=str(scope.workspace_id),
            commit_id=str(scope.commit_id),
        )
        context = ProductionBundleAssemblyContext(
            data_dir=data_dir.resolve(),
            request=request,
            profile=profile,
            scope=scope,
            onboarding=manifest,
            provisioning=provisioning,
            implementation_set=self._implementation_set(templates),
            resolved=resolved,
            materialized=materialized,
            template_record_refs=record_refs,
            records=records,
            queries=queries,
            artifacts=artifacts,
            configuration=configuration,
        )
        assembly = self._assemble(context)
        policy_ref = run_evidence[manifest.policy_artifact_sha256]
        git_refs = tuple(
            dict.fromkeys(
                item.profile_ref
                for item in provisioning.capabilities
                if item.slot in {"GIT_CLONE", "GIT_CHECKOUT"}
            )
        )
        return ProfileBackedProductionCapabilityBundle(
            profile_hash=manifest.profile_hash,
            data_dir=data_dir.resolve(),
            analysis_id=scope.analysis_id,
            workspace_id=scope.workspace_id,
            commit_id=scope.commit_id,
            repository_ref=scope.repository_ref,
            host_id=profile.host_id,
            llm_adapters=assembly.llm_adapters,
            approved_llm_routes=assembly.approved_llm_routes,
            workspace_dependency_refs=(policy_ref, *git_refs),
            records=records,
            queries=queries,
            artifacts=artifacts,
            configuration=configuration,
            configuration_evidence=trusted,
            install=assembly.install,
        )

    @staticmethod
    def _verified_bytes(evidence: Callable[[str], bytes], digest: str) -> bytes:
        raw = evidence(digest)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ProductionCapabilityUnavailable("PRODUCTION_EVIDENCE_STALE")
        return raw

    @classmethod
    def _import_evidence(
        cls,
        *,
        artifacts: LocalArtifactStore,
        evidence: Callable[[str], bytes],
        digests: frozenset[str],
        scope: PlannedRunScope,
    ) -> tuple[Mapping[str, StoredDataRef], Mapping[str, RunStoredDataRef]]:
        workspace: dict[str, StoredDataRef] = {}
        run: dict[str, RunStoredDataRef] = {}
        for digest in sorted(digests):
            raw = cls._verified_bytes(evidence, digest)
            promoted = artifacts.promote(
                artifacts.stage_bytes(raw, "application/octet-stream")
            )
            if promoted != digest:
                raise ProductionCapabilityUnavailable("PRODUCTION_EVIDENCE_STALE")
            workspace[digest] = StoredDataRef(
                stored_data_id=StoredDataId(digest),
                data_kind="artifact",
                content_hash=digest,
                workspace_id=scope.workspace_id,
                commit_id=scope.commit_id,
                record_id=None,
            )
            run[digest] = RunStoredDataRef(
                stored_data_id=StoredDataId(digest),
                data_kind="artifact",
                content_hash=digest,
                analysis_id=scope.analysis_id,
                record_id=None,
            )
        return workspace, run

    @staticmethod
    def _evidence_digests(
        manifest: ProductionOnboardingManifest,
        templates: Mapping[str, ParsedProvisioningTemplate],
    ) -> frozenset[str]:
        declared = {
            digest
            for document in templates.values()
            for digest in document.evidence_sha256
        }
        return frozenset(
            {
                manifest.policy_artifact_sha256,
                *declared,
                *(
                    observation.evidence_sha256
                    for provider in manifest.provider_approvals
                    for observation in provider.tests
                ),
                *(
                    digest
                    for route in manifest.route_approvals
                    for digest in (
                        route.template_sha256,
                        route.evaluation_result_sha256,
                        route.recommendation_sha256,
                    )
                ),
            }
        )

    @staticmethod
    def _publish_records(
        values: Mapping[str, Record],
        records: SQLiteRecordStore,
        configuration: ConfigurationRegistry,
    ) -> None:
        for record in values.values():
            if isinstance(record, VerificationPlaybook):
                configuration.register_playbook(record)
            elif isinstance(record, PlaybookPolicy):
                configuration.register_playbook_policy(record)
            elif isinstance(record, ProviderValidationEvidence):
                configuration.register_provider_validation(record)
            elif isinstance(record, ClientExecutionProfile):
                configuration.register_client_execution(record)
            elif isinstance(record, ProviderProfile):
                evidence = records.get_exact(record.validation_evidence_ref)
                if not isinstance(evidence, ProviderValidationEvidence):
                    raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH")
                configuration.register_provider_profile(
                    record, CapabilityProbeResult(evidence)
                )
            elif isinstance(record, ExecutionLimits):
                configuration.register_execution_limits(record)
            elif isinstance(record, LLMRetryPolicy):
                configuration.register_retry_policy(record)
            elif isinstance(record, LLMToolPolicy):
                configuration.register_tool_policy(record)
            elif isinstance(record, PromptRedactionPolicy):
                configuration.register_redaction_policy(record)
            elif isinstance(record, OutputSchemaSpec):
                configuration.register_output_schema(record)
            elif isinstance(record, SemanticValidatorSpec):
                configuration.register_semantic_validator(record)
            elif isinstance(record, EvaluationRunConfig):
                configuration.register_evaluation_config(record)
            elif isinstance(record, PromptRegistryEntry):
                configuration.register_prompt_entry(record)
            elif isinstance(record, (EvaluationRunResult, EvaluationRecommendation)):
                FilesystemAnalysisCapabilityProvisioner._publish_current(
                    records, record
                )
            elif isinstance(
                record, (OfficialPolicySourceConfig, PolicyFreshnessCriterion)
            ):
                FilesystemAnalysisCapabilityProvisioner._publish_current(
                    records, record
                )
            elif isinstance(record, SandboxProfile):
                configuration.register_sandbox_profile(record)
            else:
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_KIND_UNSUPPORTED")

    @staticmethod
    def _publish_current(records: SQLiteRecordStore, record: Record) -> None:
        ref = reference(record)
        if not isinstance(ref, StoredDataRef):
            raise ValueError("PRODUCTION_RECORD_TEMPLATE_SCOPE_INVALID")
        with records.database.write() as connection:
            if records.stage(connection, record) != ref:
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_REFERENCE_MISMATCH")
            records.publish(connection, ref)
            table = models.current_records
            logical_id = str(record.meta.logical_record_id)
            current = (
                connection.execute(
                    select(table).where(table.c.logical_record_id == logical_id)
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                connection.execute(
                    insert(table).values(
                        logical_record_id=logical_id,
                        record_id=str(record.meta.record_id),
                        state_version=1,
                    )
                )
            elif current["record_id"] != str(record.meta.record_id):
                if current["record_id"] != str(record.meta.previous_record_id):
                    raise ValueError("PRODUCTION_RECORD_TEMPLATE_STALE")
                changed = connection.execute(
                    update(table)
                    .where(
                        table.c.logical_record_id == logical_id,
                        table.c.state_version == current["state_version"],
                    )
                    .values(
                        record_id=str(record.meta.record_id),
                        state_version=current["state_version"] + 1,
                    )
                )
                if changed.rowcount != 1:
                    raise ValueError("PRODUCTION_RECORD_TEMPLATE_STALE")

    @staticmethod
    def _implementation_set(
        templates: Mapping[str, ParsedProvisioningTemplate],
    ) -> ProductionImplementationSet:
        static = cast(StaticAnalysisProvisioningTemplate, templates["STATIC_ANALYSIS"])
        providers = cast(
            ProviderConfigurationProvisioningTemplate,
            templates["PROVIDER_CONFIGURATION"],
        )
        policy = cast(PolicyCatalogProvisioningTemplate, templates["POLICY_CATALOG"])
        sandbox = cast(SandboxProfileProvisioningTemplate, templates["SANDBOX_PROFILE"])
        prompts = cast(PromptRoutesProvisioningTemplate, templates["PROMPT_ROUTES"])
        return ProductionImplementationSet(
            static_routes=tuple(
                f"{item.tool}:{item.adapter_key}:{item.decoder_key}"
                for item in static.routes
            ),
            provider_adapters=tuple(
                item.implementation_key
                for item in providers.provider_implementation_bindings
            ),
            policy_parser=policy.parser_implementation_key,
            sandbox_authorization=sandbox.authorization_implementation_key,
            sandbox_setup=sandbox.setup_implementation_key,
            semantic_validators=tuple(
                item.implementation_key for item in prompts.semantic_validator_bindings
            ),
        )


__all__ = [
    "ExactProvisioningTrustedEvidence",
    "FilesystemAnalysisCapabilityProvisioner",
    "ProductionBundleAssembly",
    "ProductionBundleAssemblyContext",
    "ProductionBundleAssemblyPort",
    "ProductionBundleAssemblyRegistry",
    "ProductionImplementationSet",
]
