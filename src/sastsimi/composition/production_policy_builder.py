"""Build the official-policy production feature from exact approved evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from pydantic import model_validator

from sastsimi.composition.production_feature_installer import (
    PolicyProductionFeature,
    build_official_policy_feature,
)
from sastsimi.composition.production_filesystem_provisioner import (
    ProductionBundleAssemblyContext,
)
from sastsimi.config.production_profile import PolicySource
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    ProgramId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.policy import (
    OfficialPolicySourceConfig,
    PolicyFreshnessCriterion,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.production_context import (
    ProductionCapabilityUnavailable,
    ProductionInstallationContext,
)
from sastsimi.orchestration.production_provisioning import PolicyCatalogProvisioning
from sastsimi.policy.adapters.official_http import (
    OfficialHttpPolicySource,
    PinnedHttpsTransport,
    resolve_public_addresses,
)
from sastsimi.policy.program_catalog import ProgramCatalog
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.policy_catalog import ProgramCatalogEntry
from sastsimi.verification.production_llm_work_handlers import ProductionCallPort


class PolicySourceEvidence(ContractModel):
    """Credential-free policy source configuration approved by the operator."""

    schema_version: Literal[1]
    program_id: ProgramId
    policy: PolicySource


class PolicyFreshnessEvidence(ContractModel):
    """The exact freshness rule approved for one source revision."""

    schema_version: Literal[1]
    program_id: ProgramId
    source_version: str
    freshness_ttl_seconds: int

    @model_validator(mode="after")
    def valid_freshness(self) -> PolicyFreshnessEvidence:
        if not self.source_version.strip() or self.freshness_ttl_seconds <= 0:
            raise ValueError("PRODUCTION_POLICY_FRESHNESS_INVALID")
        return self


def policy_source_evidence_bytes(program_id: ProgramId, policy: PolicySource) -> bytes:
    """Return the only accepted canonical source-configuration evidence bytes."""

    return canonical_bytes(
        PolicySourceEvidence(schema_version=1, program_id=program_id, policy=policy)
    )


def policy_freshness_evidence_bytes(
    program_id: ProgramId, policy: PolicySource
) -> bytes:
    """Return the only accepted canonical freshness-criterion evidence bytes."""

    return canonical_bytes(
        PolicyFreshnessEvidence(
            schema_version=1,
            program_id=program_id,
            source_version=policy.source_version,
            freshness_ttl_seconds=policy.freshness_ttl_seconds,
        )
    )


def build_policy_catalog_entry(
    *,
    program_id: ProgramId,
    analysis_id: AnalysisId,
    workspace_id: WorkspaceId,
    commit_id: CommitId,
    expected: PolicySource,
    document: PolicyCatalogProvisioning,
    source_config: OfficialPolicySourceConfig,
    freshness_criterion: PolicyFreshnessCriterion,
    evidence: Mapping[str, bytes],
    artifacts: ArtifactStore,
) -> ProgramCatalogEntry:
    """Validate the profile against hashed evidence and bind exact artifact refs."""

    if (
        document.parser_implementation_key != "OFFICIAL_HTTP_POLICY_V1"
        or document.analysis_id != str(analysis_id)
        or document.workspace_id != str(workspace_id)
        or document.commit_id != str(commit_id)
        or source_config.meta.analysis_id != analysis_id
        or source_config.meta.workspace_id != workspace_id
        or source_config.meta.commit_id != commit_id
        or freshness_criterion.meta.analysis_id != analysis_id
        or freshness_criterion.meta.workspace_id != workspace_id
        or freshness_criterion.meta.commit_id != commit_id
    ):
        raise ProductionCapabilityUnavailable("PRODUCTION_POLICY_SCOPE_MISMATCH")
    try:
        source_raw = evidence[document.source_configuration_sha256]
        freshness_raw = evidence[document.freshness_criterion_sha256]
        source = PolicySourceEvidence.model_validate_json(source_raw)
        freshness = PolicyFreshnessEvidence.model_validate_json(freshness_raw)
    except (KeyError, TypeError, ValueError):
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_POLICY_CONFIGURATION_INVALID"
        ) from None
    if (
        source.program_id != program_id
        or source.policy != expected
        or freshness.program_id != program_id
        or freshness.source_version != expected.source_version
        or freshness.freshness_ttl_seconds != expected.freshness_ttl_seconds
        or source_raw != policy_source_evidence_bytes(program_id, expected)
        or freshness_raw != policy_freshness_evidence_bytes(program_id, expected)
        or source_config.program_id != program_id
        or source_config.source_artifact_ref.content_hash
        != document.source_configuration_sha256
        or source_config.program_namespace != expected.program_namespace
        or source_config.external_program_id != expected.external_program_id
        or source_config.source_version != expected.source_version
        or source_config.official_endpoint != expected.official_endpoint
        or source_config.publisher != expected.publisher
        or source_config.parser_name != expected.parser_name
        or source_config.parser_version != expected.parser_version
        or source_config.timeout_seconds != expected.timeout_seconds
        or source_config.max_response_bytes != expected.max_response_bytes
        or source_config.allowed_content_types != expected.allowed_content_types
        or source_config.allowed_redirect_hosts != expected.allowed_redirect_hosts
        or freshness_criterion.program_id != program_id
        or freshness_criterion.criterion_artifact_ref.content_hash
        != document.freshness_criterion_sha256
        or freshness_criterion.source_version != expected.source_version
        or freshness_criterion.freshness_ttl_seconds != expected.freshness_ttl_seconds
    ):
        raise ProductionCapabilityUnavailable("PRODUCTION_POLICY_CONFIGURATION_STALE")
    source_artifact_ref = _artifact_ref(
        document.source_configuration_sha256, workspace_id, commit_id
    )
    freshness_artifact_ref = _artifact_ref(
        document.freshness_criterion_sha256, workspace_id, commit_id
    )
    source_ref = reference(source_config)
    freshness_ref = reference(freshness_criterion)
    if (
        not isinstance(source_ref, StoredDataRef)
        or not isinstance(freshness_ref, StoredDataRef)
        or set(document.record_refs) != {source_ref, freshness_ref}
        or source_config.source_artifact_ref != source_artifact_ref
        or freshness_criterion.criterion_artifact_ref != freshness_artifact_ref
    ):
        raise ProductionCapabilityUnavailable("PRODUCTION_POLICY_RECORD_MISMATCH")
    try:
        if (
            artifacts.open_verified(source_artifact_ref).read() != source_raw
            or artifacts.open_verified(freshness_artifact_ref).read() != freshness_raw
        ):
            raise ValueError
    except (OSError, ValueError):
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_POLICY_EVIDENCE_STALE"
        ) from None
    return ProgramCatalogEntry(
        program_id=program_id,
        program_namespace=expected.program_namespace,
        external_program_id=expected.external_program_id,
        source_config_ref=source_ref,
        source_version=expected.source_version,
        official_endpoint=expected.official_endpoint,
        publisher=expected.publisher,
        parser_name=expected.parser_name,
        parser_version=expected.parser_version,
        freshness_criterion_ref=freshness_ref,
        freshness_ttl_seconds=expected.freshness_ttl_seconds,
        timeout_seconds=expected.timeout_seconds,
        max_response_bytes=expected.max_response_bytes,
        allowed_content_types=expected.allowed_content_types,
        allowed_redirect_hosts=expected.allowed_redirect_hosts,
    )


@dataclass(frozen=True, slots=True)
class ProductionPolicyFeatureFactory:
    """Create runtime-owned policy services without changing approved inputs."""

    catalog: ProgramCatalog

    def __call__(
        self,
        context: ProductionInstallationContext,
        calls: ProductionCallPort,
    ) -> PolicyProductionFeature:
        source = OfficialHttpPolicySource(
            catalog=self.catalog,
            artifacts=context.runtime.unit_of_work.artifacts,
            transport=PinnedHttpsTransport(),
            resolver=resolve_public_addresses,
            clock=context.clock,
        )
        return build_official_policy_feature(
            context=context,
            calls=calls,
            catalog=self.catalog,
            source=source,
        )


def build_production_policy_feature_factory(
    context: ProductionBundleAssemblyContext,
) -> ProductionPolicyFeatureFactory:
    """Resolve one exact official-policy feature factory from a bundle context."""

    document = context.materialized.documents.get("POLICY_CATALOG")
    if not isinstance(document, PolicyCatalogProvisioning):
        raise ProductionCapabilityUnavailable("PRODUCTION_POLICY_CONFIGURATION_MISSING")
    source_configs = tuple(
        record
        for record in context.materialized.records.values()
        if isinstance(record, OfficialPolicySourceConfig)
    )
    freshness_criteria = tuple(
        record
        for record in context.materialized.records.values()
        if isinstance(record, PolicyFreshnessCriterion)
    )
    if len(source_configs) != 1 or len(freshness_criteria) != 1:
        raise ProductionCapabilityUnavailable("PRODUCTION_POLICY_RECORD_MISSING")
    entry = build_policy_catalog_entry(
        program_id=ProgramId(str(context.request.program_id)),
        analysis_id=context.scope.analysis_id,
        workspace_id=context.scope.workspace_id,
        commit_id=context.scope.commit_id,
        expected=context.profile.policy,
        document=document,
        source_config=source_configs[0],
        freshness_criterion=freshness_criteria[0],
        evidence=context.materialized.evidence,
        artifacts=cast(ArtifactStore, context.artifacts),
    )
    return ProductionPolicyFeatureFactory(ProgramCatalog((entry,)))


def _artifact_ref(
    digest: str, workspace_id: WorkspaceId, commit_id: CommitId
) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(digest),
        data_kind="artifact",
        content_hash=digest,
        workspace_id=workspace_id,
        commit_id=commit_id,
        record_id=None,
    )


__all__ = [
    "PolicyFreshnessEvidence",
    "PolicySourceEvidence",
    "ProductionPolicyFeatureFactory",
    "build_policy_catalog_entry",
    "build_production_policy_feature_factory",
    "policy_freshness_evidence_bytes",
    "policy_source_evidence_bytes",
]
