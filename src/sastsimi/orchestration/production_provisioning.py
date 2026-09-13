"""Resolve exact operator-approved provisioning inputs without defaults."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import ClassVar, Literal, Self, cast

from pydantic import model_validator

from sastsimi.contracts.base import ContractModel, NonEmptyStr, Sha256
from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.evaluation import EvaluationRecommendation
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
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef, reference
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort
from sastsimi.ports.dto import Record
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort

from .production_onboarding import ProductionProvisioningManifest

type ProvisioningSlot = Literal[
    "WORKSPACE_STORAGE",
    "STATIC_ANALYSIS",
    "VERIFICATION_PLAYBOOKS",
    "SANDBOX_PROFILE",
    "POLICY_CATALOG",
    "PROVIDER_CONFIGURATION",
    "PROMPT_ROUTES",
]


class _ProvisioningArtifactDocument(ContractModel):
    """Common exact scope and immutable inputs for one approved slot."""

    SLOT: ClassVar[str]
    ALLOWED_KINDS: ClassVar[frozenset[str]]
    REQUIRED_KINDS: ClassVar[frozenset[str]] = frozenset()

    schema_version: Literal[1]
    slot: ProvisioningSlot
    profile_hash: Sha256
    analysis_id: NonEmptyStr
    workspace_id: NonEmptyStr
    commit_id: NonEmptyStr
    record_refs: tuple[StoredDataRef, ...]
    evidence_sha256: tuple[Sha256, ...] = ()

    @model_validator(mode="after")
    def exact_inventory(self) -> Self:
        kinds = tuple(item.data_kind for item in self.record_refs)
        if (
            self.slot != self.SLOT
            or len(self.record_refs) != len(set(self.record_refs))
            or len(self.evidence_sha256) != len(set(self.evidence_sha256))
            or any(kind not in self.ALLOWED_KINDS for kind in kinds)
            or not self.REQUIRED_KINDS <= set(kinds)
            or any(ref.record_id is None for ref in self.record_refs)
            or any(
                (str(ref.workspace_id), str(ref.commit_id))
                != (self.workspace_id, self.commit_id)
                for ref in self.record_refs
            )
        ):
            raise ValueError("PRODUCTION_PROVISIONING_ARTIFACT_INVALID")
        return self


class WorkspaceStorageProvisioning(_ProvisioningArtifactDocument):
    SLOT = "WORKSPACE_STORAGE"
    ALLOWED_KINDS = frozenset()
    slot: Literal["WORKSPACE_STORAGE"]
    backend: Literal["SQLITE_RECORDS_AND_CAS"]


class StaticAnalysisProvisioning(_ProvisioningArtifactDocument):
    SLOT = "STATIC_ANALYSIS"
    ALLOWED_KINDS = frozenset()
    slot: Literal["STATIC_ANALYSIS"]
    enabled_tools: tuple[Literal["AST", "CODEQL", "OPENGREP"], ...]

    @model_validator(mode="after")
    def exact_tools(self) -> Self:
        if (
            not self.enabled_tools
            or "AST" not in self.enabled_tools
            or len(self.enabled_tools) != len(set(self.enabled_tools))
        ):
            raise ValueError("PRODUCTION_STATIC_TOOL_SET_INVALID")
        return self


class VerificationPlaybooksProvisioning(_ProvisioningArtifactDocument):
    SLOT = "VERIFICATION_PLAYBOOKS"
    ALLOWED_KINDS = frozenset({"verification_playbook", "playbook_policy"})
    REQUIRED_KINDS = frozenset({"verification_playbook", "playbook_policy"})
    slot: Literal["VERIFICATION_PLAYBOOKS"]

    @model_validator(mode="after")
    def one_policy(self) -> Self:
        if tuple(ref.data_kind for ref in self.record_refs).count(
            "playbook_policy"
        ) != 1:
            raise ValueError("PRODUCTION_PLAYBOOK_POLICY_AMBIGUOUS")
        return self


class SandboxProfileProvisioning(_ProvisioningArtifactDocument):
    SLOT = "SANDBOX_PROFILE"
    ALLOWED_KINDS = frozenset({"sandbox_profile"})
    REQUIRED_KINDS = ALLOWED_KINDS
    slot: Literal["SANDBOX_PROFILE"]
    container_user: NonEmptyStr
    max_execute_turns: int

    @model_validator(mode="after")
    def safe_execution_settings(self) -> Self:
        if (
            len(self.record_refs) != 1
            or self.max_execute_turns < 1
            or self.max_execute_turns > 128
        ):
            raise ValueError("PRODUCTION_SANDBOX_EXECUTION_INVALID")
        return self


class PolicyCatalogProvisioning(_ProvisioningArtifactDocument):
    SLOT = "POLICY_CATALOG"
    ALLOWED_KINDS = frozenset()
    slot: Literal["POLICY_CATALOG"]
    source_configuration_sha256: Sha256
    freshness_criterion_sha256: Sha256

    @model_validator(mode="after")
    def policy_evidence_is_declared(self) -> Self:
        if not {
            self.source_configuration_sha256,
            self.freshness_criterion_sha256,
        } <= set(self.evidence_sha256):
            raise ValueError("PRODUCTION_POLICY_EVIDENCE_INCOMPLETE")
        return self


class ProviderConfigurationProvisioning(_ProvisioningArtifactDocument):
    SLOT = "PROVIDER_CONFIGURATION"
    ALLOWED_KINDS = frozenset(
        {
            "provider_validation_evidence",
            "client_execution_profile",
            "provider_profile",
        }
    )
    REQUIRED_KINDS = frozenset(
        {"provider_validation_evidence", "provider_profile"}
    )
    slot: Literal["PROVIDER_CONFIGURATION"]

    @model_validator(mode="after")
    def matched_provider_evidence(self) -> Self:
        kinds = tuple(ref.data_kind for ref in self.record_refs)
        if kinds.count("provider_profile") != kinds.count(
            "provider_validation_evidence"
        ):
            raise ValueError("PRODUCTION_PROVIDER_EVIDENCE_INCOMPLETE")
        return self


class PromptRoutesProvisioning(_ProvisioningArtifactDocument):
    SLOT = "PROMPT_ROUTES"
    ALLOWED_KINDS = frozenset(
        {
            "execution_limits",
            "llm_retry_policy",
            "llm_tool_policy",
            "prompt_redaction_policy",
            "output_schema_spec",
            "semantic_validator_spec",
            "prompt_registry_entry",
            "evaluation_recommendation",
        }
    )
    REQUIRED_KINDS = frozenset(
        {
            "execution_limits",
            "llm_retry_policy",
            "llm_tool_policy",
            "prompt_redaction_policy",
            "output_schema_spec",
            "semantic_validator_spec",
            "prompt_registry_entry",
            "evaluation_recommendation",
        }
    )
    slot: Literal["PROMPT_ROUTES"]
    semantic_validator_keys: tuple[NonEmptyStr, ...]

    @model_validator(mode="after")
    def exact_validators(self) -> Self:
        if not self.semantic_validator_keys or len(
            self.semantic_validator_keys
        ) != len(set(self.semantic_validator_keys)):
            raise ValueError("PRODUCTION_SEMANTIC_VALIDATOR_SET_INVALID")
        return self


type ParsedProvisioningArtifact = (
    WorkspaceStorageProvisioning
    | StaticAnalysisProvisioning
    | VerificationPlaybooksProvisioning
    | SandboxProfileProvisioning
    | PolicyCatalogProvisioning
    | ProviderConfigurationProvisioning
    | PromptRoutesProvisioning
)

_ARTIFACT_MODELS: Mapping[str, type[_ProvisioningArtifactDocument]] = {
    item.SLOT: item
    for item in (
        WorkspaceStorageProvisioning,
        StaticAnalysisProvisioning,
        VerificationPlaybooksProvisioning,
        SandboxProfileProvisioning,
        PolicyCatalogProvisioning,
        ProviderConfigurationProvisioning,
        PromptRoutesProvisioning,
    )
}

_PROVISIONED_RECORD_MODELS: Mapping[str, type[Record]] = cast(
    Mapping[str, type[Record]],
    {
        VerificationPlaybook.KIND: VerificationPlaybook,
        PlaybookPolicy.KIND: PlaybookPolicy,
        SandboxProfile.KIND: SandboxProfile,
        ProviderValidationEvidence.KIND: ProviderValidationEvidence,
        ClientExecutionProfile.KIND: ClientExecutionProfile,
        ProviderProfile.KIND: ProviderProfile,
        ExecutionLimits.KIND: ExecutionLimits,
        LLMRetryPolicy.KIND: LLMRetryPolicy,
        LLMToolPolicy.KIND: LLMToolPolicy,
        PromptRedactionPolicy.KIND: PromptRedactionPolicy,
        OutputSchemaSpec.KIND: OutputSchemaSpec,
        SemanticValidatorSpec.KIND: SemanticValidatorSpec,
        PromptRegistryEntry.KIND: PromptRegistryEntry,
        EvaluationRecommendation.KIND: EvaluationRecommendation,
    },
)


@dataclass(frozen=True, slots=True)
class MaterializedProvisioningArtifacts:
    documents: Mapping[str, ParsedProvisioningArtifact]
    records: Mapping[StoredDataRef, Record]
    evidence: Mapping[str, bytes]


class ExactProvisioningArtifactMaterializer:
    """Parse all seven slots and recheck exact-current records and evidence."""

    def __init__(
        self,
        *,
        records: RecordStore,
        queries: RuntimeQueryPort,
        evidence: Callable[[str], bytes],
    ) -> None:
        self._records = records
        self._queries = queries
        self._evidence = evidence

    def materialize(
        self,
        artifacts: Mapping[str, bytes],
        *,
        profile_hash: str,
        analysis_id: str,
        workspace_id: str,
        commit_id: str,
    ) -> MaterializedProvisioningArtifacts:
        documents = self.parse(
            artifacts,
            profile_hash=profile_hash,
            analysis_id=analysis_id,
            workspace_id=workspace_id,
            commit_id=commit_id,
        )
        resolved_records: dict[StoredDataRef, Record] = {}
        resolved_evidence: dict[str, bytes] = {}
        for document in documents.values():
            for ref in document.record_refs:
                try:
                    record = self._records.get_exact(ref)
                except (LookupError, TypeError, ValueError):
                    raise ValueError(
                        "PRODUCTION_PROVISIONING_RECORD_MISSING"
                    ) from None
                meta = getattr(record, "meta", None)
                expected_model = _PROVISIONED_RECORD_MODELS.get(ref.data_kind)
                if (
                    expected_model is None
                    or not isinstance(record, expected_model)
                    or not isinstance(meta, RecordMeta)
                    or str(meta.analysis_id) != analysis_id
                    or str(meta.workspace_id) != workspace_id
                    or str(meta.commit_id) != commit_id
                    or reference(record) != ref
                ):
                    raise ValueError(
                        "PRODUCTION_PROVISIONING_RECORD_SCOPE_MISMATCH"
                    )
                current = tuple(
                    item
                    for item in self._queries.current_records(
                        analysis_id, str(meta.record_type)
                    )
                    if isinstance(getattr(item, "meta", None), RecordMeta)
                    and item.meta.logical_record_id == meta.logical_record_id
                )
                if len(current) != 1 or reference(current[0]) != ref:
                    raise ValueError("PRODUCTION_PROVISIONING_RECORD_STALE")
                resolved_records[ref] = record
            for digest in document.evidence_sha256:
                try:
                    payload = self._evidence(digest)
                except (KeyError, LookupError, OSError, TypeError, ValueError):
                    raise ValueError(
                        "PRODUCTION_PROVISIONING_EVIDENCE_MISSING"
                    ) from None
                if hashlib.sha256(payload).hexdigest() != digest:
                    raise ValueError("PRODUCTION_PROVISIONING_EVIDENCE_STALE")
                resolved_evidence[digest] = payload
        prompt = documents["PROMPT_ROUTES"]
        assert isinstance(prompt, PromptRoutesProvisioning)
        validator_keys = {
            record.validator_key
            for record in resolved_records.values()
            if isinstance(record, SemanticValidatorSpec)
        }
        if validator_keys != set(prompt.semantic_validator_keys):
            raise ValueError("PRODUCTION_SEMANTIC_VALIDATOR_SET_MISMATCH")
        return MaterializedProvisioningArtifacts(
            documents, resolved_records, resolved_evidence
        )

    @staticmethod
    def parse(
        artifacts: Mapping[str, bytes],
        *,
        profile_hash: str,
        analysis_id: str,
        workspace_id: str,
        commit_id: str,
    ) -> Mapping[str, ParsedProvisioningArtifact]:
        """Parse the complete seven-slot set before any record is consumed."""

        if set(artifacts) != set(_ARTIFACT_MODELS):
            raise ValueError("PRODUCTION_PROVISIONING_ARTIFACT_SET_INCOMPLETE")
        documents: dict[str, ParsedProvisioningArtifact] = {}
        for slot, raw in artifacts.items():
            model = _ARTIFACT_MODELS[slot]
            try:
                document = cast(
                    ParsedProvisioningArtifact, model.model_validate_json(raw)
                )
            except ValueError:
                raise ValueError("PRODUCTION_PROVISIONING_ARTIFACT_INVALID") from None
            if (
                document.profile_hash != profile_hash
                or document.analysis_id != analysis_id
                or document.workspace_id != workspace_id
                or document.commit_id != commit_id
            ):
                raise ValueError("PRODUCTION_PROVISIONING_ARTIFACT_SCOPE_MISMATCH")
            documents[slot] = document
        return documents


@dataclass(frozen=True, slots=True)
class ResolvedProductionProvisioning:
    """Exact current host records plus verified immutable configuration bytes."""

    capabilities: Mapping[str, RuntimeCapabilityProfile | StaticToolProfile]
    artifacts: Mapping[str, bytes]


class ExactProductionProvisioningResolver:
    """Revalidate every exact ref and its declared provisioning purpose."""

    def __init__(
        self,
        *,
        configuration: ProductionCapabilityResolverPort,
        evidence: Callable[[str], bytes],
    ) -> None:
        self._configuration = configuration
        self._evidence = evidence

    def resolve(
        self, manifest: ProductionProvisioningManifest
    ) -> ResolvedProductionProvisioning:
        capabilities: dict[str, RuntimeCapabilityProfile | StaticToolProfile] = {}
        for item in manifest.capabilities:
            profile = self._configuration.resolve_pinned_active_profile(
                item.profile_ref
            )
            if reference(profile) != item.profile_ref:
                raise ValueError("PRODUCTION_CAPABILITY_REFERENCE_MISMATCH")
            self._require_slot(item.slot, item.profile_ref, profile)
            capabilities[item.slot] = profile
        artifacts: dict[str, bytes] = {
            item.slot: self._evidence(item.content_sha256)
            for item in manifest.artifacts
        }
        if any(not value for value in artifacts.values()):
            raise ValueError("PRODUCTION_PROVISIONING_ARTIFACT_EMPTY")
        return ResolvedProductionProvisioning(capabilities, artifacts)

    def resolve_materialized(
        self,
        manifest: ProductionProvisioningManifest,
        *,
        records: RecordStore,
        queries: RuntimeQueryPort,
        profile_hash: str,
        analysis_id: str,
        workspace_id: str,
        commit_id: str,
    ) -> tuple[ResolvedProductionProvisioning, MaterializedProvisioningArtifacts]:
        """Resolve host capabilities and the complete exact run artifact set."""

        resolved = self.resolve(manifest)
        materialized = ExactProvisioningArtifactMaterializer(
            records=records,
            queries=queries,
            evidence=self._evidence,
        ).materialize(
            resolved.artifacts,
            profile_hash=profile_hash,
            analysis_id=analysis_id,
            workspace_id=workspace_id,
            commit_id=commit_id,
        )
        return resolved, materialized

    @staticmethod
    def _require_slot(
        slot: str,
        expected_ref: HostConfigurationRef,
        profile: RuntimeCapabilityProfile | StaticToolProfile,
    ) -> None:
        runtime = {
            "GIT_CLONE": ("GIT", "CLONE"),
            "GIT_CHECKOUT": ("GIT", "CHECKOUT"),
            "PYTHON_RUNTIME": ("PYTHON_RUNTIME", "START"),
            "DOCKER": ("DOCKER", "CONTAINER_RUN"),
        }
        static = {
            "AST": "PYTHON_AST",
            "CODEQL": "CODEQL",
            "OPENGREP": "OPENGREP",
        }
        if slot in runtime:
            kind, required_operation = runtime[slot]
            if (
                not isinstance(profile, RuntimeCapabilityProfile)
                or expected_ref.data_kind != RuntimeCapabilityProfile.KIND
                or profile.status != "ACTIVE"
                or profile.purpose != "PRODUCTION"
                or profile.capability_kind != kind
                or required_operation not in profile.operations
            ):
                raise ValueError("PRODUCTION_CAPABILITY_SLOT_MISMATCH")
            if slot == "DOCKER" and not {
                "IMAGE_BUILD",
                "CONTAINER_RUN",
                "HEALTH_CHECK",
                "CLEANUP",
            } <= set(profile.operations):
                raise ValueError("PRODUCTION_CAPABILITY_SLOT_MISMATCH")
            return
        adapter = static.get(slot)
        if (
            adapter is None
            or not isinstance(profile, StaticToolProfile)
            or expected_ref.data_kind != StaticToolProfile.KIND
            or profile.status != "ACTIVE"
            or profile.purpose != "PRODUCTION"
            or profile.adapter_key != adapter
        ):
            raise ValueError("PRODUCTION_CAPABILITY_SLOT_MISMATCH")


__all__ = [
    "ExactProductionProvisioningResolver",
    "ExactProvisioningArtifactMaterializer",
    "MaterializedProvisioningArtifacts",
    "PolicyCatalogProvisioning",
    "PromptRoutesProvisioning",
    "ProviderConfigurationProvisioning",
    "ResolvedProductionProvisioning",
    "SandboxProfileProvisioning",
    "StaticAnalysisProvisioning",
    "VerificationPlaybooksProvisioning",
    "WorkspaceStorageProvisioning",
]
