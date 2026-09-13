"""Resolve exact operator-approved provisioning inputs without defaults."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, ClassVar, Literal, Self, cast

from pydantic import JsonValue, model_validator

from sastsimi.contracts.base import ContractModel, NonEmptyStr, Sha256
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.evaluation import (
    EvaluationRecommendation,
    EvaluationRunConfig,
    EvaluationRunResult,
)
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    LogicalRecordId,
    RecordId,
    WorkspaceId,
)
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
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
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

type StaticProvisioningTool = Literal["AST", "CODEQL", "OPENGREP"]
type StaticAdapterKey = Literal["PYTHON_AST", "CODEQL", "OPENGREP"]
type StaticDecoderKey = Literal[
    "PYTHON_AST_JSON_V1",
    "CODEQL_SARIF_V1",
    "OPENGREP_JSON_V1",
]
type SemanticValidatorImplementationKey = Literal["JSON_SCHEMA_AND_AUTHORITY_V1",]


class ProvisioningRecordTemplateRef(ContractModel):
    """Immutable operator input that will become one run-scoped record."""

    template_key: NonEmptyStr
    data_kind: NonEmptyStr
    content_sha256: Sha256


class ProvisioningRecordEnvelope(ContractModel):
    """Approved record body with symbolic, never guessed, dependencies."""

    schema_version: Literal[1]
    template_key: NonEmptyStr
    data_kind: NonEmptyStr
    logical_key: NonEmptyStr
    record_schema_version: NonEmptyStr
    revision_number: int
    previous_template_key: NonEmptyStr | None
    created_at: datetime
    payload: dict[str, JsonValue]

    @model_validator(mode="after")
    def revision_shape(self) -> Self:
        if (
            self.revision_number < 1
            or (self.revision_number == 1) != (self.previous_template_key is None)
            or "meta" in self.payload
        ):
            raise ValueError("PRODUCTION_RECORD_TEMPLATE_REVISION_INVALID")
        return self


class ProvisioningRecordEnvelopeMaterializer:
    """Resolve approved symbolic records in dependency order for one run."""

    _RECORD_MARKER = "$record_template_ref"
    _EVIDENCE_MARKER = "$evidence_ref"
    _RUN_EVIDENCE_MARKER = "$run_evidence_ref"

    @classmethod
    def materialize(
        cls,
        *,
        templates: tuple[ProvisioningRecordTemplateRef, ...],
        payloads: Mapping[str, bytes],
        evidence_refs: Mapping[str, StoredDataRef],
        run_evidence_refs: Mapping[str, RunStoredDataRef] | None = None,
        analysis_id: str,
        workspace_id: str,
        commit_id: str,
    ) -> Mapping[str, Record]:
        by_key = {item.template_key: item for item in templates}
        if len(by_key) != len(templates):
            raise ValueError("PRODUCTION_RECORD_TEMPLATE_KEY_DUPLICATED")
        envelopes: dict[str, ProvisioningRecordEnvelope] = {}
        for item in templates:
            try:
                raw = payloads[item.content_sha256]
            except KeyError:
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_MISSING") from None
            if hashlib.sha256(raw).hexdigest() != item.content_sha256:
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_STALE")
            try:
                envelope = ProvisioningRecordEnvelope.model_validate_json(raw)
            except ValueError:
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_INVALID") from None
            if (
                envelope.template_key != item.template_key
                or envelope.data_kind != item.data_kind
            ):
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_IDENTITY_MISMATCH")
            if envelope.data_kind not in _PROVISIONED_RECORD_MODELS:
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_KIND_UNSUPPORTED")
            envelopes[item.template_key] = envelope

        dependencies = {
            key: cls._dependencies(envelope) for key, envelope in envelopes.items()
        }
        for values in dependencies.values():
            if not values <= set(envelopes):
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_REFERENCE_MISSING")

        ordered: list[str] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(key: str) -> None:
            if key in visiting:
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_CYCLE")
            if key in visited:
                return
            visiting.add(key)
            for dependency in sorted(dependencies[key]):
                visit(dependency)
            visiting.remove(key)
            visited.add(key)
            ordered.append(key)

        for item in templates:
            visit(item.template_key)

        built: dict[str, Record] = {}
        run_refs = run_evidence_refs or {}
        for key in ordered:
            envelope = envelopes[key]
            previous = (
                None
                if envelope.previous_template_key is None
                else built[envelope.previous_template_key]
            )
            logical_id = LogicalRecordId(
                cls._stable_id("logical", analysis_id, envelope.logical_key)
            )
            if previous is not None and (
                previous.meta.logical_record_id != logical_id
                or previous.meta.record_type != envelope.data_kind
                or previous.meta.revision_number + 1 != envelope.revision_number
            ):
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_REVISION_INVALID")
            meta = RecordMeta(
                record_id=RecordId(cls._stable_id("record", analysis_id, key)),
                logical_record_id=logical_id,
                record_type=envelope.data_kind,
                schema_version=envelope.record_schema_version,
                revision_number=envelope.revision_number,
                previous_record_id=(
                    None if previous is None else previous.meta.record_id
                ),
                created_at=envelope.created_at,
                analysis_id=AnalysisId(analysis_id),
                workspace_id=WorkspaceId(workspace_id),
                commit_id=CommitId(commit_id),
                hypothesis_id=None,
                attempt_id=None,
            )
            payload = cls._resolve_value(
                envelope.payload,
                records=built,
                evidence_refs=evidence_refs,
                run_evidence_refs=run_refs,
            )
            if not isinstance(payload, dict):
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_INVALID")
            try:
                model = cast(Any, _PROVISIONED_RECORD_MODELS[envelope.data_kind])
                built[key] = cast(
                    Record,
                    model.model_validate_json(
                        canonical_bytes({"meta": meta, **payload})
                    ),
                )
            except ValueError:
                raise ValueError("PRODUCTION_RECORD_TEMPLATE_INVALID") from None
        return built

    @classmethod
    def _dependencies(cls, envelope: ProvisioningRecordEnvelope) -> set[str]:
        result: set[str] = set()
        if envelope.previous_template_key is not None:
            result.add(envelope.previous_template_key)

        def walk(value: JsonValue) -> None:
            if isinstance(value, dict):
                marker = value.get(cls._RECORD_MARKER)
                if marker is not None:
                    if set(value) != {cls._RECORD_MARKER} or not isinstance(
                        marker, str
                    ):
                        raise ValueError("PRODUCTION_RECORD_TEMPLATE_MARKER_INVALID")
                    result.add(marker)
                    return
                if cls._EVIDENCE_MARKER in value or cls._RUN_EVIDENCE_MARKER in value:
                    marker_keys = {
                        key
                        for key in (cls._EVIDENCE_MARKER, cls._RUN_EVIDENCE_MARKER)
                        if key in value
                    }
                    if (
                        len(marker_keys) != 1
                        or len(value) != 1
                        or not isinstance(value[next(iter(marker_keys))], str)
                    ):
                        raise ValueError("PRODUCTION_RECORD_TEMPLATE_MARKER_INVALID")
                    return
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        walk(envelope.payload)
        return result

    @classmethod
    def _resolve_value(
        cls,
        value: JsonValue,
        *,
        records: Mapping[str, Record],
        evidence_refs: Mapping[str, StoredDataRef],
        run_evidence_refs: Mapping[str, RunStoredDataRef],
    ) -> object:
        if isinstance(value, dict):
            if set(value) == {cls._RECORD_MARKER}:
                key = value[cls._RECORD_MARKER]
                if not isinstance(key, str) or key not in records:
                    raise ValueError("PRODUCTION_RECORD_TEMPLATE_REFERENCE_MISSING")
                return reference(records[key]).model_dump(mode="json")
            for marker, refs in (
                (cls._EVIDENCE_MARKER, evidence_refs),
                (cls._RUN_EVIDENCE_MARKER, run_evidence_refs),
            ):
                if set(value) == {marker}:
                    digest = value[marker]
                    if not isinstance(digest, str) or digest not in refs:
                        raise ValueError("PRODUCTION_RECORD_EVIDENCE_REFERENCE_MISSING")
                    return refs[digest].model_dump(mode="json")
            return {
                key: cls._resolve_value(
                    item,
                    records=records,
                    evidence_refs=evidence_refs,
                    run_evidence_refs=run_evidence_refs,
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                cls._resolve_value(
                    item,
                    records=records,
                    evidence_refs=evidence_refs,
                    run_evidence_refs=run_evidence_refs,
                )
                for item in value
            ]
        return value

    @staticmethod
    def _stable_id(namespace: str, analysis_id: str, key: str) -> str:
        return hashlib.sha256(
            f"sastsimi:{namespace}:{analysis_id}:{key}".encode()
        ).hexdigest()


class StaticRouteProvisioning(ContractModel):
    """One explicit static adapter/config binding; no executable is guessed."""

    tool: StaticProvisioningTool
    adapter_key: StaticAdapterKey
    executable_slot: Literal["PYTHON_RUNTIME", "CODEQL", "OPENGREP"]
    decoder_key: StaticDecoderKey
    analysis_config_sha256: Sha256
    rule_catalog_sha256: Sha256 | None = None
    rule_selection_sha256: Sha256 | None = None
    rule_mapping_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def matched_route(self) -> Self:
        expected = {
            "AST": ("PYTHON_AST", "PYTHON_RUNTIME", "PYTHON_AST_JSON_V1"),
            "CODEQL": ("CODEQL", "CODEQL", "CODEQL_SARIF_V1"),
            "OPENGREP": ("OPENGREP", "OPENGREP", "OPENGREP_JSON_V1"),
        }[self.tool]
        rule_values = (
            self.rule_catalog_sha256,
            self.rule_selection_sha256,
            self.rule_mapping_sha256,
        )
        if (
            (self.adapter_key, self.executable_slot, self.decoder_key) != expected
            or (self.tool == "AST" and any(value is not None for value in rule_values))
            or (self.tool != "AST" and any(value is None for value in rule_values))
        ):
            raise ValueError("PRODUCTION_STATIC_ROUTE_INVALID")
        return self


class SemanticValidatorBinding(ContractModel):
    """Map an approved validator key only to a compiled-in implementation."""

    validator_key: NonEmptyStr
    implementation_key: SemanticValidatorImplementationKey


class ProviderImplementationBinding(ContractModel):
    """Bind one configured Provider profile key to a compiled-in adapter."""

    provider_profile_key: NonEmptyStr
    implementation_key: Literal[
        "OPENAI_RESPONSES_API_V1",
        "CODEX_OFFICIAL_CLIENT_V1",
        "ANTHROPIC_MESSAGES_API_V1",
        "CLAUDE_CODE_OFFICIAL_CLIENT_V1",
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
    root_relative: NonEmptyStr
    capacity_bytes: int
    backend_key: NonEmptyStr
    enforcement_evidence_sha256: Sha256

    @model_validator(mode="after")
    def enforceable_storage(self) -> Self:
        path = PurePosixPath(self.root_relative)
        if (
            path.is_absolute()
            or ".." in path.parts
            or "." in path.parts
            or "\\" in self.root_relative
            or self.capacity_bytes <= 0
            or self.enforcement_evidence_sha256 not in self.evidence_sha256
        ):
            raise ValueError("PRODUCTION_WORKSPACE_STORAGE_INVALID")
        return self


class StaticAnalysisProvisioning(_ProvisioningArtifactDocument):
    SLOT = "STATIC_ANALYSIS"
    ALLOWED_KINDS = frozenset()
    slot: Literal["STATIC_ANALYSIS"]
    enabled_tools: tuple[StaticProvisioningTool, ...]
    routes: tuple[StaticRouteProvisioning, ...]

    @model_validator(mode="after")
    def exact_tools(self) -> Self:
        route_evidence = {
            digest
            for route in self.routes
            for digest in (
                route.analysis_config_sha256,
                route.rule_catalog_sha256,
                route.rule_selection_sha256,
                route.rule_mapping_sha256,
            )
            if digest is not None
        }
        if (
            not self.enabled_tools
            or "AST" not in self.enabled_tools
            or len(self.enabled_tools) != len(set(self.enabled_tools))
            or tuple(item.tool for item in self.routes) != self.enabled_tools
            or not route_evidence <= set(self.evidence_sha256)
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
        if (
            tuple(ref.data_kind for ref in self.record_refs).count("playbook_policy")
            != 1
        ):
            raise ValueError("PRODUCTION_PLAYBOOK_POLICY_AMBIGUOUS")
        return self


class SandboxProfileProvisioning(_ProvisioningArtifactDocument):
    SLOT = "SANDBOX_PROFILE"
    ALLOWED_KINDS = frozenset({"sandbox_profile"})
    REQUIRED_KINDS = ALLOWED_KINDS
    slot: Literal["SANDBOX_PROFILE"]
    container_user: NonEmptyStr
    max_execute_turns: int
    resource_journal_relative: NonEmptyStr
    authorization_policy_sha256: Sha256
    authorization_implementation_key: Literal["RUNTIME_DYNAMIC_AUTHORIZATION_V1"]
    setup_implementation_key: Literal["DOCKER_REPRODUCTION_SETUP_V1"]

    @model_validator(mode="after")
    def safe_execution_settings(self) -> Self:
        if (
            len(self.record_refs) != 1
            or self.max_execute_turns < 1
            or self.max_execute_turns > 128
            or PurePosixPath(self.resource_journal_relative).is_absolute()
            or ".." in PurePosixPath(self.resource_journal_relative).parts
            or "\\" in self.resource_journal_relative
            or self.authorization_policy_sha256 not in self.evidence_sha256
        ):
            raise ValueError("PRODUCTION_SANDBOX_EXECUTION_INVALID")
        return self


class PolicyCatalogProvisioning(_ProvisioningArtifactDocument):
    SLOT = "POLICY_CATALOG"
    ALLOWED_KINDS = frozenset()
    slot: Literal["POLICY_CATALOG"]
    source_configuration_sha256: Sha256
    freshness_criterion_sha256: Sha256
    parser_implementation_key: Literal["OFFICIAL_HTTP_POLICY_V1"]

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
    REQUIRED_KINDS = frozenset({"provider_validation_evidence", "provider_profile"})
    slot: Literal["PROVIDER_CONFIGURATION"]
    provider_implementation_bindings: tuple[ProviderImplementationBinding, ...]

    @model_validator(mode="after")
    def matched_provider_evidence(self) -> Self:
        kinds = tuple(ref.data_kind for ref in self.record_refs)
        binding_keys = tuple(
            item.provider_profile_key for item in self.provider_implementation_bindings
        )
        if (
            kinds.count("provider_profile")
            != kinds.count("provider_validation_evidence")
            or not binding_keys
            or len(binding_keys) != len(set(binding_keys))
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
            "evaluation_run_config",
            "evaluation_run_result",
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
    semantic_validator_bindings: tuple[SemanticValidatorBinding, ...]

    @model_validator(mode="after")
    def exact_validators(self) -> Self:
        if not self.semantic_validator_keys or len(self.semantic_validator_keys) != len(
            set(self.semantic_validator_keys)
        ):
            raise ValueError("PRODUCTION_SEMANTIC_VALIDATOR_SET_INVALID")
        binding_keys = tuple(
            item.validator_key for item in self.semantic_validator_bindings
        )
        if binding_keys != self.semantic_validator_keys or len(binding_keys) != len(
            set(binding_keys)
        ):
            raise ValueError("PRODUCTION_SEMANTIC_VALIDATOR_BINDING_INVALID")
        return self


class _ProvisioningTemplateDocument(ContractModel):
    """Host/profile-scoped approval input created before a run ID exists."""

    SLOT: ClassVar[str]
    ALLOWED_KINDS: ClassVar[frozenset[str]]
    REQUIRED_KINDS: ClassVar[frozenset[str]] = frozenset()

    schema_version: Literal[1]
    template_scope: Literal["HOST_PROFILE"]
    slot: ProvisioningSlot
    profile_hash: Sha256
    host_id: NonEmptyStr
    record_templates: tuple[ProvisioningRecordTemplateRef, ...]
    evidence_sha256: tuple[Sha256, ...] = ()

    @model_validator(mode="after")
    def exact_template_inventory(self) -> Self:
        keys = tuple(item.template_key for item in self.record_templates)
        kinds = tuple(item.data_kind for item in self.record_templates)
        digests = tuple(item.content_sha256 for item in self.record_templates)
        if (
            self.slot != self.SLOT
            or len(keys) != len(set(keys))
            or len(digests) != len(set(digests))
            or len(self.evidence_sha256) != len(set(self.evidence_sha256))
            or any(kind not in self.ALLOWED_KINDS for kind in kinds)
            or not self.REQUIRED_KINDS <= set(kinds)
            or not set(digests) <= set(self.evidence_sha256)
        ):
            raise ValueError("PRODUCTION_PROVISIONING_TEMPLATE_INVALID")
        return self


class WorkspaceStorageProvisioningTemplate(_ProvisioningTemplateDocument):
    SLOT = "WORKSPACE_STORAGE"
    ALLOWED_KINDS = frozenset()
    slot: Literal["WORKSPACE_STORAGE"]
    backend: Literal["SQLITE_RECORDS_AND_CAS"]
    root_relative: NonEmptyStr
    capacity_bytes: int
    backend_key: NonEmptyStr
    enforcement_evidence_sha256: Sha256

    @model_validator(mode="after")
    def enforceable_storage(self) -> Self:
        path = PurePosixPath(self.root_relative)
        if (
            path.is_absolute()
            or ".." in path.parts
            or "." in path.parts
            or "\\" in self.root_relative
            or self.capacity_bytes <= 0
            or self.enforcement_evidence_sha256 not in self.evidence_sha256
        ):
            raise ValueError("PRODUCTION_WORKSPACE_STORAGE_INVALID")
        return self


class StaticAnalysisProvisioningTemplate(_ProvisioningTemplateDocument):
    SLOT = "STATIC_ANALYSIS"
    ALLOWED_KINDS = frozenset()
    slot: Literal["STATIC_ANALYSIS"]
    enabled_tools: tuple[StaticProvisioningTool, ...]
    routes: tuple[StaticRouteProvisioning, ...]

    @model_validator(mode="after")
    def exact_tools(self) -> Self:
        route_evidence = {
            digest
            for route in self.routes
            for digest in (
                route.analysis_config_sha256,
                route.rule_catalog_sha256,
                route.rule_selection_sha256,
                route.rule_mapping_sha256,
            )
            if digest is not None
        }
        if (
            not self.enabled_tools
            or "AST" not in self.enabled_tools
            or len(self.enabled_tools) != len(set(self.enabled_tools))
            or tuple(item.tool for item in self.routes) != self.enabled_tools
            or not route_evidence <= set(self.evidence_sha256)
        ):
            raise ValueError("PRODUCTION_STATIC_TOOL_SET_INVALID")
        return self


class VerificationPlaybooksProvisioningTemplate(_ProvisioningTemplateDocument):
    SLOT = "VERIFICATION_PLAYBOOKS"
    ALLOWED_KINDS = frozenset({"verification_playbook", "playbook_policy"})
    REQUIRED_KINDS = ALLOWED_KINDS
    slot: Literal["VERIFICATION_PLAYBOOKS"]

    @model_validator(mode="after")
    def one_policy(self) -> Self:
        if (
            tuple(item.data_kind for item in self.record_templates).count(
                "playbook_policy"
            )
            != 1
        ):
            raise ValueError("PRODUCTION_PLAYBOOK_POLICY_AMBIGUOUS")
        return self


class SandboxProfileProvisioningTemplate(_ProvisioningTemplateDocument):
    SLOT = "SANDBOX_PROFILE"
    ALLOWED_KINDS = frozenset({"sandbox_profile"})
    REQUIRED_KINDS = ALLOWED_KINDS
    slot: Literal["SANDBOX_PROFILE"]
    container_user: NonEmptyStr
    max_execute_turns: int
    resource_journal_relative: NonEmptyStr
    authorization_policy_sha256: Sha256
    authorization_implementation_key: Literal["RUNTIME_DYNAMIC_AUTHORIZATION_V1"]
    setup_implementation_key: Literal["DOCKER_REPRODUCTION_SETUP_V1"]

    @model_validator(mode="after")
    def safe_execution_settings(self) -> Self:
        path = PurePosixPath(self.resource_journal_relative)
        if (
            len(self.record_templates) != 1
            or self.max_execute_turns < 1
            or self.max_execute_turns > 128
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in self.resource_journal_relative
            or self.authorization_policy_sha256 not in self.evidence_sha256
        ):
            raise ValueError("PRODUCTION_SANDBOX_EXECUTION_INVALID")
        return self


class PolicyCatalogProvisioningTemplate(_ProvisioningTemplateDocument):
    SLOT = "POLICY_CATALOG"
    ALLOWED_KINDS = frozenset()
    slot: Literal["POLICY_CATALOG"]
    source_configuration_sha256: Sha256
    freshness_criterion_sha256: Sha256
    parser_implementation_key: Literal["OFFICIAL_HTTP_POLICY_V1"]

    @model_validator(mode="after")
    def policy_evidence_is_declared(self) -> Self:
        if not {
            self.source_configuration_sha256,
            self.freshness_criterion_sha256,
        } <= set(self.evidence_sha256):
            raise ValueError("PRODUCTION_POLICY_EVIDENCE_INCOMPLETE")
        return self


class ProviderConfigurationProvisioningTemplate(_ProvisioningTemplateDocument):
    SLOT = "PROVIDER_CONFIGURATION"
    ALLOWED_KINDS = ProviderConfigurationProvisioning.ALLOWED_KINDS
    REQUIRED_KINDS = ProviderConfigurationProvisioning.REQUIRED_KINDS
    slot: Literal["PROVIDER_CONFIGURATION"]
    provider_implementation_bindings: tuple[ProviderImplementationBinding, ...]

    @model_validator(mode="after")
    def matched_provider_evidence(self) -> Self:
        kinds = tuple(item.data_kind for item in self.record_templates)
        binding_keys = tuple(
            item.provider_profile_key for item in self.provider_implementation_bindings
        )
        if (
            kinds.count("provider_profile")
            != kinds.count("provider_validation_evidence")
            or not binding_keys
            or len(binding_keys) != len(set(binding_keys))
        ):
            raise ValueError("PRODUCTION_PROVIDER_EVIDENCE_INCOMPLETE")
        return self


class PromptRoutesProvisioningTemplate(_ProvisioningTemplateDocument):
    SLOT = "PROMPT_ROUTES"
    ALLOWED_KINDS = PromptRoutesProvisioning.ALLOWED_KINDS
    REQUIRED_KINDS = PromptRoutesProvisioning.REQUIRED_KINDS
    slot: Literal["PROMPT_ROUTES"]
    semantic_validator_bindings: tuple[SemanticValidatorBinding, ...]

    @model_validator(mode="after")
    def exact_validators(self) -> Self:
        keys = tuple(item.validator_key for item in self.semantic_validator_bindings)
        if not keys or len(keys) != len(set(keys)):
            raise ValueError("PRODUCTION_SEMANTIC_VALIDATOR_SET_INVALID")
        return self


type ParsedProvisioningTemplate = (
    WorkspaceStorageProvisioningTemplate
    | StaticAnalysisProvisioningTemplate
    | VerificationPlaybooksProvisioningTemplate
    | SandboxProfileProvisioningTemplate
    | PolicyCatalogProvisioningTemplate
    | ProviderConfigurationProvisioningTemplate
    | PromptRoutesProvisioningTemplate
)

_TEMPLATE_MODELS: Mapping[str, type[_ProvisioningTemplateDocument]] = {
    item.SLOT: item
    for item in (
        WorkspaceStorageProvisioningTemplate,
        StaticAnalysisProvisioningTemplate,
        VerificationPlaybooksProvisioningTemplate,
        SandboxProfileProvisioningTemplate,
        PolicyCatalogProvisioningTemplate,
        ProviderConfigurationProvisioningTemplate,
        PromptRoutesProvisioningTemplate,
    )
}


class ProvisioningTemplateMaterializer:
    """Bind pre-approved host/profile templates only after run IDs exist."""

    @staticmethod
    def parse(
        artifacts: Mapping[str, bytes], *, profile_hash: str, host_id: str
    ) -> Mapping[str, ParsedProvisioningTemplate]:
        if set(artifacts) != set(_TEMPLATE_MODELS):
            raise ValueError("PRODUCTION_PROVISIONING_TEMPLATE_SET_INCOMPLETE")
        documents: dict[str, ParsedProvisioningTemplate] = {}
        for slot, raw in artifacts.items():
            try:
                document = cast(
                    ParsedProvisioningTemplate,
                    _TEMPLATE_MODELS[slot].model_validate_json(raw),
                )
            except ValueError:
                raise ValueError("PRODUCTION_PROVISIONING_TEMPLATE_INVALID") from None
            if document.profile_hash != profile_hash or document.host_id != host_id:
                raise ValueError("PRODUCTION_PROVISIONING_TEMPLATE_SCOPE_MISMATCH")
            documents[slot] = document
        template_keys = tuple(
            item.template_key
            for document in documents.values()
            for item in document.record_templates
        )
        if len(template_keys) != len(set(template_keys)):
            raise ValueError("PRODUCTION_PROVISIONING_TEMPLATE_KEY_DUPLICATED")
        return documents

    @staticmethod
    def bind_run(
        templates: Mapping[str, ParsedProvisioningTemplate],
        *,
        analysis_id: str,
        workspace_id: str,
        commit_id: str,
        record_refs: Mapping[str, StoredDataRef],
    ) -> Mapping[str, bytes]:
        expected = {
            item.template_key: item
            for document in templates.values()
            for item in document.record_templates
        }
        if set(record_refs) != set(expected) or any(
            ref.data_kind != expected[key].data_kind
            or ref.record_id is None
            or (str(ref.workspace_id), str(ref.commit_id)) != (workspace_id, commit_id)
            for key, ref in record_refs.items()
        ):
            raise ValueError("PRODUCTION_PROVISIONING_RUN_RECORD_MISMATCH")
        bound: dict[str, bytes] = {}
        template_fields = {
            "template_scope",
            "host_id",
            "record_templates",
        }
        for slot, document in templates.items():
            payload = document.model_dump(mode="python")
            for field in template_fields:
                payload.pop(field, None)
            payload.update(
                {
                    "schema_version": 1,
                    "analysis_id": analysis_id,
                    "workspace_id": workspace_id,
                    "commit_id": commit_id,
                    "record_refs": tuple(
                        record_refs[item.template_key]
                        for item in document.record_templates
                    ),
                }
            )
            if isinstance(document, PromptRoutesProvisioningTemplate):
                payload["semantic_validator_keys"] = tuple(
                    item.validator_key for item in document.semantic_validator_bindings
                )
            bound[slot] = (
                _ARTIFACT_MODELS[slot]
                .model_validate(payload)
                .model_dump_json(exclude_none=True)
                .encode()
            )
        return bound


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
        EvaluationRunConfig.KIND: EvaluationRunConfig,
        EvaluationRunResult.KIND: EvaluationRunResult,
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
                    raise ValueError("PRODUCTION_PROVISIONING_RECORD_MISSING") from None
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
                    raise ValueError("PRODUCTION_PROVISIONING_RECORD_SCOPE_MISMATCH")
                current = tuple(
                    item
                    for item in self._queries.current_records(
                        analysis_id, str(meta.record_type)
                    )
                    if isinstance(getattr(item, "meta", None), RecordMeta)
                    and item.meta.logical_record_id == meta.logical_record_id
                )
                if len(current) != 1:
                    raise ValueError("PRODUCTION_PROVISIONING_RECORD_STALE")
                current_ref = reference(current[0])
                if current_ref != ref and not self._records.is_revision_descendant(
                    ref, current_ref
                ):
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
        record_refs: Mapping[str, StoredDataRef],
        profile_hash: str,
        analysis_id: str,
        workspace_id: str,
        commit_id: str,
    ) -> tuple[ResolvedProductionProvisioning, MaterializedProvisioningArtifacts]:
        """Resolve host capabilities and the complete exact run artifact set."""

        resolved = self.resolve(manifest)
        templates = ProvisioningTemplateMaterializer.parse(
            resolved.artifacts,
            profile_hash=profile_hash,
            host_id=manifest.host_id,
        )
        run_artifacts = ProvisioningTemplateMaterializer.bind_run(
            templates,
            analysis_id=analysis_id,
            workspace_id=workspace_id,
            commit_id=commit_id,
            record_refs=record_refs,
        )
        materialized = ExactProvisioningArtifactMaterializer(
            records=records,
            queries=queries,
            evidence=self._evidence,
        ).materialize(
            run_artifacts,
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
    "ParsedProvisioningTemplate",
    "PolicyCatalogProvisioning",
    "PolicyCatalogProvisioningTemplate",
    "PromptRoutesProvisioning",
    "PromptRoutesProvisioningTemplate",
    "ProviderImplementationBinding",
    "ProvisioningRecordEnvelope",
    "ProvisioningRecordEnvelopeMaterializer",
    "ProvisioningRecordTemplateRef",
    "ProvisioningTemplateMaterializer",
    "ProviderConfigurationProvisioning",
    "ProviderConfigurationProvisioningTemplate",
    "ResolvedProductionProvisioning",
    "SandboxProfileProvisioning",
    "SandboxProfileProvisioningTemplate",
    "SemanticValidatorBinding",
    "StaticAnalysisProvisioning",
    "StaticAnalysisProvisioningTemplate",
    "StaticRouteProvisioning",
    "VerificationPlaybooksProvisioning",
    "VerificationPlaybooksProvisioningTemplate",
    "WorkspaceStorageProvisioning",
    "WorkspaceStorageProvisioningTemplate",
]
