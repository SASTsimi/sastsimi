"""Typed host configuration publication; no generic record installer."""

from typing import Protocol

from sastsimi.contracts.budget import (
    DynamicReproductionLifecycleProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.capabilities import (
    CapabilityApprovalEvidence,
    CapabilityArchitecture,
    CapabilityKind,
    CapabilityLanguage,
    CapabilityOperatingSystem,
    CapabilityOperation,
    RuntimeCapabilityProfile,
    RuntimeCapabilitySelection,
    StaticToolCapabilitySelection,
)
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.evaluation import EvaluationRunConfig
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    ExecutionLimits,
    LLMCallSpec,
    LLMRetryPolicy,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptPayload,
    PromptRedactionPolicy,
    PromptRegistryEntry,
    ProviderCapabilities,
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.ports.dto import CapabilityProbeResult


class ConfigurationRegistryPort(Protocol):
    def register_capability_approval(
        self, record: CapabilityApprovalEvidence
    ) -> StoredDataRef: ...

    def register_runtime_capability(
        self, record: RuntimeCapabilityProfile
    ) -> StoredDataRef: ...

    def get_runtime_capability(
        self, profile_ref: StoredDataRef
    ) -> RuntimeCapabilityProfile: ...

    def resolve_active_capability(
        self,
        *,
        capability_kind: CapabilityKind,
        language: CapabilityLanguage,
        operation: CapabilityOperation,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> RuntimeCapabilitySelection: ...

    def register_production_static_tool_profile(
        self, record: StaticToolProfile
    ) -> StoredDataRef: ...

    def get_production_static_tool_profile(
        self, profile_ref: StoredDataRef
    ) -> StaticToolProfile: ...

    def resolve_production_static_tool_profile(
        self, profile_ref: StoredDataRef
    ) -> StaticToolProfile: ...

    def resolve_active_static_tool(
        self,
        *,
        adapter_key: str,
        language: CapabilityLanguage,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> StaticToolCapabilitySelection: ...

    def register_static_tool_profile(
        self, record: StaticToolProfile
    ) -> StoredDataRef: ...

    def resolve_static_tool_profile(
        self, profile_ref: StoredDataRef
    ) -> StaticToolProfile: ...

    def register_work_budget(self, record: WorkBudgetProfile) -> StoredDataRef: ...
    def register_verification_budget(
        self, record: VerificationBudgetProfile
    ) -> StoredDataRef: ...
    def register_dynamic_lifecycle(
        self, record: DynamicReproductionLifecycleProfile
    ) -> StoredDataRef: ...
    def register_playbook(self, record: VerificationPlaybook) -> StoredDataRef: ...
    def register_playbook_policy(self, record: PlaybookPolicy) -> StoredDataRef: ...
    def register_provider_validation(
        self, record: ProviderValidationEvidence
    ) -> StoredDataRef: ...
    def derive_provider_capabilities(
        self, record: ProviderValidationEvidence
    ) -> ProviderCapabilities: ...
    def register_provider_profile(
        self, record: ProviderProfile, probe: CapabilityProbeResult
    ) -> StoredDataRef: ...
    def register_client_execution(
        self, record: ClientExecutionProfile
    ) -> StoredDataRef: ...
    def register_execution_limits(self, record: ExecutionLimits) -> StoredDataRef: ...
    def register_retry_policy(self, record: LLMRetryPolicy) -> StoredDataRef: ...
    def register_tool_policy(self, record: LLMToolPolicy) -> StoredDataRef: ...
    def register_redaction_policy(
        self, record: PromptRedactionPolicy
    ) -> StoredDataRef: ...
    def register_output_schema(self, record: OutputSchemaSpec) -> StoredDataRef: ...
    def register_semantic_validator(
        self, record: SemanticValidatorSpec
    ) -> StoredDataRef: ...
    def register_prompt_entry(self, record: PromptRegistryEntry) -> StoredDataRef: ...
    def register_prompt_payload(self, record: PromptPayload) -> StoredDataRef: ...
    def register_call_spec(self, record: LLMCallSpec) -> StoredDataRef: ...
    def register_evaluation_config(
        self, record: EvaluationRunConfig
    ) -> StoredDataRef: ...
    def register_sandbox_profile(self, record: SandboxProfile) -> StoredDataRef: ...
