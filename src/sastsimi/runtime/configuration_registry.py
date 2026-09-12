"""Public typed configuration facade."""

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
from sastsimi.ports.configuration_registry import ConfigurationRegistryPort
from sastsimi.ports.dto import CapabilityProbeResult


class ConfigurationRegistry:
    def __init__(self, registry: ConfigurationRegistryPort) -> None:
        self.registry = registry

    def register_capability_approval(
        self, record: CapabilityApprovalEvidence
    ) -> StoredDataRef:
        return self.registry.register_capability_approval(record)

    def register_runtime_capability(
        self, record: RuntimeCapabilityProfile
    ) -> StoredDataRef:
        return self.registry.register_runtime_capability(record)

    def get_runtime_capability(
        self, profile_ref: StoredDataRef
    ) -> RuntimeCapabilityProfile:
        return self.registry.get_runtime_capability(profile_ref)

    def resolve_active_capability(
        self,
        *,
        capability_kind: CapabilityKind,
        language: CapabilityLanguage,
        operation: CapabilityOperation,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> RuntimeCapabilitySelection:
        return self.registry.resolve_active_capability(
            capability_kind=capability_kind,
            language=language,
            operation=operation,
            operating_system=operating_system,
            architecture=architecture,
        )

    def register_production_static_tool_profile(
        self, record: StaticToolProfile
    ) -> StoredDataRef:
        return self.registry.register_production_static_tool_profile(record)

    def get_production_static_tool_profile(
        self, profile_ref: StoredDataRef
    ) -> StaticToolProfile:
        return self.registry.get_production_static_tool_profile(profile_ref)

    def resolve_production_static_tool_profile(
        self, profile_ref: StoredDataRef
    ) -> StaticToolProfile:
        return self.registry.resolve_production_static_tool_profile(profile_ref)

    def resolve_active_static_tool(
        self,
        *,
        adapter_key: str,
        language: CapabilityLanguage,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> StaticToolCapabilitySelection:
        return self.registry.resolve_active_static_tool(
            adapter_key=adapter_key,
            language=language,
            operating_system=operating_system,
            architecture=architecture,
        )

    def register_static_tool_profile(self, record: StaticToolProfile) -> StoredDataRef:
        return self.registry.register_static_tool_profile(record)

    def resolve_static_tool_profile(
        self, profile_ref: StoredDataRef
    ) -> StaticToolProfile:
        return self.registry.resolve_static_tool_profile(profile_ref)

    def register_work_budget(self, record: WorkBudgetProfile) -> StoredDataRef:
        return self.registry.register_work_budget(record)

    def register_verification_budget(
        self, record: VerificationBudgetProfile
    ) -> StoredDataRef:
        return self.registry.register_verification_budget(record)

    def register_dynamic_lifecycle(
        self, record: DynamicReproductionLifecycleProfile
    ) -> StoredDataRef:
        return self.registry.register_dynamic_lifecycle(record)

    def register_playbook(self, record: VerificationPlaybook) -> StoredDataRef:
        return self.registry.register_playbook(record)

    def register_playbook_policy(self, record: PlaybookPolicy) -> StoredDataRef:
        return self.registry.register_playbook_policy(record)

    def register_provider_validation(
        self, record: ProviderValidationEvidence
    ) -> StoredDataRef:
        return self.registry.register_provider_validation(record)

    def derive_provider_capabilities(
        self, record: ProviderValidationEvidence
    ) -> ProviderCapabilities:
        return self.registry.derive_provider_capabilities(record)

    def register_provider_profile(
        self, record: ProviderProfile, probe: CapabilityProbeResult
    ) -> StoredDataRef:
        return self.registry.register_provider_profile(record, probe)

    def register_client_execution(
        self, record: ClientExecutionProfile
    ) -> StoredDataRef:
        return self.registry.register_client_execution(record)

    def register_execution_limits(self, record: ExecutionLimits) -> StoredDataRef:
        return self.registry.register_execution_limits(record)

    def register_retry_policy(self, record: LLMRetryPolicy) -> StoredDataRef:
        return self.registry.register_retry_policy(record)

    def register_tool_policy(self, record: LLMToolPolicy) -> StoredDataRef:
        return self.registry.register_tool_policy(record)

    def register_redaction_policy(self, record: PromptRedactionPolicy) -> StoredDataRef:
        return self.registry.register_redaction_policy(record)

    def register_output_schema(self, record: OutputSchemaSpec) -> StoredDataRef:
        return self.registry.register_output_schema(record)

    def register_semantic_validator(
        self, record: SemanticValidatorSpec
    ) -> StoredDataRef:
        return self.registry.register_semantic_validator(record)

    def register_prompt_entry(self, record: PromptRegistryEntry) -> StoredDataRef:
        return self.registry.register_prompt_entry(record)

    def register_prompt_payload(self, record: PromptPayload) -> StoredDataRef:
        return self.registry.register_prompt_payload(record)

    def register_call_spec(self, record: LLMCallSpec) -> StoredDataRef:
        return self.registry.register_call_spec(record)

    def register_evaluation_config(self, record: EvaluationRunConfig) -> StoredDataRef:
        return self.registry.register_evaluation_config(record)

    def register_sandbox_profile(self, record: SandboxProfile) -> StoredDataRef:
        return self.registry.register_sandbox_profile(record)
