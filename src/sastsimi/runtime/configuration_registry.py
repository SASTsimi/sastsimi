"""Public typed configuration facade."""

from sastsimi.contracts.budget import (
    DynamicReproductionLifecycleProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.dynamic import SandboxProfile
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
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.ports.configuration_registry import ConfigurationRegistryPort


class ConfigurationRegistry:
    def __init__(self, registry: ConfigurationRegistryPort) -> None:
        self.registry = registry

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

    def register_provider_profile(self, record: ProviderProfile) -> StoredDataRef:
        return self.registry.register_provider_profile(record)

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

    def register_sandbox_profile(self, record: SandboxProfile) -> StoredDataRef:
        return self.registry.register_sandbox_profile(record)
