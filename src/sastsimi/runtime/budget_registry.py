"""Analysis-local budget publication through the trusted registry port."""

from sastsimi.contracts.budget import BudgetProfileBinding, ExecutionBudgetProfile
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef
from sastsimi.ports.runtime_store import BudgetRegistryPort


class BudgetProfileRegistry:
    def __init__(self, registry: BudgetRegistryPort) -> None:
        self.registry = registry

    def pin_execution(self, profile: ExecutionBudgetProfile) -> RunStoredDataRef:
        return self.registry.pin_execution(profile)

    def pin_binding(
        self, binding: BudgetProfileBinding, workspace_ref: RunStoredDataRef
    ) -> StoredDataRef:
        return self.registry.pin_binding(binding, workspace_ref)
