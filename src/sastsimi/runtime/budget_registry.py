"""Analysis-local budget publication through the trusted registry port."""

from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.budget import BudgetProfileBinding, ExecutionBudgetProfile
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef
from sastsimi.ports.runtime_store import BudgetRegistryPort


class BudgetProfileRegistry:
    def __init__(self, registry: BudgetRegistryPort) -> None:
        self.registry = registry

    def pin_execution(
        self, profile: ExecutionBudgetProfile, state: AnalysisRunState | None = None
    ) -> RunStoredDataRef:
        return self.registry.pin_execution(profile, state)

    def current_state(self, analysis_id: str) -> AnalysisRunState:
        return self.registry.current_state(analysis_id)

    def pin_binding(
        self,
        binding: BudgetProfileBinding,
        workspace_ref: RunStoredDataRef,
        analysis_state_ref: RunStoredDataRef | None = None,
    ) -> StoredDataRef:
        return self.registry.pin_binding(binding, workspace_ref, analysis_state_ref)
