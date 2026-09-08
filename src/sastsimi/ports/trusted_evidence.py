"""Host-injected evidence, never an Agent-supplied PASS or persisted schema."""

from typing import Protocol

from sastsimi.contracts.actions import ActionRequest, CheckType, RequesterRole
from sastsimi.contracts.budget import BudgetProfileBinding, ExecutionBudgetProfile
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef
from sastsimi.contracts.work import WorkExecutionState


class TrustedEvidencePort(Protocol):
    def authorized_outputs(
        self, action: ActionRequest
    ) -> tuple[RecordRef, ...] | None: ...
    def identity_role(self, ref: BudgetScopeRef) -> RequesterRole | None: ...
    def approved(
        self, profile: ExecutionBudgetProfile | BudgetProfileBinding
    ) -> bool: ...
    def pricing(self, profile: ExecutionBudgetProfile) -> bool: ...
    def action_evidence(
        self, action: ActionRequest, check: CheckType
    ) -> tuple[BudgetScopeRef, ...] | None: ...
    def item_count(
        self, action: ActionRequest, work: WorkExecutionState
    ) -> int | None: ...


class UnprovenEvidence:
    def authorized_outputs(self, action: ActionRequest) -> tuple[RecordRef, ...] | None:
        return None

    def identity_role(self, ref: BudgetScopeRef) -> RequesterRole | None:
        return None

    def approved(self, profile: ExecutionBudgetProfile | BudgetProfileBinding) -> bool:
        return False

    def pricing(self, profile: ExecutionBudgetProfile) -> bool:
        return False

    def action_evidence(
        self, action: ActionRequest, check: CheckType
    ) -> tuple[BudgetScopeRef, ...] | None:
        return None

    def item_count(self, action: ActionRequest, work: WorkExecutionState) -> int | None:
        return None
