"""Host-injected evidence, never an Agent-supplied PASS or persisted schema."""

from typing import Protocol

from sastsimi.contracts.actions import ActionRequest, CheckType, RequesterRole
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.capabilities import CapabilityApprovalEvidence
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.llm import LLMRecord
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.contracts.work import WorkExecutionState


class TrustedEvidencePort(Protocol):
    def capability_approval_authorized(
        self, evidence: CapabilityApprovalEvidence
    ) -> bool: ...

    def static_tool_configuration_approved(
        self, profile: StaticToolProfile
    ) -> bool: ...

    def generation_restart_evidence(
        self, action: ActionRequest
    ) -> tuple[BudgetScopeRef, ...] | None: ...
    def authorized_outputs(
        self, action: ActionRequest
    ) -> tuple[RecordRef, ...] | None: ...
    def identity_role(self, ref: BudgetScopeRef) -> RequesterRole | None: ...
    def approved(
        self, profile: ExecutionBudgetProfile | BudgetProfileBinding
    ) -> bool: ...
    def pricing(self, profile: ExecutionBudgetProfile) -> bool: ...
    def budget_configuration_approved(
        self,
        profile: WorkBudgetProfile
        | VerificationBudgetProfile
        | DynamicReproductionLifecycleProfile,
    ) -> bool: ...
    def playbook_configuration_approved(
        self, record: VerificationPlaybook | PlaybookPolicy
    ) -> bool: ...
    def llm_configuration_approved(self, record: LLMRecord) -> bool: ...
    def sandbox_configuration_approved(self, profile: SandboxProfile) -> bool: ...
    def action_evidence(
        self, action: ActionRequest, check: CheckType
    ) -> tuple[BudgetScopeRef, ...] | None: ...
    def item_count(
        self, action: ActionRequest, work: WorkExecutionState
    ) -> int | None: ...


class UnprovenEvidence:
    def capability_approval_authorized(
        self, evidence: CapabilityApprovalEvidence
    ) -> bool:
        return False

    def static_tool_configuration_approved(self, profile: StaticToolProfile) -> bool:
        return False

    def generation_restart_evidence(
        self, action: ActionRequest
    ) -> tuple[BudgetScopeRef, ...] | None:
        return None

    def authorized_outputs(self, action: ActionRequest) -> tuple[RecordRef, ...] | None:
        return None

    def identity_role(self, ref: BudgetScopeRef) -> RequesterRole | None:
        return None

    def approved(self, profile: ExecutionBudgetProfile | BudgetProfileBinding) -> bool:
        return False

    def pricing(self, profile: ExecutionBudgetProfile) -> bool:
        return False

    def budget_configuration_approved(
        self,
        profile: WorkBudgetProfile
        | VerificationBudgetProfile
        | DynamicReproductionLifecycleProfile,
    ) -> bool:
        return False

    def playbook_configuration_approved(
        self, record: VerificationPlaybook | PlaybookPolicy
    ) -> bool:
        return False

    def llm_configuration_approved(self, record: LLMRecord) -> bool:
        return False

    def sandbox_configuration_approved(self, profile: SandboxProfile) -> bool:
        return False

    def action_evidence(
        self, action: ActionRequest, check: CheckType
    ) -> tuple[BudgetScopeRef, ...] | None:
        return None

    def item_count(self, action: ActionRequest, work: WorkExecutionState) -> int | None:
        return None
