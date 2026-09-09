"""Host-owned fixture evidence; never exposed as a workflow authorization API."""

from sastsimi.contracts.actions import ActionRequest, CheckType, RequesterRole
from sastsimi.contracts.budget import BudgetProfileBinding, ExecutionBudgetProfile
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.refs import BudgetScopeRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.trusted_evidence import UnprovenEvidence


class FixtureEvidence(UnprovenEvidence):
    def __init__(self) -> None:
        self.approvals: set[str] = set()
        self.identities: dict[BudgetScopeRef, RequesterRole] = {}
        self.items: int | None = 1

    def identity_role(self, ref: BudgetScopeRef) -> RequesterRole | None:
        return self.identities.get(ref)

    def approved(self, profile: ExecutionBudgetProfile | BudgetProfileBinding) -> bool:
        return content_hash(profile) in self.approvals

    def pricing(self, profile: ExecutionBudgetProfile) -> bool:
        return content_hash(profile) in self.approvals

    def action_evidence(
        self, action: ActionRequest, check: CheckType
    ) -> tuple[BudgetScopeRef, ...] | None:
        return (
            (action.requester_identity_ref,)
            if action.requester_identity_ref in self.identities
            else None
        )

    def item_count(self, action: ActionRequest, work: WorkExecutionState) -> int | None:
        return self.items
