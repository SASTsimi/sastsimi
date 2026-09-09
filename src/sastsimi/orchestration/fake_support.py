"""Host-owned deterministic dependencies for the local fake pipeline."""

from datetime import UTC, datetime

from sastsimi.contracts.actions import ActionRequest, CheckType, RequesterRole
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.ids import OpaqueId
from sastsimi.contracts.llm import LLMRecord
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.trusted_evidence import UnprovenEvidence


class FakeClock:
    def __init__(self) -> None:
        self.wall_time = datetime(2026, 9, 8, tzinfo=UTC)
        self.tick = 0

    def now(self) -> datetime:
        return self.wall_time

    def monotonic_ms(self) -> int:
        return self.tick


class FakeIds:
    def __init__(self) -> None:
        self.index = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.index += 1
        return kind(f"fake-{kind.__name__.lower()}-{self.index}")


class FakeEvidence(UnprovenEvidence):
    """Evidence controlled by composition, never by workflow inputs."""

    def __init__(self) -> None:
        self.approvals: set[str] = set()
        self.budget_approvals: set[str] = set()
        self.playbook_approvals: set[str] = set()
        self.llm_approvals: set[str] = set()
        self.sandbox_approvals: set[str] = set()
        self.identities: dict[BudgetScopeRef, RequesterRole] = {}
        self.next_outputs: tuple[RecordRef, ...] | None = None

    def authorized_outputs(self, action: ActionRequest) -> tuple[RecordRef, ...] | None:
        return self.next_outputs

    def identity_role(self, ref: BudgetScopeRef) -> RequesterRole | None:
        return self.identities.get(ref)

    def approved(self, profile: ExecutionBudgetProfile | BudgetProfileBinding) -> bool:
        return content_hash(profile) in self.approvals

    def pricing(self, profile: ExecutionBudgetProfile) -> bool:
        return content_hash(profile) in self.approvals

    def budget_configuration_approved(
        self,
        profile: WorkBudgetProfile
        | VerificationBudgetProfile
        | DynamicReproductionLifecycleProfile,
    ) -> bool:
        return content_hash(profile) in self.budget_approvals

    def playbook_configuration_approved(
        self, record: VerificationPlaybook | PlaybookPolicy
    ) -> bool:
        return content_hash(record) in self.playbook_approvals

    def llm_configuration_approved(self, record: LLMRecord) -> bool:
        return content_hash(record) in self.llm_approvals

    def sandbox_configuration_approved(self, profile: SandboxProfile) -> bool:
        return content_hash(profile) in self.sandbox_approvals

    def action_evidence(
        self, action: ActionRequest, check: CheckType
    ) -> tuple[BudgetScopeRef, ...] | None:
        if action.requester_identity_ref not in self.identities:
            return None
        refs: list[BudgetScopeRef] = [action.requester_identity_ref]
        if check in {CheckType.PROVIDER, CheckType.SESSION, CheckType.REDACTION}:
            if action.provider_profile_ref is not None:
                refs.append(action.provider_profile_ref)
            if action.llm_call_spec_ref is not None:
                refs.append(action.llm_call_spec_ref)
        return tuple(refs)

    def item_count(self, action: ActionRequest, work: WorkExecutionState) -> int | None:
        return 1
