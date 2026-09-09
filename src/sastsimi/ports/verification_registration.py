"""Atomic trusted Verification registration; callers never supply application IDs."""

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.contracts.verification import PlaybookApplication
from sastsimi.contracts.work import WorkExecutionState


@dataclass(frozen=True)
class VerificationRegistration:
    work: WorkExecutionState
    application: PlaybookApplication
    assignment_ref: StoredDataRef
    process_ref: StoredDataRef


class VerificationRegistrationPort(Protocol):
    def register(
        self,
        *,
        hypothesis_ref: StoredDataRef,
        proposal_ref: StoredDataRef,
        policy_ref: StoredDataRef,
        playbook_ref: StoredDataRef,
        expected_process_ref: StoredDataRef,
        owner_identity_ref: StoredDataRef,
        requester_identity_ref: BudgetScopeRef,
        budget_binding_ref: StoredDataRef,
    ) -> VerificationRegistration: ...

    def revise(
        self,
        *,
        technical_review_ref: StoredDataRef,
        hypothesis_ref: StoredDataRef,
        proposal_ref: StoredDataRef,
        policy_ref: StoredDataRef,
        playbook_ref: StoredDataRef,
        expected_process_ref: StoredDataRef,
        owner_identity_ref: StoredDataRef,
        requester_identity_ref: BudgetScopeRef,
        budget_binding_ref: StoredDataRef,
    ) -> VerificationRegistration: ...
