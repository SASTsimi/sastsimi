"""Non-LLM registration facade; mutation/IDs stay behind the trusted port."""

from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.ports.verification_registration import (
    VerificationRegistration,
    VerificationRegistrationPort,
)


class VerificationRegistrationService:
    def __init__(self, store: VerificationRegistrationPort) -> None:
        self.store = store

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
    ) -> VerificationRegistration:
        return self.store.register(
            hypothesis_ref=hypothesis_ref,
            proposal_ref=proposal_ref,
            policy_ref=policy_ref,
            playbook_ref=playbook_ref,
            expected_process_ref=expected_process_ref,
            owner_identity_ref=owner_identity_ref,
            requester_identity_ref=requester_identity_ref,
            budget_binding_ref=budget_binding_ref,
        )

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
    ) -> VerificationRegistration:
        return self.store.revise(
            technical_review_ref=technical_review_ref,
            hypothesis_ref=hypothesis_ref,
            proposal_ref=proposal_ref,
            policy_ref=policy_ref,
            playbook_ref=playbook_ref,
            expected_process_ref=expected_process_ref,
            owner_identity_ref=owner_identity_ref,
            requester_identity_ref=requester_identity_ref,
            budget_binding_ref=budget_binding_ref,
        )
