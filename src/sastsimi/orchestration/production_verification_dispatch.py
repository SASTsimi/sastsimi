"""Non-LLM handoff from committed hypotheses to Verification work."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    HypothesisProposal,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.contracts.work import WorkStatus
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.runtime.verification_registration import VerificationRegistrationService
from sastsimi.runtime.workflow_runner import WorkflowRunner


@dataclass(frozen=True, slots=True)
class InitialVerificationDispatcher:
    """Register and enqueue one Verification generation per committed proposal.

    The Hypothesis Agent only proposes records.  This runtime-owned adapter
    resolves the trusted projections created by that commit and performs the
    state-changing assignment with exact policy, playbook, and static evidence.
    """

    records: RecordStore
    current: RuntimeQueryPort
    registrar: VerificationRegistrationService
    runner: WorkflowRunner
    policy_ref: StoredDataRef
    verification_identity_ref: StoredDataRef
    orchestration_identity_ref: BudgetScopeRef

    def __call__(self, proposal_refs: tuple[StoredDataRef, ...]) -> None:
        if len(proposal_refs) != len(set(proposal_refs)):
            raise ValueError("HYPOTHESIS_OUTPUT_CLOSURE_MISMATCH")
        policy = self._exact(self.policy_ref, PlaybookPolicy)
        for proposal_ref in proposal_refs:
            proposal = self._exact(proposal_ref, HypothesisProposal)
            analysis_id = str(proposal.meta.analysis_id)
            hypothesis = self._one(
                analysis_id,
                "vulnerability_hypothesis",
                VulnerabilityHypothesis,
                _proposal_matches(proposal_ref),
            )
            process = self._one(
                analysis_id,
                "hypothesis_process_state",
                HypothesisProcessState,
                _hypothesis_matches(str(hypothesis.meta.hypothesis_id)),
            )
            bundle = self._one(
                analysis_id,
                "static_fact_bundle",
                StaticFactBundle,
                _code_scope_matches(
                    str(hypothesis.meta.workspace_id), str(hypothesis.meta.commit_id)
                ),
            )
            book_ref = self._select_playbook(policy, proposal)
            self._exact(book_ref, VerificationPlaybook)
            scope = self.runner.runtime.budget_registry.current_state(
                analysis_id
            ).budget_binding_ref
            if not isinstance(scope, StoredDataRef):
                raise ValueError("CURRENT_BUDGET_SCOPE_REQUIRED")
            registered = self.registrar.register(
                hypothesis_ref=self._stored_ref(hypothesis),
                proposal_ref=proposal_ref,
                policy_ref=self.policy_ref,
                playbook_ref=book_ref,
                expected_process_ref=self._stored_ref(process),
                owner_identity_ref=self.verification_identity_ref,
                requester_identity_ref=self.orchestration_identity_ref,
                budget_binding_ref=scope,
                evidence_ref=self._stored_ref(bundle),
            )
            ready = self.runner.enqueue_registered(
                registered.work,
                scope,
                self.verification_identity_ref,
                role="VERIFICATION",
            )
            if ready.status != WorkStatus.READY:
                raise ValueError("VERIFICATION_HANDOFF_NOT_READY")

    def _select_playbook(
        self, policy: PlaybookPolicy, proposal: HypothesisProposal
    ) -> StoredDataRef:
        mappings = {
            item.vulnerability_type: item.playbook_ref for item in policy.type_playbooks
        }
        candidates = proposal.vulnerability_type_candidates
        if len(candidates) == 1 and candidates[0] in mappings:
            return mappings[candidates[0]]
        return policy.common_playbook_ref

    def _one[T](
        self,
        analysis_id: str,
        kind: str,
        model: type[T],
        predicate: Callable[[T], bool],
    ) -> T:
        matches = tuple(
            item
            for item in self.current.current_records(analysis_id, kind)
            if isinstance(item, model) and predicate(item)
        )
        if len(matches) != 1:
            raise ValueError("VERIFICATION_HANDOFF_INPUT_MISMATCH")
        return matches[0]

    def _exact[T](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self.records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:  # type: ignore[arg-type]
            raise ValueError("VERIFICATION_HANDOFF_INPUT_MISMATCH")
        return value

    @staticmethod
    def _stored_ref(value: object) -> StoredDataRef:
        ref = reference(value)  # type: ignore[arg-type]
        if not isinstance(ref, StoredDataRef):
            raise ValueError("VERIFICATION_HANDOFF_INPUT_MISMATCH")
        return ref


def _proposal_matches(
    proposal_ref: StoredDataRef,
) -> Callable[[VulnerabilityHypothesis], bool]:
    return lambda item: item.proposal_ref == proposal_ref


def _hypothesis_matches(
    hypothesis_id: str,
) -> Callable[[HypothesisProcessState], bool]:
    return lambda item: str(item.meta.hypothesis_id) == hypothesis_id


def _code_scope_matches(
    workspace_id: str, commit_id: str
) -> Callable[[StaticFactBundle], bool]:
    return lambda item: (
        str(item.meta.workspace_id) == workspace_id
        and str(item.meta.commit_id) == commit_id
    )


__all__ = ["InitialVerificationDispatcher"]
