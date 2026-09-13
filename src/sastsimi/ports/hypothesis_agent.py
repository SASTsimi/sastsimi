"""Orchestration-facing port for the Hypothesis Agent."""

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.work import WorkExecutionState

from .llm_invocation import PersistedLLMInvocation


@dataclass(frozen=True)
class HypothesisAgentOutcome:
    """Trusted proposals and the exact invocation that produced them."""

    invocation: PersistedLLMInvocation
    proposals: tuple[HypothesisProposal, ...]


class HypothesisAgentPort(Protocol):
    """Narrow boundary used by orchestration to request initial hypotheses."""

    async def propose(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
        static_bundle: StaticFactBundle,
        static_bundle_ref: StoredDataRef,
    ) -> HypothesisAgentOutcome: ...


__all__ = ["HypothesisAgentOutcome", "HypothesisAgentPort"]
