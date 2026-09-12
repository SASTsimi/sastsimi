"""Shared invocation DTOs and narrow Agent-facing interfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.ids import AttemptId
from sastsimi.contracts.llm import LLMInvocationRequest, LLMInvocationResult
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.work import WorkExecutionState


@dataclass(frozen=True)
class PersistedLLMInvocation:
    request: LLMInvocationRequest
    result: LLMInvocationResult
    log_ref: StoredDataRef
    dispatch_state: Literal["RETURNED", "UNRESOLVED"]


class InvocationMetadataFactory(Protocol):
    def __call__(
        self,
        source: RecordMeta,
        record_type: str,
        attempt_id: AttemptId | None,
    ) -> RecordMeta: ...


@dataclass(frozen=True)
class HypothesisAgentOutcome:
    invocation: PersistedLLMInvocation
    proposals: tuple[HypothesisProposal, ...]


class HypothesisProposalAgent(Protocol):
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
