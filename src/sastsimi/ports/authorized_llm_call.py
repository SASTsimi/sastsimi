"""Exact authority attached to one running LLM child work."""

from dataclasses import dataclass

from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.work import WorkExecutionState


@dataclass(frozen=True)
class AuthorizedLLMCall:
    """One already-authorized call bound to a running evidence child work."""

    work: WorkExecutionState
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef
