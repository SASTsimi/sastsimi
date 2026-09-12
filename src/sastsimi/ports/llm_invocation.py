"""Stable Agent-facing types for one persisted LLM invocation."""

from dataclasses import dataclass
from typing import Literal, Protocol

from sastsimi.contracts.ids import AttemptId
from sastsimi.contracts.llm import LLMInvocationRequest, LLMInvocationResult
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef

type ExternalDispatchState = Literal["RETURNED", "UNRESOLVED"]


@dataclass(frozen=True)
class PersistedLLMInvocation:
    """One exact request/result/log set persisted by the trusted runtime."""

    request: LLMInvocationRequest
    result: LLMInvocationResult
    log_ref: StoredDataRef
    dispatch_state: ExternalDispatchState


class InvocationMetadataFactory(Protocol):
    """Issue immutable record metadata at the composition boundary."""

    def __call__(
        self,
        source: RecordMeta,
        record_type: str,
        attempt_id: AttemptId | None,
    ) -> RecordMeta: ...


__all__ = [
    "ExternalDispatchState",
    "InvocationMetadataFactory",
    "PersistedLLMInvocation",
]
