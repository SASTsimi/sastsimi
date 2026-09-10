"""Trusted immutable Context request provenance, never an arbitrary record writer."""

from typing import Protocol

from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.static import (
    CodeContextRequest,
    CodeLocation,
    CodeSymbol,
    ContextRetrievalLimits,
)


class ContextBindingPort(Protocol):
    def bind(
        self,
        work_id: str,
        used_decision_ref: RecordRef,
        *,
        requested_entities: tuple[CodeSymbol, ...],
        requested_locations: tuple[CodeLocation, ...],
        relation_query: tuple[str, ...],
        limits: ContextRetrievalLimits,
    ) -> CodeContextRequest: ...
