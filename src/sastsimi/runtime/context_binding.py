"""Context Retrieval Service's narrow request-binding runtime port."""

from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.static import (
    CodeContextRequest,
    CodeLocation,
    CodeSymbol,
    ContextRetrievalLimits,
)
from sastsimi.ports.context_binding import ContextBindingPort


class ContextBindingService:
    def __init__(self, store: ContextBindingPort) -> None:
        self.store = store

    def bind(
        self,
        work_id: str,
        used_decision_ref: RecordRef,
        *,
        requested_entities: tuple[CodeSymbol, ...],
        requested_locations: tuple[CodeLocation, ...],
        relation_query: tuple[str, ...],
        limits: ContextRetrievalLimits,
    ) -> CodeContextRequest:
        return self.store.bind(
            work_id,
            used_decision_ref,
            requested_entities=requested_entities,
            requested_locations=requested_locations,
            relation_query=relation_query,
            limits=limits,
        )
