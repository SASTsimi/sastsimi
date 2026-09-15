"""Trusted runtime facades for atomic Chaining cohort persistence."""

from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.records import RecordMetadata
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.ports.chaining import (
    ChainingCohortPort,
    ChainingCohortRegistration,
    ChainingCommittedSourcePort,
    ChainingPoolHistory,
    ChainingPoolHistoryPort,
    PrimitiveUpdateOutcome,
)


class ChainingCommittedSourceService:
    """Read only exact committed sources when recovering post-commit work."""

    def __init__(self, store: ChainingCommittedSourcePort) -> None:
        self.store = store

    def primitive_update(
        self, source_update_ref: StoredDataRef
    ) -> PrimitiveUpdateOutcome:
        return self.store.primitive_update(source_update_ref)

    def chaining_result(self, source_result_ref: StoredDataRef) -> ChainingResult:
        return self.store.chaining_result(source_result_ref)


class ChainingRegistrationService:
    """Expose cohort mutation without exposing a database connection."""

    def __init__(self, store: ChainingCohortPort) -> None:
        self.store = store

    def register_pending(
        self,
        *,
        outcome: PrimitiveUpdateOutcome,
        scope: BudgetScopeRef,
        requester_identity_ref: BudgetScopeRef,
        metadata: RecordMetadata,
        generation: int,
    ) -> ChainingCohortRegistration:
        return self.store.register_pending(
            outcome=outcome,
            scope=scope,
            requester_identity_ref=requester_identity_ref,
            metadata=metadata,
            generation=generation,
        )

    def promote_ready(
        self,
        *,
        registration: ChainingCohortRegistration,
        scope: BudgetScopeRef,
        requester_identity_ref: BudgetScopeRef,
    ) -> ChainingCohortRegistration:
        return self.store.promote_ready(
            registration=registration,
            scope=scope,
            requester_identity_ref=requester_identity_ref,
        )


class ChainingPoolService:
    """Historical exact-pool read facade used by workers and recovery."""

    def __init__(self, store: ChainingPoolHistoryPort) -> None:
        self.store = store

    def get_for_trigger(self, trigger_work_ref: StoredDataRef) -> ChainingPoolHistory:
        return self.store.get_for_trigger(trigger_work_ref)

    def get_for_primitive(
        self, trigger_primitive_ref: StoredDataRef
    ) -> ChainingPoolHistory:
        return self.store.get_for_primitive(trigger_primitive_ref)


__all__ = [
    "ChainingCommittedSourceService",
    "ChainingPoolService",
    "ChainingRegistrationService",
]
