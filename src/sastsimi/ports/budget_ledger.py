from typing import Protocol, runtime_checkable

from sastsimi.contracts.budget import (
    BudgetLedgerEntry,
    BudgetRemaining,
    BudgetReservation,
)
from sastsimi.contracts.refs import BudgetScopeRef

from .dto import BudgetCommitRequest, BudgetReleaseRequest, BudgetReservationRequest


@runtime_checkable
class BudgetLedgerPort(Protocol):
    """Reserve atomically against committed usage plus active reservations.

    Exactly one entry per reservation; commit/release are terminal/idempotent.
    Unknown actual use remains reserved, never zeroed or released speculatively.
    remaining must reject a consuming analysis outside the exact budget scope.
    """

    def reserve(self, request: BudgetReservationRequest) -> BudgetReservation: ...
    def commit_usage(self, request: BudgetCommitRequest) -> BudgetLedgerEntry: ...
    def release(self, request: BudgetReleaseRequest) -> BudgetReservation: ...
    def remaining(
        self, budget_scope_ref: BudgetScopeRef, analysis_id: str
    ) -> BudgetRemaining: ...
