"""Public budget service. Reservation and usage atomicity belong to the ledger."""

from sastsimi.contracts.budget import (
    BudgetLedgerEntry,
    BudgetRemaining,
    BudgetReservation,
)
from sastsimi.contracts.refs import BudgetScopeRef
from sastsimi.ports.budget_ledger import BudgetLedgerPort
from sastsimi.ports.dto import (
    BudgetCommitRequest,
    BudgetReleaseRequest,
    BudgetReservationRequest,
)


class BudgetService:
    def __init__(self, ledger: BudgetLedgerPort) -> None:
        self.ledger = ledger

    def reserve(self, request: BudgetReservationRequest) -> BudgetReservation:
        return self.ledger.reserve(request)

    def commit_usage(self, request: BudgetCommitRequest) -> BudgetLedgerEntry:
        return self.ledger.commit_usage(request)

    def release(self, request: BudgetReleaseRequest) -> BudgetReservation:
        return self.ledger.release(request)

    def remaining(
        self, budget_scope_ref: BudgetScopeRef, analysis_id: str
    ) -> BudgetRemaining:
        return self.ledger.remaining(budget_scope_ref, analysis_id)
