"""Composed runtime dependencies exposed to later workflow packages."""

from dataclasses import dataclass

from sastsimi.ports.unit_of_work import UnitOfWork

from .action_validator import RuntimeValidator
from .attempt_service import AttemptService
from .budget_registry import BudgetProfileRegistry
from .budget_service import BudgetService
from .external_call_service import ExternalCallService
from .recovery_service import RecoveryService
from .transition_service import TransitionService
from .work_service import WorkService


@dataclass(frozen=True)
class RuntimeServices:
    work: WorkService
    attempts: AttemptService
    validator: RuntimeValidator
    budget_registry: BudgetProfileRegistry
    budget: BudgetService
    transitions: TransitionService
    external: ExternalCallService
    recovery: RecoveryService
    unit_of_work: UnitOfWork
