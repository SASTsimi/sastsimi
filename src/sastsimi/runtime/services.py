"""Composed runtime dependencies exposed to later workflow packages."""

from dataclasses import dataclass

from sastsimi.ports.chaining import ChainingLineagePort
from sastsimi.ports.unit_of_work import UnitOfWork

from .action_validator import RuntimeValidator
from .analysis_finalization import AnalysisFinalizationService
from .attempt_service import AttemptService
from .budget_registry import BudgetProfileRegistry
from .budget_service import BudgetService
from .configuration_registry import ConfigurationRegistry
from .context_binding import ContextBindingService
from .dynamic_registration import DynamicRegistrationService
from .external_call_service import ExternalCallService
from .intermediate_publication import IntermediatePublicationService
from .llm_call_service import LLMCallService
from .policy_runtime import PolicyRuntimeService
from .queries import RuntimeQueries
from .recovery_service import RecoveryService
from .transition_service import TransitionService
from .verification_registration import VerificationRegistrationService
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
    intermediate: IntermediatePublicationService
    context: ContextBindingService
    verification_registration: VerificationRegistrationService
    queries: RuntimeQueries
    dynamic_registration: DynamicRegistrationService
    configuration: ConfigurationRegistry
    finalization: AnalysisFinalizationService
    llm_calls: LLMCallService
    policy: PolicyRuntimeService
    chaining_lineage: ChainingLineagePort | None
