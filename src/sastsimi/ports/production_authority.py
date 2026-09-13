"""Data-only authority inspection snapshot; it cannot authorize an action."""

from collections.abc import Mapping
from dataclasses import dataclass

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.production_authority import ProductionAuthorityCatalog
from sastsimi.contracts.refs import BudgetScopeRef


@dataclass(frozen=True, slots=True)
class ProductionAuthoritySnapshot:
    catalog: ProductionAuthorityCatalog
    execution: ExecutionBudgetProfile
    binding: BudgetProfileBinding
    work: WorkBudgetProfile
    verification: VerificationBudgetProfile
    dynamic: DynamicReproductionLifecycleProfile
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef]
