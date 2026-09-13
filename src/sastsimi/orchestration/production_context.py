"""Neutral installation values and capability ports shared by the application."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
)
from sastsimi.contracts.work import WorkType
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.scheduler import ExternalCancellationPort, SchedulerStorePort
from sastsimi.ports.trusted_evidence import TrustedEvidencePort
from sastsimi.ports.work_handler import WorkHandler
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.work_service import HandlerFailureRecorder
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .production_application import (
    ProductionReadinessPort,
)
from .production_call_authority import AnalysisApprovedRoute
from .production_operator_profiles import (
    ProductionOperatorProfiles,
)
from .run_initialization import PostWorkspaceSeederPort
from .run_scope_plan import PlannedRunScope

_SAFE_REASON = re.compile(r"[A-Z0-9_]{1,96}\Z")


class ProductionCapabilityUnavailable(RuntimeError):
    """A safe, operator-actionable reason why exact production input is absent."""

    def __init__(self, reason_code: str) -> None:
        if _SAFE_REASON.fullmatch(reason_code) is None:
            raise ValueError("PRODUCTION_CAPABILITY_REASON_INVALID")
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ProductionInstallationContext:
    """Scope-bound services exposed to the T08-T13 capability installer.

    The installer uses existing public builders for the workspace/static graph,
    T10 LLM verification, lazy T11 dynamic reproduction, T12 reporting, and T13
    chaining. It may not replace the runtime, scheduler, identities, or budget
    binding created here.
    """

    data_dir: Path
    request: AnalysisStartRequest
    profile: ProductionProfile
    scope: PlannedRunScope
    clock: Clock
    ids: IdGenerator
    profiles: ProductionOperatorProfiles
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef]
    approved_llm_routes: tuple[AnalysisApprovedRoute, ...]
    budget_binding_ref: StoredDataRef
    runtime: RuntimeServices
    scheduler_store: SchedulerStorePort
    runner: WorkflowRunner


@dataclass(frozen=True, slots=True)
class InstalledProductionServices:
    """Complete domain handler graph installed from exact capability records."""

    handlers: tuple[tuple[WorkType, WorkHandler], ...]
    seeder: PostWorkspaceSeederPort
    readiness: ProductionReadinessPort
    external_cancellation: ExternalCancellationPort


type ProductionFeatureInstaller = Callable[
    [ProductionInstallationContext], InstalledProductionServices
]


@dataclass(frozen=True, slots=True)
class ResolvedProductionCapabilities:
    """Pre-runtime capability closure with no credential values."""

    llm_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter]
    approved_llm_routes: tuple[AnalysisApprovedRoute, ...]
    workspace_dependency_refs: tuple[RecordRef, ...]
    handler_failure_recorder: HandlerFailureRecorder
    install: ProductionFeatureInstaller
    configuration_evidence: TrustedEvidencePort
    production_profile_ref: RunStoredDataRef | None = None
    production_onboarding_ref: RunStoredDataRef | None = None


class ProductionCapabilityResolver(Protocol):
    """Resolve only explicit, currently ACTIVE capability and approval records."""

    def resolve(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> ResolvedProductionCapabilities: ...
