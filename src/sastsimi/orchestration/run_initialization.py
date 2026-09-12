"""Fail-closed run initialization over public runtime ports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.budget import BudgetProfileBinding, ExecutionBudgetProfile
from sastsimi.contracts.refs import BudgetScopeRef, RunStoredDataRef, StoredDataRef
from sastsimi.contracts.refs import reference as exact_reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.ready_work import ReadyWorkPort
from sastsimi.ports.runtime_store import BudgetRegistryPort


class ActiveBudgetProfilesPort(Protocol):
    """Resolve and immediately revalidate exact current ACTIVE profiles."""

    def resolve_active_execution(
        self, request: AnalysisStartRequest
    ) -> ExecutionBudgetProfile: ...

    def require_current_execution(self, profile: ExecutionBudgetProfile) -> None: ...

    def resolve_active_binding(
        self, request: AnalysisStartRequest, state: AnalysisRunState
    ) -> BudgetProfileBinding: ...

    def require_current_binding(self, binding: BudgetProfileBinding) -> None: ...


class AnalysisStateFactoryPort(Protocol):
    """Runtime-owned analysis identity and initial-state creation seam."""

    def create(
        self,
        request: AnalysisStartRequest,
        execution_ref: RunStoredDataRef,
    ) -> AnalysisRunState: ...


class RunWorkQueryPort(Protocol):
    def work_for_run(self, analysis_id: str) -> tuple[WorkExecutionState, ...]: ...


class PostWorkspaceSeederPort(Protocol):
    """T08-T13 composition seam for the first post-workspace READY work."""

    def enqueue_initial(
        self,
        request: AnalysisStartRequest,
        state: AnalysisRunState,
        binding_ref: StoredDataRef,
    ) -> tuple[WorkExecutionState, ...]: ...


@dataclass(frozen=True, slots=True)
class InitializedRun:
    request: AnalysisStartRequest
    state: AnalysisRunState
    execution_ref: RunStoredDataRef
    workspace_work: WorkExecutionState

    @property
    def analysis_id(self) -> str:
        return str(self.state.meta.analysis_id)


@dataclass(frozen=True, slots=True)
class BoundRun:
    initialized: InitializedRun
    state: AnalysisRunState
    binding_ref: StoredDataRef
    initial_work: tuple[WorkExecutionState, ...]


class RunInitializationService:
    """Pin budgets in their required order and expose READY work only afterward."""

    def __init__(
        self,
        *,
        profiles: ActiveBudgetProfilesPort,
        state_factory: AnalysisStateFactoryPort,
        budgets: BudgetRegistryPort,
        ready_work: ReadyWorkPort,
        work_query: RunWorkQueryPort,
        workspace_identity_ref: BudgetScopeRef,
        seeder: PostWorkspaceSeederPort,
    ) -> None:
        self._profiles = profiles
        self._state_factory = state_factory
        self._budgets = budgets
        self._ready_work = ready_work
        self._work_query = work_query
        self._workspace_identity_ref = workspace_identity_ref
        self._seeder = seeder

    def start(self, request: AnalysisStartRequest) -> InitializedRun:
        execution = self._profiles.resolve_active_execution(request)
        if execution.status != "ACTIVE" or execution.purpose != request.purpose:
            raise ValueError("ACTIVE_EXECUTION_PROFILE_REQUIRED")
        execution_ref = exact_reference(execution)
        if not isinstance(execution_ref, RunStoredDataRef):
            raise ValueError("RUN_EXECUTION_PROFILE_REQUIRED")
        state = self._state_factory.create(request, execution_ref)
        self._validate_initial_state(request, execution_ref, state)

        # This call is deliberately adjacent to the atomic pin. A resolver may
        # reject a profile retired or replaced after its earlier lookup.
        self._profiles.require_current_execution(execution)
        pinned = self._budgets.pin_execution(execution, state)
        if pinned != execution_ref:
            raise ValueError("EXECUTION_PROFILE_PIN_MISMATCH")
        current = self._budgets.current_state(str(state.meta.analysis_id))
        if current != state:
            raise ValueError("ANALYSIS_INITIAL_STATE_MISMATCH")

        workspace_work = self._ready_work.enqueue(
            pinned,
            current.meta,
            WorkType.WORKSPACE_PREP,
            "ANALYSIS",
            str(current.meta.analysis_id),
            self._workspace_identity_ref,
        )
        if (
            workspace_work.work_type != WorkType.WORKSPACE_PREP
            or workspace_work.status != WorkStatus.READY
            or workspace_work.meta.analysis_id != current.meta.analysis_id
        ):
            raise ValueError("WORKSPACE_PREP_ENQUEUE_MISMATCH")
        return InitializedRun(request, current, pinned, workspace_work)

    def bind_workspace_and_seed(self, initialized: InitializedRun) -> BoundRun:
        works = self._work_query.work_for_run(initialized.analysis_id)
        workspace = tuple(
            item for item in works if item.work_type == WorkType.WORKSPACE_PREP
        )
        if len(workspace) != 1 or workspace[0].status != WorkStatus.SUCCEEDED:
            raise ValueError("WORKSPACE_PREP_NOT_SUCCEEDED")
        if any(item.work_type != WorkType.WORKSPACE_PREP for item in works):
            raise ValueError("POST_WORKSPACE_WORK_BEFORE_BUDGET_BINDING")

        state = self._budgets.current_state(initialized.analysis_id)
        if (
            state.status != "RUNNING"
            or state.execution_budget_profile_ref != initialized.execution_ref
            or state.budget_binding_ref is not None
            or state.workspace_id is None
            or state.commit_id is None
            or state.workspace_ref is None
        ):
            raise ValueError("WORKSPACE_STATE_NOT_READY_FOR_BINDING")
        binding = self._profiles.resolve_active_binding(initialized.request, state)
        binding_ref = exact_reference(binding)
        if (
            binding.status != "ACTIVE"
            or binding.purpose != initialized.request.purpose
            or binding.execution_budget_profile_ref != initialized.execution_ref
            or binding.meta.analysis_id != state.meta.analysis_id
            or binding.meta.workspace_id != state.workspace_id
            or binding.meta.commit_id != state.commit_id
            or not isinstance(binding_ref, StoredDataRef)
        ):
            raise ValueError("ACTIVE_BUDGET_BINDING_REQUIRED")
        state_ref = exact_reference(state)
        if not isinstance(state_ref, RunStoredDataRef):
            raise ValueError("ANALYSIS_STATE_REFERENCE_REQUIRED")

        self._profiles.require_current_binding(binding)
        pinned = self._budgets.pin_binding(binding, state.workspace_ref, state_ref)
        if pinned != binding_ref:
            raise ValueError("BUDGET_BINDING_PIN_MISMATCH")
        bound_state = self._budgets.current_state(initialized.analysis_id)
        if bound_state.budget_binding_ref != pinned:
            raise ValueError("BUDGET_BINDING_STATE_MISMATCH")

        initial_work = self._seeder.enqueue_initial(
            initialized.request,
            bound_state,
            pinned,
        )
        if any(
            item.work_type == WorkType.WORKSPACE_PREP
            or item.status != WorkStatus.READY
            or item.meta.analysis_id != bound_state.meta.analysis_id
            for item in initial_work
        ):
            raise ValueError("POST_WORKSPACE_ENQUEUE_MISMATCH")
        return BoundRun(initialized, bound_state, pinned, initial_work)

    @staticmethod
    def _validate_initial_state(
        request: AnalysisStartRequest,
        execution_ref: RunStoredDataRef,
        state: AnalysisRunState,
    ) -> None:
        if (
            state.meta.record_type != "analysis_run_state"
            or state.purpose != request.purpose
            or state.program_id != request.program_id
            or state.execution_budget_profile_ref != execution_ref
            or state.budget_binding_ref is not None
            or state.workspace_id is not None
            or state.commit_id is not None
            or state.workspace_ref is not None
            or state.run_policy_state_ref is not None
            or state.status != "RUNNING"
            or state.analysis_result_ref is not None
        ):
            raise ValueError("ANALYSIS_INITIAL_STATE_INVALID")


__all__ = [
    "ActiveBudgetProfilesPort",
    "AnalysisStateFactoryPort",
    "BoundRun",
    "InitializedRun",
    "PostWorkspaceSeederPort",
    "RunInitializationService",
    "RunWorkQueryPort",
]
