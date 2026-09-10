"""Canonical §08 analysis state, separate from its terminal result."""

from typing import Literal, Self

from pydantic import AwareDatetime, model_validator

from .base import ContractModel, NonEmptyStr, NonNegativeInt
from .budget import Purpose
from .ids import CommitId, ProgramId, WorkspaceId
from .records import RecordMeta, RunMeta
from .refs import BudgetScopeRef, RunStoredDataRef, StoredDataRef, require_record_ref
from .work import ScopedRecord


class AnalysisStartRequest(ContractModel):
    """An input command; program resolution precedes analysis ID allocation."""

    repository_ref: NonEmptyStr
    requested_git_ref: NonEmptyStr
    program_id: ProgramId
    purpose: Purpose


class AnalysisRunState(ScopedRecord):
    meta: RunMeta
    purpose: Purpose
    eval_config_refs: tuple[BudgetScopeRef, ...]
    program_id: ProgramId
    execution_budget_profile_ref: RunStoredDataRef
    budget_binding_ref: StoredDataRef | None
    workspace_id: WorkspaceId | None
    commit_id: CommitId | None
    workspace_ref: RunStoredDataRef | None
    run_policy_state_ref: StoredDataRef | None
    status: Literal["RUNNING", "COMPLETE", "PARTIAL", "FAILED", "CANCELLED"]
    analysis_result_ref: RunStoredDataRef | None
    started_at: AwareDatetime
    finished_at: AwareDatetime | None
    elapsed_ms: NonNegativeInt

    @model_validator(mode="after")
    def state_shape(self) -> Self:
        if isinstance(self.meta, RecordMeta):
            raise ValueError("AnalysisRunState requires RunMeta")
        if bool(self.eval_config_refs) != (self.purpose == Purpose.EVALUATION):
            raise ValueError("Only EVALUATION requires exact evaluation configuration")
        if (self.status == "RUNNING") != (self.analysis_result_ref is None):
            raise ValueError("Terminal analysis requires its result")
        if (self.status == "RUNNING") != (self.finished_at is None):
            raise ValueError("Only terminal analysis has finished_at")
        if self.status in {"COMPLETE", "PARTIAL"} and (
            self.workspace_id is None or self.commit_id is None
        ):
            raise ValueError("Completed analysis requires workspace and commit")
        for ref, kind in (
            (self.execution_budget_profile_ref, "execution_budget_profile"),
            (self.budget_binding_ref, "budget_profile_binding"),
            (self.workspace_ref, "code_workspace"),
            (self.run_policy_state_ref, "run_policy_state"),
            (self.analysis_result_ref, "analysis_run_result"),
        ):
            if ref is not None:
                require_record_ref(ref, kind)
        if self.budget_binding_ref is not None and (
            self.workspace_id is None
            or self.commit_id is None
            or self.workspace_ref is None
        ):
            raise ValueError("Binding requires exact workspace identity")
        return self
