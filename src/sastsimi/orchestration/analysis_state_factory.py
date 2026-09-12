"""Runtime-owned, immutable bootstrap records for one production analysis."""

from __future__ import annotations

from sastsimi.contracts.analysis import (
    AnalysisRunInput,
    AnalysisRunState,
    AnalysisStartRequest,
)
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import AnalysisId, LogicalRecordId, RecordId
from sastsimi.contracts.records import RunMeta
from sastsimi.contracts.refs import BudgetScopeRef, RunStoredDataRef, reference
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator

from .run_initialization import RunBootstrap


class AnalysisStateFactory:
    """Create exact input/state records in the run-local budget profile scope."""

    def __init__(
        self,
        clock: Clock,
        ids: IdGenerator,
        *,
        eval_config_refs: tuple[BudgetScopeRef, ...] = (),
    ) -> None:
        self._clock = clock
        self._ids = ids
        self._eval_config_refs = eval_config_refs

    def _meta(self, kind: str, analysis_id: AnalysisId) -> RunMeta:
        record_id = self._ids.new(RecordId)
        return RunMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=self._clock.now(),
            analysis_id=analysis_id,
        )

    def create(
        self,
        request: AnalysisStartRequest,
        execution_ref: RunStoredDataRef,
    ) -> RunBootstrap:
        if bool(self._eval_config_refs) != (request.purpose == Purpose.EVALUATION):
            raise ValueError("ANALYSIS_EVALUATION_CONFIG_INVALID")
        analysis_id = execution_ref.analysis_id
        run_input = AnalysisRunInput(
            meta=self._meta("analysis_run_input", analysis_id),
            repository_ref=request.repository_ref,
            requested_git_ref=request.requested_git_ref,
            program_id=request.program_id,
            purpose=request.purpose,
        )
        input_ref = reference(run_input)
        if not isinstance(input_ref, RunStoredDataRef):
            raise ValueError("ANALYSIS_INPUT_REFERENCE_INVALID")
        state = AnalysisRunState(
            meta=self._meta("analysis_run_state", analysis_id),
            purpose=request.purpose,
            eval_config_refs=self._eval_config_refs,
            analysis_input_ref=input_ref,
            program_id=request.program_id,
            execution_budget_profile_ref=execution_ref,
            budget_binding_ref=None,
            workspace_id=None,
            commit_id=None,
            workspace_ref=None,
            run_policy_state_ref=None,
            status="RUNNING",
            analysis_result_ref=None,
            started_at=self._clock.now(),
            finished_at=None,
            elapsed_ms=0,
        )
        return RunBootstrap(run_input, state)


__all__ = ["AnalysisStateFactory"]
