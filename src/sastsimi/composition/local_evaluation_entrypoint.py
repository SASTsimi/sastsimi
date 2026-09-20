"""Build the shipped explicit ``LOCAL_EVALUATION`` command entrypoint."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.orchestration.run_scope_plan import PlannedRunScope


def _load_local_resume_scope(
    data_dir: Path, analysis_id: str
) -> tuple[AnalysisStartRequest, PlannedRunScope]:
    from sastsimi.config.runtime_paths import RuntimePaths
    from sastsimi.contracts.analysis import AnalysisRunInput
    from sastsimi.contracts.budget import Purpose
    from sastsimi.storage.database import Database
    from sastsimi.storage.repositories import SQLiteRecordStore
    from sastsimi.storage.run_states import get_run

    database = Database(RuntimePaths(data_dir).database)
    try:
        database.check_ready()
        records = SQLiteRecordStore(database)
        with database.engine.connect() as connection:
            state = get_run(connection, analysis_id)
            run_input = records.resolve(connection, state.analysis_input_ref)
        if (
            not isinstance(run_input, AnalysisRunInput)
            or state.purpose != Purpose.LOCAL_EVALUATION
            or run_input.purpose != Purpose.LOCAL_EVALUATION
            or str(state.meta.analysis_id) != analysis_id
            or state.workspace_id is None
            or state.commit_id is None
            or run_input.program_id != state.program_id
        ):
            raise ValueError("LOCAL_EVALUATION_RESUME_SCOPE_INVALID")
        request = AnalysisStartRequest(
            repository_ref=run_input.repository_ref,
            requested_git_ref=str(state.commit_id),
            program_id=state.program_id,
            purpose=Purpose.LOCAL_EVALUATION,
        )
        return request, PlannedRunScope(
            analysis_id=state.meta.analysis_id,
            workspace_id=state.workspace_id,
            commit_id=state.commit_id,
            repository_ref=run_input.repository_ref,
        )
    finally:
        database.engine.dispose()


def build_local_evaluation_analyze() -> object:
    """Return the real local-evaluation service; never select a Fake adapter."""

    from sastsimi.composition.local_evaluation_composition import (
        ConcreteLocalEvaluationApplicationFactory,
    )
    from sastsimi.composition.local_evaluation_preflight import (
        ConcreteLocalEvaluationPreflight,
    )
    from sastsimi.config.local_evaluation_profile import (
        load_local_evaluation_profile,
    )
    from sastsimi.orchestration.local_evaluation_entrypoint import (
        LocalEvaluationAnalyzeService,
        LocalEvaluationApplicationFactory,
        LocalEvaluationApplicationPreflight,
    )
    from sastsimi.runtime.system_support import UUIDIds

    return LocalEvaluationAnalyzeService(
        ids=UUIDIds(),
        load_profile=load_local_evaluation_profile,
        factory=cast(
            LocalEvaluationApplicationFactory,
            ConcreteLocalEvaluationApplicationFactory(),
        ),
        preflight=cast(
            LocalEvaluationApplicationPreflight,
            ConcreteLocalEvaluationPreflight(),
        ),
        load_resume_scope=_load_local_resume_scope,
    )


__all__ = ["build_local_evaluation_analyze"]
