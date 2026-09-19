from datetime import UTC, datetime

import pytest

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    OpaqueId,
    ProgramId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import RunStoredDataRef, reference
from sastsimi.orchestration.analysis_state_factory import AnalysisStateFactory
from sastsimi.orchestration.run_scope_plan import PlannedRunScope


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 13, tzinfo=UTC)

    def monotonic_ms(self) -> int:
        return 1


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind.model_validate(f"id-{self.value}")


def _execution_ref() -> RunStoredDataRef:
    return RunStoredDataRef(
        stored_data_id=StoredDataId("execution"),
        data_kind="execution_budget_profile",
        content_hash="a" * 64,
        analysis_id=AnalysisId("published-for-run"),
        record_id=RecordId("execution-record"),
    )


def test_factory_pins_one_exact_credential_free_input_to_initial_state() -> None:
    built = AnalysisStateFactory(_Clock(), _Ids()).create(
        AnalysisStartRequest(
            repository_ref="https://example.invalid/team/repository.git",
            requested_git_ref="a" * 40,
            program_id=ProgramId("program-a"),
            purpose=Purpose.PRODUCTION,
        ),
        _execution_ref(),
    )

    assert isinstance(built.run_input.meta.analysis_id, AnalysisId)
    assert built.state.meta.analysis_id == built.run_input.meta.analysis_id
    assert built.state.analysis_input_ref == reference(built.run_input)
    assert built.state.execution_budget_profile_ref == _execution_ref()
    assert built.state.workspace_ref is None
    assert built.state.status == "RUNNING"


def test_factory_rejects_evaluation_without_exact_config_refs() -> None:
    with pytest.raises(ValueError, match="ANALYSIS_EVALUATION_CONFIG_INVALID"):
        AnalysisStateFactory(_Clock(), _Ids()).create(
            AnalysisStartRequest(
                repository_ref="https://example.invalid/team/repository.git",
                requested_git_ref="a" * 40,
                program_id=ProgramId("program-a"),
                purpose=Purpose.EVALUATION,
            ),
            _execution_ref(),
        )


def test_factory_pins_local_evaluation_scope_without_production_descriptors() -> None:
    commit = CommitId("b" * 40)
    scope = PlannedRunScope(
        analysis_id=AnalysisId("published-for-run"),
        workspace_id=WorkspaceId("workspace-local"),
        commit_id=commit,
        repository_ref="https://example.invalid/team/repository.git",
    )
    built = AnalysisStateFactory(_Clock(), _Ids(), scope=scope).create(
        AnalysisStartRequest(
            repository_ref=scope.repository_ref,
            requested_git_ref=str(commit),
            program_id=ProgramId("program-a"),
            purpose=Purpose.LOCAL_EVALUATION,
        ),
        _execution_ref(),
    )

    assert built.run_input.meta.analysis_id == scope.analysis_id
    assert built.run_input.workspace_id == scope.workspace_id
    assert built.run_input.commit_id == scope.commit_id
    assert built.run_input.production_profile_ref is None
    assert built.run_input.production_onboarding_ref is None
    assert built.run_input.production_authority_catalog_ref is None


def test_factory_keeps_scoped_production_descriptors_mandatory() -> None:
    commit = CommitId("b" * 40)
    scope = PlannedRunScope(
        analysis_id=AnalysisId("published-for-run"),
        workspace_id=WorkspaceId("workspace-production"),
        commit_id=commit,
        repository_ref="https://example.invalid/team/repository.git",
    )

    with pytest.raises(ValueError, match="PRODUCTION_DESCRIPTOR_SCOPE_MISMATCH"):
        AnalysisStateFactory(_Clock(), _Ids(), scope=scope).create(
            AnalysisStartRequest(
                repository_ref=scope.repository_ref,
                requested_git_ref=str(commit),
                program_id=ProgramId("program-a"),
                purpose=Purpose.PRODUCTION,
            ),
            _execution_ref(),
        )


def test_factory_rejects_production_descriptors_on_local_evaluation() -> None:
    commit = CommitId("b" * 40)
    scope = PlannedRunScope(
        analysis_id=AnalysisId("published-for-run"),
        workspace_id=WorkspaceId("workspace-local"),
        commit_id=commit,
        repository_ref="https://example.invalid/team/repository.git",
    )

    with pytest.raises(ValueError, match="LOCAL_EVALUATION_DESCRIPTOR_INVALID"):
        AnalysisStateFactory(
            _Clock(),
            _Ids(),
            scope=scope,
            production_profile_ref=_execution_ref(),
        ).create(
            AnalysisStartRequest(
                repository_ref=scope.repository_ref,
                requested_git_ref=str(commit),
                program_id=ProgramId("program-a"),
                purpose=Purpose.LOCAL_EVALUATION,
            ),
            _execution_ref(),
        )
