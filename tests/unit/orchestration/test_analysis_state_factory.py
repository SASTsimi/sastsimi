from datetime import UTC, datetime

import pytest

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import AnalysisId, OpaqueId
from sastsimi.contracts.refs import RunStoredDataRef, reference
from sastsimi.orchestration.analysis_state_factory import AnalysisStateFactory


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
        return kind(f"id-{self.value}")


def _execution_ref() -> RunStoredDataRef:
    return RunStoredDataRef(
        stored_data_id="execution",
        data_kind="execution_budget_profile",
        content_hash="a" * 64,
        analysis_id="published-for-run",
        record_id="execution-record",
    )


def test_factory_pins_one_exact_credential_free_input_to_initial_state() -> None:
    built = AnalysisStateFactory(_Clock(), _Ids()).create(
        AnalysisStartRequest(
            repository_ref="https://example.invalid/team/repository.git",
            requested_git_ref="a" * 40,
            program_id="program-a",
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
                program_id="program-a",
                purpose=Purpose.EVALUATION,
            ),
            _execution_ref(),
        )
