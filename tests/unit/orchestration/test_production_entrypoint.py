from dataclasses import dataclass
from pathlib import Path

import pytest

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.ids import AnalysisId, OpaqueId
from sastsimi.orchestration.production_entrypoint import ProductionAnalyzeService
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.scheduler import RunOutcome


@dataclass(frozen=True)
class _Input:
    data_dir: Path
    repository: str
    commit: str
    profile: Path


class _Ids:
    def new[T: OpaqueId](self, cls: type[T]) -> T:
        return cls("analysis-1" if cls is AnalysisId else "workspace-1")


def _profile() -> ProductionProfile:
    return ProductionProfile.model_construct(program_id="program")


class _Application:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.ran: AnalysisStartRequest | None = None
        self.shutdown_calls = 0

    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        self.ran = request
        if self.fail:
            raise RuntimeError("safe test failure")
        return RunOutcome("analysis-1", "BLOCKED", None)

    async def shutdown(self) -> None:
        self.shutdown_calls += 1


class _Factory:
    def __init__(self, application: _Application) -> None:
        self.application = application
        self.calls: list[tuple[Path, AnalysisStartRequest, PlannedRunScope]] = []

    def build(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> _Application:
        assert profile is PROFILE
        self.calls.append((data_dir, request, scope))
        return self.application


PROFILE = _profile()
COMMIT = "a" * 40


@pytest.mark.asyncio
async def test_loads_profile_then_runs_one_exact_scope_and_always_shuts_down(
    tmp_path: Path,
) -> None:
    application = _Application()
    factory = _Factory(application)
    loaded: list[Path] = []

    def load(path: Path) -> ProductionProfile:
        loaded.append(path)
        return PROFILE

    service = ProductionAnalyzeService(ids=_Ids(), load_profile=load, factory=factory)
    command = _Input(
        data_dir=tmp_path / "data",
        repository=str(tmp_path / "repo"),
        commit=COMMIT,
        profile=tmp_path / "production.toml",
    )

    outcome = await service(command)

    assert outcome == RunOutcome("analysis-1", "BLOCKED", None)
    assert loaded == [command.profile]
    assert application.shutdown_calls == 1
    assert application.ran == factory.calls[0][1]
    data_dir, request, scope = factory.calls[0]
    assert data_dir == command.data_dir
    assert request.repository_ref == command.repository
    assert request.requested_git_ref == COMMIT
    assert str(request.program_id) == "program"
    assert str(scope.analysis_id) == "analysis-1"
    assert str(scope.workspace_id) == "workspace-1"
    assert str(scope.commit_id) == COMMIT


@pytest.mark.asyncio
async def test_run_failure_still_stops_scope_owned_workers(tmp_path: Path) -> None:
    application = _Application(fail=True)
    service = ProductionAnalyzeService(
        ids=_Ids(),
        load_profile=lambda _path: PROFILE,
        factory=_Factory(application),
    )

    with pytest.raises(RuntimeError, match="safe test failure"):
        await service(
            _Input(
                data_dir=tmp_path / "data",
                repository="https://example.invalid/repo.git",
                commit=COMMIT,
                profile=tmp_path / "production.toml",
            )
        )

    assert application.shutdown_calls == 1


@pytest.mark.asyncio
async def test_invalid_profile_fails_before_scope_allocation(tmp_path: Path) -> None:
    class _FailIfUsedIds:
        def new[T: OpaqueId](self, cls: type[T]) -> T:
            raise AssertionError(cls)

    def invalid(_path: Path) -> ProductionProfile:
        raise ValueError("invalid")

    service = ProductionAnalyzeService(
        ids=_FailIfUsedIds(),
        load_profile=invalid,
        factory=_Factory(_Application()),
    )

    with pytest.raises(ValueError, match="invalid"):
        await service(
            _Input(
                data_dir=tmp_path / "data",
                repository="https://example.invalid/repo.git",
                commit=COMMIT,
                profile=tmp_path / "bad.toml",
            )
        )
