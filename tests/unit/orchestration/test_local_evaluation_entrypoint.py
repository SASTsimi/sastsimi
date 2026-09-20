from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.orchestration.local_evaluation_entrypoint import (
    LocalEvaluationAnalyzeService,
    LocalEvaluationApplicationFactory,
    LocalEvaluationProfile,
)
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.scheduler import RunOutcome
from sastsimi.runtime.system_support import UUIDIds


class _Profile:
    program_id = "local-program"


class _Application:
    def __init__(
        self,
        expected: AnalysisStartRequest,
        scope: PlannedRunScope,
        outcomes: list[str] | None = None,
    ) -> None:
        self.expected = expected
        self.scope = scope
        self.shutdown_calls = 0
        self.resume_calls = 0
        self.outcomes = outcomes or ["TERMINAL"]

    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        assert request == self.expected
        return RunOutcome(str(self.scope.analysis_id), self.outcomes.pop(0), None)  # type: ignore[arg-type]

    async def resume(self, analysis_id: str) -> RunOutcome:
        assert analysis_id == str(self.scope.analysis_id)
        self.resume_calls += 1
        return RunOutcome(str(self.scope.analysis_id), self.outcomes.pop(0), None)  # type: ignore[arg-type]

    async def shutdown(self) -> None:
        self.shutdown_calls += 1


class _Factory:
    def __init__(self, outcomes: list[str] | None = None) -> None:
        self.request: AnalysisStartRequest | None = None
        self.scope: PlannedRunScope | None = None
        self.application: _Application | None = None
        self.outcomes = outcomes

    def build(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
    ) -> _Application:
        assert data_dir == Path("data")
        assert profile.program_id == _Profile.program_id
        self.request = request
        self.scope = scope
        self.application = _Application(request, scope, self.outcomes)
        return self.application


class _Preflight:
    def __init__(self, prepared: _Factory) -> None:
        self.prepared = prepared
        self.calls = 0

    async def prepare(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
    ) -> LocalEvaluationApplicationFactory:
        assert data_dir == Path("data")
        assert request.purpose == Purpose.LOCAL_EVALUATION
        assert profile.program_id == _Profile.program_id
        assert scope.repository_ref == request.repository_ref
        self.calls += 1
        return self.prepared


@pytest.mark.asyncio
async def test_local_evaluation_allocates_exact_scope_without_production_manifest() -> (
    None
):
    factory = _Factory()
    service = LocalEvaluationAnalyzeService(
        ids=UUIDIds(),
        load_profile=lambda _path: _Profile(),
        factory=factory,
    )

    outcome = await service(
        type(
            "Command",
            (),
            {
                "data_dir": Path("data"),
                "repository": "https://example.invalid/repository.git",
                "commit": "B" * 40,
                "profile": Path("local-evaluation.toml"),
            },
        )()
    )

    assert outcome.disposition == "TERMINAL"
    assert factory.request is not None
    assert factory.request.purpose == Purpose.LOCAL_EVALUATION
    assert factory.request.requested_git_ref == "b" * 40
    assert factory.scope is not None
    assert factory.scope.repository_ref == factory.request.repository_ref
    assert str(factory.scope.commit_id) == "b" * 40
    assert factory.application is not None
    assert factory.application.shutdown_calls == 1


@pytest.mark.asyncio
async def test_local_evaluation_resumes_blocked_work_without_new_run() -> None:
    factory = _Factory(["BLOCKED", "BLOCKED", "TERMINAL"])
    service = LocalEvaluationAnalyzeService(
        ids=UUIDIds(),
        load_profile=lambda _path: _Profile(),
        factory=factory,
    )

    outcome = await service(
        type(
            "Command",
            (),
            {
                "data_dir": Path("data"),
                "repository": "https://example.invalid/repository.git",
                "commit": "E" * 40,
                "profile": Path("local-evaluation.toml"),
            },
        )()
    )

    assert outcome.disposition == "TERMINAL"
    assert factory.application is not None
    assert factory.application.resume_calls == 2
    assert factory.application.shutdown_calls == 1


@pytest.mark.asyncio
async def test_async_preflight_returns_prepared_factory_before_sync_build() -> None:
    unprepared = _Factory()
    prepared = _Factory()
    preflight = _Preflight(prepared)
    service = LocalEvaluationAnalyzeService(
        ids=UUIDIds(),
        load_profile=lambda _path: _Profile(),
        factory=unprepared,
        preflight=preflight,
    )

    outcome = await service(
        type(
            "Command",
            (),
            {
                "data_dir": Path("data"),
                "repository": "https://example.invalid/repository.git",
                "commit": "C" * 40,
                "profile": Path("local-evaluation.toml"),
            },
        )()
    )

    assert outcome.disposition == "TERMINAL"
    assert preflight.calls == 1
    assert unprepared.application is None
    assert prepared.application is not None


class _FailingPreflight:
    async def prepare(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
    ) -> LocalEvaluationApplicationFactory:
        del data_dir, request, profile, scope
        raise RuntimeError("CODEX_PREFLIGHT_FAILED")


@pytest.mark.asyncio
async def test_preflight_failure_never_enters_sync_factory_build() -> None:
    factory = _Factory()
    service = LocalEvaluationAnalyzeService(
        ids=UUIDIds(),
        load_profile=lambda _path: _Profile(),
        factory=factory,
        preflight=_FailingPreflight(),
    )

    with pytest.raises(RuntimeError, match="CODEX_PREFLIGHT_FAILED"):
        await service(
            type(
                "Command",
                (),
                {
                    "data_dir": Path("data"),
                    "repository": "https://example.invalid/repository.git",
                    "commit": "D" * 40,
                    "profile": Path("local-evaluation.toml"),
                },
            )()
        )

    assert factory.application is None
