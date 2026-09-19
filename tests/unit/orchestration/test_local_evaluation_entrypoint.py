from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.orchestration.local_evaluation_entrypoint import (
    LocalEvaluationAnalyzeService,
)
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.scheduler import RunOutcome
from sastsimi.runtime.system_support import UUIDIds


@dataclass(frozen=True)
class _Profile:
    program_id: str = "local-program"


class _Application:
    def __init__(self, expected: AnalysisStartRequest, scope: PlannedRunScope) -> None:
        self.expected = expected
        self.scope = scope
        self.shutdown_calls = 0

    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        assert request == self.expected
        return RunOutcome(str(self.scope.analysis_id), "TERMINAL", None)

    async def shutdown(self) -> None:
        self.shutdown_calls += 1


class _Factory:
    def __init__(self) -> None:
        self.request: AnalysisStartRequest | None = None
        self.scope: PlannedRunScope | None = None
        self.application: _Application | None = None

    def build(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: _Profile,
        scope: PlannedRunScope,
    ) -> _Application:
        assert data_dir == Path("data")
        assert profile == _Profile()
        self.request = request
        self.scope = scope
        self.application = _Application(request, scope)
        return self.application


@pytest.mark.asyncio
async def test_local_evaluation_allocates_exact_scope_without_production_manifest(
) -> None:
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
