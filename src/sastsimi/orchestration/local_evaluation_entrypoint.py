"""One-shot LOCAL_EVALUATION scope without production approval claims."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import ProgramId
from sastsimi.orchestration.run_scope_plan import (
    PlannedRunScope,
    ProductionRunScopeAllocator,
)
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.scheduler import RunOutcome


class LocalEvaluationCommandInput(Protocol):
    @property
    def data_dir(self) -> Path: ...

    @property
    def repository(self) -> str: ...

    @property
    def commit(self) -> str: ...

    @property
    def profile(self) -> Path: ...


class LocalEvaluationResumeCommandInput(Protocol):
    @property
    def data_dir(self) -> Path: ...

    @property
    def analysis_id(self) -> str: ...

    @property
    def profile(self) -> Path: ...


class LocalEvaluationProfile(Protocol):
    @property
    def program_id(self) -> str: ...


class ScopeOwnedLocalEvaluationApplication(Protocol):
    async def run(self, request: AnalysisStartRequest) -> RunOutcome: ...

    async def resume(self, analysis_id: str) -> RunOutcome: ...

    async def shutdown(self) -> None: ...


class LocalEvaluationApplicationFactory(Protocol):
    def build(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
    ) -> ScopeOwnedLocalEvaluationApplication: ...


class LocalEvaluationApplicationPreflight(Protocol):
    """Await external validation and return a synchronously prepared factory."""

    async def prepare(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
    ) -> LocalEvaluationApplicationFactory: ...


class LocalEvaluationResumeScopeLoader(Protocol):
    def __call__(
        self, data_dir: Path, analysis_id: str
    ) -> tuple[AnalysisStartRequest, PlannedRunScope]: ...


class LocalEvaluationAnalyzeService:
    """Allocate an exact run labelled LOCAL_EVALUATION, never PRODUCTION."""

    def __init__(
        self,
        *,
        ids: IdGenerator,
        load_profile: Callable[[Path], LocalEvaluationProfile],
        factory: LocalEvaluationApplicationFactory,
        preflight: LocalEvaluationApplicationPreflight | None = None,
        load_resume_scope: LocalEvaluationResumeScopeLoader | None = None,
    ) -> None:
        self._scopes = ProductionRunScopeAllocator(ids)
        self._load_profile = load_profile
        self._factory = factory
        self._preflight = preflight
        self._load_resume_scope = load_resume_scope

    async def __call__(self, command: LocalEvaluationCommandInput) -> RunOutcome:
        profile = self._load_profile(command.profile)
        request = AnalysisStartRequest(
            repository_ref=command.repository,
            requested_git_ref=command.commit.lower(),
            program_id=ProgramId(profile.program_id),
            purpose=Purpose.LOCAL_EVALUATION,
        )
        scope = self._scopes.allocate(request)
        factory = self._factory
        if self._preflight is not None:
            factory = await self._preflight.prepare(
                data_dir=command.data_dir,
                request=request,
                profile=profile,
                scope=scope,
            )
            if not callable(getattr(factory, "build", None)):
                raise ValueError("LOCAL_EVALUATION_PREFLIGHT_FACTORY_INVALID")
        application = factory.build(
            data_dir=command.data_dir,
            request=request,
            profile=profile,
            scope=scope,
        )
        try:
            outcome = await application.run(request)
            if outcome.analysis_id != str(scope.analysis_id) or (
                outcome.result_ref is not None
                and outcome.result_ref.analysis_id != scope.analysis_id
            ):
                raise ValueError("LOCAL_EVALUATION_SCOPE_MISMATCH")
            return outcome
        finally:
            await application.shutdown()

    async def resume(
        self, command: LocalEvaluationResumeCommandInput
    ) -> RunOutcome:
        """Resume exactly one persisted blocked cohort, never retry in a loop."""

        if self._load_resume_scope is None:
            raise ValueError("LOCAL_EVALUATION_RESUME_LOADER_REQUIRED")
        profile = self._load_profile(command.profile)
        request, scope = self._load_resume_scope(
            command.data_dir, command.analysis_id
        )
        factory = self._factory
        if self._preflight is not None:
            factory = await self._preflight.prepare(
                data_dir=command.data_dir,
                request=request,
                profile=profile,
                scope=scope,
            )
        application = factory.build(
            data_dir=command.data_dir,
            request=request,
            profile=profile,
            scope=scope,
        )
        try:
            outcome = await application.resume(command.analysis_id)
            if outcome.analysis_id != command.analysis_id or (
                outcome.result_ref is not None
                and outcome.result_ref.analysis_id != scope.analysis_id
            ):
                raise ValueError("LOCAL_EVALUATION_SCOPE_MISMATCH")
            return outcome
        finally:
            await application.shutdown()


__all__ = [
    "LocalEvaluationAnalyzeService",
    "LocalEvaluationApplicationPreflight",
    "LocalEvaluationApplicationFactory",
    "LocalEvaluationCommandInput",
    "LocalEvaluationProfile",
    "LocalEvaluationResumeCommandInput",
    "LocalEvaluationResumeScopeLoader",
    "ScopeOwnedLocalEvaluationApplication",
]
