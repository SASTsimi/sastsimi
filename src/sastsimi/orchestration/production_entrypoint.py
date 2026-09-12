"""One-shot production command composition without a Fake fallback."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import ProgramId
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.scheduler import RunOutcome

from .run_scope_plan import (
    PlannedRunScope,
    ProductionRunScopeAllocator,
)


class ProductionCommandInput(Protocol):
    @property
    def data_dir(self) -> Path: ...

    @property
    def repository(self) -> str: ...

    @property
    def commit(self) -> str: ...

    @property
    def profile(self) -> Path: ...


class ScopeOwnedProductionApplication(Protocol):
    async def run(self, request: AnalysisStartRequest) -> RunOutcome: ...

    async def shutdown(self) -> None: ...


class ProductionApplicationFactory(Protocol):
    def build(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> ScopeOwnedProductionApplication: ...


class ProductionAnalyzeService:
    """Load one explicit profile and own one immutable analysis scope."""

    def __init__(
        self,
        *,
        ids: IdGenerator,
        load_profile: Callable[[Path], ProductionProfile],
        factory: ProductionApplicationFactory,
    ) -> None:
        self._scopes = ProductionRunScopeAllocator(ids)
        self._load_profile = load_profile
        self._factory = factory

    async def __call__(self, command: ProductionCommandInput) -> RunOutcome:
        # Parse the credential-free profile before allocating any durable run ID.
        profile = self._load_profile(command.profile)
        request = AnalysisStartRequest(
            repository_ref=command.repository,
            requested_git_ref=command.commit.lower(),
            program_id=ProgramId(profile.program_id),
            purpose=Purpose.PRODUCTION,
        )
        scope = self._scopes.allocate(request)
        application = self._factory.build(
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
                raise ValueError("PRODUCTION_ANALYSIS_SCOPE_MISMATCH")
            return outcome
        finally:
            await application.shutdown()


__all__ = [
    "ProductionAnalyzeService",
    "ProductionApplicationFactory",
    "ProductionCommandInput",
    "ScopeOwnedProductionApplication",
]
