"""Production analysis application entry point."""

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.ports.scheduler import RunOutcome

from .production_pipeline import ProductionPipeline


class AnalysisService:
    """Start a new analysis through the production pipeline."""

    def __init__(self, pipeline: ProductionPipeline) -> None:
        self.pipeline = pipeline

    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        return await self.pipeline.run(request)


__all__ = ["AnalysisService"]
