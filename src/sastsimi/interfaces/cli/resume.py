"""Same-input production resume command leaf."""

from sastsimi.interfaces.cli.run import project
from sastsimi.ports.scheduler import AnalysisApplicationPort


async def run(
    application: AnalysisApplicationPort, analysis_id: str
) -> dict[str, object]:
    return project(await application.resume(analysis_id))


__all__ = ["run"]
