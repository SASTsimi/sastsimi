"""Durable production cancellation command leaf."""

from sastsimi.ports.scheduler import AnalysisApplicationPort, AnalysisStatusView


async def run(
    application: AnalysisApplicationPort, analysis_id: str
) -> dict[str, object]:
    return project(await application.cancel(analysis_id))


def project(view: AnalysisStatusView) -> dict[str, object]:
    return {
        "analysis_id": view.analysis_id,
        "status": view.run_status,
        "cancel_requested": view.cancel_requested,
    }


__all__ = ["project", "run"]
