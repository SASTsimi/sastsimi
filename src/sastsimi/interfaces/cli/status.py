"""Read-only production analysis status leaf."""

from sastsimi.ports.scheduler import AnalysisApplicationPort, AnalysisStatusView


def run(application: AnalysisApplicationPort, analysis_id: str) -> dict[str, object]:
    return project(application.status(analysis_id))


def project(view: AnalysisStatusView) -> dict[str, object]:
    return {
        "analysis_id": view.analysis_id,
        "status": view.run_status,
        "work_counts": dict(view.work_counts),
        "cancel_requested": view.cancel_requested,
        "waiting_for": list(view.waiting_for),
        "result_record_id": str(view.result_ref.record_id)
        if view.result_ref is not None
        else None,
    }


__all__ = ["project", "run"]
