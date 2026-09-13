"""Production repository-analysis command leaf."""

from __future__ import annotations

import json

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.ports.scheduler import AnalysisApplicationPort, RunOutcome


def request(
    *,
    repository: str,
    commit: str,
    program_id: str,
    purpose: str = "PRODUCTION",
) -> AnalysisStartRequest:
    """Build typed production input; Provider/profile stays in composition."""
    return AnalysisStartRequest.model_validate_json(
        json.dumps(
            {
                "repository_ref": repository,
                "requested_git_ref": commit,
                "program_id": program_id,
                "purpose": purpose,
            }
        )
    )


async def run(
    application: AnalysisApplicationPort,
    value: AnalysisStartRequest,
) -> dict[str, object]:
    return project(await application.run(value))


def project(outcome: RunOutcome) -> dict[str, object]:
    return {
        "analysis_id": outcome.analysis_id,
        "status": outcome.disposition,
        "result_record_id": str(outcome.result_ref.record_id)
        if outcome.result_ref is not None
        else None,
    }


__all__ = ["project", "request", "run"]
