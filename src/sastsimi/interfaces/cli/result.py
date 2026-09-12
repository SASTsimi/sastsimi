"""Exact terminal analysis result command leaf with safe projections."""

from __future__ import annotations

from typing import Literal, Protocol

from sastsimi.contracts.evaluation import AnalysisRunResult


class ResultApplicationPort(Protocol):
    def result(self, analysis_id: str) -> AnalysisRunResult: ...


def run(
    application: ResultApplicationPort,
    analysis_id: str,
    *,
    output_format: Literal["json", "summary"] = "summary",
) -> dict[str, object]:
    result = application.result(analysis_id)
    return project(result, output_format=output_format)


def project(
    result: AnalysisRunResult,
    *,
    output_format: Literal["json", "summary"],
) -> dict[str, object]:
    base: dict[str, object] = {
        "analysis_id": str(result.meta.analysis_id),
        "status": result.status,
        "program_id": str(result.program_id),
        "workspace_id": str(result.workspace_id) if result.workspace_id else None,
        "commit_id": str(result.commit_id) if result.commit_id else None,
        "hypothesis_counts": dict(result.hypothesis_counts),
        "verdict_counts": dict(result.verdict_counts),
        "gate_counts": dict(result.gate_counts),
        "finding_count": len(result.finding_refs),
        "report_count": len(result.report_draft_refs),
        "elapsed_ms": result.elapsed_ms,
    }
    if output_format == "json":
        base.update(
            failed_hypothesis_count=result.failed_hypothesis_count,
            finding_record_ids=[str(item.record_id) for item in result.finding_refs],
            report_record_ids=[
                str(item.record_id) for item in result.report_draft_refs
            ],
            error_codes=[item.code for item in result.errors],
            gap_codes=[item.code for item in result.gaps],
        )
    return base


__all__ = ["project", "run"]
