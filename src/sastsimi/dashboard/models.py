"""Safe public view models for the local dashboard."""

from __future__ import annotations

from datetime import datetime

from sastsimi.contracts.base import ContractModel
from sastsimi.observability.agent_activity import ActivityKind


class AnalysisSummaryView(ContractModel):
    analysis_id: str
    workspace_id: str | None = None
    commit_id: str | None = None
    current_stage: str
    status: str
    completed_count: int
    stage_count: int
    hypothesis_count: int
    finding_count: int
    updated_at: datetime | None = None
    elapsed_ms: int | None = None


class HypothesisProgressView(ContractModel):
    analysis_id: str
    hypothesis_id: str
    current_stage: str
    status: str
    completed_count: int
    stage_count: int
    error_code: str | None = None
    verdict: str | None = None
    validated_poc: bool = False
    updated_at: datetime | None = None


class AgentActivityView(ContractModel):
    event_id: str
    analysis_id: str
    hypothesis_id: str | None
    stage: str
    agent_role: str
    attempt_id: str
    sequence: int
    kind: ActivityKind
    status: str
    summary_ko: str
    tool_name: str | None = None
    error_code: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    elapsed_ms: int | None = None


class FindingReportView(ContractModel):
    analysis_id: str
    display_id: str
    url: str


class AnalysisDetailView(AnalysisSummaryView):
    hypotheses: tuple[HypothesisProgressView, ...] = ()
    reports: tuple[FindingReportView, ...] = ()


__all__ = [
    "AgentActivityView",
    "AnalysisDetailView",
    "AnalysisSummaryView",
    "FindingReportView",
    "HypothesisProgressView",
]
