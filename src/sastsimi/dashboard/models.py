"""Safe public view models for the local dashboard."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from sastsimi.contracts.base import ContractModel
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.simple_runtime.recovery import MAX_RECOVERY_ATTEMPTS


class AnalysisSummaryView(ContractModel):
    analysis_id: str
    display_analysis_id: str | None = None
    workspace_id: str | None = None
    commit_id: str | None = None
    current_stage: str
    status: str
    completed_count: int
    stage_count: int
    hypothesis_count: int
    finding_count: int
    inconclusive_hypothesis_count: int = 0
    rejected_hypothesis_count: int = 0
    llm_provider: str | None = None
    on_demand_possible: bool = False
    llm_attempt_count: int = 0
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0
    llm_cost_minor_units: float | None = None
    llm_unknown_cost_calls: int = 0
    cursor_input_tokens: int = 0
    cursor_output_tokens: int = 0
    cursor_cost_cents: float | None = None
    progress_percent: int = 0
    completed_units: int = 0
    known_units: int = 0
    admitted_primitive_count: int = 0
    excluded_primitive_count: int = 0
    child_hypothesis_count: int = 0
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
    disposition: str | None = None
    scope_status: str | None = None
    scope_collection_status: str | None = None
    scope_source_url: str | None = None
    scope_source_revision: str | None = None
    scope_reasons: tuple[str, ...] = ()
    scope_missing_information: tuple[str, ...] = ()
    scope_axes: dict[str, dict[str, object]] = Field(default_factory=dict)
    private_reporting_policy_passed: bool = False
    external_disclosure_allowed: bool = False
    resume_available: bool = False
    validated_poc: bool = False
    parent_hypothesis_ids: tuple[str, ...] = ()
    chain_depth: int = 0
    attempt_number: int = 1
    attempt_limit: int = MAX_RECOVERY_ATTEMPTS
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
