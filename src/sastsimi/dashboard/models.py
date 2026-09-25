"""Safe public view models for the local dashboard."""

from __future__ import annotations

from datetime import datetime

from pydantic import JsonValue

from sastsimi.contracts.base import ContractModel
from sastsimi.observability.agent_activity import ActivityKind


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
    progress_percent: int = 0
    completed_units: int = 0
    known_units: int = 0
    admitted_primitive_count: int = 0
    excluded_primitive_count: int = 0
    child_hypothesis_count: int = 0
    updated_at: datetime | None = None
    elapsed_ms: int | None = None
    repository: str | None = None
    profile_ref: str | None = None
    provider: str | None = None
    model: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    last_updated_at: datetime | None = None
    stale: bool = False


class StageProgressView(ContractModel):
    stage: str
    label_ko: str
    status: str
    hypothesis_id: str | None = None
    agent_role: str
    attempt_number: int = 0
    output_count: int = 0
    retryable: bool = False
    error_code: str | None = None
    updated_at: datetime | None = None


class StaticToolProgressView(ContractModel):
    tool: str
    status: str
    finding_count: int | None = None


class ReadinessCheckView(ContractModel):
    key: str
    label_ko: str
    status: str
    detail_ko: str
    required: bool = True


class UsageSummaryView(ContractModel):
    invocation_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    retry_count: int = 0
    known_usage_count: int = 0
    unknown_usage_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    elapsed_ms: int = 0


class ArtifactView(ContractModel):
    artifact_id: str
    kind: str
    data_kind: str
    media_type: str
    size_bytes: int
    stages: tuple[str, ...] = ()
    hypothesis_ids: tuple[str, ...] = ()
    view_url: str
    download_url: str


class LLMInvocationView(ContractModel):
    invocation_id: str
    agent_role: str
    provider: str
    model: str
    template_revision: str | None = None
    stage: str
    hypothesis_id: str | None = None
    status: str
    prompt_digest: str | None = None
    output_digest: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    elapsed_ms: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    attempt_number: int = 0
    retry_count: int = 0
    request_artifact_id: str | None = None
    response_artifact_id: str | None = None


class ArtifactContentView(ContractModel):
    artifact_id: str
    kind: str
    media_type: str
    content: JsonValue | str


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
    parent_hypothesis_ids: tuple[str, ...] = ()
    chain_depth: int = 0
    title: str | None = None
    vulnerability_type: str | None = None
    summary: str | None = None
    source: str | None = None
    sink: str | None = None
    code_locations: tuple[str, ...] = ()
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
    provider: str | None = None
    model: str | None = None
    prompt_digest: str | None = None
    output_digest: str | None = None


class FindingReportView(ContractModel):
    analysis_id: str
    display_id: str
    url: str
    view_url: str
    download_url: str


class AnalysisDetailView(AnalysisSummaryView):
    hypotheses: tuple[HypothesisProgressView, ...] = ()
    reports: tuple[FindingReportView, ...] = ()
    pipeline: tuple[StageProgressView, ...] = ()
    static_tools: tuple[StaticToolProgressView, ...] = ()
    readiness: tuple[ReadinessCheckView, ...] = ()
    usage: UsageSummaryView = UsageSummaryView()
    artifacts: tuple[ArtifactView, ...] = ()
    llm_invocations: tuple[LLMInvocationView, ...] = ()
    poc_artifact_ids: tuple[str, ...] = ()
    evidence_artifact_ids: tuple[str, ...] = ()
    logs_url: str | None = None
    bundle_url: str | None = None


__all__ = [
    "AgentActivityView",
    "ArtifactContentView",
    "ArtifactView",
    "AnalysisDetailView",
    "AnalysisSummaryView",
    "FindingReportView",
    "HypothesisProgressView",
    "LLMInvocationView",
    "ReadinessCheckView",
    "StageProgressView",
    "StaticToolProgressView",
    "UsageSummaryView",
]
