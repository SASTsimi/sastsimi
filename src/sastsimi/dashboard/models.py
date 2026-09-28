"""Safe public view models for the local dashboard."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, JsonValue

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
    guidance_ko: str | None = None
    updated_at: datetime | None = None


class StaticToolProgressView(ContractModel):
    tool: str
    status: str
    finding_count: int | None = None


class StaticToolFindingView(ContractModel):
    location: str
    tools: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    overlap: bool = False


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


class ArtifactRelationView(ContractModel):
    source_artifact_id: str
    target_artifact_id: str
    relation: str
    source_kind: str
    target_kind: str


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
    title: str | None = None
    vulnerability_type: str | None = None
    summary: str | None = None
    source: str | None = None
    sink: str | None = None
    code_locations: tuple[str, ...] = ()
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
    provider: str | None = None
    model: str | None = None
    prompt_digest: str | None = None
    output_digest: str | None = None
    substage: str | None = None
    metrics: dict[str, int] = Field(default_factory=dict)


class DashboardKpiView(ContractModel):
    discovery_done: int | None = None
    discovery_total: int | None = None
    verification_done: int | None = None
    verification_total: int | None = None
    remaining_work: int | None = None
    confirmed_findings: int = 0


class StatusCellView(ContractModel):
    id: str
    kind: str
    status: str
    label_ko: str
    detail_url: str


class StatusCellPageView(ContractModel):
    items: tuple[StatusCellView, ...]
    total: int
    offset: int
    limit: int


class FindingReportView(ContractModel):
    analysis_id: str
    display_id: str
    url: str
    view_url: str
    download_url: str
    english_available: bool = False
    english_view_url: str | None = None
    english_download_url: str | None = None
    attachment_urls: dict[str, str] = {}


class FindingTraceView(ContractModel):
    display_id: str
    hypothesis_id: str | None = None
    title: str | None = None
    vulnerability_type: str | None = None
    source: str | None = None
    sink: str | None = None
    verdict: str | None = None
    validated_poc: bool = False
    artifact_ids: tuple[str, ...] = ()
    poc_artifact_ids: tuple[str, ...] = ()
    evidence_artifact_ids: tuple[str, ...] = ()
    report_view_url: str
    report_download_url: str
    english_available: bool = False


class AnalysisDetailView(AnalysisSummaryView):
    kpis: DashboardKpiView = Field(default_factory=DashboardKpiView)
    static_coverage_expected: int | None = None
    static_coverage_verified: int | None = None
    static_coverage_gap_count: int | None = None
    static_coverage_gap_preview: tuple[dict[str, str], ...] = ()
    static_coverage_unsupported: tuple[tuple[str, int], ...] = ()
    static_ast_parse_error_count: int | None = None
    static_ast_truncated: bool | None = None
    static_coverage_engines: dict[str, int] = Field(default_factory=dict)
    static_codeql_configured: bool | None = None
    static_codeql_executed: bool | None = None
    static_codeql_scope: str | None = None
    hypotheses: tuple[HypothesisProgressView, ...] = ()
    reports: tuple[FindingReportView, ...] = ()
    pipeline: tuple[StageProgressView, ...] = ()
    static_tools: tuple[StaticToolProgressView, ...] = ()
    static_tool_findings: tuple[StaticToolFindingView, ...] = ()
    readiness: tuple[ReadinessCheckView, ...] = ()
    usage: UsageSummaryView = UsageSummaryView()
    artifacts: tuple[ArtifactView, ...] = ()
    artifact_relations: tuple[ArtifactRelationView, ...] = ()
    finding_traces: tuple[FindingTraceView, ...] = ()
    llm_invocations: tuple[LLMInvocationView, ...] = ()
    poc_artifact_ids: tuple[str, ...] = ()
    evidence_artifact_ids: tuple[str, ...] = ()
    logs_url: str | None = None
    bundle_url: str | None = None
    presentation_bundle_url: str | None = None


__all__ = [
    "AgentActivityView",
    "ArtifactContentView",
    "ArtifactRelationView",
    "ArtifactView",
    "AnalysisDetailView",
    "AnalysisSummaryView",
    "DashboardKpiView",
    "FindingReportView",
    "FindingTraceView",
    "HypothesisProgressView",
    "LLMInvocationView",
    "ReadinessCheckView",
    "StageProgressView",
    "StatusCellPageView",
    "StatusCellView",
    "StaticToolProgressView",
    "StaticToolFindingView",
    "UsageSummaryView",
]
