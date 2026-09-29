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
    error_code: str | None = None
    static_disposition: str | None = None
    completed_count: int
    stage_count: int
    hypothesis_count: int
    finding_count: int
    candidate_total_count: int | None = None
    candidate_decision_counts: dict[str, int] = Field(default_factory=dict)
    deep_analysis_running_count: int = 0
    deep_analysis_completed_count: int = 0
    deep_analysis_pending_count: int = 0
    deep_analysis_error_count: int = 0
    resume_action: str | None = None
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
    updated_at: datetime | None = None


class StaticToolProgressView(ContractModel):
    tool: str
    status: str
    finding_count: int | None = None


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
    attachment_urls: dict[str, str] = {}


class AnalysisDetailView(AnalysisSummaryView):
    artifact_projection_complete: bool = True
    artifact_omitted_count: int = 0
    static_coverage_expected: int | None = None
    static_coverage_verified: int | None = None
    static_coverage_gap_count: int | None = None
    static_coverage_gap_preview: tuple[dict[str, str], ...] = ()
    static_unavailable_file_count: int | None = None
    static_unavailable_file_preview: tuple[dict[str, str], ...] = ()
    static_unavailable_reason_counts: dict[str, int] = Field(default_factory=dict)
    static_excluded_test_file_count: int | None = None
    static_excluded_test_file_preview: tuple[dict[str, str], ...] = ()
    static_excluded_test_reason_counts: dict[str, int] = Field(default_factory=dict)
    static_out_of_scope_product_count: int | None = None
    static_out_of_scope_product_preview: tuple[dict[str, str], ...] = ()
    static_out_of_scope_reason_counts: dict[str, int] = Field(default_factory=dict)
    static_coverage_unsupported: tuple[tuple[str, int], ...] = ()
    static_coverage_unsupported_count: int | None = None
    static_coverage_reason_counts: dict[str, int] = Field(default_factory=dict)
    static_coverage_digest: str | None = None
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
    artifacts: tuple[ArtifactView, ...] = ()
    llm_invocations: tuple[LLMInvocationView, ...] = ()
    poc_artifact_ids: tuple[str, ...] = ()
    evidence_artifact_ids: tuple[str, ...] = ()
    logs_url: str | None = None
    bundle_url: str | None = None


class StaticCoveragePageView(ContractModel):
    kind: str
    total: int
    offset: int
    limit: int
    coverage_digest: str
    items: tuple[dict[str, str], ...]


__all__ = [
    "AgentActivityView",
    "ArtifactContentView",
    "ArtifactView",
    "AnalysisDetailView",
    "AnalysisSummaryView",
    "FindingReportView",
    "HypothesisProgressView",
    "LLMInvocationView",
    "StageProgressView",
    "StaticToolProgressView",
]
