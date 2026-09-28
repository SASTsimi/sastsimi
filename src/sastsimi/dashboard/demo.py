"""Clearly synthetic, in-memory dashboard data for presentation rehearsal."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sastsimi.observability.agent_activity import ActivityKind

from .models import (
    AgentActivityView,
    AnalysisDetailView,
    AnalysisSummaryView,
    DashboardKpiView,
    HypothesisProgressView,
    StageProgressView,
    StaticToolProgressView,
    StatusCellPageView,
    StatusCellView,
)
from .query import DashboardBadRequest, DashboardNotFound, DashboardQuery

_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
_ANALYSIS_ID = "demo-analysis"
_DISPLAY_ID = "DEMO-001"
_HYPOTHESIS_IDS = tuple(f"demo-hypothesis-{index}" for index in range(1, 5))
_STATUSES = ("COMPLETE", "COMPLETE", "RUNNING", "PENDING")


class DemoDashboardQuery(DashboardQuery):
    """Implement only the read routes used by the dashboard; never open a database."""

    def __init__(self) -> None:
        # Deliberately do not call DashboardQuery.__init__: no production paths
        # or connections are needed by the four overridden read methods.
        self._detail = AnalysisDetailView(
            analysis_id=_ANALYSIS_ID,
            display_analysis_id=_DISPLAY_ID,
            repository="https://example.invalid/sastsimi-demo",
            commit_id="synthetic-demo-data",
            current_stage="VERIFICATION_INITIAL",
            status="RUNNING",
            completed_count=3,
            stage_count=4,
            hypothesis_count=4,
            finding_count=0,
            progress_percent=75,
            static_coverage_expected=24,
            static_coverage_verified=24,
            static_coverage_gap_count=0,
            static_coverage_engines={"AST": 8, "OpenGrep": 12, "CodeQL": 4},
            kpis=DashboardKpiView(
                discovery_done=24,
                discovery_total=24,
                verification_done=2,
                verification_total=4,
                remaining_work=2,
                confirmed_findings=0,
            ),
            hypotheses=tuple(
                HypothesisProgressView(
                    analysis_id=_ANALYSIS_ID,
                    hypothesis_id=hypothesis_id,
                    current_stage="VERIFICATION_INITIAL",
                    status=status,
                    completed_count=2 if status == "COMPLETE" else 1,
                    stage_count=3,
                    title=f"시연용 가설 {index}",
                    summary="실제 저장소나 취약점에 관한 판정이 아닌 예시입니다.",
                )
                for index, (hypothesis_id, status) in enumerate(
                    zip(_HYPOTHESIS_IDS, _STATUSES, strict=True), 1
                )
            ),
            pipeline=(
                StageProgressView(
                    stage="STATIC_DONE",
                    label_ko="정적 검사 (시연 데이터)",
                    status="SUCCEEDED",
                    agent_role="static",
                    output_count=24,
                    updated_at=_TIME,
                ),
                StageProgressView(
                    stage="VERIFICATION_INITIAL",
                    label_ko="가설 검토 (시연 데이터)",
                    status="RUNNING",
                    agent_role="verification",
                    output_count=2,
                    updated_at=_TIME + timedelta(minutes=1),
                ),
            ),
            static_tools=(
                StaticToolProgressView(tool="AST", status="SUCCEEDED", finding_count=8),
                StaticToolProgressView(
                    tool="OpenGrep", status="SUCCEEDED", finding_count=12
                ),
                StaticToolProgressView(
                    tool="CodeQL", status="SUCCEEDED", finding_count=4
                ),
            ),
        )
        self._events = tuple(
            AgentActivityView(
                event_id=f"demo-event-{index}",
                analysis_id=_ANALYSIS_ID,
                hypothesis_id=None,
                stage=stage,
                agent_role=role,
                attempt_id=f"demo-attempt-{index}",
                sequence=index,
                kind=(
                    ActivityKind.STAGE_COMPLETED
                    if index < 3
                    else ActivityKind.STAGE_STARTED
                ),
                status="SUCCEEDED" if index < 3 else "RUNNING",
                summary_ko=summary,
                substage=substage,
                metrics=metrics,
                started_at=_TIME + timedelta(seconds=index * 20),
                elapsed_ms=1200,
            )
            for index, stage, role, summary, substage, metrics in (
                (
                    1,
                    "STATIC_DONE",
                    "static",
                    "시연용 AST 조사 완료",
                    "ast",
                    {"processed": 8, "artifacts": 1},
                ),
                (
                    2,
                    "STATIC_DONE",
                    "static",
                    "시연용 규칙 검사 완료",
                    "opengrep",
                    {"verified": 12, "candidates": 3},
                ),
                (
                    3,
                    "VERIFICATION_INITIAL",
                    "verification",
                    "시연용 가설 검토 시작",
                    "hypotheses",
                    {"processed": 2, "remaining": 2},
                ),
            )
        )

    def list_analyses(self) -> tuple[AnalysisSummaryView, ...]:
        detail = self._detail.model_dump()
        summary = {name: detail[name] for name in AnalysisSummaryView.model_fields}
        return (AnalysisSummaryView.model_validate(summary),)

    def get_analysis(self, analysis_id: str) -> AnalysisDetailView:
        self._ensure_demo_id(analysis_id)
        return self._detail

    def list_status_cells(
        self, analysis_id: str, *, offset: int = 0, limit: int = 100
    ) -> StatusCellPageView:
        self._ensure_demo_id(analysis_id)
        if (
            type(offset) is not int
            or type(limit) is not int
            or offset < 0
            or not 1 <= limit <= 200
        ):
            raise DashboardBadRequest("DASHBOARD_PAGE_INVALID")
        items = tuple(
            StatusCellView(
                id=hypothesis_id,
                kind="hypothesis",
                status=_STATUSES[index],
                label_ko=f"시연용 가설 {index + 1}",
                detail_url=f"/analyses/{_DISPLAY_ID}#hypothesis-{hypothesis_id}",
            )
            for index, hypothesis_id in enumerate(_HYPOTHESIS_IDS)
        )
        return StatusCellPageView(
            items=items[offset : offset + limit],
            total=len(items),
            offset=offset,
            limit=limit,
        )

    def list_events(
        self, analysis_id: str, *, after_event_id: str | None = None
    ) -> tuple[AgentActivityView, ...]:
        self._ensure_demo_id(analysis_id)
        if after_event_id is None:
            return self._events
        for index, event in enumerate(self._events):
            if event.event_id == after_event_id:
                return self._events[index + 1 :]
        raise DashboardBadRequest("DASHBOARD_EVENT_CURSOR_INVALID")

    @staticmethod
    def _ensure_demo_id(analysis_id: str) -> None:
        if analysis_id not in {_ANALYSIS_ID, _DISPLAY_ID}:
            raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND")


__all__ = ["DemoDashboardQuery"]
