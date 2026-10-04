"""Read-only SQLite and report projection for the local dashboard."""

from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast, overload
from urllib.parse import quote

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import AgentActivityEvent
from sastsimi.progress.projector import ProgressProjector
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.bundle_files import (
    MAX_BUNDLE_FILE_BYTES,
    ReportBundleManifest,
    read_bundle_file,
)
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.gate_guard import technical_gate_accepted
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    terminal_gate_outcome,
    terminal_poc_outcome,
)
from sastsimi.simple_runtime.scope_policy import (
    project_scope_review,
    safe_public_report,
)
from sastsimi.simple_runtime.store import ROLE_BY_STAGE, SimpleCheckpointStore

from .markdown_view import preview_markdown
from .models import (
    AgentActivityView,
    AnalysisDetailView,
    AnalysisSummaryView,
    ArtifactContentView,
    ArtifactRelationView,
    ArtifactView,
    DashboardKpiView,
    DashboardShellView,
    FindingReportView,
    FindingTraceView,
    HypothesisProgressView,
    LLMInvocationDetailView,
    LLMInvocationView,
    ReadinessCheckView,
    StageProgressView,
    StaticToolFindingView,
    StaticToolProgressView,
    StatusCellPageView,
    StatusCellView,
    UsageSummaryView,
)

_ANALYSIS_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_DISPLAY_ID = re.compile(r"F-[0-9]{3,}\Z")
_RULE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ARTIFACT_BYTES = 1024 * 1024
_MAX_ARTIFACTS = 512
_INCOMPLETE_ARTIFACT_PREVIEW = 32
_MAX_PROJECTED_ARTIFACT_BYTES = 64 * 1024 * 1024
_STALE_SECONDS = 30
_STAGE_LABELS: dict[SimpleStage, str] = {
    SimpleStage.STATIC_DONE: "저장소 준비·정적 분석",
    SimpleStage.HYPOTHESIS_DONE: "취약점 가설 생성",
    SimpleStage.PRO_CON_DONE: "찬성·반대 근거 수집",
    SimpleStage.VERIFICATION_INITIAL_DONE: "초기 검증 판정",
    SimpleStage.POC_CANDIDATE_DONE: "PoC 후보 생성",
    SimpleStage.POC_EXECUTION_DONE: "PoC 격리 실행",
    SimpleStage.VERIFICATION_FINAL_DONE: "최종 검증 판정",
    SimpleStage.CWE_DONE: "CWE 분류",
    SimpleStage.TECH_GATE_DONE: "기술 근거 Gate",
    SimpleStage.SCOPE_GATE_DONE: "분석 범위 Gate",
    SimpleStage.PRIMITIVE_ADMISSION_DONE: "Primitive 승인",
    SimpleStage.CHAINING_DONE: "연계 취약점 탐색",
    SimpleStage.FINDING_DONE: "Finding 확정",
    SimpleStage.REPORT_DONE: "보고서 생성",
}


class DashboardNotFound(LookupError):
    pass


class DashboardBadRequest(ValueError):
    pass


class DashboardIncomplete(RuntimeError):
    """A download would silently omit verified results."""


class _CheckpointProjection:
    def __init__(self, checkpoints: tuple[StageCheckpoint, ...]) -> None:
        self._checkpoints = checkpoints

    def list_checkpoints(self, analysis_id: str) -> tuple[StageCheckpoint, ...]:
        return tuple(
            item
            for item in self._checkpoints
            if item.identity.analysis_id == analysis_id
        )


class DashboardQuery:
    def __init__(self, data_dir: str | Path) -> None:
        self._data_dir = Path(data_dir).resolve()
        self._database = RuntimePaths(self._data_dir).database.resolve()

    def _connect(self) -> sqlite3.Connection:
        if not self._database.is_file():
            raise DashboardNotFound("DASHBOARD_DATABASE_NOT_FOUND")
        connection = sqlite3.connect(
            f"file:{self._database.as_posix()}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _table_exists(connection: sqlite3.Connection, name: str) -> bool:
        return (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (name,),
            ).fetchone()
            is not None
        )

    def _checkpoints(
        self, analysis_id: str | None = None
    ) -> tuple[StageCheckpoint, ...]:
        with self._connect() as connection:
            if not self._table_exists(connection, "simple_runtime_checkpoints"):
                return ()
            if analysis_id is None:
                rows = connection.execute(
                    "SELECT checkpoint_json FROM simple_runtime_checkpoints"
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT checkpoint_json FROM simple_runtime_checkpoints
                    WHERE analysis_id = ?
                    """,
                    (analysis_id,),
                ).fetchall()
        return tuple(StageCheckpoint.model_validate_json(row[0]) for row in rows)

    def list_analyses(self) -> tuple[AnalysisSummaryView, ...]:
        checkpoints = self._checkpoints()
        by_analysis: dict[str, list[StageCheckpoint]] = defaultdict(list)
        for checkpoint in checkpoints:
            by_analysis[checkpoint.identity.analysis_id].append(checkpoint)
        summaries = [
            self._project_analysis(analysis_id, values)
            for analysis_id, values in by_analysis.items()
        ]
        known = set(by_analysis)
        for summary in self._full_runtime_summaries():
            if summary.analysis_id not in known:
                summaries.append(summary)
        return tuple(sorted(summaries, key=lambda item: item.analysis_id))

    def get_analysis(self, analysis_id: str) -> AnalysisDetailView:
        try:
            analysis_id = self._resolve_analysis_id(analysis_id)
        except (LookupError, OSError, sqlite3.Error, ValueError) as error:
            raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND") from error
        self._validate_analysis_id(analysis_id)
        values = self._checkpoints(analysis_id)
        if not values:
            summary = next(
                (
                    item
                    for item in self._full_runtime_summaries()
                    if item.analysis_id == analysis_id
                ),
                None,
            )
            if summary is None:
                raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND")
            return AnalysisDetailView(**summary.model_dump())
        return self._project_analysis(analysis_id, list(values), detail=True)

    def get_analysis_shell(self, analysis_id: str) -> DashboardShellView:
        """Return only data needed outside the selected tab."""
        exact = self._resolved(analysis_id)
        values = list(self._checkpoints(exact))
        if not values:
            summary = next(
                (
                    item
                    for item in self._full_runtime_summaries()
                    if item.analysis_id == exact
                ),
                None,
            )
            if summary is None:
                raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND")
            return DashboardShellView(**summary.model_dump())
        summary = self._project_analysis(exact, values)
        run = self._simple_run(exact)
        groups = self._hypothesis_groups(values)
        known_ids = set(run.hypothesis_ids) if run is not None else set()
        total = len(known_ids | set(groups)) if run is not None or groups else None
        verified = sum(self._final_verdict_saved(items) for items in groups.values())
        validated = sum(self._validated_poc(items) for items in groups.values())
        confirmed = sum(self._confirmed_hypothesis(items) for items in groups.values())
        coverage = self._static_coverage_projection(values)
        return DashboardShellView.model_validate(
            {
                **summary.model_dump(),
                "kpis": DashboardKpiView(
                    discovery_done=cast(
                        int | None, coverage.get("static_coverage_verified")
                    ),
                    discovery_total=cast(
                        int | None, coverage.get("static_coverage_expected")
                    ),
                    verification_done=verified if total is not None else None,
                    verification_total=total,
                    remaining_work=(
                        max(0, total - verified) if total is not None else None
                    ),
                    confirmed_findings=confirmed,
                ),
                "validated_poc_count": validated if total is not None else None,
                "llm_token_usage_known": self._known_token_usage(exact),
                "logs_url": f"/api/analyses/{exact}/logs/download",
                "bundle_url": f"/api/analyses/{exact}/bundle.zip",
                "presentation_bundle_url": f"/api/analyses/{exact}/presentation.zip",
            }
        )

    def get_analysis_tab(
        self,
        analysis_id: str,
        tab: str,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, object]:
        """Build only the selected tab's projection."""
        if tab not in {
            "overview",
            "progress",
            "findings",
            "coverage",
            "artifacts",
            "llm",
            "outputs",
            "logs",
        }:
            raise DashboardNotFound("DASHBOARD_TAB_NOT_FOUND")
        if (
            type(offset) is not int
            or type(limit) is not int
            or offset < 0
            or not 1 <= limit <= 200
        ):
            raise DashboardBadRequest("DASHBOARD_PAGE_INVALID")
        exact = self._resolved(analysis_id)
        values = list(self._checkpoints(exact))
        run = self._simple_run(exact)
        if not values and run is None:
            raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND")
        if not values:
            return {
                "tab": tab,
                "items": [],
                "total": 0,
                "offset": offset,
                "limit": limit,
            }

        groups = self._hypothesis_groups(values)
        hypotheses = tuple(
            self._project_hypothesis(exact, hypothesis_id, checkpoints, run)
            for hypothesis_id, checkpoints in sorted(groups.items())
        )
        reports = self._reports(exact)
        coverage = self._static_coverage_projection(values)

        if tab == "overview":
            static_tools = self._static_tools(run, values, coverage) if run else ()
            artifact_count = len(
                {
                    ref.content_hash
                    for checkpoint in values
                    for ref in (*checkpoint.input_refs, *checkpoint.output_refs)
                    if ref.data_kind == "artifact"
                }
            )
            return {
                "tab": tab,
                "readiness": [
                    item.model_dump(mode="json")
                    for item in self._readiness(
                        exact, run, static_tools, artifact_count, reports
                    )
                ],
            }
        if tab == "progress":
            events = self._event_models(exact)
            return {
                "tab": tab,
                "pipeline": [
                    item.model_dump(mode="json") for item in self._pipeline(values, run)
                ],
                "history": [
                    self._activity_view(item).model_dump(mode="json")
                    for item in events[-12:]
                ],
            }
        if tab == "logs":
            return {"tab": tab, "logs_url": f"/api/analyses/{exact}/logs/download"}

        artifacts: tuple[ArtifactView, ...] = ()
        contents: dict[str, tuple[str, str, bytes, Any | None]] = {}
        invocations: tuple[LLMInvocationView, ...] = ()
        poc_ids: tuple[str, ...] = ()
        evidence_ids: tuple[str, ...] = ()
        omitted = 0
        if run is not None:
            artifacts, contents, invocations, poc_ids, evidence_ids, omitted = (
                self._artifact_projection(exact, values, run)
            )
            hypotheses = self._with_hypothesis_metadata(hypotheses, contents)
        traces = self._finding_traces(
            exact, reports, hypotheses, artifacts, contents, poc_ids, evidence_ids
        )

        if tab == "findings":
            finding_page = hypotheses[offset : offset + limit]
            return {
                "tab": tab,
                "items": [item.model_dump(mode="json") for item in finding_page],
                "total": len(hypotheses),
                "offset": offset,
                "limit": limit,
                "finding_traces": [item.model_dump(mode="json") for item in traces],
            }
        if tab == "coverage":
            static_tools = self._static_tools(run, values, coverage) if run else ()
            return {
                "tab": tab,
                **coverage,
                "static_tools": [item.model_dump(mode="json") for item in static_tools],
                "static_tool_findings": [
                    item.model_dump(mode="json")
                    for item in self._static_tool_findings(contents)
                ],
            }
        if tab == "artifacts":
            artifact_page = artifacts[offset : offset + limit]
            return {
                "tab": tab,
                "items": [item.model_dump(mode="json") for item in artifact_page],
                "total": len(artifacts),
                "offset": offset,
                "limit": limit,
                "omitted_count": omitted,
                "projection_complete": omitted == 0,
                "relations": [
                    item.model_dump(mode="json")
                    for item in self._artifact_relations(contents)
                ],
            }
        if tab == "llm":
            by_hypothesis: dict[str, tuple[str, ...]] = {
                item.hypothesis_id: (item.display_id,)
                for item in traces
                if item.hypothesis_id is not None
            }
            enriched = tuple(
                item.model_copy(
                    update={
                        "finding_ids": by_hypothesis.get(item.hypothesis_id or "", ())
                    }
                )
                for item in invocations
            )
            invocation_page = enriched[offset : offset + limit]
            return {
                "tab": tab,
                "items": [item.model_dump(mode="json") for item in invocation_page],
                "total": len(enriched),
                "offset": offset,
                "limit": limit,
            }
        output_artifact_ids = set(poc_ids) | set(evidence_ids)
        output_artifacts = tuple(
            item for item in artifacts if item.artifact_id in output_artifact_ids
        )
        return {
            "tab": tab,
            "reports": [item.model_dump(mode="json") for item in reports],
            "finding_traces": [item.model_dump(mode="json") for item in traces],
            "artifacts": [item.model_dump(mode="json") for item in output_artifacts],
            "poc_artifact_ids": list(poc_ids),
            "evidence_artifact_ids": list(evidence_ids),
        }

    def get_llm_invocation(
        self, analysis_id: str, invocation_id: str
    ) -> LLMInvocationDetailView:
        exact = self._resolved(analysis_id)
        values = list(self._checkpoints(exact))
        run = self._simple_run(exact)
        if run is None or not values:
            raise DashboardNotFound("DASHBOARD_INVOCATION_NOT_FOUND")
        artifacts, contents, invocations, poc_ids, evidence_ids, _ = (
            self._artifact_projection(exact, values, run)
        )
        invocation = next(
            (item for item in invocations if item.invocation_id == invocation_id), None
        )
        if invocation is None:
            raise DashboardNotFound("DASHBOARD_INVOCATION_NOT_FOUND")
        hypotheses = tuple(
            self._project_hypothesis(exact, hypothesis_id, checkpoints, run)
            for hypothesis_id, checkpoints in sorted(
                self._hypothesis_groups(values).items()
            )
        )
        reports = self._reports(exact)
        traces = self._finding_traces(
            exact,
            reports,
            self._with_hypothesis_metadata(hypotheses, contents),
            artifacts,
            contents,
            poc_ids,
            evidence_ids,
        )
        finding_ids = tuple(
            trace.display_id
            for trace in traces
            if trace.hypothesis_id == invocation.hypothesis_id
        )
        invocation = invocation.model_copy(update={"finding_ids": finding_ids})

        request = self._invocation_payload(contents, invocation.request_artifact_id)
        response = self._invocation_payload(contents, invocation.response_artifact_id)
        system_prompt = self._prompt_text(request, "system_prompt", "system")
        user_prompt = self._prompt_text(request, "user_prompt", "prompt", "user")
        result = response.get("response") if isinstance(response, dict) else None
        return LLMInvocationDetailView(
            invocation=invocation,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_result=cast(Any, result),
            stored_request_json=cast(Any, request),
            stored_response_json=cast(Any, response),
        )

    def list_status_cells(
        self, analysis_id: str, *, offset: int = 0, limit: int = 100
    ) -> StatusCellPageView:
        if (
            type(offset) is not int
            or type(limit) is not int
            or offset < 0
            or not 1 <= limit <= 200
        ):
            raise DashboardBadRequest("DASHBOARD_PAGE_INVALID")
        try:
            exact = self._resolve_analysis_id(analysis_id)
        except (LookupError, OSError, sqlite3.Error, ValueError) as error:
            raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND") from error
        self._validate_analysis_id(exact)
        values = self._checkpoints(exact)
        run = self._simple_run(exact)
        if not values and run is None:
            raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND")
        groups: dict[str, list[StageCheckpoint]] = defaultdict(list)
        for checkpoint in values:
            hypothesis_id = checkpoint.identity.hypothesis_id
            if hypothesis_id is not None:
                groups[hypothesis_id].append(checkpoint)
        ids = sorted(set(groups) | set(run.hypothesis_ids if run else ()))
        items: list[StatusCellView] = []
        for ordinal, hypothesis_id in enumerate(
            ids[offset : offset + limit], offset + 1
        ):
            checkpoints = groups.get(hypothesis_id, [])
            if self._confirmed_hypothesis(checkpoints):
                status = "CONFIRMED"
            elif checkpoints:
                status = (
                    ProgressProjector(_CheckpointProjection(tuple(checkpoints)))
                    .snapshot(exact)
                    .status
                )
            else:
                status = "PENDING"
            items.append(
                StatusCellView(
                    id=hypothesis_id,
                    kind="hypothesis",
                    status=status,
                    label_ko=f"가설 {ordinal}",
                    detail_url=(
                        f"/analyses/{quote(exact, safe='')}"
                        f"#hypothesis-{quote(hypothesis_id, safe='')}"
                    ),
                )
            )
        return StatusCellPageView(
            items=tuple(items), total=len(ids), offset=offset, limit=limit
        )

    def list_events(
        self,
        analysis_id: str,
        *,
        after_event_id: str | None = None,
    ) -> tuple[AgentActivityView, ...]:
        try:
            analysis_id = self._resolve_analysis_id(analysis_id)
        except (LookupError, OSError, sqlite3.Error, ValueError) as error:
            raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND") from error
        self._validate_analysis_id(analysis_id)
        with self._connect() as connection:
            if not self._table_exists(connection, "agent_activity_events"):
                return ()
            if after_event_id is None:
                rows = connection.execute(
                    """
                    SELECT event_json FROM agent_activity_events
                    WHERE analysis_id = ? ORDER BY rowid
                    """,
                    (analysis_id,),
                ).fetchall()
            else:
                cursor = connection.execute(
                    """
                    SELECT rowid FROM agent_activity_events
                    WHERE analysis_id = ? AND event_id = ?
                    """,
                    (analysis_id, after_event_id),
                ).fetchone()
                if cursor is None:
                    raise DashboardNotFound("DASHBOARD_EVENT_CURSOR_NOT_FOUND")
                rows = connection.execute(
                    """
                    SELECT event_json FROM agent_activity_events
                    WHERE analysis_id = ? AND rowid > ? ORDER BY rowid
                    """,
                    (analysis_id, cursor[0]),
                ).fetchall()
        events = [AgentActivityEvent.model_validate_json(row[0]) for row in rows]
        return tuple(self._activity_view(event) for event in events)

    def list_event_page(
        self, analysis_id: str, *, offset: int = 0, limit: int = 50
    ) -> dict[str, object]:
        if (
            type(offset) is not int
            or type(limit) is not int
            or offset < 0
            or not 1 <= limit <= 200
        ):
            raise DashboardBadRequest("DASHBOARD_PAGE_INVALID")
        exact = self._resolved(analysis_id)
        with self._connect() as connection:
            if not self._table_exists(connection, "agent_activity_events"):
                return {"items": [], "total": 0, "offset": offset, "limit": limit}
            total_row = connection.execute(
                "SELECT COUNT(*) FROM agent_activity_events WHERE analysis_id = ?",
                (exact,),
            ).fetchone()
            total = int(total_row[0]) if total_row is not None else 0
            rows = connection.execute(
                """
                SELECT event_json FROM agent_activity_events
                WHERE analysis_id = ? ORDER BY rowid DESC LIMIT ? OFFSET ?
                """,
                (exact, limit, offset),
            ).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            try:
                event = AgentActivityEvent.model_validate_json(row[0])
            except ValueError:
                continue
            items.append(self._activity_view(event).model_dump(mode="json"))
        return {
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    @staticmethod
    def _activity_view(event: AgentActivityEvent) -> AgentActivityView:
        return AgentActivityView(
            event_id=event.event_id,
            analysis_id=event.analysis_id,
            hypothesis_id=event.hypothesis_id,
            stage=event.stage,
            agent_role=event.agent_role,
            attempt_id=event.attempt_id,
            sequence=event.sequence,
            kind=event.kind,
            status=event.status,
            summary_ko=event.summary_ko,
            tool_name=event.tool_name,
            error_code=event.error_code,
            started_at=event.started_at,
            finished_at=event.finished_at,
            elapsed_ms=event.elapsed_ms,
            provider=event.provider,
            model=event.model,
            prompt_digest=event.prompt_digest,
            output_digest=event.output_digest,
            substage=event.substage,
            metrics=event.metrics,
        )

    def artifact_content(
        self, analysis_id: str, artifact_id: str
    ) -> ArtifactContentView:
        if _DIGEST.fullmatch(artifact_id) is None:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_NOT_FOUND")
        exact = self._resolved(analysis_id)
        values = list(self._checkpoints(exact))
        run = self._simple_run(exact)
        if run is None or not values:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_NOT_FOUND")
        _, contents, _, _, _, _ = self._artifact_projection(exact, values, run)
        item = contents.get(artifact_id)
        if item is None:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_NOT_FOUND")
        kind, media_type, raw, parsed = item
        preview = (
            preview_markdown(raw.decode("utf-8", "replace"))
            if media_type in {"text/markdown", "text/plain"}
            else None
        )
        return ArtifactContentView(
            artifact_id=artifact_id,
            kind=kind,
            media_type=media_type,
            content=(
                parsed
                if parsed is not None
                else preview.markdown
                if preview is not None and media_type == "text/markdown"
                else raw.decode("utf-8", "replace")
            ),
            rendered_html=preview.rendered_html if preview is not None else None,
            truncated=preview.truncated if preview is not None else False,
            download_url=(
                f"/api/analyses/{quote(exact, safe='')}/artifacts/{artifact_id}"
                "?download=1"
            ),
        )

    def artifact_bytes(
        self, analysis_id: str, artifact_id: str
    ) -> tuple[str, str, bytes]:
        if _DIGEST.fullmatch(artifact_id) is None:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_NOT_FOUND")
        exact = self._resolved(analysis_id)
        values = list(self._checkpoints(exact))
        run = self._simple_run(exact)
        if run is None or not values:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_NOT_FOUND")
        _, contents, _, _, _, _ = self._artifact_projection(exact, values, run)
        item = contents.get(artifact_id)
        if item is None:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_NOT_FOUND")
        kind, media_type, raw, _ = item
        return kind, media_type, raw

    def report_markdown(
        self,
        analysis_id: str,
        display_id: str,
        *,
        language: Literal["ko", "en"] = "ko",
    ) -> str:
        exact = self._resolved(analysis_id)
        try:
            if language == "en":
                body, _ = self.report_attachment(exact, display_id, "report_en.md")
            else:
                body = self.report_content(exact, display_id)
            return body.decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error

    def logs_bytes(self, analysis_id: str) -> bytes:
        exact = self._resolved(analysis_id)
        path = (RuntimePaths(self._data_dir).logs / f"{exact}.log").resolve()
        expected = RuntimePaths(self._data_dir).logs.resolve()
        if path.parent == expected and path.is_file():
            try:
                raw = path.read_bytes()
                return redact_untrusted_text(raw).data
            except (OSError, ValueError):
                pass
        lines = [
            json.dumps(item.model_dump(mode="json"), ensure_ascii=False)
            for item in self.list_events(exact)
        ]
        return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")

    def bundle_members(
        self,
        analysis_id: str,
        *,
        artifact_ids: frozenset[str] | None = None,
        report_ids: frozenset[str] | None = None,
        include_logs: bool = True,
    ) -> dict[str, bytes]:
        exact = self._resolved(analysis_id)
        detail = self.get_analysis(exact)
        if artifact_ids is None and not detail.artifact_projection_complete:
            raise DashboardIncomplete("DASHBOARD_BUNDLE_INCOMPLETE")
        members: dict[str, bytes] = {
            "manifest.json": json.dumps(
                detail.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
            ).encode("utf-8"),
        }
        if include_logs:
            members["logs/console.log"] = self.logs_bytes(exact)
        known_artifacts = {item.artifact_id for item in detail.artifacts}
        known_reports = {item.display_id for item in detail.reports}
        if artifact_ids is not None and not artifact_ids <= known_artifacts:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_NOT_FOUND")
        if report_ids is not None and not report_ids <= known_reports:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
        values = list(self._checkpoints(exact))
        run = self._simple_run(exact)
        contents: dict[str, tuple[str, str, bytes, Any | None]] = {}
        if run is not None and values:
            _, contents, _, _, _, _ = self._artifact_projection(exact, values, run)
        for artifact in detail.artifacts:
            if artifact_ids is not None and artifact.artifact_id not in artifact_ids:
                continue
            item = contents.get(artifact.artifact_id)
            if item is None:
                continue
            kind, media_type, raw, _ = item
            suffix = ".json" if media_type == "application/json" else ".txt"
            safe_kind = re.sub(r"[^A-Za-z0-9_.-]", "-", kind)[:80] or "artifact"
            members[f"artifacts/{safe_kind}-{artifact.artifact_id[:12]}{suffix}"] = raw
        for report in detail.reports:
            if report_ids is not None and report.display_id not in report_ids:
                continue
            members[f"reports/{report.display_id}.md"] = self.report_markdown(
                exact, report.display_id
            ).encode("utf-8")
            try:
                manifest, _, artifacts = self._report_bundle(exact, report.display_id)
            except DashboardNotFound as error:
                finding_ref = FindingDisplayIdStore.resolve_existing(
                    self._database, exact, report.display_id
                )
                if any(
                    checkpoint.stage is SimpleStage.REPORT_DONE
                    and finding_ref in checkpoint.input_refs
                    and (
                        checkpoint.bundle_manifest_ref is not None
                        or checkpoint.bundle_archive_ref is not None
                    )
                    for checkpoint in values
                ):
                    raise DashboardIncomplete(
                        "DASHBOARD_REPORT_BUNDLE_UNAVAILABLE"
                    ) from error
                # Older reports have no verified attachment manifest. Never read
                # a loose English file or other unverified disk attachment.
                continue

            def read_verified(
                ref: StoredDataRef,
                repository: SimpleArtifactRepository = artifacts,
            ) -> bytes:
                return repository.read_bounded(ref, MAX_BUNDLE_FILE_BYTES)

            for entry in manifest.files:
                try:
                    body, _ = read_bundle_file(manifest, entry.path, read_verified)
                except (OSError, ValueError) as error:
                    raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error
                if entry.path == "report_kr.md":
                    members[f"reports/{report.display_id}.md"] = body
                elif entry.path == "report_en.md":
                    members[f"reports/en/{report.display_id}.md"] = body
                else:
                    members[f"reports/{report.display_id}/{entry.path}"] = body
        return members

    def presentation_bundle_members(self, analysis_id: str) -> dict[str, bytes]:
        exact = self._resolved(analysis_id)
        detail = self.get_analysis(exact)
        members = self.bundle_members(exact)
        english = [
            report.display_id for report in detail.reports if report.english_available
        ]
        steps = (
            "# SASTSIMI 발표 패키지\n\n"
            "1. manifest.json에서 저장소·commit·분석 상태를 확인합니다.\n"
            "2. logs/console.log에서 단계별 진행 상황을 보여 줍니다.\n"
            "3. artifacts/에서 정적분석·PoC·증거·LLM 안전 사본을 확인합니다.\n"
            "4. reports/에서 한국어 보고서와 준비된 영문 보고서를 엽니다.\n\n"
            f"영문 보고서 준비: {', '.join(english) if english else '없음'}\n"
        )
        members["presentation/README.md"] = steps.encode("utf-8")
        members["presentation/summary.json"] = json.dumps(
            {
                "analysis_id": detail.analysis_id,
                "display_analysis_id": detail.display_analysis_id,
                "repository": detail.repository,
                "commit_id": detail.commit_id,
                "status": detail.status,
                "progress_percent": detail.progress_percent,
                "finding_count": detail.finding_count,
                "english_report_ids": english,
                "usage": detail.usage.model_dump(mode="json"),
                "readiness": [
                    item.model_dump(mode="json") for item in detail.readiness
                ],
            },
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        return members

    def _resolved(self, value: str) -> str:
        try:
            exact = self._resolve_analysis_id(value)
            self._validate_analysis_id(exact)
            return exact
        except (LookupError, OSError, sqlite3.Error, ValueError) as error:
            raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND") from error

    def _event_models(self, analysis_id: str) -> tuple[AgentActivityEvent, ...]:
        with self._connect() as connection:
            if not self._table_exists(connection, "agent_activity_events"):
                return ()
            rows = connection.execute(
                """
                SELECT event_json FROM agent_activity_events
                WHERE analysis_id = ? ORDER BY started_at, rowid
                """,
                (analysis_id,),
            ).fetchall()
        events: list[AgentActivityEvent] = []
        for row in rows:
            try:
                events.append(AgentActivityEvent.model_validate_json(row[0]))
            except ValueError:
                continue
        return tuple(events)

    @staticmethod
    def _nested_refs(value: object) -> tuple[StoredDataRef, ...]:
        refs: list[StoredDataRef] = []

        def visit(item: object) -> None:
            if isinstance(item, dict):
                try:
                    refs.append(StoredDataRef.model_validate(item))
                    return
                except ValueError:
                    for child in item.values():
                        visit(child)
            elif isinstance(item, list):
                for child in item:
                    visit(child)

        visit(value)
        return tuple(refs)

    def _safe_ref_bytes(
        self,
        repository: SimpleArtifactRepository,
        ref: StoredDataRef,
    ) -> tuple[str, bytes, Any | None, tuple[int | None, int | None] | None]:
        try:
            raw = (
                repository.read_bounded(ref, _MAX_ARTIFACT_BYTES)
                if ref.record_id is None
                else repository.read(ref)
            )
        except (OSError, sqlite3.Error, ValueError) as error:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_NOT_FOUND") from error
        if len(raw) > _MAX_ARTIFACT_BYTES:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_TOO_LARGE")
        try:
            original = json.loads(raw)
            token_usage: tuple[int | None, int | None] | None = None
            if (
                isinstance(original, dict)
                and original.get("kind") == "simple_llm_response"
                and isinstance(original.get("usage"), dict)
            ):
                usage = original["usage"]

                def token_count(key: str) -> int | None:
                    value = usage.get(key)
                    return (
                        value
                        if isinstance(value, int)
                        and not isinstance(value, bool)
                        and value >= 0
                        else None
                    )

                token_usage = (
                    token_count("input_tokens"),
                    token_count("output_tokens"),
                )
            safe = redact_projected_json(raw).data
            return "application/json", safe, json.loads(safe), token_usage
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            try:
                safe = redact_untrusted_text(raw).data
            except ValueError:
                safe = b"[CONTENT_REDACTED]"
            media = "text/markdown" if safe.lstrip().startswith(b"#") else "text/plain"
            return media, safe, None, None

    def _artifact_projection(
        self,
        analysis_id: str,
        values: list[StageCheckpoint],
        run: SimpleAnalysisRun,
    ) -> tuple[
        tuple[ArtifactView, ...],
        dict[str, tuple[str, str, bytes, Any | None]],
        tuple[LLMInvocationView, ...],
        tuple[str, ...],
        tuple[str, ...],
        int,
    ]:
        identity = CheckpointIdentity(
            analysis_id=analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        repository = SimpleArtifactRepository(self._data_dir, identity)
        sources: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: {"stages": set(), "hypotheses": set()}
        )
        agents: dict[str, set[str]] = defaultdict(set)
        created_at: dict[str, datetime] = {}
        refs: dict[str, StoredDataRef] = {}
        expected_artifacts: set[str] = set()
        queue: list[tuple[StoredDataRef, str, str | None]] = []
        projection_limit = _MAX_ARTIFACTS

        def enqueue(
            ref: StoredDataRef | None,
            stage: str,
            hypothesis: str | None,
            agent_role: str | None = None,
            timestamp: datetime | None = None,
        ) -> None:
            if ref is None:
                return
            if (
                str(ref.workspace_id) != run.workspace_id
                or str(ref.commit_id) != run.commit_id
            ):
                return
            digest = ref.content_hash
            if ref.data_kind == "artifact":
                expected_artifacts.add(digest)
            sources[digest]["stages"].add(stage)
            if hypothesis:
                sources[digest]["hypotheses"].add(hypothesis)
            if agent_role:
                agents[digest].add(agent_role)
            if timestamp is not None and (
                digest not in created_at or timestamp < created_at[digest]
            ):
                created_at[digest] = timestamp
            if digest not in refs and len(refs) < projection_limit:
                refs[digest] = ref
                queue.append((ref, stage, hypothesis))

        enqueue(
            run.repository_profile_ref, "REPOSITORY", None, "Runtime", run.started_at
        )
        enqueue(
            run.static_bundle_ref,
            SimpleStage.STATIC_DONE.value,
            None,
            "Static Analysis",
            run.started_at,
        )
        for checkpoint in values:
            stage = checkpoint.stage.value
            hypothesis = checkpoint.identity.hypothesis_id
            for ref in (*checkpoint.input_refs, *checkpoint.output_refs):
                enqueue(
                    ref,
                    stage,
                    hypothesis,
                    ROLE_BY_STAGE.get(checkpoint.stage),
                    checkpoint.updated_at,
                )
            for optional_ref in (
                checkpoint.recipe_ref,
                checkpoint.validated_poc_ref,
                checkpoint.report_ref,
            ):
                enqueue(
                    optional_ref,
                    stage,
                    hypothesis,
                    ROLE_BY_STAGE.get(checkpoint.stage),
                    checkpoint.updated_at,
                )
        events = self._event_models(analysis_id)
        for event in events:
            for ref in (*event.input_refs, *event.output_refs, *event.tool_result_refs):
                enqueue(
                    ref,
                    event.stage,
                    event.hypothesis_id,
                    event.agent_role,
                    event.started_at,
                )

        # Once the safety limit is exceeded, a small representative preview is
        # enough to explain the omission and support selected downloads. Reading
        # hundreds of files here would delay every legacy detail request even
        # though the complete export is deliberately blocked below.
        if len(expected_artifacts) > _MAX_ARTIFACTS:
            projection_limit = _INCOMPLETE_ARTIFACT_PREVIEW
            preview_digests = set(tuple(refs)[:projection_limit])
            refs = {
                digest: ref for digest, ref in refs.items() if digest in preview_digests
            }
            queue = [item for item in queue if item[0].content_hash in preview_digests]

        contents: dict[str, tuple[str, str, bytes, Any | None]] = {}
        token_usage: dict[str, tuple[int | None, int | None]] = {}
        projected_bytes = 0
        index = 0
        while index < len(queue) and len(contents) < projection_limit:
            ref, stage, hypothesis = queue[index]
            index += 1
            if ref.content_hash in contents:
                continue
            try:
                media_type, raw, parsed, usage = self._safe_ref_bytes(repository, ref)
            except DashboardNotFound:
                continue
            if usage is not None:
                token_usage[ref.content_hash] = usage
            if projected_bytes + len(raw) > _MAX_PROJECTED_ARTIFACT_BYTES:
                continue
            kind = ref.data_kind
            if isinstance(parsed, dict):
                kind = str(
                    parsed.get("kind")
                    or (parsed.get("meta") or {}).get("record_type")
                    or kind
                )
                for nested in self._nested_refs(parsed):
                    enqueue(nested, stage, hypothesis)
            contents[ref.content_hash] = (kind, media_type, raw, parsed)
            projected_bytes += len(raw)

        markdown_digests = {
            checkpoint.output_refs[1].content_hash
            for checkpoint in values
            if checkpoint.stage is SimpleStage.REPORT_DONE
            and checkpoint.status is StageStatus.SUCCEEDED
            and len(checkpoint.output_refs) >= 2
        }
        for _, _, _, parsed in contents.values():
            if (
                not isinstance(parsed, dict)
                or parsed.get("kind") != "simple_policy_snapshot"
            ):
                continue
            try:
                body_ref = StoredDataRef.model_validate(parsed["body_ref"])
            except (KeyError, TypeError, ValueError):
                continue
            markdown_digests.add(body_ref.content_hash)
        for digest in markdown_digests & contents.keys():
            kind, media_type, raw, parsed = contents[digest]
            if media_type == "text/plain":
                contents[digest] = (kind, "text/markdown", raw, parsed)

        artifacts = tuple(
            ArtifactView(
                artifact_id=digest,
                kind=item[0],
                data_kind=refs[digest].data_kind,
                media_type=item[1],
                size_bytes=len(item[2]),
                stages=tuple(sorted(sources[digest]["stages"])),
                hypothesis_ids=tuple(sorted(sources[digest]["hypotheses"])),
                label_ko=self._artifact_label(item[0]),
                purpose_ko=self._artifact_purpose(item[0]),
                agent_roles=tuple(sorted(agents[digest])),
                created_at=created_at.get(digest),
                view_url=f"/api/analyses/{analysis_id}/artifacts/{digest}",
                download_url=(
                    f"/api/analyses/{analysis_id}/artifacts/{digest}?download=1"
                ),
            )
            for digest, item in sorted(
                contents.items(), key=lambda pair: (pair[1][0], pair[0])
            )
        )
        invocations = self._llm_invocations(
            events, contents, sources, values, token_usage
        )
        poc_ids = tuple(
            item.artifact_id
            for item in artifacts
            if item.kind.startswith("simple_poc")
            or item.kind in {"simple_validated_poc", "simple_dynamic_interpretation"}
        )
        evidence_ids = tuple(
            item.artifact_id
            for item in artifacts
            if "evidence" in item.kind
            or item.kind
            in {
                "simple_static_fact_bundle",
                "simple_poc_execution",
                "simple_dynamic_interpretation",
            }
        )
        return (
            artifacts,
            contents,
            invocations,
            poc_ids,
            evidence_ids,
            len(expected_artifacts.difference(contents)),
        )

    @staticmethod
    def _llm_invocations(
        events: tuple[AgentActivityEvent, ...],
        contents: dict[str, tuple[str, str, bytes, Any | None]],
        sources: dict[str, dict[str, set[str]]],
        checkpoints: list[StageCheckpoint],
        token_usage: dict[str, tuple[int | None, int | None]],
    ) -> tuple[LLMInvocationView, ...]:
        result: list[LLMInvocationView] = []
        seen: set[str] = set()

        def attempt(stage: str, hypothesis_id: str | None) -> int:
            return next(
                (
                    item.attempt_number
                    for item in checkpoints
                    if item.stage.value == stage
                    and item.identity.hypothesis_id == hypothesis_id
                ),
                0,
            )

        for event in events:
            if event.provider is None:
                continue
            request: dict[str, Any] | None = None
            response: dict[str, Any] | None = None
            request_id: str | None = None
            response_id: str | None = None
            for ref in event.tool_result_refs:
                item = contents.get(ref.content_hash)
                if item is None or not isinstance(item[3], dict):
                    continue
                payload = item[3]
                if payload.get("kind") == "simple_llm_request":
                    request = payload
                    request_id = ref.content_hash
                elif payload.get("kind") == "simple_llm_response":
                    response = payload
                    response_id = ref.content_hash
            invocation_id = str(
                (request or {}).get("invocation_id")
                or (response or {}).get("invocation_id")
                or event.event_id
            )
            if invocation_id in seen:
                continue
            seen.add(invocation_id)
            input_tokens, output_tokens = token_usage.get(
                response_id or "", (None, None)
            )
            result.append(
                LLMInvocationView(
                    invocation_id=invocation_id,
                    agent_role=event.agent_role,
                    provider=event.provider,
                    model=event.model or "미확인",
                    template_revision=(request or {}).get("template_revision"),
                    stage=event.stage,
                    hypothesis_id=event.hypothesis_id,
                    status=event.status,
                    prompt_digest=event.prompt_digest,
                    output_digest=event.output_digest,
                    started_at=event.started_at,
                    finished_at=event.finished_at,
                    elapsed_ms=event.elapsed_ms,
                    input_tokens=(
                        input_tokens if isinstance(input_tokens, int) else None
                    ),
                    output_tokens=(
                        output_tokens if isinstance(output_tokens, int) else None
                    ),
                    attempt_number=attempt(event.stage, event.hypothesis_id),
                    retry_count=max(
                        0,
                        attempt(event.stage, event.hypothesis_id) - 1,
                    ),
                    request_artifact_id=request_id,
                    response_artifact_id=response_id,
                )
            )
        artifacts_by_invocation: dict[str, dict[str, tuple[str, dict[str, Any]]]] = (
            defaultdict(dict)
        )
        for artifact_id, item in contents.items():
            artifact_payload = item[3]
            if not isinstance(artifact_payload, dict):
                continue
            kind = artifact_payload.get("kind")
            artifact_invocation_id = artifact_payload.get("invocation_id")
            if kind not in {
                "simple_llm_request",
                "simple_llm_response",
            } or not isinstance(artifact_invocation_id, str):
                continue
            artifacts_by_invocation[artifact_invocation_id][str(kind)] = (
                artifact_id,
                artifact_payload,
            )
        for invocation_id, artifacts in sorted(artifacts_by_invocation.items()):
            if invocation_id in seen:
                continue
            request_entry = artifacts.get("simple_llm_request")
            response_entry = artifacts.get("simple_llm_response")
            representative = request_entry or response_entry
            if representative is None:
                continue
            artifact_id, payload = representative
            source = sources.get(artifact_id, {"stages": set(), "hypotheses": set()})
            stage = next(iter(sorted(source["stages"])), "UNKNOWN")
            hypothesis_id = next(iter(sorted(source["hypotheses"])), None)
            try:
                role = ROLE_BY_STAGE[SimpleStage(stage)]
            except (KeyError, ValueError):
                role = "LLM Agent"
            input_tokens, output_tokens = token_usage.get(
                response_entry[0] if response_entry else "", (None, None)
            )
            result.append(
                LLMInvocationView(
                    invocation_id=invocation_id,
                    agent_role=role,
                    provider=str(payload.get("provider") or "미확인"),
                    model=str(payload.get("model") or "미확인"),
                    template_revision=(
                        str(payload["template_revision"])
                        if isinstance(payload.get("template_revision"), str)
                        else None
                    ),
                    stage=stage,
                    hypothesis_id=hypothesis_id,
                    status="SUCCEEDED" if response_entry else "REQUEST_ONLY",
                    input_tokens=(
                        input_tokens if isinstance(input_tokens, int) else None
                    ),
                    output_tokens=(
                        output_tokens if isinstance(output_tokens, int) else None
                    ),
                    attempt_number=attempt(stage, hypothesis_id),
                    retry_count=max(0, attempt(stage, hypothesis_id) - 1),
                    request_artifact_id=(request_entry[0] if request_entry else None),
                    response_artifact_id=(
                        response_entry[0] if response_entry else None
                    ),
                )
            )
        return tuple(result)

    def report_path(
        self,
        analysis_id: str,
        display_id: str,
        *,
        language: Literal["ko", "en"] = "ko",
    ) -> Path:
        self._validate_analysis_id(analysis_id)
        if _DISPLAY_ID.fullmatch(display_id) is None:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
        try:
            finding_ref = FindingDisplayIdStore.resolve_existing(
                self._database, analysis_id, display_id
            )
        except (LookupError, OSError, sqlite3.Error, ValueError) as error:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error
        checkpoints = tuple(
            checkpoint
            for checkpoint in self._checkpoints()
            if checkpoint.identity.analysis_id == analysis_id
        )
        finding = next(
            (
                checkpoint
                for checkpoint in checkpoints
                if checkpoint.stage is SimpleStage.FINDING_DONE
                and checkpoint.status is StageStatus.SUCCEEDED
                and finding_ref in checkpoint.output_refs
            ),
            None,
        )
        if finding is None:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
        report = next(
            (
                checkpoint
                for checkpoint in checkpoints
                if checkpoint.identity.hypothesis_id == finding.identity.hypothesis_id
                and checkpoint.stage is SimpleStage.REPORT_DONE
                and checkpoint.status is StageStatus.SUCCEEDED
                and checkpoint.stage_version == STAGE_VERSION[SimpleStage.REPORT_DONE]
                and finding_ref in checkpoint.input_refs
                and len(checkpoint.output_refs) >= 2
                and checkpoint.markdown_path is not None
            ),
            None,
        )
        gate = next(
            (
                checkpoint
                for checkpoint in checkpoints
                if checkpoint.identity.hypothesis_id == finding.identity.hypothesis_id
                and checkpoint.stage is SimpleStage.TECH_GATE_DONE
            ),
            None,
        )
        if report is None or report.markdown_path is None:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
        try:
            accepted = technical_gate_accepted(
                gate, SimpleArtifactRepository(self._data_dir, finding.identity)
            )
        except (OSError, ValueError, sqlite3.Error) as error:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error
        if not accepted:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
        root = (self._data_dir / "reports").resolve()
        expected_parent = root / analysis_id
        suffix = ".en.md" if language == "en" else ".md"
        path = expected_parent / f"{display_id}{suffix}"
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error
        if (
            resolved.parent != expected_parent
            or not resolved.is_file()
            or (language == "ko" and resolved != Path(report.markdown_path).resolve())
        ):
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
        return resolved

    def report_content(self, analysis_id: str, display_id: str) -> bytes:
        """Serve a guarded projection, never an old unverified ALLOW file."""

        self.report_path(analysis_id, display_id)
        try:
            finding_ref = FindingDisplayIdStore.resolve_existing(
                self._database, analysis_id, display_id
            )
            checkpoints = self._checkpoints()
            finding = next(
                checkpoint
                for checkpoint in checkpoints
                if checkpoint.identity.analysis_id == analysis_id
                and checkpoint.stage is SimpleStage.FINDING_DONE
                and finding_ref in checkpoint.output_refs
            )
            report = next(
                checkpoint
                for checkpoint in checkpoints
                if checkpoint.identity == finding.identity
                and checkpoint.stage is SimpleStage.REPORT_DONE
                and checkpoint.status is StageStatus.SUCCEEDED
                and checkpoint.stage_version == STAGE_VERSION[SimpleStage.REPORT_DONE]
                and finding_ref in checkpoint.input_refs
                and len(checkpoint.output_refs) >= 2
            )
            scope = next(
                (
                    checkpoint
                    for checkpoint in checkpoints
                    if checkpoint.identity == finding.identity
                    and checkpoint.stage is SimpleStage.SCOPE_GATE_DONE
                ),
                None,
            )
            review = self._scope_review(
                finding.identity, scope, self._simple_run(analysis_id)
            )
            raw = SimpleArtifactRepository(self._data_dir, finding.identity).read(
                report.output_refs[1]
            )
            return safe_public_report(raw, review)
        except (LookupError, OSError, ValueError, sqlite3.Error) as error:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error

    def _report_bundle(
        self, analysis_id: str, display_id: str
    ) -> tuple[ReportBundleManifest, bytes, SimpleArtifactRepository]:
        """Authorize the current bundle, not a path found on disk."""

        self.report_path(analysis_id, display_id)
        try:
            finding_ref = FindingDisplayIdStore.resolve_existing(
                self._database, analysis_id, display_id
            )
            checkpoints = self._checkpoints()
            finding = next(
                item
                for item in checkpoints
                if item.identity.analysis_id == analysis_id
                and item.stage is SimpleStage.FINDING_DONE
                and item.status is StageStatus.SUCCEEDED
                and finding_ref in item.output_refs
            )
            artifacts = SimpleArtifactRepository(self._data_dir, finding.identity)
            prior = {
                item.stage: item
                for item in checkpoints
                if item.identity == finding.identity
            }
            review = self._scope_review(
                finding.identity,
                prior.get(SimpleStage.SCOPE_GATE_DONE),
                self._simple_run(analysis_id),
            )
            manifest, archive = artifacts.verified_report_bundle(
                checkpoints=prior,
                finding_ref=finding_ref,
                display_id=display_id,
                scope_status=str(review["status"]),
                public_projection=lambda body: safe_public_report(body, review),
            )
            return manifest, archive, artifacts
        except (
            LookupError,
            OSError,
            ValueError,
            TypeError,
            StopIteration,
            sqlite3.Error,
        ) as error:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error

    def report_attachment(
        self, analysis_id: str, display_id: str, path: str
    ) -> tuple[bytes, str]:
        manifest, archive, artifacts = self._report_bundle(analysis_id, display_id)
        try:
            if path == "bundle.zip":
                return archive, "application/zip"
            return read_bundle_file(
                manifest,
                path,
                lambda ref: artifacts.read_bounded(ref, MAX_BUNDLE_FILE_BYTES),
            )
        except (OSError, ValueError) as error:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error

    @overload
    def _project_analysis(
        self,
        analysis_id: str,
        values: list[StageCheckpoint],
        *,
        detail: Literal[False] = False,
    ) -> AnalysisSummaryView: ...

    @overload
    def _project_analysis(
        self,
        analysis_id: str,
        values: list[StageCheckpoint],
        *,
        detail: Literal[True],
    ) -> AnalysisDetailView: ...

    def _project_analysis(
        self,
        analysis_id: str,
        values: list[StageCheckpoint],
        *,
        detail: bool = False,
    ) -> AnalysisSummaryView | AnalysisDetailView:
        hypothesis_groups: dict[str, list[StageCheckpoint]] = defaultdict(list)
        for checkpoint in values:
            if checkpoint.identity.hypothesis_id is not None:
                hypothesis_groups[checkpoint.identity.hypothesis_id].append(checkpoint)
        run = self._simple_run(analysis_id)
        usage = self._usage_summary(analysis_id)
        hypotheses = tuple(
            self._project_hypothesis(
                analysis_id,
                hypothesis_id,
                checkpoints,
                run,
            )
            for hypothesis_id, checkpoints in sorted(hypothesis_groups.items())
        )
        latest = max(values, key=lambda item: item.updated_at)
        started = min(values, key=lambda item: item.updated_at).updated_at
        completed = sum(item.status is StageStatus.SUCCEEDED for item in values)
        reports = self._reports(analysis_id)
        coverage = self._static_coverage_projection(values) if detail else {}
        known_hypotheses = set(run.hypothesis_ids) if run is not None else set()
        hypothesis_total = (
            len(known_hypotheses | set(hypothesis_groups))
            if run is not None or hypothesis_groups
            else None
        )
        verification_done = sum(
            self._final_verdict_saved(checkpoints)
            for checkpoints in hypothesis_groups.values()
        )
        confirmed_count = sum(
            self._confirmed_hypothesis(checkpoints)
            for checkpoints in hypothesis_groups.values()
        )
        progress = ProgressProjector(_CheckpointProjection(tuple(values))).snapshot(
            analysis_id
        )
        admissions = [
            item
            for item in values
            if item.stage is SimpleStage.PRIMITIVE_ADMISSION_DONE
            and item.status is StageStatus.SUCCEEDED
        ]
        data = AnalysisSummaryView(
            analysis_id=analysis_id,
            display_analysis_id=(run.display_analysis_id if run else None),
            workspace_id=latest.identity.workspace_id,
            commit_id=latest.identity.commit_id,
            current_stage=progress.current_stage or latest.stage.value,
            status=progress.status,
            completed_count=completed,
            stage_count=len(values),
            hypothesis_count=len(hypotheses),
            finding_count=len(reports),
            confirmed_finding_count=confirmed_count,
            failed_stage=(
                progress.current_stage
                if progress.status in {"FAILED", "BLOCKED"}
                else None
            ),
            inconclusive_hypothesis_count=progress.inconclusive_hypothesis_count,
            rejected_hypothesis_count=progress.rejected_hypothesis_count,
            llm_provider=(run.llm_provider if run else None),
            on_demand_possible=(run.on_demand_possible if run else False),
            llm_attempt_count=int(usage["calls"] or 0),
            llm_input_tokens=int(usage["input_tokens"] or 0),
            llm_output_tokens=int(usage["output_tokens"] or 0),
            llm_cost_minor_units=(
                float(usage["cost_minor_units"])
                if usage["cost_minor_units"] is not None
                else None
            ),
            llm_unknown_cost_calls=int(usage["unknown_cost_calls"] or 0),
            cursor_input_tokens=int(usage["input_tokens"] or 0),
            cursor_output_tokens=int(usage["output_tokens"] or 0),
            cursor_cost_cents=(
                float(usage["cost_minor_units"])
                if usage["cost_minor_units"] is not None
                else None
            ),
            progress_percent=progress.percent,
            completed_units=progress.completed_units,
            known_units=progress.known_units,
            admitted_primitive_count=sum(
                len(item.output_refs) > 1 for item in admissions
            ),
            excluded_primitive_count=sum(
                len(item.output_refs) <= 1 for item in admissions
            ),
            child_hypothesis_count=(len(run.parent_hypothesis_ids) if run else 0),
            updated_at=latest.updated_at,
            repository=(run.repository if run else None),
            profile_ref=(run.profile_ref if run else None),
            provider=(run.provider if run else None),
            model=(run.model if run else None),
            started_at=started,
            finished_at=(
                latest.updated_at
                if progress.status in {"COMPLETE", "BLOCKED", "FAILED"}
                else None
            ),
            last_updated_at=latest.updated_at,
            elapsed_ms=max(
                0,
                int(
                    (
                        (
                            latest.updated_at
                            if progress.status in {"COMPLETE", "BLOCKED", "FAILED"}
                            else datetime.now(UTC)
                        )
                        - started
                    ).total_seconds()
                    * 1000
                ),
            ),
            stale=(
                progress.status == "RUNNING"
                and (datetime.now(UTC) - latest.updated_at).total_seconds()
                > _STALE_SECONDS
            ),
        )
        if detail:
            artifacts: tuple[ArtifactView, ...] = ()
            contents: dict[str, tuple[str, str, bytes, Any | None]] = {}
            invocations: tuple[LLMInvocationView, ...] = ()
            poc_ids: tuple[str, ...] = ()
            evidence_ids: tuple[str, ...] = ()
            static_tools: tuple[StaticToolProgressView, ...] = ()
            artifact_omitted_count = 0
            coverage = self._static_coverage_projection(values)
            if run is not None:
                (
                    artifacts,
                    contents,
                    invocations,
                    poc_ids,
                    evidence_ids,
                    artifact_omitted_count,
                ) = self._artifact_projection(analysis_id, values, run)
                static_tools = self._static_tools(run, values, coverage)
                hypotheses = self._with_hypothesis_metadata(hypotheses, contents)
            return AnalysisDetailView.model_validate(
                {
                    **data.model_dump(),
                    **coverage,
                    "artifact_projection_complete": artifact_omitted_count == 0,
                    "artifact_omitted_count": artifact_omitted_count,
                    "kpis": DashboardKpiView(
                        discovery_done=cast(
                            int | None, coverage.get("static_coverage_verified")
                        ),
                        discovery_total=cast(
                            int | None, coverage.get("static_coverage_expected")
                        ),
                        verification_done=verification_done
                        if hypothesis_total is not None
                        else None,
                        verification_total=hypothesis_total,
                        remaining_work=(
                            max(0, hypothesis_total - verification_done)
                            if hypothesis_total is not None
                            else None
                        ),
                        confirmed_findings=confirmed_count,
                    ),
                    "hypotheses": hypotheses,
                    "reports": reports,
                    "pipeline": self._pipeline(values, run),
                    "static_tools": static_tools,
                    "static_tool_findings": self._static_tool_findings(contents),
                    "readiness": self._readiness(
                        analysis_id,
                        run,
                        static_tools,
                        artifacts,
                        reports,
                    ),
                    "usage": self._invocation_usage_summary(invocations),
                    "artifacts": artifacts,
                    "artifact_relations": self._artifact_relations(contents),
                    "finding_traces": self._finding_traces(
                        analysis_id,
                        reports,
                        hypotheses,
                        artifacts,
                        contents,
                        poc_ids,
                        evidence_ids,
                    ),
                    "llm_invocations": invocations,
                    "poc_artifact_ids": poc_ids,
                    "evidence_artifact_ids": evidence_ids,
                    "logs_url": f"/api/analyses/{analysis_id}/logs/download",
                    "bundle_url": f"/api/analyses/{analysis_id}/bundle.zip",
                    "presentation_bundle_url": (
                        f"/api/analyses/{analysis_id}/presentation.zip"
                    ),
                }
            )
        return data

    @staticmethod
    def _hypothesis_groups(
        values: list[StageCheckpoint],
    ) -> dict[str, list[StageCheckpoint]]:
        groups: dict[str, list[StageCheckpoint]] = defaultdict(list)
        for checkpoint in values:
            if checkpoint.identity.hypothesis_id is not None:
                groups[checkpoint.identity.hypothesis_id].append(checkpoint)
        return groups

    @staticmethod
    def _final_verdict_saved(values: list[StageCheckpoint]) -> bool:
        return any(
            item.stage is SimpleStage.VERIFICATION_FINAL_DONE
            and item.status is StageStatus.SUCCEEDED
            and item.verdict in {"TRUE", "FALSE", "HOLD"}
            for item in values
        )

    @staticmethod
    def _validated_poc(values: list[StageCheckpoint]) -> bool:
        return any(
            item.stage is SimpleStage.POC_EXECUTION_DONE
            and item.status is StageStatus.SUCCEEDED
            and item.validated_poc_ref is not None
            for item in values
        )

    def _known_token_usage(self, analysis_id: str) -> bool:
        with self._connect() as connection:
            if not self._table_exists(connection, "simple_llm_attempts"):
                return False
            row = connection.execute(
                """
                SELECT COUNT(*) FROM simple_llm_attempts
                WHERE analysis_id = ?
                  AND (input_tokens IS NOT NULL OR output_tokens IS NOT NULL)
                """,
                (analysis_id,),
            ).fetchone()
        return row is not None and int(row[0]) > 0

    @staticmethod
    def _invocation_payload(
        contents: dict[str, tuple[str, str, bytes, Any | None]],
        artifact_id: str | None,
    ) -> dict[str, Any] | None:
        if artifact_id is None:
            return None
        item = contents.get(artifact_id)
        if item is None or not isinstance(item[3], dict):
            return None
        return cast(dict[str, Any], item[3])

    @staticmethod
    def _prompt_text(payload: dict[str, Any] | None, *keys: str) -> str | None:
        if payload is None:
            return None
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return None

    @staticmethod
    def _artifact_label(kind: str) -> str:
        exact = {
            "simple_llm_request": "LLM 요청",
            "simple_llm_response": "LLM 응답",
            "simple_static_fact_bundle": "정적분석 사실 묶음",
            "simple_validated_poc": "검증된 PoC",
            "simple_poc_execution": "PoC 실행 결과",
            "simple_dynamic_interpretation": "동적 검증 해석",
            "simple_hypothesis_proposal": "취약점 가설",
            "simple_policy_snapshot": "정책 스냅샷",
        }
        if kind in exact:
            return exact[kind]
        return kind.replace("simple_", "").replace("_", " ").strip().title()

    @staticmethod
    def _artifact_purpose(kind: str) -> str:
        if "llm_request" in kind:
            return "Agent가 Provider에 전달한 정제된 요청 기록"
        if "llm_response" in kind:
            return "Provider 응답에서 저장한 정제된 결과 기록"
        if "poc" in kind:
            return "취약점 재현과 검증에 사용된 PoC 자료"
        if "evidence" in kind or "static_fact" in kind:
            return "Finding 판정을 뒷받침하는 정적·동적 근거"
        if "report" in kind:
            return "검증 결과를 정리한 보고서 자료"
        if "hypothesis" in kind:
            return "검증 대상으로 생성된 취약점 가설"
        if "policy" in kind:
            return "Scope Gate 판정에 사용된 정책 근거"
        return "분석 단계에서 생성·참조된 저장 아티팩트"

    @staticmethod
    def _confirmed_hypothesis(values: list[StageCheckpoint]) -> bool:
        return (
            any(
                item.stage is SimpleStage.VERIFICATION_FINAL_DONE
                and item.status is StageStatus.SUCCEEDED
                and item.verdict == "TRUE"
                for item in values
            )
            and any(item.validated_poc_ref is not None for item in values)
            and any(
                item.stage is SimpleStage.FINDING_DONE
                and item.status is StageStatus.SUCCEEDED
                for item in values
            )
            and any(
                item.stage is SimpleStage.REPORT_DONE
                and item.status is StageStatus.SUCCEEDED
                for item in values
            )
        )

    def _static_coverage_projection(
        self, checkpoints: list[StageCheckpoint]
    ) -> dict[str, object]:
        static = next(
            (
                item
                for item in checkpoints
                if item.stage is SimpleStage.STATIC_DONE
                and item.identity.hypothesis_id is None
            ),
            None,
        )
        if static is None:
            return {}
        artifacts = SimpleArtifactRepository(self._data_dir, static.identity)
        coverage: object = None
        try:
            if static.status is StageStatus.SUCCEEDED:
                if len(static.output_refs) < 2:
                    return {}
                bundle = json.loads(artifacts.read(static.output_refs[1]))
                if (
                    not isinstance(bundle, dict)
                    or bundle.get("kind") != "simple_static_fact_bundle"
                ):
                    return {}
                coverage_ref = StoredDataRef.model_validate(
                    bundle["static_coverage_ref"]
                )
                coverage = json.loads(artifacts.read(coverage_ref))
            elif static.status is StageStatus.BLOCKED:
                for ref in static.output_refs:
                    candidate = json.loads(artifacts.read(ref))
                    if (
                        isinstance(candidate, dict)
                        and candidate.get("kind") == "simple_static_coverage_v1"
                    ):
                        coverage = candidate
                        break
        except (OSError, ValueError, KeyError, TypeError):
            return {}
        if (
            not isinstance(coverage, dict)
            or coverage.get("kind") != "simple_static_coverage_v1"
        ):
            return {}
        if (
            coverage.get("analysis_id") != static.identity.analysis_id
            or coverage.get("workspace_id") != static.identity.workspace_id
            or coverage.get("commit_id") != static.identity.commit_id
        ):
            return {}
        expected = coverage.get("expected_count")
        verified = coverage.get("verified_count")
        gaps = coverage.get("gaps")
        if (
            type(expected) is not int
            or type(verified) is not int
            or expected < 0
            or verified < 0
            or verified > expected
            or not isinstance(gaps, list)
            or len(gaps) != expected - verified
        ):
            return {}
        preview: list[dict[str, str]] = []
        for item in gaps[:100]:
            if not isinstance(item, dict):
                return {}
            path = item.get("path")
            rule_id = item.get("rule_id")
            reason = item.get("reason")
            if (
                not isinstance(path, str)
                or not path
                or len(path) > 512
                or path.startswith("/")
                or ".." in PurePosixPath(path).parts
                or "\\" in path
                or ":" in path
                or any(ord(character) < 32 for character in path)
                or not isinstance(rule_id, str)
                or not _RULE_NAME.fullmatch(rule_id)
                or not isinstance(reason, str)
                or not _RULE_NAME.fullmatch(reason)
            ):
                return {}
            preview.append({"path": path, "rule_id": rule_id, "reason": reason})
        raw_unsupported = coverage.get("unsupported", [])
        if not isinstance(raw_unsupported, list):
            return {}
        unsupported: list[tuple[str, int]] = []
        for item in raw_unsupported:
            if not isinstance(item, dict):
                return {}
            extension = item.get("extension")
            count = item.get("file_count")
            if (
                not isinstance(extension, str)
                or not re.fullmatch(r"\.[A-Za-z0-9]{1,12}", extension)
                or type(count) is not int
                or count < 0
            ):
                return {}
            unsupported.append((extension, count))
        parse_count = coverage.get("ast_parse_error_count")
        truncated = coverage.get("ast_truncated")
        engines = coverage.get("engine_verified_counts", {})
        codeql_configured = coverage.get("codeql_configured")
        codeql_executed = coverage.get("codeql_executed")
        codeql_scope = coverage.get("codeql_scope")
        if (
            type(parse_count) is not int
            or parse_count < 0
            or type(truncated) is not bool
            or not isinstance(engines, dict)
            or any(
                name not in {"opengrep", "semgrep"}
                or type(count) is not int
                or count < 0
                for name, count in engines.items()
            )
            or (codeql_configured is not None and type(codeql_configured) is not bool)
            or (codeql_executed is not None and type(codeql_executed) is not bool)
            or codeql_scope not in (None, "python_only")
        ):
            return {}
        return {
            "static_coverage_expected": expected,
            "static_coverage_verified": verified,
            "static_coverage_gap_count": len(gaps),
            "static_coverage_gap_preview": tuple(preview),
            "static_coverage_unsupported": tuple(unsupported),
            "static_ast_parse_error_count": parse_count,
            "static_ast_truncated": truncated,
            "static_coverage_engines": engines,
            "static_codeql_configured": codeql_configured,
            "static_codeql_executed": codeql_executed,
            "static_codeql_scope": codeql_scope,
        }

    @staticmethod
    def _artifact_relations(
        contents: dict[str, tuple[str, str, bytes, Any | None]],
    ) -> tuple[ArtifactRelationView, ...]:
        relations: list[ArtifactRelationView] = []
        seen: set[tuple[str, str]] = set()
        for target_id, target in contents.items():
            parsed = target[3]
            if not isinstance(parsed, dict):
                continue
            for ref in DashboardQuery._nested_refs(parsed):
                source_id = ref.content_hash
                if source_id not in contents or source_id == target_id:
                    continue
                identity = (source_id, target_id)
                if identity in seen:
                    continue
                seen.add(identity)
                relations.append(
                    ArtifactRelationView(
                        source_artifact_id=source_id,
                        target_artifact_id=target_id,
                        relation="INPUT_TO_OUTPUT",
                        source_kind=contents[source_id][0],
                        target_kind=target[0],
                    )
                )
        return tuple(
            sorted(
                relations,
                key=lambda item: (
                    item.target_kind,
                    item.source_kind,
                    item.source_artifact_id,
                ),
            )
        )

    @staticmethod
    def _static_tool_findings(
        contents: dict[str, tuple[str, str, bytes, Any | None]],
    ) -> tuple[StaticToolFindingView, ...]:
        bundle = next(
            (
                item[3]
                for item in contents.values()
                if item[0] == "simple_static_fact_bundle" and isinstance(item[3], dict)
            ),
            None,
        )
        if not isinstance(bundle, dict):
            return ()
        grouped: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: {"tools": set(), "rules": set()}
        )
        ast_summary = bundle.get("ast_summary")
        findings_by_tool = (
            (
                "AST",
                (
                    bundle.get("ast_findings"),
                    bundle.get("ast_facts"),
                    (
                        ast_summary.get("facts")
                        if isinstance(ast_summary, dict)
                        else None
                    ),
                ),
            ),
            ("OpenGrep", (bundle.get("opengrep_findings"),)),
            ("CodeQL", (bundle.get("codeql_findings"),)),
        )
        for tool, finding_groups in findings_by_tool:
            for raw in finding_groups:
                if not isinstance(raw, list):
                    continue
                for value in raw[:500]:
                    if not isinstance(value, dict):
                        continue
                    path = next(
                        (
                            str(value[name])
                            for name in ("path", "file", "uri")
                            if isinstance(value.get(name), str)
                        ),
                        "위치 미기록",
                    )
                    line = next(
                        (
                            value[name]
                            for name in ("line", "start_line", "line_number")
                            if isinstance(value.get(name), int)
                        ),
                        None,
                    )
                    location = f"{path}:{line}" if line is not None else path
                    grouped[location]["tools"].add(tool)
                    rule = next(
                        (
                            str(value[name])
                            for name in ("rule_id", "check_id", "query", "name")
                            if isinstance(value.get(name), str)
                        ),
                        None,
                    )
                    if rule:
                        grouped[location]["rules"].add(rule[:200])
        return tuple(
            StaticToolFindingView(
                location=location[:500],
                tools=tuple(sorted(values["tools"])),
                rule_ids=tuple(sorted(values["rules"])),
                overlap=len(values["tools"]) > 1,
            )
            for location, values in sorted(grouped.items())
        )

    def _finding_traces(
        self,
        analysis_id: str,
        reports: tuple[FindingReportView, ...],
        hypotheses: tuple[HypothesisProgressView, ...],
        artifacts: tuple[ArtifactView, ...],
        contents: dict[str, tuple[str, str, bytes, Any | None]],
        poc_ids: tuple[str, ...],
        evidence_ids: tuple[str, ...],
    ) -> tuple[FindingTraceView, ...]:
        hypothesis_map = {item.hypothesis_id: item for item in hypotheses}
        traces: list[FindingTraceView] = []
        for report in reports:
            try:
                finding_ref = FindingDisplayIdStore.resolve_existing(
                    self._database, analysis_id, report.display_id
                )
            except (LookupError, OSError, sqlite3.Error, ValueError):
                continue
            parsed = contents.get(finding_ref.content_hash, ("", "", b"", None))[3]
            hypothesis_id = (
                str(parsed.get("hypothesis_id"))
                if isinstance(parsed, dict)
                and isinstance(parsed.get("hypothesis_id"), str)
                else None
            )
            hypothesis = hypothesis_map.get(hypothesis_id or "")
            related = {
                item.artifact_id
                for item in artifacts
                if hypothesis_id and hypothesis_id in item.hypothesis_ids
            }
            if finding_ref.content_hash in contents:
                related.add(finding_ref.content_hash)
            if isinstance(parsed, dict):
                related.update(
                    ref.content_hash
                    for ref in self._nested_refs(parsed)
                    if ref.content_hash in contents
                )
            traces.append(
                FindingTraceView(
                    display_id=report.display_id,
                    hypothesis_id=hypothesis_id,
                    title=(hypothesis.title if hypothesis else None),
                    vulnerability_type=(
                        hypothesis.vulnerability_type if hypothesis else None
                    ),
                    source=(hypothesis.source if hypothesis else None),
                    sink=(hypothesis.sink if hypothesis else None),
                    verdict=(hypothesis.verdict if hypothesis else None),
                    validated_poc=(hypothesis.validated_poc if hypothesis else False),
                    artifact_ids=tuple(sorted(related)),
                    poc_artifact_ids=tuple(item for item in poc_ids if item in related),
                    evidence_artifact_ids=tuple(
                        item for item in evidence_ids if item in related
                    ),
                    report_view_url=report.view_url,
                    report_download_url=report.download_url,
                    english_available=report.english_available,
                )
            )
        return tuple(traces)

    @staticmethod
    def _with_hypothesis_metadata(
        hypotheses: tuple[HypothesisProgressView, ...],
        contents: dict[str, tuple[str, str, bytes, Any | None]],
    ) -> tuple[HypothesisProgressView, ...]:
        proposals: dict[str, dict[str, Any]] = {}
        for _kind, _media_type, _raw, parsed in contents.values():
            if not isinstance(parsed, dict):
                continue
            if parsed.get("kind") != "simple_hypothesis_proposal":
                continue
            hypothesis_id = parsed.get("hypothesis_id")
            proposal = parsed.get("proposal")
            if isinstance(hypothesis_id, str) and isinstance(proposal, dict):
                proposals[hypothesis_id] = proposal

        def text(value: object, limit: int = 500) -> str | None:
            return str(value)[:limit] if isinstance(value, str) and value else None

        enriched: list[HypothesisProgressView] = []
        for hypothesis in hypotheses:
            proposal = proposals.get(hypothesis.hypothesis_id, {})
            raw_locations = proposal.get("code_locations", [])
            locations = (
                tuple(str(item)[:300] for item in raw_locations[:12])
                if isinstance(raw_locations, list)
                else ()
            )
            enriched.append(
                hypothesis.model_copy(
                    update={
                        "title": text(proposal.get("title"), 300),
                        "vulnerability_type": text(
                            proposal.get("vulnerability_type"), 160
                        ),
                        "summary": text(proposal.get("summary"), 700),
                        "source": text(proposal.get("source")),
                        "sink": text(proposal.get("sink")),
                        "code_locations": locations,
                    }
                )
            )
        return tuple(enriched)

    def _readiness(
        self,
        analysis_id: str,
        run: SimpleAnalysisRun | None,
        static_tools: tuple[StaticToolProgressView, ...],
        artifacts: tuple[ArtifactView, ...] | int,
        reports: tuple[FindingReportView, ...],
    ) -> tuple[ReadinessCheckView, ...]:
        def present(value: object) -> bool:
            return value is not None and str(value).strip() != ""

        artifact_count = artifacts if isinstance(artifacts, int) else len(artifacts)
        tool_status = {item.tool: item.status for item in static_tools}
        core = [tool_status.get("AST"), tool_status.get("OpenGrep")]
        if any(status in {"FAILED", "BLOCKED"} for status in core):
            static_status = "BLOCKED"
        elif core and all(status == "SUCCEEDED" for status in core):
            static_status = "READY"
        elif any(status == "RUNNING" for status in core):
            static_status = "RUNNING"
        else:
            static_status = "WAITING"
        codeql = tool_status.get("CodeQL")
        codeql_status = (
            "READY"
            if codeql == "SUCCEEDED"
            else "OPTIONAL"
            if codeql == "SKIPPED"
            else "BLOCKED"
            if codeql in {"FAILED", "BLOCKED"}
            else "RUNNING"
            if codeql == "RUNNING"
            else "WAITING"
        )
        log_ready = (self._data_dir / "logs" / f"{analysis_id}.log").is_file()
        return (
            ReadinessCheckView(
                key="exact-target",
                label_ko="저장소·commit 고정",
                status=(
                    "READY"
                    if run is not None
                    and present(run.repository)
                    and present(run.commit_id)
                    else "BLOCKED"
                ),
                detail_ko=(
                    "재현 가능한 분석 대상을 기록했습니다."
                    if run is not None
                    and present(run.repository)
                    and present(run.commit_id)
                    else "저장소 또는 commit 기록이 없습니다."
                ),
            ),
            ReadinessCheckView(
                key="runtime-profile",
                label_ko="실행 프로필",
                status=(
                    "READY"
                    if run is not None and present(run.profile_ref)
                    else "WAITING"
                ),
                detail_ko=(
                    "분석 실행 프로필이 연결되어 있습니다."
                    if run is not None and present(run.profile_ref)
                    else "이전 분석이어서 프로필 기록이 없을 수 있습니다."
                ),
            ),
            ReadinessCheckView(
                key="llm-provider",
                label_ko="LLM Provider·모델",
                status=(
                    "READY"
                    if run is not None and present(run.provider) and present(run.model)
                    else "WAITING"
                ),
                detail_ko=(
                    "Provider와 모델 provenance를 확인했습니다."
                    if run is not None and present(run.provider) and present(run.model)
                    else "Provider 또는 모델 기록을 기다리는 중입니다."
                ),
            ),
            ReadinessCheckView(
                key="static-core",
                label_ko="AST·OpenGrep",
                status=static_status,
                detail_ko="필수 정적분석 도구의 저장 결과 기준 상태입니다.",
            ),
            ReadinessCheckView(
                key="codeql",
                label_ko="CodeQL",
                status=codeql_status,
                detail_ko=(
                    "선택 프로필에서 CodeQL을 사용하지 않았습니다."
                    if codeql_status == "OPTIONAL"
                    else "CodeQL 저장 결과 기준 상태입니다."
                ),
                required=False,
            ),
            ReadinessCheckView(
                key="presentation-output",
                label_ko="발표 결과물",
                status=(
                    "READY" if artifact_count and (reports or log_ready) else "WAITING"
                ),
                detail_ko=(
                    f"아티팩트 {artifact_count}개·보고서 {len(reports)}개"
                    + ("·로그 있음" if log_ready else "·로그 없음")
                ),
                required=False,
            ),
        )

    @staticmethod
    def _invocation_usage_summary(
        invocations: tuple[LLMInvocationView, ...],
    ) -> UsageSummaryView:
        input_tokens = sum(item.input_tokens or 0 for item in invocations)
        output_tokens = sum(item.output_tokens or 0 for item in invocations)
        known = sum(
            item.input_tokens is not None or item.output_tokens is not None
            for item in invocations
        )
        return UsageSummaryView(
            invocation_count=len(invocations),
            succeeded_count=sum(
                item.status in {"SUCCEEDED", "COMPLETE"} for item in invocations
            ),
            failed_count=sum(
                item.status in {"FAILED", "BLOCKED", "TIMED_OUT", "CANCELLED"}
                for item in invocations
            ),
            retry_count=sum(item.retry_count for item in invocations),
            known_usage_count=known,
            unknown_usage_count=len(invocations) - known,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            elapsed_ms=sum(item.elapsed_ms or 0 for item in invocations),
        )

    @staticmethod
    def _failure_guidance(error_code: str | None) -> str | None:
        if not error_code:
            return None
        code = error_code.upper()
        if any(value in code for value in ("AUTH", "CREDENTIAL", "PROVIDER")):
            return "Provider 인증 상태를 확인한 뒤 같은 분석을 resume 하세요."
        if any(value in code for value in ("DOCKER", "SANDBOX", "CONTAINER")):
            return "Docker 실행 상태와 승인된 격리 프로필을 확인하세요."
        if "CODEQL" in code:
            return "CodeQL bundle·query pack과 출력 quota 준비 상태를 확인하세요."
        if any(value in code for value in ("OPENGREP", "AST", "TOOL")):
            return "setup에서 선택한 정적분석 도구 경로와 실행 권한을 확인하세요."
        if any(value in code for value in ("RATE_LIMIT", "TIMEOUT")):
            return (
                "Provider 한도와 네트워크 상태를 확인한 뒤 실패 단계부터 resume 하세요."
            )
        return (
            "오류 코드를 기록하고 docs/troubleshooting.md의 안전한 복구 "
            "절차를 확인하세요."
        )

    @staticmethod
    def _pipeline(
        values: list[StageCheckpoint], run: SimpleAnalysisRun | None
    ) -> tuple[StageProgressView, ...]:
        actual = {(item.identity.hypothesis_id, item.stage): item for item in values}
        result: list[StageProgressView] = []

        def append(stage: SimpleStage, hypothesis_id: str | None) -> None:
            checkpoint = actual.get((hypothesis_id, stage))
            result.append(
                StageProgressView(
                    stage=stage.value,
                    label_ko=_STAGE_LABELS[stage],
                    status=(checkpoint.status.value if checkpoint else "NOT_STARTED"),
                    hypothesis_id=hypothesis_id,
                    agent_role=ROLE_BY_STAGE[stage],
                    attempt_number=(checkpoint.attempt_number if checkpoint else 0),
                    output_count=(len(checkpoint.output_refs) if checkpoint else 0),
                    retryable=(checkpoint.retryable if checkpoint else False),
                    error_code=(checkpoint.error_code if checkpoint else None),
                    guidance_ko=DashboardQuery._failure_guidance(
                        checkpoint.error_code if checkpoint else None
                    ),
                    updated_at=(checkpoint.updated_at if checkpoint else None),
                )
            )

        append(SimpleStage.STATIC_DONE, None)
        append(SimpleStage.HYPOTHESIS_DONE, None)
        hypothesis_ids = (
            run.hypothesis_ids
            if run and run.hypothesis_ids
            else tuple(
                sorted(
                    {
                        item.identity.hypothesis_id
                        for item in values
                        if item.identity.hypothesis_id is not None
                    }
                )
            )
        )
        for hypothesis_id in hypothesis_ids:
            for stage in HYPOTHESIS_STAGES:
                append(stage, hypothesis_id)
        return tuple(result)

    def _static_tools(
        self,
        run: SimpleAnalysisRun,
        values: list[StageCheckpoint],
        coverage: dict[str, object],
    ) -> tuple[StaticToolProgressView, ...]:
        checkpoint = next(
            (item for item in values if item.stage is SimpleStage.STATIC_DONE), None
        )
        base_status = checkpoint.status.value if checkpoint else "NOT_STARTED"
        bundle: dict[str, Any] = {}
        if run.static_bundle_ref is not None:
            repository = SimpleArtifactRepository(
                self._data_dir,
                CheckpointIdentity(
                    analysis_id=run.analysis_id,
                    workspace_id=run.workspace_id,
                    commit_id=run.commit_id,
                    hypothesis_id=None,
                ),
            )
            try:
                raw = repository.read(run.static_bundle_ref)
                value = json.loads(raw)
                if isinstance(value, dict):
                    bundle = value
            except (
                OSError,
                sqlite3.Error,
                UnicodeDecodeError,
                json.JSONDecodeError,
                ValueError,
            ):
                bundle = {}
        completed = base_status == StageStatus.SUCCEEDED.value
        expected = coverage.get("static_coverage_expected")
        engines = coverage.get("static_coverage_engines")
        engine_counts = engines if isinstance(engines, dict) else {}
        ast_partial = bool(
            coverage.get("static_ast_parse_error_count")
            or coverage.get("static_ast_truncated")
        )
        opengrep_count = engine_counts.get("opengrep")
        semgrep_count = engine_counts.get("semgrep")
        if not completed:
            ast_status = opengrep_status = base_status
        else:
            ast_status = (
                "PARTIAL" if ast_partial else "SUCCEEDED" if coverage else "UNKNOWN"
            )
            opengrep_status = (
                "UNKNOWN"
                if not isinstance(opengrep_count, int) or not isinstance(expected, int)
                else "SUCCEEDED"
                if expected > 0 and opengrep_count == expected
                else "PARTIAL"
                if opengrep_count > 0
                else "SKIPPED"
            )
        codeql_executed = coverage.get("static_codeql_executed")
        if codeql_executed is None:
            codeql_executed = bundle.get("codeql_executed")
        tools = [
            StaticToolProgressView(
                tool="AST",
                status=ast_status,
            ),
            StaticToolProgressView(
                tool="OpenGrep",
                status=opengrep_status,
                finding_count=(
                    len(bundle.get("opengrep_findings", []))
                    if isinstance(bundle.get("opengrep_findings"), list)
                    else None
                ),
            ),
        ]
        if isinstance(semgrep_count, int) and semgrep_count > 0:
            tools.append(
                StaticToolProgressView(
                    tool="Semgrep CE",
                    status=(
                        base_status
                        if not completed
                        else "SUCCEEDED"
                        if isinstance(expected, int) and semgrep_count == expected
                        else "PARTIAL"
                    ),
                )
            )
        tools.append(
            StaticToolProgressView(
                tool="CodeQL",
                status=(
                    "SUCCEEDED"
                    if completed and codeql_executed
                    else "SKIPPED"
                    if completed
                    else base_status
                ),
                finding_count=(
                    len(bundle.get("codeql_findings", []))
                    if isinstance(bundle.get("codeql_findings"), list)
                    else None
                ),
            )
        )
        return tuple(tools)

    def _project_hypothesis(
        self,
        analysis_id: str,
        hypothesis_id: str,
        values: list[StageCheckpoint],
        run: SimpleAnalysisRun | None,
    ) -> HypothesisProgressView:
        latest = max(values, key=lambda item: item.updated_at)
        completed = sum(item.status is StageStatus.SUCCEEDED for item in values)
        final = next(
            (
                item
                for item in values
                if item.stage is SimpleStage.VERIFICATION_FINAL_DONE
            ),
            None,
        )
        execution = next(
            (item for item in values if item.stage is SimpleStage.POC_EXECUTION_DONE),
            None,
        )
        gate = next(
            (item for item in values if item.stage is SimpleStage.TECH_GATE_DONE),
            None,
        )
        scope = next(
            (item for item in values if item.stage is SimpleStage.SCOPE_GATE_DONE),
            None,
        )
        review = self._scope_review(latest.identity, scope, run)
        source = review["policy_source"]
        assert isinstance(source, dict)
        progress = ProgressProjector(_CheckpointProjection(tuple(values))).snapshot(
            analysis_id
        )
        return HypothesisProgressView(
            analysis_id=analysis_id,
            hypothesis_id=hypothesis_id,
            current_stage=progress.current_stage or latest.stage.value,
            status=progress.status,
            completed_count=completed,
            stage_count=len(values),
            error_code=progress.error_code,
            verdict=final.verdict if final else None,
            disposition=terminal_poc_outcome(execution) or terminal_gate_outcome(gate),
            scope_status=str(review["status"]),
            scope_collection_status=str(source.get("collection_status", "UNVERIFIED")),
            scope_source_url=(
                source.get("source_url")
                if isinstance(source.get("source_url"), str)
                and review["provenance_verified"] is True
                else None
            ),
            scope_source_revision=(
                source.get("blob_sha")
                if isinstance(source.get("blob_sha"), str)
                and review["provenance_verified"] is True
                else None
            ),
            scope_reasons=tuple(
                str(item) for item in cast(list[object], review["checks"])
            ),
            scope_missing_information=tuple(
                str(item) for item in cast(list[object], review["missing_information"])
            ),
            scope_axes=cast(dict[str, dict[str, object]], review["axes"]),
            private_reporting_policy_passed=(
                review["private_reporting_policy_passed"] is True
            ),
            external_disclosure_allowed=(review["external_disclosure_allowed"] is True),
            resume_available=(
                progress.status in {"BLOCKED", "FAILED"}
                and any(item.retryable for item in values)
            ),
            validated_poc=any(item.validated_poc_ref is not None for item in values),
            parent_hypothesis_ids=(
                run.parent_hypothesis_ids.get(hypothesis_id, ()) if run else ()
            ),
            chain_depth=(run.chain_depths.get(hypothesis_id, 0) if run else 0),
            attempt_number=progress.attempt_number,
            updated_at=latest.updated_at,
        )

    def _scope_review(
        self,
        identity: CheckpointIdentity,
        checkpoint: StageCheckpoint | None,
        run: SimpleAnalysisRun | None,
    ) -> dict[str, object]:
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        return project_scope_review(
            checkpoint,
            artifacts,
            policy_snapshot_ref=run.policy_snapshot_ref if run else None,
            repository_url=run.repository if run else None,
        )

    def _simple_run(self, analysis_id: str) -> SimpleAnalysisRun | None:
        with self._connect() as connection:
            if not self._table_exists(connection, "simple_analysis_runs"):
                return None
            row = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            return SimpleAnalysisRun.model_validate_json(row[0])
        except ValueError:
            return None

    def _usage_summary(self, analysis_id: str) -> dict[str, int | float | None]:
        with self._connect() as connection:
            if not self._table_exists(connection, "simple_llm_attempts"):
                return {
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost_minor_units": None,
                    "unknown_cost_calls": 0,
                }
            return SimpleCheckpointStore.usage_summary_from_connection(
                connection, analysis_id
            )

    def _resolve_analysis_id(self, value: str) -> str:
        """Resolve public A-NNN names without breaking older exact-ID data."""
        if value.startswith("A-"):
            return AnalysisDisplayIdStore.resolve_existing(self._database, value)
        self._validate_analysis_id(value)
        return value

    def _reports(self, analysis_id: str) -> tuple[FindingReportView, ...]:
        with self._connect() as connection:
            if not self._table_exists(connection, "finding_display_ids"):
                return ()
            rows = connection.execute(
                """
                SELECT display_number FROM finding_display_ids
                WHERE analysis_id = ? ORDER BY display_number
                """,
                (analysis_id,),
            ).fetchall()
        reports: list[FindingReportView] = []
        for row in rows:
            display_id = f"F-{int(row[0]):03d}"
            try:
                self.report_path(analysis_id, display_id)
            except DashboardNotFound:
                continue
            english_available = self._english_report_available(analysis_id, display_id)
            reports.append(
                FindingReportView(
                    analysis_id=analysis_id,
                    display_id=display_id,
                    url=f"/reports/{analysis_id}/{display_id}.md",
                    view_url=(f"/api/analyses/{analysis_id}/reports/{display_id}"),
                    download_url=(
                        f"/api/analyses/{analysis_id}/reports/{display_id}/download"
                    ),
                    english_available=english_available,
                    english_view_url=(
                        f"/api/analyses/{analysis_id}/reports/{display_id}?lang=en"
                        if english_available
                        else None
                    ),
                    english_download_url=(
                        f"/api/analyses/{analysis_id}/reports/{display_id}/download?lang=en"
                        if english_available
                        else None
                    ),
                    attachment_urls=self._attachment_urls(analysis_id, display_id),
                    attachment_preview_urls=self._attachment_preview_urls(
                        analysis_id, display_id
                    ),
                )
            )
        return tuple(reports)

    def _english_report_available(self, analysis_id: str, display_id: str) -> bool:
        try:
            self.report_attachment(analysis_id, display_id, "report_en.md")
        except DashboardNotFound:
            return False
        return True

    def _attachment_urls(self, analysis_id: str, display_id: str) -> dict[str, str]:
        try:
            manifest, _, _ = self._report_bundle(analysis_id, display_id)
        except DashboardNotFound:
            return {}
        prefix = f"/reports/{analysis_id}/{display_id}"
        return {
            **{item.path: f"{prefix}/files/{item.path}" for item in manifest.files},
            "bundle.zip": f"{prefix}/bundle.zip",
        }

    def _attachment_preview_urls(
        self, analysis_id: str, display_id: str
    ) -> dict[str, str]:
        try:
            manifest, _, _ = self._report_bundle(analysis_id, display_id)
        except DashboardNotFound:
            return {}
        prefix = f"/reports/{analysis_id}/{display_id}/files"
        return {
            item.path: f"{prefix}/{item.path}/preview"
            for item in manifest.files
            if item.path.endswith(".md")
            and item.media_type.lower().startswith("text/markdown")
        }

    def _full_runtime_summaries(self) -> tuple[AnalysisSummaryView, ...]:
        with self._connect() as connection:
            if not self._table_exists(connection, "analysis_runs"):
                return ()
            rows = connection.execute(
                "SELECT analysis_id, payload FROM analysis_runs"
            ).fetchall()
        summaries: list[AnalysisSummaryView] = []
        for row in rows:
            try:
                payload = json.loads(row[1])
                summaries.append(
                    AnalysisSummaryView(
                        analysis_id=str(row[0]),
                        workspace_id=payload.get("workspace_id"),
                        commit_id=payload.get("commit_id"),
                        current_stage="PRODUCTION_RUNTIME",
                        status=str(payload.get("status", "UNKNOWN")),
                        completed_count=0,
                        stage_count=0,
                        hypothesis_count=0,
                        finding_count=0,
                        updated_at=payload.get("finished_at")
                        or payload.get("started_at"),
                        elapsed_ms=payload.get("elapsed_ms"),
                    )
                )
            except (TypeError, ValueError):
                continue
        return tuple(summaries)

    @staticmethod
    def _aggregate_status(values: list[StageCheckpoint]) -> str:
        for status in (
            StageStatus.RUNNING,
            StageStatus.BLOCKED,
            StageStatus.FAILED,
        ):
            if any(item.status is status for item in values):
                return status.value
        if any(
            item.stage is SimpleStage.REPORT_DONE
            and item.status is StageStatus.SUCCEEDED
            for item in values
        ):
            return "COMPLETE"
        return "SUCCEEDED"

    @staticmethod
    def _validate_analysis_id(analysis_id: str) -> None:
        if _ANALYSIS_ID.fullmatch(analysis_id) is None:
            raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND")


__all__ = [
    "DashboardBadRequest",
    "DashboardIncomplete",
    "DashboardNotFound",
    "DashboardQuery",
]
