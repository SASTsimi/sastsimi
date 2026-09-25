"""Read-only SQLite and report projection for the local dashboard."""

from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Literal, overload

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.observability.agent_activity import AgentActivityEvent
from sastsimi.progress.projector import ProgressProjector
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.models import (
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore

from .models import (
    AgentActivityView,
    AnalysisDetailView,
    AnalysisSummaryView,
    FindingReportView,
    HypothesisProgressView,
)

_ANALYSIS_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_DISPLAY_ID = re.compile(r"F-[0-9]{3,}\Z")


class DashboardNotFound(LookupError):
    pass


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

    def _checkpoints(self) -> tuple[StageCheckpoint, ...]:
        with self._connect() as connection:
            if not self._table_exists(connection, "simple_runtime_checkpoints"):
                return ()
            rows = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints"
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
        values = tuple(
            checkpoint
            for checkpoint in self._checkpoints()
            if checkpoint.identity.analysis_id == analysis_id
        )
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
            rows = connection.execute(
                """
                SELECT event_json FROM agent_activity_events
                WHERE analysis_id = ? ORDER BY started_at, rowid
                """,
                (analysis_id,),
            ).fetchall()
        events = [AgentActivityEvent.model_validate_json(row[0]) for row in rows]
        if after_event_id is not None:
            for index, event in enumerate(events):
                if event.event_id == after_event_id:
                    events = events[index + 1 :]
                    break
            else:
                raise DashboardNotFound("DASHBOARD_EVENT_CURSOR_NOT_FOUND")
        return tuple(
            AgentActivityView(
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
            )
            for event in events
        )

    def report_path(self, analysis_id: str, display_id: str) -> Path:
        self._validate_analysis_id(analysis_id)
        if _DISPLAY_ID.fullmatch(display_id) is None:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
        try:
            FindingDisplayIdStore.resolve_existing(
                self._database, analysis_id, display_id
            )
        except (LookupError, OSError, sqlite3.Error, ValueError) as error:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error
        root = (self._data_dir / "reports").resolve()
        expected_parent = root / analysis_id
        path = expected_parent / f"{display_id}.md"
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error
        if resolved.parent != expected_parent or not resolved.is_file():
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
        return resolved

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
        completed = sum(item.status is StageStatus.SUCCEEDED for item in values)
        reports = self._reports(analysis_id)
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
            current_stage=latest.stage.value,
            status=self._aggregate_status(values),
            completed_count=completed,
            stage_count=len(values),
            hypothesis_count=len(hypotheses),
            finding_count=len(reports),
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
        )
        if detail:
            return AnalysisDetailView(
                **data.model_dump(),
                hypotheses=hypotheses,
                reports=reports,
            )
        return data

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
        return HypothesisProgressView(
            analysis_id=analysis_id,
            hypothesis_id=hypothesis_id,
            current_stage=latest.stage.value,
            status=DashboardQuery._aggregate_status(values),
            completed_count=completed,
            stage_count=len(values),
            error_code=latest.error_code,
            verdict=final.verdict if final else None,
            validated_poc=any(item.validated_poc_ref is not None for item in values),
            parent_hypothesis_ids=(
                run.parent_hypothesis_ids.get(hypothesis_id, ()) if run else ()
            ),
            chain_depth=(run.chain_depths.get(hypothesis_id, 0) if run else 0),
            attempt_number=max(1, latest.attempt_number),
            updated_at=latest.updated_at,
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
            reports.append(
                FindingReportView(
                    analysis_id=analysis_id,
                    display_id=display_id,
                    url=f"/reports/{analysis_id}/{display_id}.md",
                )
            )
        return tuple(reports)

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


__all__ = ["DashboardNotFound", "DashboardQuery"]
