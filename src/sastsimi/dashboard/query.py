"""Read-only SQLite and report projection for the local dashboard."""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Literal, cast, overload

from sastsimi.config.runtime_paths import RuntimePaths
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
from sastsimi.simple_runtime.store import SimpleCheckpointStore

from .models import (
    AgentActivityView,
    AnalysisDetailView,
    AnalysisSummaryView,
    FindingReportView,
    HypothesisProgressView,
    StaticCoveragePageView,
)

_ANALYSIS_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_DISPLAY_ID = re.compile(r"F-[0-9]{3,}\Z")
_RULE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


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
        recorded_path = report.markdown_path
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
        path = expected_parent / f"{display_id}.md"
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND") from error
        if (
            resolved.parent != expected_parent
            or not resolved.is_file()
            or resolved != Path(recorded_path).resolve()
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
            current_stage=progress.current_stage or latest.stage.value,
            status=(
                "PARTIAL"
                if progress.status == "COMPLETE"
                and run is not None
                and getattr(run, "static_disposition", "FULL") == "PARTIAL"
                else progress.status
            ),
            static_disposition=(
                getattr(run, "static_disposition", "FULL") if run else None
            ),
            completed_count=completed,
            stage_count=len(values),
            hypothesis_count=len(hypotheses),
            finding_count=len(reports),
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
        )
        if detail:
            return AnalysisDetailView.model_validate(
                {
                    **data.model_dump(),
                    **self._static_coverage_projection(values),
                    "hypotheses": hypotheses,
                    "reports": reports,
                }
            )
        return data

    def _static_coverage_projection(
        self, checkpoints: list[StageCheckpoint]
    ) -> dict[str, object]:
        loaded = self._validated_static_coverage(checkpoints)
        if loaded is None:
            return {}
        coverage, digest = loaded
        expected = coverage["expected_count"]
        verified = coverage["verified_count"]
        gaps = coverage["gaps"]
        unsupported_files = coverage.get("unsupported_files", [])
        assert isinstance(expected, int)
        assert isinstance(verified, int)
        assert isinstance(gaps, list)
        assert isinstance(unsupported_files, list)
        raw_unsupported = coverage["unsupported"]
        assert isinstance(raw_unsupported, list)
        unsupported = tuple(
            (str(item["extension"]), int(item["file_count"]))
            for item in raw_unsupported
        )
        reasons = Counter(str(item["reason"]) for item in gaps + unsupported_files)
        parse_count = coverage.get("ast_parse_error_count")
        oversize_count = coverage.get("ast_oversize_count", 0)
        codeql_error = coverage.get("codeql_error")
        engine_errors = coverage.get("engine_errors", [])
        truncated = coverage.get("ast_truncated")
        engines = coverage.get("engine_verified_counts", {})
        codeql_configured = coverage.get("codeql_configured")
        codeql_executed = coverage.get("codeql_executed")
        codeql_scope = coverage.get("codeql_scope")
        if (
            type(parse_count) is not int
            or parse_count < 0
            or type(oversize_count) is not int
            or oversize_count < 0
            or (codeql_error is not None and (
                not isinstance(codeql_error, str)
                or not _RULE_NAME.fullmatch(codeql_error)
            ))
            or not isinstance(engine_errors, list)
            or len(engine_errors) > 32
            or any(
                not isinstance(error, str) or not _RULE_NAME.fullmatch(error)
                for error in engine_errors
            )
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
        if parse_count:
            reasons["ast_parse_errors"] += parse_count
        if oversize_count:
            reasons["ast_oversize_files"] += oversize_count
        if codeql_error is not None:
            reasons["codeql_error"] += 1
        reasons.update(engine_errors)
        return {
            "static_coverage_expected": expected,
            "static_coverage_verified": verified,
            "static_coverage_gap_count": len(gaps),
            "static_coverage_gap_preview": tuple(gaps[:100]),
            "static_coverage_unsupported": unsupported,
            "static_coverage_unsupported_count": (
                len(unsupported_files)
                if "unsupported_files" in coverage
                else sum(count for _, count in unsupported)
            ),
            "static_coverage_reason_counts": dict(sorted(reasons.items())),
            "static_coverage_digest": digest,
            "static_ast_parse_error_count": parse_count,
            "static_ast_truncated": truncated,
            "static_coverage_engines": engines,
            "static_codeql_configured": codeql_configured,
            "static_codeql_executed": codeql_executed,
            "static_codeql_scope": codeql_scope,
        }

    def get_static_coverage_page(
        self, analysis_id: str, *, kind: str, offset: int, limit: int
    ) -> StaticCoveragePageView:
        if kind not in {"gaps", "unsupported"} or offset < 0 or not 1 <= limit <= 100:
            raise ValueError("DASHBOARD_COVERAGE_PAGE_INVALID")
        analysis_id = self._resolve_analysis_id(analysis_id)
        self._validate_analysis_id(analysis_id)
        checkpoints = [
            item
            for item in self._checkpoints()
            if item.identity.analysis_id == analysis_id
        ]
        loaded = self._validated_static_coverage(checkpoints)
        if loaded is None:
            raise DashboardNotFound("DASHBOARD_COVERAGE_NOT_FOUND")
        coverage, digest = loaded
        items = coverage.get("gaps" if kind == "gaps" else "unsupported_files", [])
        assert isinstance(items, list)
        return StaticCoveragePageView(
            kind=kind,
            total=len(items),
            offset=offset,
            limit=limit,
            coverage_digest=digest,
            items=tuple(items[offset : offset + limit]),
        )

    def _validated_static_coverage(
        self, checkpoints: list[StageCheckpoint]
    ) -> tuple[dict[str, object], str] | None:
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
            return None
        artifacts = SimpleArtifactRepository(self._data_dir, static.identity)
        coverage: object = None
        try:
            if static.status is StageStatus.SUCCEEDED:
                if len(static.output_refs) < 2:
                    return None
                bundle = json.loads(artifacts.read(static.output_refs[1]))
                if (
                    not isinstance(bundle, dict)
                    or bundle.get("kind") != "simple_static_fact_bundle"
                ):
                    return None
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
                        coverage_ref = ref
                        break
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if (
            not isinstance(coverage, dict)
            or coverage.get("kind") != "simple_static_coverage_v1"
        ):
            return None
        if (
            coverage.get("analysis_id") != static.identity.analysis_id
            or coverage.get("workspace_id") != static.identity.workspace_id
            or coverage.get("commit_id") != static.identity.commit_id
        ):
            return None
        run = self._simple_run(static.identity.analysis_id)
        run_ref = getattr(run, "static_coverage_ref", None) if run else None
        if run_ref is not None and run_ref != coverage_ref:
            return None
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
            return None
        for item in gaps:
            if not isinstance(item, dict):
                return None
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
                return None
        unsupported_files = coverage.get("unsupported_files", [])
        if not isinstance(unsupported_files, list):
            return None
        for item in unsupported_files:
            if not isinstance(item, dict) or set(item) != {"path", "reason"}:
                return None
            path, reason = item["path"], item["reason"]
            if (
                not isinstance(path, str)
                or not path
                or len(path) > 512
                or path.startswith("/")
                or ".." in PurePosixPath(path).parts
                or "\\" in path
                or ":" in path
                or any(ord(character) < 32 for character in path)
                or not isinstance(reason, str)
                or not _RULE_NAME.fullmatch(reason)
            ):
                return None
        raw_unsupported = coverage.get("unsupported", [])
        if not isinstance(raw_unsupported, list):
            return None
        for item in raw_unsupported:
            if not isinstance(item, dict):
                return None
            extension = item.get("extension")
            count = item.get("file_count")
            if (
                not isinstance(extension, str)
                or (
                    extension != ""
                    and not re.fullmatch(r"\.[A-Za-z0-9]{1,12}", extension)
                )
                or type(count) is not int
                or count < 0
            ):
                return None
        return coverage, coverage_ref.content_hash

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
            scope_source_url=source.get("source_url")
            if isinstance(source.get("source_url"), str)
            and review["provenance_verified"] is True
            else None,
            scope_source_revision=source.get("blob_sha")
            if isinstance(source.get("blob_sha"), str)
            and review["provenance_verified"] is True
            else None,
            scope_reasons=tuple(
                str(item) for item in cast(list[object], review["checks"])
            ),
            scope_missing_information=tuple(
                str(item) for item in cast(list[object], review["missing_information"])
            ),
            scope_axes=cast(dict[str, dict[str, object]], review["axes"]),
            private_reporting_policy_passed=review["private_reporting_policy_passed"]
            is True,
            external_disclosure_allowed=review["external_disclosure_allowed"] is True,
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
            reports.append(
                FindingReportView(
                    analysis_id=analysis_id,
                    display_id=display_id,
                    url=f"/reports/{analysis_id}/{display_id}.md",
                    attachment_urls=self._attachment_urls(analysis_id, display_id),
                )
            )
        return tuple(reports)

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
    def _validate_analysis_id(analysis_id: str) -> None:
        if _ANALYSIS_ID.fullmatch(analysis_id) is None:
            raise DashboardNotFound("DASHBOARD_ANALYSIS_NOT_FOUND")


__all__ = ["DashboardNotFound", "DashboardQuery"]
