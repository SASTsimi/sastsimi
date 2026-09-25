"""Read-only SQLite and report projection for the local dashboard."""

from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, overload

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import AgentActivityEvent
from sastsimi.progress.projector import ProgressProjector
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from sastsimi.simple_runtime.store import ROLE_BY_STAGE

from .models import (
    AgentActivityView,
    AnalysisDetailView,
    AnalysisSummaryView,
    ArtifactContentView,
    ArtifactView,
    FindingReportView,
    HypothesisProgressView,
    LLMInvocationView,
    ReadinessCheckView,
    StageProgressView,
    StaticToolProgressView,
    UsageSummaryView,
)

_ANALYSIS_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_DISPLAY_ID = re.compile(r"F-[0-9]{3,}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ARTIFACT_BYTES = 1024 * 1024
_MAX_ARTIFACTS = 512
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
                provider=event.provider,
                model=event.model,
                prompt_digest=event.prompt_digest,
                output_digest=event.output_digest,
            )
            for event in events
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
        _, contents, _, _, _ = self._artifact_projection(exact, values, run)
        item = contents.get(artifact_id)
        if item is None:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_NOT_FOUND")
        kind, media_type, raw, parsed = item
        return ArtifactContentView(
            artifact_id=artifact_id,
            kind=kind,
            media_type=media_type,
            content=parsed if parsed is not None else raw.decode("utf-8", "replace"),
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
        _, contents, _, _, _ = self._artifact_projection(exact, values, run)
        item = contents.get(artifact_id)
        if item is None:
            raise DashboardNotFound("DASHBOARD_ARTIFACT_NOT_FOUND")
        kind, media_type, raw, _ = item
        return kind, media_type, raw

    def report_markdown(self, analysis_id: str, display_id: str) -> str:
        exact = self._resolved(analysis_id)
        try:
            return self.report_path(exact, display_id).read_text(encoding="utf-8")
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
            _, contents, _, _, _ = self._artifact_projection(exact, values, run)
        for artifact in detail.artifacts:
            if artifact_ids is not None and artifact.artifact_id not in artifact_ids:
                continue
            item = contents.get(artifact.artifact_id)
            if item is None:
                continue
            kind, media_type, raw, _ = item
            suffix = ".json" if media_type == "application/json" else ".txt"
            safe_kind = re.sub(r"[^A-Za-z0-9_.-]", "-", kind)[:80] or "artifact"
            members[
                f"artifacts/{safe_kind}-{artifact.artifact_id[:12]}{suffix}"
            ] = raw
        for report in detail.reports:
            if report_ids is not None and report.display_id not in report_ids:
                continue
            members[f"reports/{report.display_id}.md"] = self.report_markdown(
                exact, report.display_id
            ).encode("utf-8")
            english = (
                RuntimePaths(self._data_dir).reports
                / exact
                / f"{report.display_id}.en.md"
            ).resolve()
            expected_parent = (RuntimePaths(self._data_dir).reports / exact).resolve()
            if english.parent == expected_parent and english.is_file():
                try:
                    members[f"reports/en/{report.display_id}.md"] = english.read_bytes()
                except OSError:
                    pass
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
            raw = repository.read(ref)
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
            media = (
                "text/markdown"
                if safe.lstrip().startswith(b"#")
                else "text/plain"
            )
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
        refs: dict[str, StoredDataRef] = {}
        queue: list[tuple[StoredDataRef, str, str | None]] = []

        def enqueue(
            ref: StoredDataRef | None,
            stage: str,
            hypothesis: str | None,
        ) -> None:
            if ref is None:
                return
            if (
                str(ref.workspace_id) != run.workspace_id
                or str(ref.commit_id) != run.commit_id
            ):
                return
            digest = ref.content_hash
            sources[digest]["stages"].add(stage)
            if hypothesis:
                sources[digest]["hypotheses"].add(hypothesis)
            if digest not in refs and len(refs) < _MAX_ARTIFACTS:
                refs[digest] = ref
                queue.append((ref, stage, hypothesis))

        enqueue(run.repository_profile_ref, "REPOSITORY", None)
        enqueue(run.static_bundle_ref, SimpleStage.STATIC_DONE.value, None)
        for checkpoint in values:
            stage = checkpoint.stage.value
            hypothesis = checkpoint.identity.hypothesis_id
            for ref in (*checkpoint.input_refs, *checkpoint.output_refs):
                enqueue(ref, stage, hypothesis)
            for optional_ref in (
                checkpoint.recipe_ref,
                checkpoint.validated_poc_ref,
                checkpoint.report_ref,
            ):
                enqueue(optional_ref, stage, hypothesis)
        events = self._event_models(analysis_id)
        for event in events:
            for ref in (*event.input_refs, *event.output_refs, *event.tool_result_refs):
                enqueue(ref, event.stage, event.hypothesis_id)

        contents: dict[str, tuple[str, str, bytes, Any | None]] = {}
        token_usage: dict[str, tuple[int | None, int | None]] = {}
        index = 0
        while index < len(queue) and len(contents) < _MAX_ARTIFACTS:
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

        artifacts = tuple(
            ArtifactView(
                artifact_id=digest,
                kind=item[0],
                data_kind=refs[digest].data_kind,
                media_type=item[1],
                size_bytes=len(item[2]),
                stages=tuple(sorted(sources[digest]["stages"])),
                hypothesis_ids=tuple(sorted(sources[digest]["hypotheses"])),
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
        return artifacts, contents, invocations, poc_ids, evidence_ids

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
            if (
                kind not in {"simple_llm_request", "simple_llm_response"}
                or not isinstance(artifact_invocation_id, str)
            ):
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
            if run is not None:
                artifacts, contents, invocations, poc_ids, evidence_ids = (
                    self._artifact_projection(analysis_id, values, run)
                )
                static_tools = self._static_tools(run, values)
                hypotheses = self._with_hypothesis_metadata(hypotheses, contents)
            return AnalysisDetailView(
                **data.model_dump(),
                hypotheses=hypotheses,
                reports=reports,
                pipeline=self._pipeline(values, run),
                static_tools=static_tools,
                readiness=self._readiness(
                    analysis_id,
                    run,
                    static_tools,
                    artifacts,
                    reports,
                ),
                usage=self._usage_summary(invocations),
                artifacts=artifacts,
                llm_invocations=invocations,
                poc_artifact_ids=poc_ids,
                evidence_artifact_ids=evidence_ids,
                logs_url=f"/api/analyses/{analysis_id}/logs/download",
                bundle_url=f"/api/analyses/{analysis_id}/bundle.zip",
            )
        return data

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
        artifacts: tuple[ArtifactView, ...],
        reports: tuple[FindingReportView, ...],
    ) -> tuple[ReadinessCheckView, ...]:
        def present(value: object) -> bool:
            return value is not None and str(value).strip() != ""

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
                status=("READY" if artifacts and (reports or log_ready) else "WAITING"),
                detail_ko=(
                    f"아티팩트 {len(artifacts)}개·보고서 {len(reports)}개"
                    + ("·로그 있음" if log_ready else "·로그 없음")
                ),
                required=False,
            ),
        )

    @staticmethod
    def _usage_summary(
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
    def _pipeline(
        values: list[StageCheckpoint], run: SimpleAnalysisRun | None
    ) -> tuple[StageProgressView, ...]:
        actual = {
            (item.identity.hypothesis_id, item.stage): item for item in values
        }
        result: list[StageProgressView] = []

        def append(stage: SimpleStage, hypothesis_id: str | None) -> None:
            checkpoint = actual.get((hypothesis_id, stage))
            result.append(
                StageProgressView(
                    stage=stage.value,
                    label_ko=_STAGE_LABELS[stage],
                    status=(
                        checkpoint.status.value if checkpoint else "NOT_STARTED"
                    ),
                    hypothesis_id=hypothesis_id,
                    agent_role=ROLE_BY_STAGE[stage],
                    attempt_number=(checkpoint.attempt_number if checkpoint else 0),
                    output_count=(len(checkpoint.output_refs) if checkpoint else 0),
                    retryable=(checkpoint.retryable if checkpoint else False),
                    error_code=(checkpoint.error_code if checkpoint else None),
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
        self, run: SimpleAnalysisRun, values: list[StageCheckpoint]
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
        codeql_executed = bool(bundle.get("codeql_executed"))
        return (
            StaticToolProgressView(
                tool="AST",
                status="SUCCEEDED" if completed else base_status,
            ),
            StaticToolProgressView(
                tool="OpenGrep",
                status="SUCCEEDED" if completed else base_status,
                finding_count=(
                    len(bundle.get("opengrep_findings", []))
                    if isinstance(bundle.get("opengrep_findings"), list)
                    else None
                ),
            ),
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
            ),
        )

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
                    view_url=(
                        f"/api/analyses/{analysis_id}/reports/{display_id}"
                    ),
                    download_url=(
                        f"/api/analyses/{analysis_id}/reports/{display_id}/download"
                    ),
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
