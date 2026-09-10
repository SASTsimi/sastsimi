"""Trusted application-side publication for repository and static outputs."""

from dataclasses import dataclass
from datetime import timedelta

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import ErrorId, GapId, WorkspaceId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import (
    AnalysisError,
    CodeLocation,
    CodeWorkspace,
    DataGap,
    RuleExecutionRecord,
    StaticFactBundle,
    ToolCoverage,
    ToolRunResult,
)
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import (
    CandidateLocation,
    PublishedStaticToolMaterial,
    PublishedWorkspaceMaterial,
    RepositoryPreparation,
    StaticToolObservation,
    StaticToolRequest,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.normalizer import (
    StaticNormalizationInput,
    StaticNormalizer,
)


class WorkspacePreparationPublisher:
    """Own metadata, persistence and terminal transition for repository loading."""

    def __init__(self, runner: WorkflowRunner, identity: BudgetScopeRef) -> None:
        self.runner = runner
        self.identity = identity

    def begin(
        self,
        work: WorkExecutionState,
        repository_url: str,
        workspace_id: WorkspaceId,
    ) -> PublishedWorkspaceMaterial:
        if work.status != "RUNNING" or work.active_attempt_id is None:
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        workspace = CodeWorkspace.model_validate_json(
            canonical_bytes(
                {
                    "meta": self.runner.metadata(work.meta, "code_workspace"),
                    "workspace_id": workspace_id,
                    "analysis_id": work.meta.analysis_id,
                    "repository_url": repository_url,
                    "commit_id": None,
                    "status": "PREPARING",
                }
            )
        )
        (workspace_ref,) = self.runner.publish_intermediate(
            work, self.identity, "REPOSITORY_LOADER", (workspace,)
        )
        if not isinstance(workspace_ref, RunStoredDataRef):
            raise ValueError("WORKSPACE_LIFECYCLE_INVALID")
        return PublishedWorkspaceMaterial(
            workspace=workspace,
            workspace_ref=workspace_ref,
            work=self.runner.runtime.work.get(str(work.work_id)),
            analysis_state=self.runner.runtime.budget_registry.current_state(
                str(work.meta.analysis_id)
            ),
        )

    def finish(
        self,
        work: WorkExecutionState,
        preparing: PublishedWorkspaceMaterial,
        outcome: RepositoryPreparation,
    ) -> PublishedWorkspaceMaterial:
        current = self.runner.runtime.work.get(str(work.work_id))
        if (
            current != preparing.work
            or current.status != "RUNNING"
            or preparing.workspace.status != "PREPARING"
            or preparing.workspace_ref != reference(preparing.workspace)
            or str(preparing.workspace.analysis_id) != outcome.analysis_id
            or str(preparing.workspace.workspace_id) != outcome.workspace_id
            or preparing.workspace.repository_url != outcome.repository_url
        ):
            raise ValueError("WORKSPACE_LIFECYCLE_INVALID")
        terminal = CodeWorkspace.model_validate_json(
            canonical_bytes(
                {
                    "meta": self.runner.revision_metadata(preparing.workspace.meta),
                    "workspace_id": preparing.workspace.workspace_id,
                    "analysis_id": preparing.workspace.analysis_id,
                    "repository_url": preparing.workspace.repository_url,
                    "commit_id": outcome.resolved_commit_id,
                    "status": outcome.status,
                }
            )
        )
        if outcome.status == "READY":
            completed = self.runner.complete(
                current, self.identity, "REPOSITORY_LOADER", (terminal,)
            )
        else:
            error_ids = tuple(
                str(self.runner.ids.new(ErrorId)) for _ in (outcome.errors or (None,))
            )
            completed = self.runner.complete(
                current,
                self.identity,
                "REPOSITORY_LOADER",
                (terminal,),
                status="FAILED",
                cause="REPOSITORY_PREPARATION_FAILED",
                error_ids=error_ids,
            )
        terminal_ref = reference(terminal)
        if not isinstance(terminal_ref, RunStoredDataRef):
            raise ValueError("WORKSPACE_LIFECYCLE_INVALID")
        return PublishedWorkspaceMaterial(
            workspace=terminal,
            workspace_ref=terminal_ref,
            work=completed,
            analysis_state=self.runner.runtime.budget_registry.current_state(
                str(work.meta.analysis_id)
            ),
        )


def _location(request: StaticToolRequest, value: CandidateLocation) -> CodeLocation:
    commit_id = request.workspace.commit_id
    if commit_id is None:
        raise ValueError("WORKSPACE_NOT_READY")
    return CodeLocation(
        workspace_id=request.workspace.workspace_id,
        commit_id=commit_id,
        file_path=value.file_path,
        start_line=value.start_line,
        start_column=value.start_column,
        end_line=value.end_line,
        end_column=value.end_column,
    )


class StaticAttemptPublisher:
    """Allocate trusted records and atomically close one static-tool attempt."""

    def __init__(self, runner: WorkflowRunner) -> None:
        self.runner = runner

    def publish(
        self, request: StaticToolRequest, observation: StaticToolObservation
    ) -> PublishedStaticToolMaterial:
        work = self._current_work(request)
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("STATIC_TOOL_PUBLICATION_INVALID")
        identity = request.action.requester_identity_ref
        now = self.runner.clock.now()
        elapsed_ms = max(
            0,
            observation.finished_monotonic_ms - observation.started_monotonic_ms,
        )
        started_at = now - timedelta(milliseconds=elapsed_ms)

        raw_ref: StoredDataRef | None = None
        if observation.raw_output is not None:
            media_type = observation.raw_media_type
            if media_type is None:
                raise ValueError("STATIC_TOOL_OBSERVATION_INVALID")
            raw_ref = self.runner.runtime.unit_of_work.artifacts.commit(
                self.runner.runtime.unit_of_work.artifacts.stage_bytes(
                    observation.raw_output, media_type
                )
            )

        gaps = tuple(
            DataGap(
                gap_id=self.runner.ids.new(GapId),
                stage=gap.stage,  # type: ignore[arg-type]
                code=gap.code,
                reason=gap.reason,  # type: ignore[arg-type]
                description=gap.description,
                affected_paths=gap.affected_paths,
                affected_languages=gap.affected_languages,
                affected_locations=tuple(
                    _location(request, location) for location in gap.affected_locations
                ),
                retryable=gap.retryable,
                related_record_ids=(),
                created_at=now,
            )
            for gap in observation.gaps
        )
        errors = tuple(
            AnalysisError(
                error_id=self.runner.ids.new(ErrorId),
                stage=error.stage,  # type: ignore[arg-type]
                code=error.code,
                safe_message=error.safe_message,
                retryable=error.retryable,
                work_id=work.work_id,
                attempt_id=work.active_attempt_id,
                related_record_ids=(),
                created_at=now,
            )
            for error in observation.errors
        )

        rule: RuleExecutionRecord | None = None
        rule_ref: StoredDataRef | None = None
        if observation.tool_kind == "RULE_BASED":
            if request.rule_catalog_ref is not None and observation.rules:
                rule = RuleExecutionRecord.model_validate_json(
                    canonical_bytes(
                        {
                            "meta": self.runner.metadata(
                                work.meta,
                                "rule_execution_record",
                                attempt_id=work.active_attempt_id,
                            ),
                            "tool_name": observation.tool_name,
                            "tool_version": observation.tool_version,
                            "analysis_config_ref": request.analysis_config_ref,
                            "rule_catalog_ref": request.rule_catalog_ref,
                            "selected_rule_packs": observation.selected_rule_packs,
                            "rules": tuple(item.__dict__ for item in observation.rules),
                        }
                    )
                )
                candidate_rule_ref = reference(rule)
                if not isinstance(candidate_rule_ref, StoredDataRef):
                    raise ValueError("RULE_EXECUTION_REQUIRED")
                rule_ref = candidate_rule_ref
            elif observation.status != "FAILED":
                raise ValueError("RULE_EXECUTION_REQUIRED")

        result = ToolRunResult.model_validate_json(
            canonical_bytes(
                {
                    "meta": self.runner.metadata(
                        work.meta,
                        "tool_run_result",
                        attempt_id=work.active_attempt_id,
                    ),
                    "tool_name": observation.tool_name,
                    "tool_version": observation.tool_version,
                    "tool_kind": observation.tool_kind,
                    "status": observation.status,
                    "coverage": ToolCoverage(
                        analyzed_paths=observation.analyzed_paths,
                        skipped_paths=observation.skipped_paths,
                        analyzed_languages=observation.analyzed_languages,
                        skipped_languages=observation.skipped_languages,
                        notes=observation.notes,
                    ),
                    "rule_execution_ref": rule_ref,
                    "raw_result_ref": raw_ref,
                    "gaps": gaps,
                    "errors": errors,
                    "started_at": started_at,
                    "finished_at": now,
                    "elapsed_ms": elapsed_ms,
                }
            )
        )
        status, cause = self._terminal_mapping(result)
        outputs = (result,) if rule is None else (result, rule)
        completed = self.runner.complete(
            work,
            identity,
            "STATIC_ANALYSIS",
            outputs,
            status=status,
            cause=cause,
            gap_ids=tuple(str(item.gap_id) for item in gaps),
            error_ids=tuple(str(item.error_id) for item in errors),
        )
        result_ref = completed.output_refs[0]
        candidate_result_ref = reference(result)
        if (
            not isinstance(result_ref, StoredDataRef)
            or not isinstance(candidate_result_ref, StoredDataRef)
            or result_ref != candidate_result_ref
        ):
            raise ValueError("STATIC_TOOL_PUBLICATION_INVALID")
        return PublishedStaticToolMaterial(
            result=result,
            result_ref=result_ref,
            rule_execution=rule,
            rule_execution_ref=rule_ref,
            observation=observation,
        )

    def _current_work(self, request: StaticToolRequest) -> WorkExecutionState:
        ref = request.action.work_ref
        if ref is None:
            raise ValueError("STATIC_TOOL_PUBLICATION_INVALID")
        referenced = self.runner.runtime.unit_of_work.records.get_exact(ref)
        if not isinstance(referenced, WorkExecutionState):
            raise ValueError("STATIC_TOOL_PUBLICATION_INVALID")
        work = self.runner.runtime.work.get(str(referenced.work_id))
        if (
            work.status != "RUNNING"
            or not isinstance(request.action.meta, RecordMeta)
            or work.active_attempt_id != request.action.meta.attempt_id
            or reference(work) != ref
            or work.work_type != "STATIC_TOOL"
        ):
            raise ValueError("STATIC_TOOL_PUBLICATION_INVALID")
        return work

    @staticmethod
    def _terminal_mapping(result: ToolRunResult) -> tuple[str, str]:
        cancelled = any(gap.code == "STATIC_TOOL_CANCELLED" for gap in result.gaps)
        if cancelled:
            if result.status not in {"SKIPPED", "PARTIAL"}:
                raise ValueError("STATIC_TOOL_STATUS_INVALID")
            return "CANCELLED", "CALLER_CANCELLED"
        if result.status == "SUCCEEDED":
            return "SUCCEEDED", "COMPLETED"
        if result.status == "PARTIAL" or result.status == "SKIPPED":
            return (
                "PARTIAL",
                "NOT_APPLICABLE" if result.status == "SKIPPED" else "PARTIAL",
            )
        return "FAILED", "STATIC_TOOL_FAILED"


@dataclass(frozen=True)
class StaticNormalizationSource:
    """Trusted identity needed to resolve one expected terminal tool work."""

    tool_work_ref: StoredDataRef
    profile_ref: StoredDataRef
    catalog_rule_ids: tuple[str, ...] = ()


class StaticNormalizationPublisher:
    """Resolve verified raw inputs and atomically publish one normalized bundle."""

    def __init__(self, runner: WorkflowRunner, normalizer: StaticNormalizer) -> None:
        self.runner = runner
        self.normalizer = normalizer

    def publish(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        workspace: CodeWorkspace,
        sources: tuple[StaticNormalizationSource, ...],
    ) -> tuple[StaticFactBundle, StoredDataRef]:
        current = self.runner.runtime.work.get(str(work.work_id))
        if current.status in {"SUCCEEDED", "PARTIAL"}:
            if len(current.output_refs) != 1:
                raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
            existing_ref = current.output_refs[0]
            existing = self.runner.runtime.unit_of_work.records.get_exact(existing_ref)
            if not isinstance(existing_ref, StoredDataRef) or not isinstance(
                existing, StaticFactBundle
            ):
                raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
            return existing, existing_ref
        if (
            current != work
            or current.status != "RUNNING"
            or current.work_type != "STATIC_NORMALIZE"
            or current.active_attempt_id is None
            or not isinstance(current.meta, RecordMeta)
            or workspace.status != "READY"
            or workspace.workspace_id != current.meta.workspace_id
            or workspace.commit_id != current.meta.commit_id
            or not sources
            or len({item.tool_work_ref for item in sources}) != len(sources)
        ):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        materials = tuple(self._resolve_source(current, source) for source in sources)
        bundle = self.normalizer.normalize(
            bundle_meta=RecordMeta.model_validate(
                self.runner.metadata(current.meta, "static_fact_bundle")
            ),
            workspace=workspace,
            materials=materials,
        )
        partial = bool(
            bundle.gaps
            or bundle.errors
            or any(result.status != "SUCCEEDED" for result in bundle.tool_runs)
        )
        completed = self.runner.complete(
            current,
            identity,
            "STATIC_ANALYSIS",
            (bundle,),
            status="PARTIAL" if partial else "SUCCEEDED",
            cause="PARTIAL" if partial else "COMPLETED",
            gap_ids=tuple(str(item.gap_id) for item in bundle.gaps),
            error_ids=tuple(str(item.error_id) for item in bundle.errors),
        )
        bundle_ref = completed.output_refs[0]
        expected_ref = reference(bundle)
        if (
            not isinstance(bundle_ref, StoredDataRef)
            or not isinstance(expected_ref, StoredDataRef)
            or bundle_ref != expected_ref
        ):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        return bundle, bundle_ref

    def _resolve_source(
        self, work: WorkExecutionState, source: StaticNormalizationSource
    ) -> StaticNormalizationInput:
        if work.input_refs.count(source.tool_work_ref) != 1:
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        records = self.runner.runtime.unit_of_work.records
        referenced = records.get_exact(source.tool_work_ref)
        if not isinstance(referenced, WorkExecutionState):
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        tool_work = self.runner.runtime.work.get(str(referenced.work_id))
        if (
            tool_work != referenced
            or tool_work.work_type != "STATIC_TOOL"
            or tool_work.status not in {"SUCCEEDED", "PARTIAL", "FAILED", "CANCELLED"}
            or tool_work.input_refs.count(source.profile_ref) != 1
        ):
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        result_refs = tuple(
            ref for ref in tool_work.output_refs if ref.data_kind == "tool_run_result"
        )
        if len(result_refs) != 1 or not isinstance(result_refs[0], StoredDataRef):
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        result = records.get_exact(result_refs[0])
        profile = self.runner.runtime.configuration.resolve_static_tool_profile(
            source.profile_ref
        )
        if not isinstance(result, ToolRunResult):
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        rule: RuleExecutionRecord | None = None
        if result.rule_execution_ref is not None:
            candidate = records.get_exact(result.rule_execution_ref)
            if not isinstance(candidate, RuleExecutionRecord):
                raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
            rule = candidate
        raw: bytes | None = None
        if result.raw_result_ref is not None:
            with self.runner.runtime.unit_of_work.artifacts.open_verified(
                result.raw_result_ref
            ) as stream:
                raw = stream.read(profile.max_artifact_read_bytes + 1)
            if len(raw) > profile.max_artifact_read_bytes:
                raise ValueError("STATIC_ARTIFACT_READ_LIMIT")
        return StaticNormalizationInput(
            result_ref=result_refs[0],
            result=result,
            profile_ref=source.profile_ref,
            profile=profile,
            raw_bytes=raw,
            rule_execution=rule,
            catalog_rule_ids=source.catalog_rule_ids,
        )
