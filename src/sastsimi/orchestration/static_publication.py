"""Trusted application-side publication for repository and static outputs."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from datetime import timedelta
from types import MappingProxyType

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import (
    ErrorId,
    GapId,
    TransitionCommitId,
    TransitionId,
    WorkspaceId,
)
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
    RuleExecutionItem,
    RuleExecutionRecord,
    StaticFactBundle,
    ToolCoverage,
    ToolRunResult,
    validate_rule_execution,
    validate_static_current,
)
from sastsimi.contracts.work import (
    StateTransition,
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
)
from sastsimi.ports.dto import (
    CandidateLocation,
    CandidateRule,
    PublishedStaticToolMaterial,
    PublishedWorkspaceMaterial,
    RepositoryPreparation,
    StaticRuleMapping,
    StaticToolObservation,
    StaticToolRequest,
    TransitionCommitRequest,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.coordinator import StaticToolCoordinator
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

    def __init__(
        self,
        runner: WorkflowRunner,
        rule_catalogs: Mapping[StoredDataRef, tuple[str, ...]] | None = None,
        rule_selections: Mapping[StoredDataRef, tuple[str, ...]] | None = None,
    ) -> None:
        self.runner = runner
        self.rule_catalogs = dict(rule_catalogs or {})
        self.rule_selections = dict(rule_selections or {})

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
        profile = self.runner.runtime.configuration.resolve_static_tool_profile(
            request.tool_profile_ref
        )
        catalog_rule_ids: tuple[str, ...] = ()
        if observation.tool_kind == "RULE_BASED":
            if request.rule_catalog_ref is None:
                raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
            try:
                catalog_rule_ids = self.rule_catalogs[request.rule_catalog_ref]
            except KeyError as error:
                raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH") from error
            if observation.status == "FAILED" and not observation.rules:
                observation = replace(
                    observation,
                    rules=self._nonexecuted_rules(
                        request.rule_catalog_ref,
                        catalog_rule_ids,
                        "TOOL_FAILURE",
                    ),
                )
            self._validate_rule_catalog(
                observation.rules, catalog_rule_ids, observation.status
            )
        elif (
            request.rule_catalog_ref is not None
            or observation.rules
            or observation.selected_rule_packs
        ):
            raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
        StaticToolCoordinator._validate_observation(
            profile, observation, request.action.file_paths
        )
        self._validate_status_shape(observation)

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
        if rule is not None:
            validate_rule_execution(result, rule, catalog_rule_ids)
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

    @staticmethod
    def _validate_rule_catalog(
        rules: tuple[CandidateRule, ...],
        catalog_rule_ids: tuple[str, ...],
        status: str | None = None,
    ) -> None:
        actual = tuple(item.rule_id for item in rules)
        if (
            not catalog_rule_ids
            or len(actual) != len(set(actual))
            or len(catalog_rule_ids) != len(set(catalog_rule_ids))
            or set(actual) != set(catalog_rule_ids)
        ):
            raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
        try:
            for item in rules:
                RuleExecutionItem.model_validate(asdict(item), strict=True)
        except ValueError as error:
            raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH") from error
        selected = tuple(item for item in rules if item.selection_status == "SELECTED")
        if (
            status == "SUCCEEDED"
            and (
                not selected
                or any(item.execution_status != "EXECUTED" for item in selected)
            )
        ) or (
            status == "SKIPPED"
            and any(item.execution_status == "EXECUTED" for item in rules)
        ):
            raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")

    @staticmethod
    def _validate_status_shape(observation: StaticToolObservation) -> None:
        has_raw = observation.raw_output is not None
        if (
            (observation.raw_output is None) != (observation.raw_media_type is None)
            or (
                observation.status == "SUCCEEDED"
                and (not has_raw or observation.gaps or observation.errors)
            )
            or (
                observation.status == "PARTIAL"
                and (not has_raw or not observation.gaps)
            )
            or (
                observation.status == "FAILED"
                and (
                    not observation.gaps
                    or not observation.errors
                    or observation.symbols
                    or observation.facts
                    or observation.relations
                )
            )
            or (
                observation.status == "SKIPPED"
                and (
                    has_raw
                    or not observation.gaps
                    or observation.errors
                    or observation.symbols
                    or observation.facts
                    or observation.relations
                )
            )
        ):
            raise ValueError("STATIC_TOOL_STATUS_INVALID")

    def _nonexecuted_rules(
        self,
        catalog_ref: StoredDataRef,
        catalog_rule_ids: tuple[str, ...],
        reason: str,
    ) -> tuple[CandidateRule, ...]:
        try:
            selected_rule_ids = self.rule_selections[catalog_ref]
        except KeyError as error:
            raise ValueError("RULE_CATALOG_SELECTION_REQUIRED") from error
        if len(selected_rule_ids) != len(set(selected_rule_ids)) or not set(
            selected_rule_ids
        ).issubset(catalog_rule_ids):
            raise ValueError("RULE_CATALOG_SELECTION_INVALID")
        selected = set(selected_rule_ids)
        return tuple(
            CandidateRule(
                rule_id,
                "SELECTED" if rule_id in selected else "NOT_SELECTED",
                "NOT_EXECUTED",
                None,
                reason if rule_id in selected else "NOT_SELECTED",
                None,
            )
            for rule_id in catalog_rule_ids
        )


@dataclass(frozen=True)
class StaticNormalizationSource:
    """Trusted identity needed to resolve one expected terminal tool work."""

    tool_work_ref: StoredDataRef
    profile_ref: StoredDataRef
    analysis_config_ref: StoredDataRef
    rule_catalog_ref: StoredDataRef | None = None
    catalog_rule_ids: tuple[str, ...] = ()


class StaticNormalizationPublisher:
    """Resolve verified raw inputs and atomically publish one normalized bundle."""

    def __init__(
        self,
        runner: WorkflowRunner,
        normalizer: StaticNormalizer,
        rule_mappings: Mapping[
            StoredDataRef, tuple[StaticRuleMapping, ...]
        ] | None = None,
    ) -> None:
        self.runner = runner
        self.normalizer = normalizer
        self._rule_mappings = MappingProxyType(dict(rule_mappings or {}))

    def publish(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        workspace: CodeWorkspace,
        sources: tuple[StaticNormalizationSource, ...],
    ) -> tuple[StaticFactBundle, StoredDataRef]:
        current = self.runner.runtime.work.get(str(work.work_id))
        self._validate_workspace_and_sources(current, workspace, sources)
        materials = tuple(
            self._resolve_source(current, workspace, source) for source in sources
        )
        if current.status in {"SUCCEEDED", "PARTIAL"}:
            if len(current.output_refs) != 1:
                raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
            existing_ref = current.output_refs[0]
            existing = self.runner.runtime.unit_of_work.records.get_exact(existing_ref)
            if not isinstance(existing_ref, StoredDataRef) or not isinstance(
                existing, StaticFactBundle
            ):
                raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
            self._validate_committed_bundle(
                current, workspace, existing, existing_ref, materials
            )
            return existing, existing_ref
        if (
            current != work
            or current.status != "RUNNING"
            or current.work_type != "STATIC_NORMALIZE"
            or current.active_attempt_id is None
            or not isinstance(current.meta, RecordMeta)
        ):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        try:
            bundle = self.normalizer.normalize(
                bundle_meta=RecordMeta.model_validate(
                    self.runner.metadata(current.meta, "static_fact_bundle")
                ),
                workspace=workspace,
                materials=materials,
            )
        except ValueError as error:
            if str(error) != "STATIC_NORMALIZATION_NO_USABLE_INPUT":
                raise
            self._fail_no_usable(current, materials)
            raise
        partial = bool(
            bundle.gaps
            or bundle.errors
            or any(result.status != "SUCCEEDED" for result in bundle.tool_runs)
        )
        bundle_ref = reference(bundle)
        if not isinstance(bundle_ref, StoredDataRef):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        self._validate_bundle_candidate(
            current,
            workspace,
            bundle,
            bundle_ref,
            materials,
            partial=partial,
        )
        self.runner.complete(
            current,
            identity,
            "STATIC_ANALYSIS",
            (bundle,),
            status="PARTIAL" if partial else "SUCCEEDED",
            cause="PARTIAL" if partial else "COMPLETED",
            gap_ids=tuple(str(item.gap_id) for item in bundle.gaps),
            error_ids=tuple(str(item.error_id) for item in bundle.errors),
        )
        return bundle, bundle_ref

    def _validate_workspace_and_sources(
        self,
        work: WorkExecutionState,
        workspace: CodeWorkspace,
        sources: tuple[StaticNormalizationSource, ...],
    ) -> None:
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        expected = [
            input_ref
            for input_ref in work.input_refs
            if isinstance(input_ref, StoredDataRef)
            and input_ref.data_kind == "work_execution_state"
        ]
        supplied = tuple(item.tool_work_ref for item in sources)
        self._validate_source_set(tuple(expected), supplied)
        config_refs = {item.analysis_config_ref for item in sources}
        catalog_refs = {
            item.rule_catalog_ref
            for item in sources
            if item.rule_catalog_ref is not None
        }
        workspace_ref = reference(workspace)
        expected_inputs = {workspace_ref, *supplied, *config_refs, *catalog_refs}
        if (
            len(config_refs) != 1
            or workspace.status != "READY"
            or workspace.workspace_id != work.meta.workspace_id
            or workspace.commit_id != work.meta.commit_id
            or len(work.input_refs) != len(expected_inputs)
            or set(work.input_refs) != expected_inputs
        ):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")

    @staticmethod
    def _validate_source_set(
        expected: tuple[StoredDataRef, ...], supplied: tuple[StoredDataRef, ...]
    ) -> None:
        if (
            not expected
            or len(expected) != len(set(expected))
            or len(supplied) != len(set(supplied))
            or set(supplied) != set(expected)
        ):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")

    def _validate_committed_bundle(
        self,
        work: WorkExecutionState,
        workspace: CodeWorkspace,
        bundle: StaticFactBundle,
        bundle_ref: StoredDataRef,
        materials: tuple[StaticNormalizationInput, ...],
    ) -> None:
        if work.last_transition_commit_ref is None:
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        records = self.runner.runtime.unit_of_work.records
        commit = records.get_exact(work.last_transition_commit_ref)
        if not isinstance(commit, TransitionCommit) or commit.attempt_id is None:
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        attempts = tuple(
            item
            for item in self.runner.runtime.queries.published_records(
                str(work.meta.analysis_id)
            )
            if isinstance(item, WorkAttempt)
            and item.work_id == work.work_id
            and item.attempt_id == commit.attempt_id
            and item.status.value == work.status.value
            and item.output_refs == work.output_refs
        )
        if len(attempts) != 1:
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        if bundle.tool_runs != self._expected_runs(materials):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        rules, catalogs, analysis_config_ref = self._rule_context(materials)
        validate_static_current(
            bundle,
            bundle_ref,
            workspace,
            work,
            commit,
            rules,
            attempt=attempts[0],
            rule_catalogs=catalogs,
            analysis_config_ref=analysis_config_ref,
        )

    def _validate_bundle_candidate(
        self,
        work: WorkExecutionState,
        workspace: CodeWorkspace,
        bundle: StaticFactBundle,
        bundle_ref: StoredDataRef,
        materials: tuple[StaticNormalizationInput, ...],
        *,
        partial: bool,
    ) -> None:
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        attempt = self._current_running_attempt(work)
        if attempt.input_hash != work.input_hash:
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        expected_runs = self._expected_runs(materials)
        scope = (work.meta.analysis_id, work.meta.workspace_id, work.meta.commit_id)
        if (
            work.status != "RUNNING"
            or work.active_attempt_id is None
            or bundle.meta.attempt_id is not None
            or (
                bundle.meta.analysis_id,
                bundle.meta.workspace_id,
                bundle.meta.commit_id,
            )
            != scope
            or (workspace.analysis_id, workspace.workspace_id, workspace.commit_id)
            != scope
            or reference(bundle) != bundle_ref
            or bundle.tool_runs != expected_runs
            or partial
            != bool(
                bundle.gaps
                or bundle.errors
                or any(run.status != "SUCCEEDED" for run in bundle.tool_runs)
            )
            or (
                partial
                and not (
                    bundle.gaps
                    or bundle.errors
                    or any(run.gaps or run.errors for run in bundle.tool_runs)
                )
            )
        ):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        rules, catalogs, analysis_config_ref = self._rule_context(materials)
        for run in bundle.tool_runs:
            if run.rule_execution_ref is None:
                continue
            matches = tuple(
                record
                for record in rules
                if record.meta.record_id == run.rule_execution_ref.record_id
            )
            if len(matches) != 1:
                raise ValueError("RULE_EXECUTION_REQUIRED")
            record = matches[0]
            if (
                record.rule_catalog_ref not in catalogs
                or record.analysis_config_ref != analysis_config_ref
            ):
                raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
            validate_rule_execution(run, record, catalogs[record.rule_catalog_ref])
        for fact in bundle.facts():
            if fact.producer.rule_id is None:
                continue
            matches = tuple(
                record
                for record in rules
                if record.meta.attempt_id == fact.producer.attempt_id
            )
            if len(matches) != 1:
                raise ValueError("RULE_EXECUTION_REQUIRED")
            executed = tuple(
                rule
                for rule in matches[0].rules
                if rule.rule_id == fact.producer.rule_id
            )
            if (
                len(executed) != 1
                or executed[0].execution_status != "EXECUTED"
                or not executed[0].hit_count
            ):
                raise ValueError("FACT_WITHOUT_RAW_HIT")

    @staticmethod
    def _expected_runs(
        materials: tuple[StaticNormalizationInput, ...],
    ) -> tuple[ToolRunResult, ...]:
        return tuple(
            item.result
            for item in sorted(
                materials,
                key=lambda item: (
                    item.result.tool_name,
                    item.result.tool_version,
                    str(item.result.meta.attempt_id),
                    str(item.result.meta.record_id),
                ),
            )
        )

    def _current_running_attempt(self, work: WorkExecutionState) -> WorkAttempt:
        if work.active_attempt_id is None:
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        attempts = tuple(
            item
            for item in self.runner.runtime.queries.published_records(
                str(work.meta.analysis_id)
            )
            if isinstance(item, WorkAttempt)
            and item.work_id == work.work_id
            and item.attempt_id == work.active_attempt_id
            and item.status == "RUNNING"
        )
        if len(attempts) != 1:
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        return attempts[0]

    @staticmethod
    def _rule_context(
        materials: tuple[StaticNormalizationInput, ...],
    ) -> tuple[
        tuple[RuleExecutionRecord, ...],
        dict[StoredDataRef, tuple[str, ...]],
        StoredDataRef | None,
    ]:
        rules: list[RuleExecutionRecord] = []
        catalogs: dict[StoredDataRef, tuple[str, ...]] = {}
        config_refs = {material.analysis_config_ref for material in materials}
        expected_catalogs = {
            material.rule_catalog_ref
            for material in materials
            if material.rule_catalog_ref is not None
        }
        if len(config_refs) != 1:
            raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
        for material in materials:
            record = material.rule_execution
            if record is None:
                if (
                    material.catalog_rule_ids
                    or material.rule_mappings
                    or material.rule_catalog_ref is not None
                ):
                    raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
                continue
            if (
                record.analysis_config_ref != material.analysis_config_ref
                or record.rule_catalog_ref != material.rule_catalog_ref
            ):
                raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
            previous = catalogs.get(record.rule_catalog_ref)
            if previous is not None and previous != material.catalog_rule_ids:
                raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
            mapping_ids = tuple(item.rule_id for item in material.rule_mappings)
            if (
                (mapping_ids and set(mapping_ids) != set(material.catalog_rule_ids))
                or (
                    material.result.status in {"SUCCEEDED", "PARTIAL"}
                    and not mapping_ids
                )
            ):
                raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
            validate_rule_execution(material.result, record, material.catalog_rule_ids)
            catalogs[record.rule_catalog_ref] = material.catalog_rule_ids
            rules.append(record)
        if set(catalogs) != expected_catalogs:
            raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
        return tuple(rules), catalogs, next(iter(config_refs))

    def _fail_no_usable(
        self,
        work: WorkExecutionState,
        materials: tuple[StaticNormalizationInput, ...],
    ) -> WorkExecutionState:
        if work.active_attempt_id is None:
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        gap_ids = tuple(
            gap.gap_id for material in materials for gap in material.result.gaps
        )
        error_ids = tuple(
            error.error_id for material in materials for error in material.result.errors
        ) or (self.runner.ids.new(ErrorId),)
        action = self.runner.action(
            work,
            self._attempt_controller_identity(work),
            "ORCHESTRATION",
            "CHANGE_WORK_STATE",
            reason="No usable static tool result can be normalized",
        )
        decision = self.runner.authorize(work, action)
        now = self.runner.clock.now()
        transition = StateTransition.model_validate_json(
            canonical_bytes(
                {
                    "meta": self.runner.metadata(
                        work.meta,
                        "state_transition",
                        attempt_id=work.active_attempt_id,
                    ),
                    "transition_id": self.runner.ids.new(TransitionId),
                    "work_id": work.work_id,
                    "action_decision_ref": decision,
                    "from_status": work.status,
                    "to_status": "FAILED",
                    "expected_state_version": work.state_version,
                    "new_state_version": work.state_version + 1,
                    "attempt_id": work.active_attempt_id,
                    "cause": "STATIC_NORMALIZATION_NO_USABLE_INPUT",
                    "output_refs": (),
                    "gap_ids": gap_ids,
                    "error_ids": error_ids,
                    "dedupe_key": content_hash(
                        (work.work_id, work.state_version, "NO_USABLE_STATIC_INPUT")
                    ),
                    "created_at": now,
                }
            )
        )
        commit = TransitionCommit.model_validate_json(
            canonical_bytes(
                {
                    "meta": self.runner.metadata(
                        work.meta,
                        "transition_commit",
                        attempt_id=work.active_attempt_id,
                    ),
                    "transition_commit_id": self.runner.ids.new(TransitionCommitId),
                    "work_id": work.work_id,
                    "transition_ref": (
                        self.runner.runtime.unit_of_work.records.stage_record(
                            transition
                        )
                    ),
                    "expected_state_version": work.state_version,
                    "target_state_version": work.state_version + 1,
                    "attempt_id": work.active_attempt_id,
                    "target_status": "FAILED",
                    "output_refs": (),
                    "gap_ids": gap_ids,
                    "error_ids": error_ids,
                    "state": "PREPARED",
                    "prepared_at": now,
                    "committed_at": None,
                    "abort_reason": None,
                }
            )
        )
        self.runner.runtime.transitions.commit(
            TransitionCommitRequest(transition, commit, ())
        )
        return self.runner.runtime.work.get(str(work.work_id))

    def _attempt_controller_identity(self, work: WorkExecutionState) -> BudgetScopeRef:
        if work.active_attempt_id is None or work.last_transition_ref is None:
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        records = self.runner.runtime.unit_of_work.records
        transition = records.get_exact(work.last_transition_ref)
        if (
            not isinstance(transition, StateTransition)
            or transition.work_id != work.work_id
            or transition.attempt_id != work.active_attempt_id
            or transition.to_status != "RUNNING"
        ):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        decision = records.get_exact(transition.action_decision_ref)
        if not isinstance(decision, ActionDecision):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        action = records.get_exact(decision.action_ref)
        if (
            not isinstance(action, ActionRequest)
            or action.action_type != "START_ATTEMPT"
            or action.requested_by != "ORCHESTRATION"
        ):
            raise ValueError("STATIC_NORMALIZATION_PUBLICATION_INVALID")
        return action.requester_identity_ref

    def _resolve_source(
        self,
        work: WorkExecutionState,
        workspace: CodeWorkspace,
        source: StaticNormalizationSource,
    ) -> StaticNormalizationInput:
        if work.input_refs.count(source.tool_work_ref) != 1:
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        records = self.runner.runtime.unit_of_work.records
        referenced = records.get_exact(source.tool_work_ref)
        if not isinstance(referenced, WorkExecutionState):
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        tool_work = self.runner.runtime.work.get(str(referenced.work_id))
        expected_inputs = {
            reference(workspace),
            source.profile_ref,
            source.analysis_config_ref,
        }
        if source.rule_catalog_ref is not None:
            expected_inputs.add(source.rule_catalog_ref)
        if (
            tool_work != referenced
            or tool_work.work_type != "STATIC_TOOL"
            or tool_work.status not in {"SUCCEEDED", "PARTIAL", "FAILED", "CANCELLED"}
            or len(tool_work.input_refs) != len(expected_inputs)
            or set(tool_work.input_refs) != expected_inputs
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
        action = self._resolve_tool_action(tool_work, result)
        self._validate_rule_ref_shape(result)
        if (result.tool_kind == "RULE_BASED") != (source.rule_catalog_ref is not None):
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        rule: RuleExecutionRecord | None = None
        if result.rule_execution_ref is not None:
            candidate = records.get_exact(result.rule_execution_ref)
            if not isinstance(candidate, RuleExecutionRecord):
                raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
            rule = candidate
            if (
                rule.analysis_config_ref != source.analysis_config_ref
                or rule.rule_catalog_ref != source.rule_catalog_ref
            ):
                raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        raw: bytes | None = None
        if result.raw_result_ref is not None:
            with self.runner.runtime.unit_of_work.artifacts.open_verified(
                result.raw_result_ref
            ) as stream:
                raw = stream.read(profile.max_artifact_read_bytes + 1)
            if len(raw) > profile.max_artifact_read_bytes:
                raise ValueError("STATIC_ARTIFACT_READ_LIMIT")
        mappings: tuple[StaticRuleMapping, ...] = ()
        if source.rule_catalog_ref is not None:
            try:
                mappings = self._rule_mappings[source.rule_catalog_ref]
            except KeyError as error:
                raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH") from error
            if {item.rule_id for item in mappings} != set(source.catalog_rule_ids):
                raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
        return StaticNormalizationInput(
            result_ref=result_refs[0],
            result=result,
            profile_ref=source.profile_ref,
            profile=profile,
            analysis_config_ref=source.analysis_config_ref,
            rule_catalog_ref=source.rule_catalog_ref,
            raw_bytes=raw,
            authorized_paths=action.file_paths,
            rule_execution=rule,
            catalog_rule_ids=source.catalog_rule_ids,
            rule_mappings=mappings,
        )

    def _resolve_tool_action(
        self,
        tool_work: WorkExecutionState,
        result: ToolRunResult,
    ) -> ActionRequest:
        """Resolve the one published RUN_TOOL action that owns this exact attempt."""

        attempt_id = result.meta.attempt_id
        if attempt_id is None:
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        records = self.runner.runtime.unit_of_work.records
        matches: list[ActionRequest] = []
        for candidate in self.runner.runtime.queries.published_records(
            str(result.meta.analysis_id)
        ):
            if (
                not isinstance(candidate, ActionRequest)
                or candidate.action_type != "RUN_TOOL"
                or candidate.requested_by != "STATIC_ANALYSIS"
                or not isinstance(candidate.meta, RecordMeta)
                or candidate.meta.attempt_id != attempt_id
                or candidate.work_ref is None
            ):
                continue
            try:
                action_work = records.get_exact(candidate.work_ref)
            except (LookupError, ValueError):
                continue
            if (
                isinstance(action_work, WorkExecutionState)
                and action_work.work_id == tool_work.work_id
                and action_work.status == "RUNNING"
                and action_work.active_attempt_id == attempt_id
                and candidate.work_ref == reference(action_work)
                and candidate.expected_state_version == action_work.state_version
            ):
                matches.append(candidate)
        if len(matches) != 1:
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        action = matches[0]
        if not isinstance(action.meta, RecordMeta):
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        expected_scope = (
            result.meta.analysis_id,
            result.meta.workspace_id,
            result.meta.commit_id,
        )
        analyzed_paths = result.coverage.analyzed_paths
        skipped_paths = result.coverage.skipped_paths
        if (
            (
                action.meta.analysis_id,
                action.meta.workspace_id,
                action.meta.commit_id,
            )
            != expected_scope
            or action.input_refs != tool_work.input_refs
            or action.tool_name != result.tool_name
            or not action.file_paths
            or len(action.file_paths) != len(set(action.file_paths))
            or len(analyzed_paths) != len(set(analyzed_paths))
            or len(skipped_paths) != len(set(skipped_paths))
            or not set(analyzed_paths).isdisjoint(skipped_paths)
            or set(analyzed_paths) | set(skipped_paths) != set(action.file_paths)
        ):
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        return action

    @staticmethod
    def _validate_rule_ref_shape(result: ToolRunResult) -> None:
        if (result.tool_kind == "RULE_BASED") != (
            result.rule_execution_ref is not None
        ):
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
