"""Production claimed-work adapters for the T08 static-analysis graph.

This module contains orchestration only.  Repository detection, tool execution,
normalization, and context reads remain owned by their existing services.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol, cast

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.records import RecordMeta, RecordMetadata
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import (
    CodeLocation,
    CodeRelation,
    CodeWorkspace,
    RepositoryExecutionSelection,
    RepositoryProfile,
    RepositorySelectedTool,
    RepositoryTrackedFile,
    StaticFactBundle,
    StaticToolProfile,
)
from sastsimi.contracts.work import (
    TERMINAL_WORK_STATUSES,
    AttemptStatus,
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.context import ContextRetrievalIntent
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    StaticToolRequest,
    WorkContext,
    WorkHandlerResult,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.coordinator import StaticToolCoordinator
from sastsimi.static_analysis.repository_profile import static_tool_work_inputs
from sastsimi.storage.context_policy import resolve_context_ceiling
from sastsimi.verification.context_service import ContextRetrievalService

from .repository_profile_handler import (
    RepositoryProfileCall,
    RepositoryProfileWorkHandler,
)
from .run_initialization import RunWorkQueryPort
from .static_external_runner import StaticExternalRunner
from .static_publication import (
    StaticNormalizationPublisher,
    StaticNormalizationSource,
)

_LANGUAGE_SUFFIXES = {
    "PYTHON": frozenset({".py", ".pyi"}),
    "JAVASCRIPT": frozenset({".js", ".jsx", ".mjs", ".cjs"}),
}


def require_current_work_context(
    context: WorkContext,
    runner: WorkflowRunner,
    expected: WorkType,
) -> None:
    """Reject a stale revision, replaced attempt, or cross-scope claim."""

    work, attempt = context.work, context.attempt
    current = runner.runtime.work.get(str(work.work_id))
    attempts = runner.runtime.work.store.attempts_for_work(str(work.work_id))
    latest = attempts[-1] if attempts else None
    if (
        current != work
        or latest != attempt
        or work.work_type != expected
        or work.status != WorkStatus.RUNNING
        or attempt.status != AttemptStatus.RUNNING
        or work.active_attempt_id is None
        or work.active_attempt_id != attempt.attempt_id
        or work.work_id != attempt.work_id
        or work.input_hash != attempt.input_hash
        or work.input_hash != content_hash(work.input_refs)
        or not isinstance(work.meta, RecordMeta)
        or not isinstance(attempt.meta, RecordMeta)
        or (
            work.meta.analysis_id,
            work.meta.workspace_id,
            work.meta.commit_id,
            work.meta.hypothesis_id,
        )
        != (
            attempt.meta.analysis_id,
            attempt.meta.workspace_id,
            attempt.meta.commit_id,
            attempt.meta.hypothesis_id,
        )
    ):
        raise ValueError("WORK_CONTEXT_NOT_CURRENT")


def selected_static_paths(
    tracked: tuple[RepositoryTrackedFile, ...],
    tool: RepositorySelectedTool,
) -> tuple[str, ...]:
    """Return only tracked source paths for the exact selected languages."""

    suffixes = frozenset(
        suffix for language in tool.languages for suffix in _LANGUAGE_SUFFIXES[language]
    )
    paths = tuple(
        sorted(
            str(item.git_path)
            for item in tracked
            if any(str(item.git_path).lower().endswith(suffix) for suffix in suffixes)
        )
    )
    if not paths:
        raise ValueError("STATIC_TOOL_PATHS_EMPTY")
    return paths


def _require_code_scope(meta: RecordMeta, refs: tuple[StoredDataRef, ...]) -> None:
    if any(
        (ref.workspace_id, ref.commit_id) != (meta.workspace_id, meta.commit_id)
        for ref in refs
    ):
        raise ValueError("STATIC_REFERENCE_SCOPE_MISMATCH")


@dataclass(frozen=True, slots=True)
class StaticToolRoute:
    """Exact non-secret configuration refs attached to one selected tool work."""

    tool_profile_ref: HostConfigurationRef
    analysis_config_ref: StoredDataRef
    rule_catalog_ref: StoredDataRef | None
    catalog_rule_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            self.tool_profile_ref.data_kind != "static_tool_profile"
            or self.tool_profile_ref.record_id is None
            or self.analysis_config_ref.record_id is not None
            or bool(self.rule_catalog_ref) != bool(self.catalog_rule_ids)
            or len(self.catalog_rule_ids) != len(set(self.catalog_rule_ids))
        ):
            raise ValueError("STATIC_TOOL_ROUTE_INVALID")


@dataclass(frozen=True, slots=True)
class StaticToolCall:
    request: StaticToolRequest
    selected_tool: RepositorySelectedTool
    recover: bool = False


@dataclass(frozen=True, slots=True)
class StaticNormalizationCall:
    workspace: CodeWorkspace
    sources: tuple[StaticNormalizationSource, ...]


@dataclass(frozen=True, slots=True)
class ContextRetrievalCall:
    intent: ContextRetrievalIntent
    workspace: CodeWorkspace
    bundle: StaticFactBundle
    budget_scope_ref: StoredDataRef


class _UncertainStaticRecoveryPort(Protocol):
    def block_uncertain(self, work: WorkExecutionState) -> None: ...


def resolve_static_tool_recovery_action(
    runner: WorkflowRunner,
    context: WorkContext,
    *,
    requester_identity_ref: BudgetScopeRef,
    tool_name: str,
    file_paths: tuple[str, ...],
) -> ActionRequest | None:
    """Return the one durable action owned by this exact current attempt.

    A prior-attempt action never closes a newer attempt.  Multiple or malformed
    actions for the same current work revision make the external outcome
    ambiguous, so the work is blocked instead of dispatching again.
    """

    require_current_work_context(context, runner, WorkType.STATIC_TOOL)
    work = context.work
    if (
        not isinstance(work.meta, RecordMeta)
        or work.status != WorkStatus.RUNNING
        or work.active_attempt_id is None
    ):
        raise ValueError("STATIC_TOOL_RECOVERY_AMBIGUOUS")
    work_ref = reference(work)
    candidates = tuple(
        item
        for item in runner.runtime.queries.published_records(
            str(work.meta.analysis_id)
        )
        if isinstance(item, ActionRequest)
        and item.action_type == ActionType.RUN_TOOL
        and item.work_ref == work_ref
    )
    if not candidates:
        return None
    action = candidates[0]
    valid = (
        len(candidates) == 1
        and isinstance(action.meta, RecordMeta)
        and action.meta.attempt_id == work.active_attempt_id
        and (
            action.meta.analysis_id,
            action.meta.workspace_id,
            action.meta.commit_id,
            action.meta.hypothesis_id,
        )
        == (
            work.meta.analysis_id,
            work.meta.workspace_id,
            work.meta.commit_id,
            work.meta.hypothesis_id,
        )
        and action.requested_by == RequesterRole.STATIC_ANALYSIS
        and action.requester_identity_ref == requester_identity_ref
        and action.expected_state_version == work.state_version
        and action.input_refs == work.input_refs
        and action.tool_name == tool_name
        and action.file_paths == file_paths
    )
    if not valid:
        recovery = runner.runtime.recovery.recovery
        if not hasattr(recovery, "block_uncertain"):
            raise ValueError("STATIC_TOOL_RECOVERY_BLOCKER_UNAVAILABLE")
        cast(_UncertainStaticRecoveryPort, recovery).block_uncertain(work)
        raise ValueError("STATIC_TOOL_RECOVERY_AMBIGUOUS")
    return action


class StaticProductionGraph:
    """Register the static fan-out/fan-in graph from exact committed refs."""

    def __init__(
        self,
        *,
        runner: WorkflowRunner,
        work_query: RunWorkQueryPort,
        requester_identity_ref: BudgetScopeRef,
        routes: tuple[StaticToolRoute, ...],
    ) -> None:
        if not routes or len({item.tool_profile_ref for item in routes}) != len(routes):
            raise ValueError("STATIC_TOOL_ROUTE_INVALID")
        self.runner = runner
        self.work_query = work_query
        self.requester_identity_ref = requester_identity_ref
        self._routes = {item.tool_profile_ref: item for item in routes}

    def route_for(self, profile_ref: HostConfigurationRef) -> StaticToolRoute:
        try:
            return self._routes[profile_ref]
        except KeyError as error:
            raise ValueError("STATIC_TOOL_ROUTE_NOT_CONFIGURED") from error

    def ensure_repository_profile(
        self,
        *,
        state_meta: RecordMeta,
        budget_scope_ref: StoredDataRef,
        workspace_ref: RunStoredDataRef,
        git_refs: tuple[HostConfigurationRef, ...],
    ) -> WorkExecutionState:
        inputs: tuple[RecordRef, ...] = (workspace_ref, *git_refs)
        return self.runner.ensure_enqueue(
            budget_scope_ref,
            state_meta,
            WorkType.REPOSITORY_PROFILE,
            SubjectType.ANALYSIS,
            str(state_meta.analysis_id),
            self.requester_identity_ref,
            stable_key=(
                "repository-profile:"
                + str(state_meta.analysis_id)
                + ":"
                + content_hash(inputs)
            ),
            inputs=inputs,
        )

    def ensure_static_tools(
        self,
        *,
        profile_work: WorkExecutionState,
        repository: RepositoryProfile,
        repository_ref: StoredDataRef,
        selection: RepositoryExecutionSelection,
        selection_ref: StoredDataRef,
    ) -> tuple[WorkExecutionState, ...]:
        current = self.runner.runtime.work.get(str(profile_work.work_id))
        if (
            current != profile_work
            or current.status != WorkStatus.SUCCEEDED
            or reference(repository) != repository_ref
            or reference(selection) != selection_ref
            or selection.status != "READY"
            or selection.repository_profile_ref != repository_ref
            or repository.workspace_ref not in profile_work.input_refs
            or current.output_refs != (repository_ref, selection_ref)
        ):
            raise ValueError("STATIC_TOOL_FANOUT_INPUT_INVALID")
        scope = self._budget_scope(current)
        plans: list[
            tuple[
                RepositorySelectedTool,
                StaticToolRoute,
                StaticToolProfile,
                tuple[str, ...],
            ]
        ] = []
        for selected in selection.selected_tools:
            route = self.route_for(selected.tool_profile_ref)
            _require_code_scope(
                repository.meta,
                (
                    repository_ref,
                    selection_ref,
                    route.analysis_config_ref,
                    *((route.rule_catalog_ref,) if route.rule_catalog_ref else ()),
                ),
            )
            resolved = (
                self.runner.runtime.configuration.resolve_static_tool_profile_ref(
                    selected.tool_profile_ref
                )
            )
            if (
                not isinstance(resolved, StaticToolProfile)
                or reference(resolved) != selected.tool_profile_ref
                or resolved.status != "ACTIVE"
                or resolved.purpose != "PRODUCTION"
                or resolved.adapter_key != selected.adapter_key
                or (resolved.tool_kind == "RULE_BASED")
                != (route.rule_catalog_ref is not None)
            ):
                raise ValueError("STATIC_TOOL_ROUTE_INVALID")
            paths = selected_static_paths(repository.tracked_files, selected)
            plans.append((selected, route, resolved, paths))

        created: list[WorkExecutionState] = []
        for selected, route, _profile, _paths in plans:
            selected_inputs = static_tool_work_inputs(
                selection, selection_ref, selected
            )
            inputs: tuple[RecordRef, ...] = (
                repository.workspace_ref,
                *selected_inputs,
                route.analysis_config_ref,
                *((route.rule_catalog_ref,) if route.rule_catalog_ref else ()),
            )
            created.append(
                self.runner.ensure_enqueue(
                    scope,
                    _fresh_analysis_meta(self.runner, current.meta, "static_tool"),
                    WorkType.STATIC_TOOL,
                    SubjectType.ANALYSIS,
                    str(current.meta.analysis_id),
                    self.requester_identity_ref,
                    stable_key=(
                        "static-tool:"
                        + selection_ref.content_hash
                        + ":"
                        + selected.tool_profile_ref.content_hash
                    ),
                    inputs=inputs,
                )
            )
        return tuple(created)

    def ensure_normalization(
        self, completed_tool: WorkExecutionState
    ) -> WorkExecutionState | None:
        current = self.runner.runtime.work.get(str(completed_tool.work_id))
        if current != completed_tool or current.work_type != WorkType.STATIC_TOOL:
            raise ValueError("STATIC_TOOL_JOIN_INPUT_INVALID")
        selection_refs = tuple(
            ref
            for ref in current.input_refs
            if isinstance(ref, StoredDataRef)
            and ref.data_kind == "repository_execution_selection"
        )
        if len(selection_refs) != 1:
            raise ValueError("STATIC_TOOL_JOIN_INPUT_INVALID")
        selection_ref = selection_refs[0]
        selection = self.runner.runtime.unit_of_work.records.get_exact(selection_ref)
        if (
            not isinstance(selection, RepositoryExecutionSelection)
            or reference(selection) != selection_ref
            or selection.status != "READY"
        ):
            raise ValueError("STATIC_TOOL_JOIN_INPUT_INVALID")
        works = tuple(
            item
            for item in self.work_query.work_for_run(str(current.meta.analysis_id))
            if item.work_type == WorkType.STATIC_TOOL
            and selection_ref in item.input_refs
        )
        expected_profiles = {item.tool_profile_ref for item in selection.selected_tools}
        actual: dict[HostConfigurationRef, WorkExecutionState] = {}
        for item in works:
            refs = tuple(
                ref for ref in item.input_refs if isinstance(ref, HostConfigurationRef)
            )
            if len(refs) != 1 or refs[0] in actual:
                raise ValueError("STATIC_TOOL_JOIN_INPUT_INVALID")
            actual[refs[0]] = item
        if set(actual) != expected_profiles:
            return None
        if any(item.status not in TERMINAL_WORK_STATUSES for item in actual.values()):
            return None
        ordered = tuple(
            actual[item.tool_profile_ref] for item in selection.selected_tools
        )
        if any(
            len(
                tuple(
                    ref
                    for ref in item.output_refs
                    if ref.data_kind == "tool_run_result"
                )
            )
            != 1
            for item in ordered
        ):
            return None
        routes = tuple(
            self.route_for(item.tool_profile_ref) for item in selection.selected_tools
        )
        configs = {route.analysis_config_ref for route in routes}
        if len(configs) != 1:
            raise ValueError("STATIC_ANALYSIS_CONFIG_MISMATCH")
        tool_work_refs = tuple(_stored_work_ref(item) for item in ordered)
        catalogs = tuple(
            sorted(
                {route.rule_catalog_ref for route in routes if route.rule_catalog_ref},
                key=lambda ref: (ref.data_kind, ref.content_hash),
            )
        )
        repository = self.runner.runtime.unit_of_work.records.get_exact(
            selection.repository_profile_ref
        )
        if not isinstance(repository, RepositoryProfile):
            raise ValueError("STATIC_TOOL_JOIN_INPUT_INVALID")
        inputs: tuple[RecordRef, ...] = (
            repository.workspace_ref,
            *tool_work_refs,
            next(iter(configs)),
            *catalogs,
        )
        return self.runner.ensure_enqueue(
            self._budget_scope(current),
            _fresh_analysis_meta(self.runner, current.meta, "static_normalize"),
            WorkType.STATIC_NORMALIZE,
            SubjectType.ANALYSIS,
            str(current.meta.analysis_id),
            self.requester_identity_ref,
            stable_key="static-normalize:" + selection_ref.content_hash,
            inputs=inputs,
        )

    def ensure_initial_hypothesis(
        self,
        *,
        normalization_work: WorkExecutionState,
        bundle: StaticFactBundle,
        bundle_ref: StoredDataRef,
    ) -> WorkExecutionState:
        current = self.runner.runtime.work.get(str(normalization_work.work_id))
        if (
            current != normalization_work
            or not isinstance(current.meta, RecordMeta)
            or current.work_type != WorkType.STATIC_NORMALIZE
            or current.status not in {WorkStatus.SUCCEEDED, WorkStatus.PARTIAL}
            or current.output_refs != (bundle_ref,)
            or reference(bundle) != bundle_ref
            or bundle.meta.analysis_id != current.meta.analysis_id
            or bundle.meta.workspace_id != current.meta.workspace_id
            or bundle.meta.commit_id != current.meta.commit_id
        ):
            raise ValueError("HYPOTHESIS_SEED_INPUT_INVALID")
        return self.runner.ensure_enqueue(
            self._budget_scope(current),
            _fresh_analysis_meta(self.runner, current.meta, "hypothesis_proposal"),
            WorkType.HYPOTHESIS_PROPOSAL,
            SubjectType.ANALYSIS,
            str(current.meta.analysis_id),
            self.requester_identity_ref,
            stable_key="initial-hypothesis:" + bundle_ref.content_hash,
            inputs=(bundle_ref,),
        )

    def _budget_scope(self, work: WorkExecutionState) -> StoredDataRef:
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("STATIC_BUDGET_SCOPE_INVALID")
        state = self.runner.runtime.budget_registry.current_state(
            str(work.meta.analysis_id)
        )
        ref = state.budget_binding_ref
        if (
            not isinstance(ref, StoredDataRef)
            or state.workspace_id != work.meta.workspace_id
            or state.commit_id != work.meta.commit_id
        ):
            raise ValueError("STATIC_BUDGET_SCOPE_INVALID")
        return ref


@dataclass(frozen=True, slots=True)
class StaticPostWorkspaceSeeder:
    """Seed RepositoryProfile only after exact workspace and budget binding."""

    runner: WorkflowRunner
    work_query: RunWorkQueryPort
    graph: StaticProductionGraph

    def ensure_initial(
        self,
        request: AnalysisStartRequest,
        state: AnalysisRunState,
        binding_ref: StoredDataRef,
    ) -> tuple[WorkExecutionState, ...]:
        current = self.runner.runtime.budget_registry.current_state(
            str(state.meta.analysis_id)
        )
        run_input = self.runner.runtime.budget_registry.current_input(
            str(state.meta.analysis_id)
        )
        workspace_ref = current.workspace_ref
        if (
            current != state
            or current.budget_binding_ref != binding_ref
            or run_input.repository_ref != request.repository_ref
            or run_input.requested_git_ref != request.requested_git_ref
            or run_input.program_id != request.program_id
            or run_input.purpose != request.purpose
            or not isinstance(workspace_ref, RunStoredDataRef)
            or current.workspace_id is None
            or current.commit_id is None
        ):
            raise ValueError("POST_WORKSPACE_STATIC_SEED_INVALID")
        workspace = self.runner.runtime.unit_of_work.records.get_exact(workspace_ref)
        works = self.work_query.work_for_run(str(current.meta.analysis_id))
        roots = tuple(
            item for item in works if item.work_type == WorkType.WORKSPACE_PREP
        )
        if (
            not isinstance(workspace, CodeWorkspace)
            or workspace.status != "READY"
            or len(roots) != 1
            or roots[0].status != WorkStatus.SUCCEEDED
            or roots[0].output_refs != (workspace_ref,)
        ):
            raise ValueError("POST_WORKSPACE_STATIC_SEED_INVALID")
        git_refs = tuple(
            ref for ref in roots[0].input_refs if isinstance(ref, HostConfigurationRef)
        )
        if len(git_refs) not in {1, 2}:
            raise ValueError("POST_WORKSPACE_STATIC_SEED_INVALID")
        meta = _fresh_analysis_meta(
            self.runner,
            current.meta,
            "repository_profile",
            workspace_id=str(current.workspace_id),
            commit_id=str(current.commit_id),
        )
        return (
            self.graph.ensure_repository_profile(
                state_meta=meta,
                budget_scope_ref=binding_ref,
                workspace_ref=workspace_ref,
                git_refs=git_refs,
            ),
        )


class ExactRepositoryProfileCallResolver:
    """Rebuild profiling input only from current durable workspace evidence."""

    def __init__(
        self,
        *,
        runner: WorkflowRunner,
        work_query: RunWorkQueryPort,
        external: StaticExternalRunner,
        timeout_ms: int,
    ) -> None:
        if timeout_ms <= 0:
            raise ValueError("REPOSITORY_PROFILE_TIMEOUT_INVALID")
        self.runner = runner
        self.work_query = work_query
        self.external = external
        self.timeout_ms = timeout_ms

    def __call__(self, context: WorkContext) -> RepositoryProfileCall:
        require_current_work_context(context, self.runner, WorkType.REPOSITORY_PROFILE)
        work = context.work
        state = self.runner.runtime.budget_registry.current_state(
            str(work.meta.analysis_id)
        )
        run_input = self.runner.runtime.budget_registry.current_input(
            str(work.meta.analysis_id)
        )
        roots = tuple(
            item
            for item in self.work_query.work_for_run(str(work.meta.analysis_id))
            if item.work_type == WorkType.WORKSPACE_PREP
        )
        workspace_refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, RunStoredDataRef) and ref.data_kind == "code_workspace"
        )
        git_refs = tuple(
            ref for ref in work.input_refs if isinstance(ref, HostConfigurationRef)
        )
        if (
            len(roots) != 1
            or len(workspace_refs) != 1
            or len(git_refs) not in {1, 2}
            or state.workspace_ref != workspace_refs[0]
            or state.budget_binding_ref is None
        ):
            raise ValueError("REPOSITORY_PROFILE_CALL_INVALID")
        root = roots[0]
        root_git = tuple(
            ref for ref in root.input_refs if isinstance(ref, HostConfigurationRef)
        )
        policies = tuple(
            ref
            for ref in root.input_refs
            if isinstance(ref, RunStoredDataRef)
            and ref.data_kind == "artifact"
            and ref.record_id is None
        )
        if root_git != git_refs or len(policies) != 1:
            raise ValueError("REPOSITORY_PROFILE_CALL_INVALID")
        workspace = self.runner.runtime.unit_of_work.records.get_exact(
            workspace_refs[0]
        )
        if not isinstance(workspace, CodeWorkspace):
            raise ValueError("REPOSITORY_PROFILE_CALL_INVALID")
        preparation = self.external.resolve_repository_preparation(
            workspace_work=root,
            run_input=run_input,
            policy_ref=policies[0],
            git_clone_profile_ref=git_refs[0],
            git_checkout_profile_ref=git_refs[-1],
        )
        started = time.monotonic_ns()
        return RepositoryProfileCall(
            workspace=workspace,
            workspace_ref=workspace_refs[0],
            preparation=preparation,
            deadline=MonotonicActionDeadline(
                action_id="repository-profile-" + str(context.attempt.attempt_id),
                started_ns=started,
                expires_ns=started + self.timeout_ms * 1_000_000,
            ),
            git_clone_profile_ref=git_refs[0],
            git_checkout_profile_ref=git_refs[-1],
        )


@dataclass(frozen=True, slots=True)
class RepositoryProfileFanoutWorkHandler:
    handler: RepositoryProfileWorkHandler
    graph: StaticProductionGraph

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        result = await self.handler.execute(context)
        current = self.graph.runner.runtime.work.get(str(context.work.work_id))
        if current.status == WorkStatus.SUCCEEDED:
            refs = tuple(
                ref for ref in current.output_refs if isinstance(ref, StoredDataRef)
            )
            repository_refs = tuple(
                ref for ref in refs if ref.data_kind == "repository_profile"
            )
            selection_refs = tuple(
                ref for ref in refs if ref.data_kind == "repository_execution_selection"
            )
            if len(repository_refs) != 1 or len(selection_refs) != 1:
                raise ValueError("STATIC_TOOL_FANOUT_INPUT_INVALID")
            repository = self.graph.runner.runtime.unit_of_work.records.get_exact(
                repository_refs[0]
            )
            selection = self.graph.runner.runtime.unit_of_work.records.get_exact(
                selection_refs[0]
            )
            if not isinstance(repository, RepositoryProfile) or not isinstance(
                selection, RepositoryExecutionSelection
            ):
                raise ValueError("STATIC_TOOL_FANOUT_INPUT_INVALID")
            self.graph.ensure_static_tools(
                profile_work=current,
                repository=repository,
                repository_ref=repository_refs[0],
                selection=selection,
                selection_ref=selection_refs[0],
            )
        return result


class ExactStaticToolCallResolver:
    def __init__(
        self,
        *,
        runner: WorkflowRunner,
        graph: StaticProductionGraph,
        requester_identity_ref: BudgetScopeRef,
    ) -> None:
        self.runner = runner
        self.graph = graph
        self.requester_identity_ref = requester_identity_ref

    def __call__(self, context: WorkContext) -> StaticToolCall:
        require_current_work_context(context, self.runner, WorkType.STATIC_TOOL)
        work = context.work
        profile_refs = tuple(
            ref for ref in work.input_refs if isinstance(ref, HostConfigurationRef)
        )
        repository_refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == "repository_profile"
        )
        selection_refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef)
            and ref.data_kind == "repository_execution_selection"
        )
        workspace_refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, RunStoredDataRef) and ref.data_kind == "code_workspace"
        )
        if not all(
            len(items) == 1
            for items in (profile_refs, repository_refs, selection_refs, workspace_refs)
        ):
            raise ValueError("STATIC_TOOL_CALL_INVALID")
        profile_ref = profile_refs[0]
        route = self.graph.route_for(profile_ref)
        selection = self.runner.runtime.unit_of_work.records.get_exact(
            selection_refs[0]
        )
        repository = self.runner.runtime.unit_of_work.records.get_exact(
            repository_refs[0]
        )
        workspace = self.runner.runtime.unit_of_work.records.get_exact(
            workspace_refs[0]
        )
        selected = tuple(
            item
            for item in getattr(selection, "selected_tools", ())
            if item.tool_profile_ref == profile_ref
        )
        expected: tuple[RecordRef, ...] = (
            workspace_refs[0],
            repository_refs[0],
            selection_refs[0],
            profile_ref,
            route.analysis_config_ref,
            *((route.rule_catalog_ref,) if route.rule_catalog_ref else ()),
        )
        if (
            work.input_refs != expected
            or not isinstance(selection, RepositoryExecutionSelection)
            or selection.status != "READY"
            or reference(selection) != selection_refs[0]
            or not isinstance(repository, RepositoryProfile)
            or reference(repository) != repository_refs[0]
            or not isinstance(workspace, CodeWorkspace)
            or reference(workspace) != workspace_refs[0]
            or repository.workspace_ref != workspace_refs[0]
            or len(selected) != 1
        ):
            raise ValueError("STATIC_TOOL_CALL_INVALID")
        assert isinstance(work.meta, RecordMeta)
        _require_code_scope(
            work.meta,
            (
                repository_refs[0],
                selection_refs[0],
                route.analysis_config_ref,
                *((route.rule_catalog_ref,) if route.rule_catalog_ref else ()),
            ),
        )
        profile = self.runner.runtime.configuration.resolve_static_tool_profile_ref(
            profile_ref
        )
        if (
            not isinstance(profile, StaticToolProfile)
            or reference(profile) != profile_ref
            or profile.status != "ACTIVE"
            or profile.purpose != "PRODUCTION"
            or profile.adapter_key != selected[0].adapter_key
            or (profile.tool_kind == "RULE_BASED")
            != (route.rule_catalog_ref is not None)
        ):
            raise ValueError("STATIC_TOOL_CALL_INVALID")
        paths = selected_static_paths(repository.tracked_files, selected[0])
        existing_action = resolve_static_tool_recovery_action(
            self.runner,
            context,
            requester_identity_ref=self.requester_identity_ref,
            tool_name=profile.tool_name,
            file_paths=paths,
        )
        action = existing_action or self.runner.action(
            work,
            self.requester_identity_ref,
            "STATIC_ANALYSIS",
            "RUN_TOOL",
            tool_name=profile.tool_name,
            file_paths=paths,
        )
        return StaticToolCall(
            StaticToolRequest(
                action=action,
                workspace=workspace,
                tool_profile_ref=profile_ref,
                analysis_config_ref=route.analysis_config_ref,
                rule_catalog_ref=route.rule_catalog_ref,
                repository_profile_ref=repository_refs[0],
                execution_selection_ref=selection_refs[0],
            ),
            selected[0],
            recover=existing_action is not None,
        )


@dataclass(frozen=True, slots=True)
class StaticToolWorkHandler:
    tools: StaticToolCoordinator
    resolve_call: ExactStaticToolCallResolver
    graph: StaticProductionGraph

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        call = self.resolve_call(context)
        if call.recover:
            await self.tools.recover(call.request)
        else:
            await self.tools.run(call.request)
        current = self.graph.runner.runtime.work.get(str(context.work.work_id))
        self.graph.ensure_normalization(current)
        return WorkHandlerResult(
            current.output_refs, action_input_refs=context.work.input_refs
        )


class ExactStaticNormalizationCallResolver:
    def __init__(self, *, runner: WorkflowRunner, graph: StaticProductionGraph) -> None:
        self.runner = runner
        self.graph = graph

    def __call__(self, context: WorkContext) -> StaticNormalizationCall:
        require_current_work_context(context, self.runner, WorkType.STATIC_NORMALIZE)
        work = context.work
        workspace_refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, RunStoredDataRef) and ref.data_kind == "code_workspace"
        )
        tool_refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef)
            and ref.data_kind == "work_execution_state"
        )
        if len(workspace_refs) != 1 or not tool_refs:
            raise ValueError("STATIC_NORMALIZATION_CALL_INVALID")
        workspace = self.runner.runtime.unit_of_work.records.get_exact(
            workspace_refs[0]
        )
        if (
            not isinstance(workspace, CodeWorkspace)
            or reference(workspace) != workspace_refs[0]
        ):
            raise ValueError("STATIC_NORMALIZATION_CALL_INVALID")
        sources: list[StaticNormalizationSource] = []
        for tool_ref in tool_refs:
            exact = self.runner.runtime.unit_of_work.records.get_exact(tool_ref)
            if not isinstance(exact, WorkExecutionState):
                raise ValueError("STATIC_NORMALIZATION_CALL_INVALID")
            current = self.runner.runtime.work.get(str(exact.work_id))
            profiles = tuple(
                ref
                for ref in current.input_refs
                if isinstance(ref, HostConfigurationRef)
            )
            repositories = tuple(
                ref
                for ref in current.input_refs
                if isinstance(ref, StoredDataRef)
                and ref.data_kind == "repository_profile"
            )
            selections = tuple(
                ref
                for ref in current.input_refs
                if isinstance(ref, StoredDataRef)
                and ref.data_kind == "repository_execution_selection"
            )
            if (
                current != exact
                or len(profiles) != 1
                or len(repositories) != 1
                or len(selections) != 1
            ):
                raise ValueError("STATIC_NORMALIZATION_CALL_INVALID")
            route = self.graph.route_for(profiles[0])
            sources.append(
                StaticNormalizationSource(
                    tool_work_ref=tool_ref,
                    profile_ref=profiles[0],
                    analysis_config_ref=route.analysis_config_ref,
                    rule_catalog_ref=route.rule_catalog_ref,
                    catalog_rule_ids=route.catalog_rule_ids,
                    repository_profile_ref=repositories[0],
                    execution_selection_ref=selections[0],
                )
            )
        expected: set[RecordRef] = {workspace_refs[0], *tool_refs}
        expected.update(source.analysis_config_ref for source in sources)
        expected.update(
            source.rule_catalog_ref
            for source in sources
            if source.rule_catalog_ref is not None
        )
        if len(work.input_refs) != len(expected) or set(work.input_refs) != expected:
            raise ValueError("STATIC_NORMALIZATION_CALL_INVALID")
        assert isinstance(work.meta, RecordMeta)
        _require_code_scope(
            work.meta,
            tuple(ref for ref in work.input_refs if isinstance(ref, StoredDataRef)),
        )
        return StaticNormalizationCall(workspace, tuple(sources))


@dataclass(frozen=True, slots=True)
class StaticNormalizationWorkHandler:
    publisher: StaticNormalizationPublisher
    resolve_call: ExactStaticNormalizationCallResolver
    graph: StaticProductionGraph
    requester_identity_ref: BudgetScopeRef

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        call = self.resolve_call(context)
        bundle, bundle_ref = self.publisher.publish(
            context.work,
            self.requester_identity_ref,
            call.workspace,
            call.sources,
        )
        current = self.graph.runner.runtime.work.get(str(context.work.work_id))
        self.graph.ensure_initial_hypothesis(
            normalization_work=current,
            bundle=bundle,
            bundle_ref=bundle_ref,
        )
        return WorkHandlerResult(current.output_refs)


class ExactContextRetrievalCallResolver:
    """Derive the read intent deterministically from exact work inputs."""

    def __init__(self, *, runner: WorkflowRunner) -> None:
        self.runner = runner

    def __call__(self, context: WorkContext) -> ContextRetrievalCall:
        require_current_work_context(context, self.runner, WorkType.CONTEXT_RETRIEVAL)
        work = context.work
        proposals = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == "hypothesis_proposal"
        )
        bundles = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == "static_fact_bundle"
        )
        if len(proposals) != 1 or len(bundles) != 1:
            raise ValueError("CONTEXT_CALL_INVALID")
        proposal = self.runner.runtime.unit_of_work.records.get_exact(proposals[0])
        bundle = self.runner.runtime.unit_of_work.records.get_exact(bundles[0])
        state = self.runner.runtime.budget_registry.current_state(
            str(work.meta.analysis_id)
        )
        if state.workspace_ref is None or not isinstance(
            state.budget_binding_ref, StoredDataRef
        ):
            raise ValueError("CONTEXT_CALL_INVALID")
        workspace = self.runner.runtime.unit_of_work.records.get_exact(
            state.workspace_ref
        )
        if (
            not isinstance(proposal, HypothesisProposal)
            or reference(proposal) != proposals[0]
            or not isinstance(work.meta, RecordMeta)
            or proposal.meta.hypothesis_id != work.meta.hypothesis_id
            or not isinstance(bundle, StaticFactBundle)
            or reference(bundle) != bundles[0]
            or not isinstance(workspace, CodeWorkspace)
            or workspace.status != "READY"
            or workspace.workspace_id != work.meta.workspace_id
            or workspace.commit_id != work.meta.commit_id
        ):
            raise ValueError("CONTEXT_CALL_INVALID")
        locations: dict[bytes, CodeLocation] = {
            canonical_bytes(item): item for item in proposal.target_locations
        }
        for entity in proposal.target_entities:
            locations[canonical_bytes(entity.location)] = entity.location
        for item in proposal.suspected_path:
            if isinstance(item, CodeLocation):
                locations[canonical_bytes(item)] = item
            elif isinstance(item, CodeRelation):
                locations[canonical_bytes(item.from_location)] = item.from_location
                locations[canonical_bytes(item.to_location)] = item.to_location
        if not locations:
            raise ValueError("CONTEXT_TARGET_REQUIRED")
        ceiling = resolve_context_ceiling(
            self.runner.runtime.unit_of_work.artifacts, work
        )
        intent = ContextRetrievalIntent(
            proposal_ref=proposals[0],
            bundle_ref=bundles[0],
            requested_entities=proposal.target_entities,
            requested_locations=tuple(locations[key] for key in sorted(locations)),
            relation_query=(
                "CALLERS",
                "CALLEES",
                "DATA_FLOW_NEIGHBORS",
                "AUTH_GUARDS",
                "ROUTE_BINDINGS",
            ),
            reason="Retrieve exact code context for the current hypothesis proposal",
            requested_limits=ceiling.limits,
        )
        return ContextRetrievalCall(
            intent,
            workspace,
            bundle,
            state.budget_binding_ref,
        )


@dataclass(frozen=True, slots=True)
class ContextRetrievalWorkHandler:
    service: ContextRetrievalService
    resolve_call: ExactContextRetrievalCallResolver
    requester_identity_ref: BudgetScopeRef
    service_identity_ref: BudgetScopeRef

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        call = self.resolve_call(context)
        _response, response_ref = await self.service.retrieve(
            work=context.work,
            intent=call.intent,
            workspace=call.workspace,
            bundle=call.bundle,
            budget_scope=call.budget_scope_ref,
            requester_identity=self.requester_identity_ref,
            requester_role="VERIFICATION",
            service_identity=self.service_identity_ref,
            work_timeout_ms=call.intent.requested_limits.timeout_ms,
        )
        return WorkHandlerResult((response_ref,))


def _fresh_analysis_meta(
    runner: WorkflowRunner,
    source: RecordMetadata,
    kind: str,
    *,
    workspace_id: str | None = None,
    commit_id: str | None = None,
) -> RecordMeta:
    raw = runner.metadata(source, kind)
    if workspace_id is not None:
        raw["workspace_id"] = workspace_id
    if commit_id is not None:
        raw["commit_id"] = commit_id
    raw["hypothesis_id"] = None
    raw["attempt_id"] = None
    return RecordMeta.model_validate(raw)


def _stored_work_ref(work: WorkExecutionState) -> StoredDataRef:
    ref = reference(work)
    if not isinstance(ref, StoredDataRef):
        raise ValueError("STATIC_TOOL_JOIN_INPUT_INVALID")
    return ref


__all__ = [
    "ContextRetrievalCall",
    "ContextRetrievalWorkHandler",
    "ExactContextRetrievalCallResolver",
    "ExactRepositoryProfileCallResolver",
    "ExactStaticNormalizationCallResolver",
    "ExactStaticToolCallResolver",
    "RepositoryProfileFanoutWorkHandler",
    "StaticNormalizationCall",
    "StaticNormalizationWorkHandler",
    "StaticPostWorkspaceSeeder",
    "StaticProductionGraph",
    "StaticToolCall",
    "StaticToolRoute",
    "StaticToolWorkHandler",
    "require_current_work_context",
    "resolve_static_tool_recovery_action",
    "selected_static_paths",
]
