from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

import pytest

from sastsimi.contracts.analysis import (
    AnalysisRunInput,
    AnalysisRunState,
    AnalysisStartRequest,
)
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    ExecutionBudgetProfile,
    ProfileStatus,
    Purpose,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.reporting import ReportProcessState
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.orchestration.analysis_service import AnalysisService
from sastsimi.orchestration.production_handlers import ProductionHandlerRegistry
from sastsimi.orchestration.production_pipeline import ProductionPipeline
from sastsimi.orchestration.result_aggregation import (
    ResultAggregationPort,
    ResultAggregationService,
)
from sastsimi.orchestration.run_initialization import (
    RunBootstrap,
    RunInitializationService,
)
from sastsimi.ports.dto import StagedArtifact, WorkContext, WorkHandlerResult
from sastsimi.ports.scheduler import RunOutcome


@dataclass(frozen=True)
class _UnusedHandler:
    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        del context
        return WorkHandlerResult(())


NOW = datetime(2026, 9, 13, tzinfo=UTC)
ANALYSIS_ID = "analysis-lane-d"
WORKSPACE_ID = "workspace-lane-d"
COMMIT_ID = "a" * 40


def _run_ref(kind: str, key: str) -> RunStoredDataRef:
    return RunStoredDataRef(
        stored_data_id=key,
        data_kind=kind,
        content_hash="a" * 64,
        analysis_id=ANALYSIS_ID,
        record_id=key,
    )


def _stored_ref(kind: str, key: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=key,
        data_kind=kind,
        content_hash="b" * 64,
        workspace_id=WORKSPACE_ID,
        commit_id=COMMIT_ID,
        record_id=key,
    )


def _run_meta(kind: str, key: str) -> RunMeta:
    return RunMeta(
        record_id=key,
        logical_record_id=key,
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=NOW,
        analysis_id=ANALYSIS_ID,
    )


def _record_meta(
    kind: str, key: str, *, hypothesis_id: str | None = None
) -> RecordMeta:
    return RecordMeta(
        **_run_meta(kind, key).model_dump(),
        workspace_id=WORKSPACE_ID,
        commit_id=COMMIT_ID,
        hypothesis_id=hypothesis_id,
        attempt_id=None,
    )


def _execution() -> ExecutionBudgetProfile:
    return ExecutionBudgetProfile(
        meta=_run_meta("execution_budget_profile", "execution-profile"),
        profile_key="production-default",
        purpose=Purpose.PRODUCTION,
        max_analysis_elapsed_ms=120_000,
        max_total_cost_minor_units=1_000,
        currency="USD",
        pricing_revision_ref=_run_ref("pricing_revision", "pricing-revision"),
        max_total_work=100,
        max_total_llm_calls=100,
        max_total_retries=10,
        max_parallel_work=2,
        approval_ref=_run_ref("approval", "execution-approval"),
        approved_by="r8",
        approved_at=NOW,
        status=ProfileStatus.ACTIVE,
    )


def _run_input(request: AnalysisStartRequest) -> AnalysisRunInput:
    return AnalysisRunInput(
        meta=_run_meta("analysis_run_input", "analysis-input"),
        repository_ref=request.repository_ref,
        requested_git_ref=request.requested_git_ref,
        program_id=request.program_id,
        purpose=request.purpose,
    )


def _binding(execution_ref: RunStoredDataRef) -> BudgetProfileBinding:
    return BudgetProfileBinding(
        meta=_record_meta("budget_profile_binding", "budget-binding"),
        binding_key="production-default",
        purpose=Purpose.PRODUCTION,
        execution_budget_profile_ref=execution_ref,
        work_budget_profile_ref=_stored_ref("work_budget_profile", "work-budget"),
        verification_budget_profile_ref=_stored_ref(
            "verification_budget_profile", "verification-budget"
        ),
        dynamic_lifecycle_profile_ref=_stored_ref(
            "dynamic_reproduction_lifecycle_profile", "dynamic-budget"
        ),
        approval_ref=_stored_ref("approval", "binding-approval"),
        approved_by="r8",
        approved_at=NOW,
        status=ProfileStatus.ACTIVE,
    )


def _workspace_work(
    *,
    status: WorkStatus = WorkStatus.READY,
    input_refs: tuple[RecordRef, ...] = (),
) -> WorkExecutionState:
    terminal = status in {
        WorkStatus.SUCCEEDED,
        WorkStatus.PARTIAL,
        WorkStatus.FAILED,
        WorkStatus.CANCELLED,
    }
    return WorkExecutionState(
        meta=_run_meta("work_execution_state", "workspace-work-state"),
        work_id="workspace-work",
        parent_work_ref=None,
        work_type=WorkType.WORKSPACE_PREP,
        subject_type=SubjectType.ANALYSIS,
        subject_id=ANALYSIS_ID,
        work_generation=1,
        status=status,
        state_version=2,
        last_transition_ref=_run_ref("state_transition", "workspace-ready"),
        last_transition_commit_ref=None,
        active_attempt_id=None,
        input_hash=content_hash(input_refs),
        dedupe_key="c" * 64,
        trigger_primitive_ref=None,
        input_refs=input_refs,
        output_refs=(),
        gap_ids=(),
        error_ids=(),
        waiting_for=(),
        stop_reason="COMPLETED" if terminal else None,
        started_at=NOW if terminal else None,
        finished_at=NOW if terminal else None,
        elapsed_ms=0,
    )


def _workspace_dependencies() -> tuple[RecordRef, ...]:
    return (
        RunStoredDataRef(
            stored_data_id="workspace-policy",
            data_kind="artifact",
            content_hash="d" * 64,
            analysis_id=ANALYSIS_ID,
            record_id=None,
        ),
        HostConfigurationRef(
            stored_data_id="git-capability",
            data_kind="runtime_capability_profile",
            content_hash="e" * 64,
            host_id="local-host",
            publication_analysis_id=ANALYSIS_ID,
            publication_workspace_id="capability-workspace",
            publication_commit_id="capability-commit",
            record_id="git-capability-record",
        ),
    )


class _Profiles:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.execution = _execution()
        execution_ref = reference(self.execution)
        assert isinstance(execution_ref, RunStoredDataRef)
        self.binding = _binding(execution_ref)

    def resolve_active_execution(
        self, request: AnalysisStartRequest
    ) -> ExecutionBudgetProfile:
        assert request.purpose == "PRODUCTION"
        self.events.append("resolve-execution")
        return self.execution

    def require_current_execution(self, profile: ExecutionBudgetProfile) -> None:
        assert profile == self.execution
        self.events.append("require-current-execution")

    def resolve_active_binding(
        self, request: AnalysisStartRequest, state: AnalysisRunState
    ) -> BudgetProfileBinding:
        assert request.program_id == state.program_id
        self.events.append("resolve-binding")
        return self.binding

    def require_current_binding(self, binding: BudgetProfileBinding) -> None:
        assert binding == self.binding
        self.events.append("require-current-binding")


class _StateFactory:
    def __init__(self) -> None:
        self.calls = 0

    def create(
        self,
        request: AnalysisStartRequest,
        execution_ref: RunStoredDataRef,
    ) -> RunBootstrap:
        self.calls += 1
        run_input = _run_input(request)
        state = AnalysisRunState(
            meta=_run_meta("analysis_run_state", "analysis-state"),
            purpose=request.purpose,
            eval_config_refs=(),
            analysis_input_ref=cast(RunStoredDataRef, reference(run_input)),
            program_id=request.program_id,
            execution_budget_profile_ref=execution_ref,
            budget_binding_ref=None,
            workspace_id=None,
            commit_id=None,
            workspace_ref=None,
            run_policy_state_ref=None,
            status="RUNNING",
            analysis_result_ref=None,
            started_at=NOW,
            finished_at=None,
            elapsed_ms=0,
        )
        return RunBootstrap(run_input, state)


class _BudgetRegistry:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.state: AnalysisRunState | None = None
        self.run_input: AnalysisRunInput | None = None

    def pin_execution(
        self,
        profile: ExecutionBudgetProfile,
        state: AnalysisRunState | None = None,
        run_input: AnalysisRunInput | None = None,
    ) -> RunStoredDataRef:
        assert state is not None
        assert run_input is not None
        assert reference(run_input) == state.analysis_input_ref
        self.events.append("pin-execution")
        self.state = state
        self.run_input = run_input
        ref = reference(profile)
        assert isinstance(ref, RunStoredDataRef)
        return ref

    def current_state(self, analysis_id: str) -> AnalysisRunState:
        assert analysis_id == ANALYSIS_ID and self.state is not None
        return self.state

    def current_input(self, analysis_id: str) -> AnalysisRunInput:
        assert analysis_id == ANALYSIS_ID and self.run_input is not None
        return self.run_input

    def pin_binding(
        self,
        binding: BudgetProfileBinding,
        workspace_ref: RunStoredDataRef,
        analysis_state_ref: RunStoredDataRef | None = None,
    ) -> StoredDataRef:
        assert analysis_state_ref == reference(cast(AnalysisRunState, self.state))
        assert self.state is not None and self.state.workspace_ref == workspace_ref
        self.events.append("pin-binding")
        binding_ref = reference(binding)
        assert isinstance(binding_ref, StoredDataRef)
        self.state = AnalysisRunState.model_validate(
            self.state.model_dump()
            | {
                "budget_binding_ref": binding_ref,
            }
        )
        return binding_ref

    def make_workspace_ready(self) -> None:
        assert self.state is not None
        workspace_ref = _run_ref("code_workspace", "workspace-ready-record")
        self.state = AnalysisRunState.model_validate(
            self.state.model_dump()
            | {
                "workspace_id": WORKSPACE_ID,
                "commit_id": COMMIT_ID,
                "workspace_ref": workspace_ref,
            }
        )


class _ReadyWork:
    def __init__(self, events: list[str], work_query: _WorkQuery) -> None:
        self.events = events
        self.work_query = work_query

    def enqueue(
        self,
        scope: BudgetScopeRef,
        metadata: RunMeta | RecordMeta,
        work_type: str,
        subject_type: str,
        subject_id: str,
        identity: BudgetScopeRef,
        **values: object,
    ) -> WorkExecutionState:
        del identity
        assert scope.data_kind == "execution_budget_profile"
        assert str(metadata.analysis_id) == ANALYSIS_ID
        assert work_type == WorkType.WORKSPACE_PREP
        assert subject_type == "ANALYSIS" and subject_id == ANALYSIS_ID
        self.events.append("enqueue-workspace")
        inputs = cast(tuple[RecordRef, ...], values["inputs"])
        work = _workspace_work(input_refs=inputs)
        self.work_query.works = (work,)
        return work

    def enqueue_registered(self, *_: object, **__: object) -> WorkExecutionState:
        raise AssertionError("initializer must not use a pre-registered work")

    def ensure_enqueue(self, *args: object, **values: object) -> WorkExecutionState:
        assert values["stable_key"] == "workspace-prep:" + ANALYSIS_ID
        return self.enqueue(*args, **values)


class _WorkQuery:
    def __init__(self) -> None:
        self.works: tuple[WorkExecutionState, ...] = ()

    def mark_workspace_succeeded(self) -> None:
        self.works = (
            _workspace_work(
                status=WorkStatus.SUCCEEDED,
                input_refs=(
                    _run_ref("analysis_run_input", "analysis-input"),
                    *_workspace_dependencies(),
                ),
            ),
        )

    def work_for_run(self, analysis_id: str) -> tuple[WorkExecutionState, ...]:
        assert analysis_id == ANALYSIS_ID
        return self.works


class _Seeder:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def ensure_initial(
        self,
        request: AnalysisStartRequest,
        state: AnalysisRunState,
        binding_ref: StoredDataRef,
    ) -> tuple[WorkExecutionState, ...]:
        assert request.program_id == state.program_id
        assert state.budget_binding_ref == binding_ref
        self.events.append("seed-after-binding")
        return ()


def test_handler_registry_rejects_missing_and_duplicate_mappings() -> None:
    handler = _UnusedHandler()
    missing = ProductionHandlerRegistry(
        (kind, handler) for kind in WorkType if kind != WorkType.REPORT_DRAFT
    )

    with pytest.raises(ValueError, match="WORK_HANDLER_MAPPING_INCOMPLETE"):
        missing.validate_complete(tuple(WorkType))

    with pytest.raises(ValueError, match="WORK_HANDLER_MAPPING_DUPLICATED"):
        ProductionHandlerRegistry(
            (
                (WorkType.WORKSPACE_PREP, handler),
                (WorkType.WORKSPACE_PREP, handler),
            )
        )


def test_run_initialization_pins_current_budgets_before_each_enqueue_phase() -> None:
    events: list[str] = []
    profiles = _Profiles(events)
    states = _StateFactory()
    budgets = _BudgetRegistry(events)
    work_query = _WorkQuery()
    initializer = RunInitializationService(
        profiles=profiles,
        state_factory=states,
        budgets=budgets,
        ready_work=_ReadyWork(events, work_query),
        work_query=work_query,
        workspace_identity_ref=_run_ref("identity", "workspace-identity"),
        workspace_dependency_refs=_workspace_dependencies(),
        seeder=_Seeder(events),
    )
    request = AnalysisStartRequest(
        repository_ref="C:/fixture/repository",
        requested_git_ref=COMMIT_ID,
        program_id="program-lane-d",
        purpose=Purpose.PRODUCTION,
    )

    initialized = initializer.start(request)

    assert states.calls == 1
    assert initialized.analysis_id == ANALYSIS_ID
    assert initialized.workspace_work.status == WorkStatus.READY
    assert events == [
        "resolve-execution",
        "require-current-execution",
        "pin-execution",
        "enqueue-workspace",
    ]

    budgets.make_workspace_ready()
    work_query.mark_workspace_succeeded()
    bound = initializer.bind_workspace_and_seed(initialized)

    assert bound.binding_ref == reference(profiles.binding)
    assert bound.initial_work == ()
    assert events == [
        "resolve-execution",
        "require-current-execution",
        "pin-execution",
        "enqueue-workspace",
        "resolve-binding",
        "require-current-binding",
        "pin-binding",
        "seed-after-binding",
    ]


ALL_WORK_TYPES = tuple(WorkType)


class _ScriptedScheduler:
    """A scheduler fake that still resolves and calls production handlers."""

    def __init__(
        self,
        registry: ProductionHandlerRegistry,
        initializer: RunInitializationService,
        budgets: _BudgetRegistry,
        work_query: _WorkQuery,
        outcomes: list[RunOutcome],
    ) -> None:
        self.registry = registry
        self.initializer = initializer
        self.budgets = budgets
        self.work_query = work_query
        self.outcomes = outcomes
        self.calls = 0
        self.handler_failures: list[WorkType] = []

    async def drain(self, analysis_id: str) -> RunOutcome:
        self.calls += 1
        work_types = (
            (WorkType.WORKSPACE_PREP,)
            if self.calls == 1
            else (
                WorkType.STATIC_TOOL,
                WorkType.HYPOTHESIS_PROPOSAL,
                WorkType.REPORT_DRAFT,
            )
        )
        for work_type in work_types:
            handler = self.registry.resolve(work_type)
            try:
                await handler.execute(cast(WorkContext, object()))
            except RuntimeError:
                self.handler_failures.append(work_type)
        if self.calls == 1:
            self.budgets.make_workspace_ready()
            self.work_query.mark_workspace_succeeded()
        return self.outcomes.pop(0)


class _NamedHandler:
    def __init__(self, name: str, events: list[str], *, fail: bool = False) -> None:
        self.name = name
        self.events = events
        self.fail = fail

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        del context
        self.events.append(self.name)
        if self.fail:
            raise RuntimeError("safe fake-provider failure")
        return WorkHandlerResult(())


class _CandidateAggregator(ResultAggregationPort):
    def __init__(self, candidate: AnalysisRunResult) -> None:
        self.candidate = candidate
        self.calls = 0

    def build(
        self,
        analysis_id: str,
        disposition: str,
    ) -> AnalysisRunResult:
        del disposition
        assert analysis_id == ANALYSIS_ID
        self.calls += 1
        return self.candidate


class _Finalizer:
    def __init__(self) -> None:
        self.results: list[AnalysisRunResult] = []

    def finalize(self, result: AnalysisRunResult) -> RunStoredDataRef:
        self.results.append(result)
        return _run_ref("analysis_run_result", "terminal-result")


def _candidate(status: str = "COMPLETE") -> AnalysisRunResult:
    from tests.contract.domain.canonical_fixtures import make

    raw = make("AnalysisRunResult")
    return AnalysisRunResult.model_validate_json(
        canonical_bytes(
            raw
            | {
                "meta": _run_meta("analysis_run_result", "result-candidate"),
                "purpose": "PRODUCTION",
                "repository_url": "C:/fixture/repository",
                "program_id": "program-lane-d",
                "workspace_id": WORKSPACE_ID,
                "commit_id": COMMIT_ID,
                "workspace_ref": _run_ref("code_workspace", "workspace-ready-record"),
                "status": status,
                "failed_hypothesis_count": 1 if status == "PARTIAL" else 0,
                "work_state_refs": (
                    (_stored_ref("work_execution_state", "hypothesis-failed-state"),)
                    if status == "PARTIAL"
                    else ()
                ),
                "eval_config_refs": (),
                "report_draft_refs": (_stored_ref("report_draft", "report-draft-one"),),
                "started_at": NOW,
                "finished_at": NOW,
                "elapsed_ms": 0,
                "debug_trace_ref": _run_ref("debug_trace", "debug-trace"),
            }
        )
    )


def _production_fixture(
    *,
    final_outcome: str = "TERMINAL",
    candidate_status: str = "COMPLETE",
    hypothesis_failure: bool = False,
) -> tuple[AnalysisService, _StateFactory, _CandidateAggregator, _Finalizer, list[str]]:
    events: list[str] = []
    handlers = {
        kind: _NamedHandler(
            "local-fake-tool"
            if kind == WorkType.WORKSPACE_PREP
            else "local-fake-provider"
            if kind == WorkType.HYPOTHESIS_PROPOSAL
            else "local-fake-reporter"
            if kind == WorkType.REPORT_DRAFT
            else f"unused-{kind.value}",
            events,
            fail=hypothesis_failure and kind == WorkType.HYPOTHESIS_PROPOSAL,
        )
        for kind in ALL_WORK_TYPES
    }
    registry = ProductionHandlerRegistry(handlers.items())
    profiles = _Profiles(events)
    states = _StateFactory()
    budgets = _BudgetRegistry(events)
    work_query = _WorkQuery()
    initializer = RunInitializationService(
        profiles=profiles,
        state_factory=states,
        budgets=budgets,
        ready_work=_ReadyWork(events, work_query),
        work_query=work_query,
        workspace_identity_ref=_run_ref("identity", "workspace-identity"),
        workspace_dependency_refs=_workspace_dependencies(),
        seeder=_Seeder(events),
    )
    outcomes = [
        RunOutcome(ANALYSIS_ID, "TERMINAL", None),
        RunOutcome(ANALYSIS_ID, final_outcome, None),
    ]
    scheduler = _ScriptedScheduler(
        registry, initializer, budgets, work_query, outcomes
    )
    aggregator = _CandidateAggregator(_candidate(candidate_status))
    finalizer = _Finalizer()
    pipeline = ProductionPipeline(
        handlers=registry,
        initializer=initializer,
        scheduler=scheduler,
        aggregator=aggregator,
        finalizer=finalizer,
        required_work_types=ALL_WORK_TYPES,
    )
    return AnalysisService(pipeline), states, aggregator, finalizer, events


@pytest.mark.asyncio
async def test_production_registry_reaches_report_draft_without_fake_pipeline() -> None:
    service, states, aggregator, finalizer, events = _production_fixture()

    outcome = await service.run(
        AnalysisStartRequest(
            repository_ref="C:/fixture/repository",
            requested_git_ref=COMMIT_ID,
            program_id="program-lane-d",
            purpose=Purpose.PRODUCTION,
        )
    )

    assert outcome.disposition == "TERMINAL"
    assert outcome.result_ref == _run_ref("analysis_run_result", "terminal-result")
    assert states.calls == 1
    assert aggregator.calls == 1
    assert finalizer.results[0].report_draft_refs == (
        _stored_ref("report_draft", "report-draft-one"),
    )
    assert "local-fake-tool" in events
    assert "local-fake-provider" in events
    assert "local-fake-reporter" in events


@pytest.mark.asyncio
async def test_one_hypothesis_failure_is_partial_and_report_sibling_continues() -> None:
    service, _, aggregator, finalizer, events = _production_fixture(
        candidate_status="PARTIAL",
        hypothesis_failure=True,
    )

    outcome = await service.run(
        AnalysisStartRequest(
            repository_ref="C:/fixture/repository",
            requested_git_ref=COMMIT_ID,
            program_id="program-lane-d",
            purpose=Purpose.PRODUCTION,
        )
    )

    assert outcome.disposition == "TERMINAL"
    assert aggregator.calls == 1
    assert finalizer.results[0].status == "PARTIAL"
    assert finalizer.results[0].work_state_refs == (
        _stored_ref("work_execution_state", "hypothesis-failed-state"),
    )
    assert "local-fake-provider" in events
    assert "local-fake-reporter" in events


@pytest.mark.asyncio
async def test_blocked_only_run_has_no_terminal_result() -> None:
    service, _, aggregator, finalizer, _ = _production_fixture(final_outcome="BLOCKED")

    outcome = await service.run(
        AnalysisStartRequest(
            repository_ref="C:/fixture/repository",
            requested_git_ref=COMMIT_ID,
            program_id="program-lane-d",
            purpose=Purpose.PRODUCTION,
        )
    )

    assert outcome == RunOutcome(ANALYSIS_ID, "BLOCKED", None)
    assert aggregator.calls == 0
    assert finalizer.results == []


@pytest.mark.asyncio
async def test_registry_defect_fails_before_run_creation() -> None:
    service, states, _, _, _ = _production_fixture()
    pipeline = cast(ProductionPipeline, service.pipeline)
    pipeline.handlers = ProductionHandlerRegistry(
        (kind, _UnusedHandler())
        for kind in ALL_WORK_TYPES
        if kind != WorkType.REPORT_DRAFT
    )

    with pytest.raises(ValueError, match="WORK_HANDLER_MAPPING_INCOMPLETE"):
        await service.run(
            AnalysisStartRequest(
                repository_ref="C:/fixture/repository",
                requested_git_ref=COMMIT_ID,
                program_id="program-lane-d",
                purpose=Purpose.PRODUCTION,
            )
        )

    assert states.calls == 0


class _ExactRecords:
    def __init__(self, records: tuple[object, ...]) -> None:
        self.values = {reference(cast(object, item)): item for item in records}

    def get_exact(self, ref: object) -> object:
        return self.values[ref]

    def is_revision_descendant(self, earlier_ref: object, later_ref: object) -> bool:
        del earlier_ref, later_ref
        return False

    def stage_record(self, record: object) -> object:
        raise AssertionError(record)

    def commit_transition(self, request: object) -> object:
        raise AssertionError(request)


class _CurrentRecords:
    def __init__(self, records: tuple[object, ...]) -> None:
        self.records = records

    def current_records(self, analysis_id: str, kind: str) -> tuple[object, ...]:
        assert analysis_id == ANALYSIS_ID
        return tuple(item for item in self.records if item.meta.record_type == kind)

    def published_records(self, analysis_id: str) -> tuple[object, ...]:
        assert analysis_id == ANALYSIS_ID
        return self.records


class _DebugArtifacts:
    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        assert b'"analysis_id":"analysis-lane-d"' in data
        return StagedArtifact(data, media_type)

    def commit_run(self, staged: StagedArtifact, analysis_id: str) -> RunStoredDataRef:
        assert staged.media_type == "application/json"
        assert str(analysis_id) == ANALYSIS_ID
        return _run_ref("debug_trace", "aggregated-debug")

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        raise AssertionError(staged)

    def open_verified(self, ref: object) -> object:
        raise AssertionError(ref)


class _FixedClock:
    def now(self) -> datetime:
        return NOW

    def monotonic_ms(self) -> int:
        return 0


class _ResultMetadata:
    def create(self, state: AnalysisRunState) -> RunMeta:
        assert str(state.meta.analysis_id) == ANALYSIS_ID
        return _run_meta("analysis_run_result", "aggregated-result")


def test_result_aggregation_uses_exact_current_report_inventory() -> None:
    execution = _execution()
    execution_ref = reference(execution)
    assert isinstance(execution_ref, RunStoredDataRef)
    workspace = CodeWorkspace(
        meta=_run_meta("code_workspace", "aggregated-workspace"),
        workspace_id=WORKSPACE_ID,
        analysis_id=ANALYSIS_ID,
        repository_url="https://example.invalid/repository.git",
        commit_id=COMMIT_ID,
        status="READY",
    )
    workspace_ref = reference(workspace)
    assert isinstance(workspace_ref, RunStoredDataRef)
    run_input = _run_input(
        AnalysisStartRequest(
            repository_ref="ignored-after-workspace-ready",
            requested_git_ref=COMMIT_ID,
            program_id="program-lane-d",
            purpose=Purpose.PRODUCTION,
        )
    )
    run_input_ref = reference(run_input)
    assert isinstance(run_input_ref, RunStoredDataRef)
    state = AnalysisRunState(
        meta=_run_meta("analysis_run_state", "aggregate-state"),
        purpose=Purpose.PRODUCTION,
        eval_config_refs=(),
        analysis_input_ref=run_input_ref,
        program_id="program-lane-d",
        execution_budget_profile_ref=execution_ref,
        budget_binding_ref=_stored_ref("budget_profile_binding", "binding-current"),
        workspace_id=WORKSPACE_ID,
        commit_id=COMMIT_ID,
        workspace_ref=workspace_ref,
        run_policy_state_ref=None,
        status="RUNNING",
        analysis_result_ref=None,
        started_at=NOW,
        finished_at=None,
        elapsed_ms=0,
    )
    report_ref = _stored_ref("report_draft", "current-report")
    report_state = ReportProcessState(
        meta=_record_meta(
            "report_process_state", "report-state", hypothesis_id="hypothesis-one"
        ),
        status="DRAFTED",
        report_draft_ref=report_ref,
        started_at=NOW,
        finished_at=NOW,
        elapsed_ms=0,
    )
    work = _workspace_work(status=WorkStatus.SUCCEEDED)
    budgets = _BudgetRegistry([])
    budgets.state = state
    records = _ExactRecords((execution, workspace))
    service = ResultAggregationService(
        states=budgets,
        queries=_CurrentRecords((work, report_state)),
        records=cast(object, records),
        artifacts=_DebugArtifacts(),
        clock=_FixedClock(),
        metadata=_ResultMetadata(),
    )

    budgets.run_input = run_input
    result = service.build(ANALYSIS_ID, "TERMINAL")

    assert result.status == "COMPLETE"
    assert result.repository_url == workspace.repository_url
    assert result.workspace_ref == workspace_ref
    assert result.report_draft_refs == (report_ref,)
    assert result.work_state_refs == (reference(work),)
    assert result.resources.work_count == 1
