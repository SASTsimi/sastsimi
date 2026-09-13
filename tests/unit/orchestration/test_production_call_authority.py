from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionCheck,
    ActionDecision,
    ActionRequest,
    CheckResult,
    Decision,
    UseStatus,
)
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    BudgetRemaining,
    BudgetReservation,
    BudgetUnits,
    ProfileStatus,
    Purpose,
)
from sastsimi.contracts.evaluation import UsageMeasurement
from sastsimi.contracts.ids import (
    AnalysisId,
    AttemptId,
    CommitId,
    DecisionId,
    LogicalRecordId,
    OpaqueId,
    ProgramId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationRequest,
    LLMInvocationResult,
    LLMRole,
    PromptPayload,
    PromptRegistryEntry,
)
from sastsimi.contracts.llm_closure import llm_action_input_refs
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import (
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.work import TransitionCommit, WorkExecutionState, WorkType
from sastsimi.orchestration.production_call_authority import (
    AnalysisApprovedRoute,
    ExactAnalysisProductionRouteLookup,
    ProductionPreparedCallAuthorizer,
    production_call_authority,
)
from sastsimi.orchestration.production_llm_work_handlers import (
    ConfiguredProductionCallResolver,
)
from sastsimi.ports.dto import (
    BudgetCommitRequest,
    BudgetReservationRequest,
    Record,
    TransitionCommitRequest,
)
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.runtime.workflow_runner import WorkflowRunner
from tests.contract.domain.fixtures import bundle


def _prompt_fixture(tmp_path: Path) -> tuple[Any, Any, Any, Any, Any]:
    fixtures = import_module("tests.unit.prompts.test_production_configuration")
    service, records, artifacts = fixtures._service(tmp_path)
    route, approval = fixtures._approved_hypothesis_route(
        service, records, artifacts
    )
    return service, records, artifacts, route, approval

NOW = datetime(2026, 9, 13, tzinfo=UTC)


@pytest.mark.parametrize(
    ("role", "action_type", "requested_by"),
    (
        ("HYPOTHESIS", "CALL_LLM", "HYPOTHESIS"),
        ("TECHNICAL_GATE", "CALL_TECHNICAL_GATE", "VERIFICATION"),
        ("RULE_SCOPE_GATE", "CALL_RULE_SCOPE_GATE", "VERIFICATION"),
        ("REPORTER", "CREATE_REPORT_DRAFT", "VERIFICATION"),
    ),
)
def test_production_call_authority_uses_role_specific_workflow_actions(
    role: Any, action_type: str, requested_by: str
) -> None:
    actual_action, actual_role = production_call_authority(role)

    assert str(actual_action) == action_type
    assert str(actual_role) == requested_by


def _stored(kind: str, name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(name),
        data_kind=kind,
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=RecordId(f"{name}-record"),
    )


def _run_ref(kind: str, name: str) -> RunStoredDataRef:
    return RunStoredDataRef(
        stored_data_id=StoredDataId(name),
        data_kind=kind,
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        analysis_id=AnalysisId("a1"),
        record_id=RecordId(f"{name}-record"),
    )


def _record_meta(kind: str, name: str, *, attempt_id: str | None = None) -> RecordMeta:
    return RecordMeta(
        record_id=RecordId(f"{name}-record"),
        logical_record_id=LogicalRecordId(f"{name}-logical"),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=NOW,
        analysis_id=AnalysisId("a1"),
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        hypothesis_id=None,
        attempt_id=AttemptId(attempt_id) if attempt_id is not None else None,
    )


def _run_meta(kind: str, name: str) -> RunMeta:
    return RunMeta(
        record_id=RecordId(f"{name}-record"),
        logical_record_id=LogicalRecordId(f"{name}-logical"),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=NOW,
        analysis_id=AnalysisId("a1"),
    )


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind.model_validate(f"call-authority-{self.value}")


class _Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic_ms(self) -> int:
        return 0


@dataclass
class _ProductionRoute:
    role: LLMRole
    task_kind: str
    provider_profile_key: str
    model: str
    prompt_key: str


def _production_route(route: Any) -> _ProductionRoute:
    return _ProductionRoute(
        role=cast(LLMRole, route.role),
        task_kind=cast(str, route.task_kind),
        provider_profile_key=cast(str, route.provider_profile_key),
        model=cast(str, route.model),
        prompt_key=cast(str, route.prompt_key),
    )


class _Records:
    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate

    def add(self, record: Record) -> StoredDataRef:
        ref = self.delegate.add(record)
        if not isinstance(ref, StoredDataRef):
            raise AssertionError("test record must be code-scoped")
        return ref

    def get_exact(self, ref: RecordRef) -> Record:
        return cast(Record, self.delegate.get_exact(ref))

    def stage_record(self, record: Record) -> RecordRef:
        exact = reference(record)
        assert isinstance(exact, StoredDataRef)
        self.delegate.values[(str(exact.record_id), exact.content_hash)] = record
        return exact

    def is_revision_descendant(
        self, earlier_ref: RecordRef, later_ref: RecordRef
    ) -> bool:
        return earlier_ref == later_ref

    def commit_transition(
        self, request: TransitionCommitRequest
    ) -> TransitionCommit:
        raise AssertionError(request)


class _Budget:
    def __init__(self) -> None:
        self.reservations: list[BudgetReservation] = []
        self.commits: list[BudgetCommitRequest] = []

    def reserve(self, request: BudgetReservationRequest) -> BudgetReservation:
        self.reservations.append(request.reservation)
        return request.reservation

    def remaining(self, _scope: object, _analysis_id: str) -> BudgetRemaining:
        reservation = self.reservations[-1]
        return BudgetRemaining(
            budget_binding_ref=reservation.budget_binding_ref,
            as_of_sequence=0,
            available_units=BudgetUnits(
                elapsed_ms=10_000,
                work_count=10,
                llm_call_count=10,
                retry_count=10,
                cost_minor_units=10_000,
                currency="USD",
            ),
            active_reservation_count=1,
        )

    def commit_usage(self, request: BudgetCommitRequest) -> object:
        self.commits.append(request)
        return request.entry

    def release(self, request: object) -> object:
        raise AssertionError(
            f"claimed call reservation must not be released: {request}"
        )


class _Validator:
    def __init__(self, records: _Records) -> None:
        self.records = records

    def authorize(
        self,
        action: ActionRequest,
        work: WorkExecutionState,
        reservation_ref: object,
    ) -> ActionDecision:
        assert reservation_ref is not None
        checks = tuple(
            ActionCheck(
                check_type=kind,
                result=CheckResult.PASS,
                reason_code="OK",
                safe_message="approved",
            )
            for kind in sorted(REQUIRED_CHECKS[action.action_type], key=str)
        )
        action_ref = self.records.stage_record(action)
        assert isinstance(action_ref, StoredDataRef)
        decision = ActionDecision(
            meta=_record_meta(
                "action_decision",
                "decision",
                attempt_id=str(work.active_attempt_id),
            ),
            decision_id=DecisionId("decision"),
            action_ref=action_ref,
            decision=Decision.ALLOW,
            required_checks=tuple(item.check_type for item in checks),
            check_results=checks,
            checked_state_version=work.state_version,
            checked_config_refs=(),
            valid_until=NOW + timedelta(minutes=1),
            error_ids=(),
            use_status=UseStatus.UNUSED,
            used_at=None,
            expired_at=None,
            expire_reason=None,
            outcome_refs=(),
            decided_at=NOW,
        )
        self.records.stage_record(decision)
        return decision


@dataclass(frozen=True)
class _BudgetRegistry:
    state: AnalysisRunState

    def current_state(self, analysis_id: str) -> AnalysisRunState:
        assert analysis_id == "a1"
        return self.state


def _binding() -> BudgetProfileBinding:
    return BudgetProfileBinding(
        meta=_record_meta("budget_profile_binding", "binding"),
        binding_key="production",
        purpose=Purpose.PRODUCTION,
        execution_budget_profile_ref=_run_ref("execution_budget_profile", "execution"),
        work_budget_profile_ref=_stored("work_budget_profile", "work-budget"),
        verification_budget_profile_ref=_stored(
            "verification_budget_profile", "verification-budget"
        ),
        dynamic_lifecycle_profile_ref=_stored(
            "dynamic_reproduction_lifecycle_profile", "dynamic-budget"
        ),
        approval_ref=_stored("approval", "binding-approval"),
        approved_by="r8",
        approved_at=NOW,
        status=ProfileStatus.ACTIVE,
    )


def _state(binding_ref: StoredDataRef) -> AnalysisRunState:
    return AnalysisRunState(
        meta=_run_meta("analysis_run_state", "run-state"),
        purpose=Purpose.PRODUCTION,
        eval_config_refs=(),
        analysis_input_ref=_run_ref("analysis_run_input", "run-input"),
        program_id=ProgramId("program"),
        execution_budget_profile_ref=_run_ref("execution_budget_profile", "execution"),
        budget_binding_ref=binding_ref,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        workspace_ref=_run_ref("code_workspace", "workspace"),
        run_policy_state_ref=None,
        status="RUNNING",
        analysis_result_ref=None,
        started_at=NOW,
        finished_at=None,
        elapsed_ms=0,
    )


def _work(source_ref: StoredDataRef) -> WorkExecutionState:
    from tests.unit.orchestration.test_production_llm_work_handlers import _context

    return _context(WorkType.HYPOTHESIS_PROPOSAL, (source_ref,)).work


def test_exact_route_authorizes_one_call_and_accounts_only_returned_usage(
    tmp_path: Path,
) -> None:
    service, prompt_records, artifacts, raw_route, approval = _prompt_fixture(tmp_path)
    route = _production_route(raw_route)
    records = _Records(prompt_records)
    facts = StaticFactBundle.model_validate_json(__import__("json").dumps(bundle()))
    facts_ref = records.add(facts)
    work = _work(facts_ref)
    binding = _binding()
    binding_ref = records.add(binding)
    budget = _Budget()
    runtime = SimpleNamespace(
        unit_of_work=SimpleNamespace(records=records),
        budget_registry=_BudgetRegistry(_state(binding_ref)),
        budget=budget,
        validator=_Validator(records),
    )
    runner = WorkflowRunner(cast(Any, runtime), _Clock(), _Ids())
    identity_ref = binding.work_budget_profile_ref
    authorizer = ProductionPreparedCallAuthorizer(
        runner=runner,
        records=records,
        requester_identities={("a1", "HYPOTHESIS"): identity_ref},
        reserved_cost_minor_units=100,
    )
    lookup = ExactAnalysisProductionRouteLookup(
        records=records,
        queries=service._queries,  # noqa: SLF001 - exact shared test registry
        approvals=(AnalysisApprovedRoute("a1", route, approval),),
    )
    resolver = ConfiguredProductionCallResolver(
        configuration=service,
        records=records,
        route_lookup=lookup,
        authorizer=authorizer,
    )

    call = resolver.resolve(
        work=work,
        role="HYPOTHESIS",
        task_kind="GENERATE_INITIAL",
        source_refs=(facts_ref,),
    )

    action = next(
        value
        for value in prompt_records.values.values()
        if isinstance(value, ActionRequest)
    )
    authorized_spec = records.get_exact(call.call_spec_ref)
    assert isinstance(authorized_spec, LLMCallSpec)
    authorized_payload = records.get_exact(authorized_spec.prompt_payload_ref)
    assert isinstance(authorized_payload, PromptPayload)
    assert action.action_type == "CALL_LLM"
    assert action.input_refs == llm_action_input_refs(
        call.call_spec_ref,
        authorized_spec,
        authorized_payload,
    )
    assert action.input_refs.count(facts_ref) == 1
    assert action.requested_by == "HYPOTHESIS"
    assert action.provider_profile_ref == authorized_spec.provider_profile_ref
    assert len(budget.reservations) == 1
    assert budget.reservations[0].budget_binding_ref == binding_ref
    assert budget.reservations[0].requested_units.llm_call_count == 1

    request = LLMInvocationRequest.model_validate(
        authorized_spec.model_dump()
        | {
            "meta": _record_meta(
                "llm_invocation_request",
                "request",
                attempt_id=str(work.active_attempt_id),
            ),
            "action_decision_ref": call.decision_ref,
            "call_spec_ref": call.call_spec_ref,
        }
    )
    records.add(request)
    usage = UsageMeasurement(
        token_source="PROVIDER_REPORTED",
        input_tokens=7,
        output_tokens=5,
        total_tokens=12,
        token_unavailable_reason=None,
        provider_units={"requests": 1},
        cost_source="PROVIDER_REPORTED",
        cost_minor_units=21,
        currency="USD",
        pricing_revision_ref=binding.approval_ref,
        cost_unavailable_reason=None,
    )
    result = LLMInvocationResult(
        meta=_record_meta(
            "llm_invocation_result", "result", attempt_id=str(work.active_attempt_id)
        ),
        llm_call_id=authorized_spec.llm_call_id,
        purpose="PRODUCTION",
        status="SUCCEEDED",
        provider="OPENAI",
        model=authorized_spec.model,
        actual_session_mode="NEW",
        session_ref="session-1",
        response_ref=_stored("artifact", "response"),
        parsed_output_ref=_stored("artifact", "response"),
        usage=usage,
        started_at=NOW,
        finished_at=NOW + timedelta(milliseconds=23),
        elapsed_ms=23,
        safe_error=None,
    )
    records.add(result)
    resolver.settle(
        call,
        PersistedLLMInvocation(
            request=request,
            result=result,
            log_ref=_stored("llm_invocation_log", "log"),
            dispatch_state="RETURNED",
        ),
    )

    assert len(budget.commits) == 1
    entry = budget.commits[0].entry
    assert entry.actual_units == runner.units(
        elapsed_ms=23, llm_call_count=1, cost_minor_units=21
    )
    assert entry.usage_refs == (reference(result),)


@pytest.mark.parametrize("failure", ["cross-analysis", "stale"])
def test_route_lookup_blocks_cross_analysis_and_stale_approval(
    tmp_path: Path, failure: str
) -> None:
    service, records, artifacts, raw_route, approval = _prompt_fixture(tmp_path)
    route = _production_route(raw_route)
    exact_records = _Records(records)
    lookup = ExactAnalysisProductionRouteLookup(
        records=exact_records,
        queries=service._queries,  # noqa: SLF001 - exact shared test registry
        approvals=(AnalysisApprovedRoute("a1", route, approval),),
    )
    analysis_id = "a2" if failure == "cross-analysis" else "a1"
    if failure == "stale":
        active = exact_records.get_exact(approval.active_prompt_ref)
        assert isinstance(active, PromptRegistryEntry)
        records.add(
            active.model_copy(
                update={
                    "meta": active.meta.model_copy(
                        update={
                            "record_id": "new-active-record",
                            "previous_record_id": active.meta.record_id,
                            "revision_number": active.meta.revision_number + 1,
                        }
                    )
                }
            )
        )

    with pytest.raises(ValueError, match="PRODUCTION_LLM_ROUTE_(NOT_APPROVED|STALE)"):
        lookup(analysis_id, "HYPOTHESIS", "GENERATE_INITIAL")
