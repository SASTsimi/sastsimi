from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest

from sastsimi.agents.dynamic_reproduction import DynamicAgentInvocation
from sastsimi.agents.verification import VerificationAgentOutcome
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    ReproductionPlan,
    SandboxEnvironment,
)
from sastsimi.contracts.hypothesis import VulnerabilityHypothesis
from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    LLMRole,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeContextResponse, StaticFactBundle
from sastsimi.contracts.verification import (
    PlaybookApplication,
    PlaybookPolicy,
    VerificationInitialAssessment,
    VerificationPlaybook,
)
from sastsimi.contracts.work import (
    AttemptStatus,
    AttemptTrigger,
    SubjectType,
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.authorized_llm_call import AuthorizedLLMCall
from sastsimi.ports.dto import (
    Record,
    TransitionCommitRequest,
    WorkContext,
    WorkHandlerResult,
)
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.verification_assembly import VerificationGenerationInputs
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.verification.debate_service import DebateIncompleteError, DebateService
from sastsimi.verification.production_llm_work_handlers import (
    DynamicVerificationPort,
    EvidenceBranchWorkHandler,
    HypothesesCommittedPort,
    HypothesisProposalWorkHandler,
    NonDynamicCompletionPort,
    ProductionDynamicStageCallResolver,
    VerificationWorkHandler,
)
from sastsimi.verification.service import VerificationService
from tests.contract.domain.canonical_fixtures import make


@pytest.fixture
def candidate_work_path() -> Generator[Path, None, None]:
    """Avoid broken pytest temp ACLs on Windows."""

    path = Path(__file__).resolve().parents[3] / f".t11-code-context-{uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _ref(kind: str, name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(name),
        data_kind=kind,
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=RecordId(f"{name}-record"),
    )


def _meta(
    kind: str, name: str, *, hypothesis_id: str | None, attempt_id: str | None
) -> RecordMeta:
    source = make("WorkExecutionState")["meta"]
    return RecordMeta.model_validate(
        source
        | {
            "record_id": f"{name}-record",
            "logical_record_id": f"{name}-logical",
            "record_type": kind,
            "analysis_id": "a1",
            "workspace_id": "ws1",
            "commit_id": "c1",
            "hypothesis_id": hypothesis_id,
            "attempt_id": attempt_id,
            "created_at": datetime(2026, 9, 13, tzinfo=UTC),
        }
    )


def _context(
    work_type: WorkType,
    inputs: tuple[StoredDataRef, ...],
    *,
    hypothesis_id: str | None = None,
    subject_type: SubjectType = SubjectType.ANALYSIS,
    subject_id: str = "a1",
    parent_ref: StoredDataRef | None = None,
) -> WorkContext:
    attempt_id = f"{work_type.value.lower()}-attempt"
    work = WorkExecutionState.model_validate(
        {
            "meta": _meta(
                "work_execution_state",
                f"{work_type.value.lower()}-work",
                hypothesis_id=hypothesis_id,
                attempt_id=None,
            ),
            "work_id": f"{work_type.value.lower()}-work",
            "parent_work_ref": parent_ref,
            "work_type": work_type,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "work_generation": 1,
            "status": WorkStatus.RUNNING,
            "state_version": 3,
            "last_transition_ref": _ref("state_transition", "transition"),
            "last_transition_commit_ref": None,
            "active_attempt_id": attempt_id,
            "input_hash": content_hash(inputs),
            "dedupe_key": "d" * 64,
            "trigger_primitive_ref": None,
            "input_refs": inputs,
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "waiting_for": (),
            "stop_reason": None,
            "started_at": _meta(
                "work_execution_state",
                "time",
                hypothesis_id=hypothesis_id,
                attempt_id=None,
            ).created_at,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )
    attempt = WorkAttempt.model_validate(
        {
            "meta": _meta(
                "work_attempt",
                f"{work_type.value.lower()}-attempt-record",
                hypothesis_id=hypothesis_id,
                attempt_id=attempt_id,
            ),
            "work_id": work.work_id,
            "attempt_id": attempt_id,
            "attempt_number": 1,
            "trigger": AttemptTrigger.INITIAL,
            "input_hash": work.input_hash,
            "status": AttemptStatus.RUNNING,
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "started_at": work.started_at,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )
    return WorkContext(work, attempt)


class _Records:
    def __init__(self, values: dict[StoredDataRef, Record]) -> None:
        self.values = values

    def get_exact(self, ref: RecordRef) -> Record:
        if not isinstance(ref, StoredDataRef):
            raise LookupError(ref)
        return self.values[ref]

    def is_revision_descendant(
        self, earlier_ref: RecordRef, later_ref: RecordRef
    ) -> bool:
        return earlier_ref == later_ref

    def stage_record(self, record: Record) -> RecordRef:
        ref = reference(record)
        if not isinstance(ref, StoredDataRef):
            raise AssertionError("test record must be code-scoped")
        self.values[ref] = record
        return ref

    def commit_transition(self, request: TransitionCommitRequest) -> TransitionCommit:
        raise AssertionError(request)


class _Calls:
    def __init__(self) -> None:
        self.requests: list[tuple[LLMRole, str, tuple[StoredDataRef, ...]]] = []
        self.settled: list[tuple[AuthorizedLLMCall, PersistedLLMInvocation]] = []
        self.sequence = 0

    def resolve(
        self,
        *,
        work: WorkExecutionState,
        role: LLMRole,
        task_kind: str,
        source_refs: tuple[StoredDataRef, ...],
    ) -> AuthorizedLLMCall:
        self.sequence += 1
        self.requests.append((role, task_kind, source_refs))
        return AuthorizedLLMCall(
            work=work,
            decision_ref=_ref("action_decision", f"allow-{self.sequence}"),
            reservation_ref=_ref("budget_reservation", f"reserve-{self.sequence}"),
            call_spec_ref=_ref("llm_call_spec", f"spec-{self.sequence}"),
        )

    def settle(
        self, call: AuthorizedLLMCall, invocation: PersistedLLMInvocation
    ) -> None:
        self.settled.append((call, invocation))


@dataclass
class _HypothesisWorkflow:
    output_ref: StoredDataRef

    async def run(self, **kwargs: object) -> Any:
        work = kwargs["work"]
        assert isinstance(work, WorkExecutionState)
        completed = work.model_copy(
            update={
                "status": WorkStatus.SUCCEEDED,
                "active_attempt_id": None,
                "output_refs": (self.output_ref,),
            }
        )
        return SimpleNamespace(
            outcome=SimpleNamespace(
                invocation=SimpleNamespace(result=SimpleNamespace(status="SUCCEEDED"))
            ),
            completed_work=completed,
        )


def test_dynamic_stage_resolver_uses_exact_stage_inputs_and_settles() -> None:
    calls = _Calls()
    context = _context(
        WorkType.DYNAMIC_REPRO,
        (_ref("dynamic_reproduction_request", "request"),),
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
        parent_ref=_ref("work_execution_state", "verification-work"),
    )
    source_refs = (
        _ref("dynamic_reproduction_request", "request"),
        _ref("environment_requirements", "requirements"),
    )
    resolver = ProductionDynamicStageCallResolver(calls, max_execute_turns=3)

    authorization = resolver.resolve(
        work=context.work,
        task_kind="PLAN_REPRODUCTION",
        context_refs=source_refs,
    )
    invocation = SimpleNamespace(
        request=SimpleNamespace(
            call_spec_ref=authorization.call_spec_ref,
            action_decision_ref=authorization.decision_ref,
            agent_role="DYNAMIC_REPRODUCTION",
        )
    )
    resolver.settle(authorization, cast(PersistedLLMInvocation, invocation))

    assert calls.requests == [
        ("DYNAMIC_REPRODUCTION", "PLAN_REPRODUCTION", source_refs)
    ]
    assert len(calls.settled) == 1


def test_dynamic_stage_resolver_rejects_unknown_settlement() -> None:
    calls = _Calls()
    resolver = ProductionDynamicStageCallResolver(calls, max_execute_turns=1)
    authorization = DynamicAgentInvocation(
        decision_ref=_ref("action_decision", "unknown"),
        reservation_ref=_ref("budget_reservation", "unknown"),
        call_spec_ref=_ref("llm_call_spec", "unknown"),
    )
    invocation = SimpleNamespace(
        request=SimpleNamespace(
            call_spec_ref=authorization.call_spec_ref,
            action_decision_ref=authorization.decision_ref,
            agent_role="DYNAMIC_REPRODUCTION",
        )
    )

    with pytest.raises(ValueError, match="DYNAMIC_LLM_SETTLEMENT_MISMATCH"):
        resolver.settle(authorization, cast(PersistedLLMInvocation, invocation))


def _dynamic_candidate_fixture(
    tmp_path: Path,
) -> tuple[
    _Records,
    LocalArtifactStore,
    WorkExecutionState,
    StoredDataRef,
    StoredDataRef,
    StoredDataRef,
    StoredDataRef,
    StoredDataRef,
]:
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts", WorkspaceId("ws1"), CommitId("c1")
    )
    fragment_ref = artifacts.commit(
        artifacts.stage_bytes(
            b"token = 'sk-sensitive-code-token'\nprint('safe')", "text/plain"
        )
    )
    response = CodeContextResponse.model_validate_json(
        canonical_bytes(
            make("CodeContextResponse")
            | {
                "meta": _meta(
                    "code_context_response",
                    "context-response",
                    hypothesis_id="h1",
                    attempt_id="upstream-context-attempt",
                ),
                "code_fragment_refs": (fragment_ref,),
                "returned_fragment_count": 1,
                "returned_bytes": len(
                    b"token = 'sk-sensitive-code-token'\nprint('safe')"
                ),
            }
        )
    )
    response_ref = cast(StoredDataRef, reference(response))
    request = DynamicReproductionRequest.model_validate_json(
        canonical_bytes(
            make("DynamicReproductionRequest")
            | {
                "meta": _meta(
                    "dynamic_reproduction_request",
                    "request",
                    hypothesis_id="h1",
                    attempt_id="upstream-verification-attempt",
                ),
                "code_refs": (response_ref,),
            }
        )
    )
    request_ref = cast(StoredDataRef, reference(request))
    work = _context(
        WorkType.DYNAMIC_REPRO,
        (request_ref,),
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
        parent_ref=_ref("work_execution_state", "verification-work"),
    ).work
    plan = ReproductionPlan.model_validate_json(
        canonical_bytes(
            make("ReproductionPlan")
            | {
                "meta": _meta(
                    "reproduction_plan",
                    "plan",
                    hypothesis_id="h1",
                    attempt_id=str(work.active_attempt_id),
                ),
                "request_ref": request_ref,
                "purpose": request.purpose,
                "hypothesis_ref": request.hypothesis_ref,
                "sandbox_profile_ref": request.sandbox_profile_ref,
            }
        )
    )
    plan_ref = cast(StoredDataRef, reference(plan))
    environment = SandboxEnvironment.model_validate_json(
        canonical_bytes(
            make("SandboxEnvironment")
            | {
                "meta": _meta(
                    "sandbox_environment",
                    "environment",
                    hypothesis_id="h1",
                    attempt_id=str(work.active_attempt_id),
                ),
                "request_ref": request_ref,
                "reproduction_plan_ref": plan_ref,
                "status": "READY",
            }
        )
    )
    environment_ref = cast(StoredDataRef, reference(environment))
    records = _Records(
        {
            request_ref: request,
            plan_ref: plan,
            environment_ref: environment,
            response_ref: response,
        }
    )
    return (
        records,
        artifacts,
        work,
        request_ref,
        plan_ref,
        environment_ref,
        response_ref,
        fragment_ref,
    )


def test_candidate_stage_expands_exact_code_context_fragments(
    candidate_work_path: Path,
) -> None:
    (
        records,
        artifacts,
        work,
        request_ref,
        plan_ref,
        environment_ref,
        response_ref,
        fragment_ref,
    ) = _dynamic_candidate_fixture(candidate_work_path)
    calls = _Calls()
    resolver = ProductionDynamicStageCallResolver(
        calls,
        max_execute_turns=1,
        records=records,
        artifacts=artifacts,
    )

    authorization = resolver.resolve(
        work=work,
        task_kind="CREATE_POC_CANDIDATE",
        context_refs=(request_ref, plan_ref, environment_ref),
    )

    expected = (
        request_ref,
        plan_ref,
        environment_ref,
        response_ref,
        fragment_ref,
    )
    assert calls.requests == [
        ("DYNAMIC_REPRODUCTION", "CREATE_POC_CANDIDATE", expected)
    ]
    assert authorization.context_refs == expected


@pytest.mark.parametrize("invalid", ("reference", "lineage", "plan", "environment"))
def test_candidate_stage_rejects_invalid_code_or_current_attempt_before_call(
    candidate_work_path: Path,
    invalid: str,
) -> None:
    (
        records,
        artifacts,
        work,
        request_ref,
        plan_ref,
        environment_ref,
        response_ref,
        _,
    ) = _dynamic_candidate_fixture(candidate_work_path)
    if invalid == "reference":
        original = records.values[response_ref]
        assert isinstance(original, CodeContextResponse)
        records.values[response_ref] = original.model_copy(
            update={
                "meta": original.meta.model_copy(
                    update={"record_id": RecordId("different-record")}
                )
            }
        )
    elif invalid == "lineage":
        original = records.values[response_ref]
        assert isinstance(original, CodeContextResponse)
        cross_hypothesis_response = original.model_copy(
            update={"meta": original.meta.model_copy(update={"hypothesis_id": "h2"})}
        )
        response_ref = cast(StoredDataRef, reference(cross_hypothesis_response))
        original_request = records.values[request_ref]
        assert isinstance(original_request, DynamicReproductionRequest)
        request = original_request.model_copy(update={"code_refs": (response_ref,)})
        request_ref = cast(StoredDataRef, reference(request))
        work = work.model_copy(update={"input_refs": (request_ref,)})
        original_plan = records.values[plan_ref]
        assert isinstance(original_plan, ReproductionPlan)
        plan = original_plan.model_copy(update={"request_ref": request_ref})
        plan_ref = cast(StoredDataRef, reference(plan))
        original_environment = records.values[environment_ref]
        assert isinstance(original_environment, SandboxEnvironment)
        environment = original_environment.model_copy(
            update={
                "request_ref": request_ref,
                "reproduction_plan_ref": plan_ref,
            }
        )
        environment_ref = cast(StoredDataRef, reference(environment))
        records.values = {
            request_ref: request,
            plan_ref: plan,
            environment_ref: environment,
            response_ref: cross_hypothesis_response,
        }
    elif invalid == "plan":
        original = records.values[plan_ref]
        assert isinstance(original, ReproductionPlan)
        records.values[plan_ref] = original.model_copy(
            update={
                "meta": original.meta.model_copy(update={"attempt_id": "old-attempt"})
            }
        )
    else:
        original = records.values[environment_ref]
        assert isinstance(original, SandboxEnvironment)
        records.values[environment_ref] = original.model_copy(
            update={
                "meta": original.meta.model_copy(update={"attempt_id": "old-attempt"})
            }
        )
    calls = _Calls()
    resolver = ProductionDynamicStageCallResolver(
        calls,
        max_execute_turns=1,
        records=records,
        artifacts=artifacts,
    )

    with pytest.raises(ValueError, match="DYNAMIC_CANDIDATE_CONTEXT_MISMATCH"):
        resolver.resolve(
            work=work,
            task_kind="CREATE_POC_CANDIDATE",
            context_refs=(request_ref, plan_ref, environment_ref),
        )

    assert calls.requests == []


class _UnreadableArtifacts:
    def open_verified(self, ref: StoredDataRef) -> object:
        raise OSError(f"unavailable: {ref.data_kind}")


def test_candidate_stage_storage_failure_stops_before_call(
    candidate_work_path: Path,
) -> None:
    (
        records,
        _,
        work,
        request_ref,
        plan_ref,
        environment_ref,
        _,
        _,
    ) = _dynamic_candidate_fixture(candidate_work_path)
    calls = _Calls()
    resolver = ProductionDynamicStageCallResolver(
        calls,
        max_execute_turns=1,
        records=records,
        artifacts=cast(Any, _UnreadableArtifacts()),
    )

    with pytest.raises(ValueError, match="DYNAMIC_CANDIDATE_CODE_UNAVAILABLE"):
        resolver.resolve(
            work=work,
            task_kind="CREATE_POC_CANDIDATE",
            context_refs=(request_ref, plan_ref, environment_ref),
        )

    assert calls.requests == []


def _persisted_invocation(
    records: _Records, name: str, *, role: str = "VERIFICATION"
) -> PersistedLLMInvocation:
    attempt = "verification-attempt"
    request = LLMInvocationRequest.model_construct(
        **(
            make("LLMInvocationRequest")
            | {
                "meta": _meta(
                    "llm_invocation_request",
                    f"{name}-request",
                    hypothesis_id="h1",
                    attempt_id=attempt,
                ),
                "llm_call_id": f"{name}-call",
                "agent_role": role,
                "task_kind": name,
                "context_refs": (),
            }
        )
    )
    result = LLMInvocationResult.model_construct(
        **(
            make("LLMInvocationResult")
            | {
                "meta": _meta(
                    "llm_invocation_result",
                    f"{name}-result",
                    hypothesis_id="h1",
                    attempt_id=attempt,
                ),
                "llm_call_id": f"{name}-call",
                "session_ref": f"{name}-session",
            }
        )
    )
    log = LLMInvocationLog.model_construct(
        **(
            make("LLMInvocationLog")
            | {
                "meta": _meta(
                    "llm_invocation_log",
                    f"{name}-log",
                    hypothesis_id="h1",
                    attempt_id=attempt,
                ),
                "llm_call_id": f"{name}-call",
            }
        )
    )
    request_ref = reference(request)
    result_ref = reference(result)
    log_ref = reference(log)
    assert isinstance(request_ref, StoredDataRef)
    assert isinstance(result_ref, StoredDataRef)
    assert isinstance(log_ref, StoredDataRef)
    records.values[request_ref] = request
    records.values[result_ref] = result
    records.values[log_ref] = log
    return PersistedLLMInvocation(request, result, log_ref, "RETURNED")


def _verification_fixture() -> tuple[
    WorkContext,
    _Records,
    StaticFactBundle,
    tuple[StoredDataRef, ...],
]:
    bundle = StaticFactBundle.model_validate_json(json.dumps(make("StaticFactBundle")))
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    location = bundle.locations[0]
    hypothesis = VulnerabilityHypothesis.model_validate_json(
        json.dumps(
            make("VulnerabilityHypothesis")
            | {
                "meta": _meta(
                    "vulnerability_hypothesis",
                    "hypothesis",
                    hypothesis_id="h1",
                    attempt_id="hypothesis-attempt",
                ).model_dump(mode="json"),
                "target_locations": (location.model_dump(mode="json"),),
                "suspected_path": (location.model_dump(mode="json"),),
                "falsification_questions": (
                    {"question_id": "hypothesis-question", "question": "Disprove?"},
                ),
                "validation_checks": (
                    {"validation_id": "validation-check", "instruction": "Check"},
                ),
            }
        )
    )
    hypothesis_ref = reference(hypothesis)
    assert isinstance(hypothesis_ref, StoredDataRef)
    playbook = VerificationPlaybook.model_validate_json(
        json.dumps(make("VerificationPlaybook"))
    )
    playbook_ref = reference(playbook)
    assert isinstance(playbook_ref, StoredDataRef)
    policy = PlaybookPolicy.model_validate_json(
        json.dumps(
            make("PlaybookPolicy")
            | {"common_playbook_ref": playbook_ref.model_dump(mode="json")}
        )
    )
    policy_ref = reference(policy)
    assert isinstance(policy_ref, StoredDataRef)
    application = PlaybookApplication.model_validate_json(
        json.dumps(
            make("PlaybookApplication")
            | {
                "verification_work_id": "verification-work",
                "hypothesis_ref": hypothesis_ref.model_dump(mode="json"),
                "proposal_ref": hypothesis.proposal_ref.model_dump(mode="json"),
                "policy_ref": policy_ref.model_dump(mode="json"),
                "playbook_ref": playbook_ref.model_dump(mode="json"),
                "selection_reason": "NO_TYPE",
                "questions": (
                    {
                        "template_key": "playbook-template",
                        "question": "Check the playbook condition",
                        "question_id": "playbook-question",
                    },
                ),
            }
        )
    )
    application_ref = reference(application)
    assert isinstance(application_ref, StoredDataRef)
    inputs = (
        hypothesis_ref,
        hypothesis.proposal_ref,
        policy_ref,
        playbook_ref,
        bundle_ref,
        application_ref,
    )
    context = _context(
        WorkType.VERIFICATION,
        inputs,
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
    )
    records = _Records(
        {
            hypothesis_ref: hypothesis,
            policy_ref: policy,
            playbook_ref: playbook,
            bundle_ref: bundle,
            application_ref: application,
        }
    )
    return context, records, bundle, inputs


class _VerificationRunner:
    def __init__(self, parent: WorkExecutionState, records: _Records) -> None:
        self.parent = parent
        self.records = records
        self.events: list[tuple[str, str]] = []
        self.running: dict[str, WorkExecutionState] = {}

    def enqueue(self, *args: object, **kwargs: object) -> WorkExecutionState:
        work_type = str(args[2])
        assert kwargs["parent"] == reference(self.parent)
        assert kwargs["inputs"] == self.parent.input_refs
        self.events.append(("enqueue", work_type))
        parent_ref = reference(self.parent)
        assert isinstance(parent_ref, StoredDataRef)
        public_inputs = tuple(
            ref for ref in self.parent.input_refs if isinstance(ref, StoredDataRef)
        )
        assert len(public_inputs) == len(self.parent.input_refs)
        running = _context(
            WorkType(work_type),
            public_inputs,
            hypothesis_id="h1",
            subject_type=SubjectType.HYPOTHESIS,
            subject_id="h1",
            parent_ref=parent_ref,
        ).work
        self.running[work_type] = running
        return running.model_copy(
            update={
                "status": WorkStatus.READY,
                "active_attempt_id": None,
                "started_at": None,
            }
        )

    def activate(
        self, registered: WorkExecutionState, *args: object, **kwargs: object
    ) -> WorkExecutionState:
        work_type = str(registered.work_type)
        self.events.append(("activate", work_type))
        return self.running[work_type]

    def publish_intermediate(
        self, work: WorkExecutionState, *args: object, **kwargs: object
    ) -> tuple[StoredDataRef, ...]:
        assert work == self.parent
        (record,) = cast(tuple[Record], args[2])
        record_ref = reference(record)
        assert isinstance(record_ref, StoredDataRef)
        self.records.values[record_ref] = record
        return (record_ref,)


class _Debate:
    def __init__(
        self,
        records: _Records,
        *,
        fail_one_branch: bool = False,
    ) -> None:
        self.pro_invocation = _persisted_invocation(records, "pro", role="PRO")
        self.con_invocation = _persisted_invocation(records, "con", role="CON")
        self.fail_one_branch = fail_one_branch
        self.requests: list[dict[str, object]] = []
        self.pro_ref = _ref("pro_evidence_result", "pro")
        self.con_ref = _ref("con_evidence_result", "con")

    async def run(self, **kwargs: object) -> Any:
        self.requests.append(kwargs)
        if self.fail_one_branch:
            raise DebateIncompleteError(
                1,
                (self.pro_ref,),
                pro_invocation=self.pro_invocation,
                con_invocation=self.con_invocation,
            )
        debate_hash = content_hash(kwargs["public_input_refs"])
        return SimpleNamespace(
            pro=SimpleNamespace(debate_input_hash=debate_hash),
            con=SimpleNamespace(debate_input_hash=debate_hash),
            pro_ref=self.pro_ref,
            con_ref=self.con_ref,
            pro_invocation=self.pro_invocation,
            con_invocation=self.con_invocation,
        )


class _Verification:
    def __init__(self, records: _Records) -> None:
        self.records = records
        self.generations: list[VerificationGenerationInputs] = []
        self.invocation = _persisted_invocation(records, "initial")

    async def assess_initial_with_invocation(self, **kwargs: object) -> object:
        self.generations.append(
            cast(VerificationGenerationInputs, kwargs["generation"])
        )
        assessment = VerificationInitialAssessment.model_construct(
            **(
                make("VerificationInitialAssessment")
                | {
                    "meta": _meta(
                        "verification_initial_assessment",
                        "assessment",
                        hypothesis_id="h1",
                        attempt_id="verification-attempt",
                    ),
                    "next_step": "FINALIZE_WITHOUT_DYNAMIC",
                }
            )
        )
        return VerificationAgentOutcome(assessment, self.invocation)


class _NonDynamic:
    def __init__(self, parent: WorkExecutionState, records: _Records) -> None:
        self.parent = parent
        self.calls: list[dict[str, object]] = []
        self.invocation = _persisted_invocation(records, "final")
        self.output_ref = _ref("verification_result", "final")

    async def complete_without_dynamic(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        completed = self.parent.model_copy(
            update={
                "status": WorkStatus.SUCCEEDED,
                "active_attempt_id": None,
                "output_refs": (self.output_ref,),
            }
        )
        return SimpleNamespace(
            outcome=SimpleNamespace(invocation=self.invocation),
            completed_work=completed,
        )


class _NoDynamic:
    async def resume_dynamic(self, **kwargs: object) -> None:
        return None

    async def complete_dynamic(self, **kwargs: object) -> object:
        raise AssertionError("debate happy path must finalize without dynamic work")


class _ResumedDynamic:
    def __init__(self) -> None:
        self.output_ref = _ref("verification_result", "resumed")
        self.calls: list[dict[str, object]] = []

    async def resume_dynamic(self, **kwargs: object) -> WorkHandlerResult:
        self.calls.append(kwargs)
        return WorkHandlerResult((self.output_ref,))

    async def complete_dynamic(self, **kwargs: object) -> object:
        raise AssertionError("a resumed generation cannot create another child")


@pytest.mark.asyncio
async def test_hypothesis_handler_uses_exact_bundle_and_settles_real_call() -> None:
    bundle = StaticFactBundle.model_validate_json(json.dumps(make("StaticFactBundle")))
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    proposal_ref = _ref("hypothesis_proposal", "proposal")
    context = _context(WorkType.HYPOTHESIS_PROPOSAL, (bundle_ref,))
    calls = _Calls()
    committed: list[tuple[StoredDataRef, ...]] = []

    def commit_hypotheses(proposal_refs: tuple[StoredDataRef, ...]) -> None:
        committed.append(proposal_refs)

    handler = HypothesisProposalWorkHandler(
        records=_Records({bundle_ref: bundle}),
        workflow=_HypothesisWorkflow(proposal_ref),
        calls=calls,
        orchestration_identity_ref=_ref("role_identity", "orchestrator"),
        hypotheses_committed=commit_hypotheses,
    )

    result = await handler.execute(context)

    assert result.output_refs == (proposal_ref,)
    assert calls.requests == [("HYPOTHESIS", "GENERATE_INITIAL", (bundle_ref,))]
    assert len(calls.settled) == 1
    assert committed == [(proposal_ref,)]


@pytest.mark.asyncio
async def test_hypothesis_handler_rejects_exact_ref_mismatch_before_llm_call() -> None:
    bundle = StaticFactBundle.model_validate_json(json.dumps(make("StaticFactBundle")))
    exact_ref = reference(bundle)
    assert isinstance(exact_ref, StoredDataRef)
    wrong_ref = exact_ref.model_copy(update={"content_hash": "f" * 64})
    context = _context(WorkType.HYPOTHESIS_PROPOSAL, (wrong_ref,))
    calls = _Calls()
    handler = HypothesisProposalWorkHandler(
        records=_Records({wrong_ref: bundle}),
        workflow=_HypothesisWorkflow(_ref("hypothesis_proposal", "proposal")),
        calls=calls,
        orchestration_identity_ref=_ref("role_identity", "orchestrator"),
        hypotheses_committed=cast(HypothesesCommittedPort, lambda _proposal_refs: None),
    )

    with pytest.raises(ValueError, match="HYPOTHESIS_STATIC_CLOSURE_MISMATCH"):
        await handler.execute(context)

    assert calls.requests == []


@pytest.mark.asyncio
async def test_evidence_handler_executes_one_claimed_branch_without_waiting() -> None:
    debate_ref = _ref("static_fact_bundle", "facts")
    parent = _context(
        WorkType.VERIFICATION,
        (_ref("vulnerability_hypothesis", "hypothesis"),),
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
    ).work.model_copy(update={"status": WorkStatus.PENDING, "active_attempt_id": None})
    parent_ref = reference(parent)
    assert isinstance(parent_ref, StoredDataRef)
    context = _context(
        WorkType.PRO_EVIDENCE,
        (debate_ref,),
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
        parent_ref=parent_ref,
    )
    output_ref = _ref("pro_evidence_result", "pro")
    calls = _Calls()
    joined: list[tuple[StoredDataRef, StoredDataRef]] = []

    class _Debate:
        async def run_branch(self, **kwargs: object) -> Any:
            assert kwargs["parent_work"] == parent
            assert kwargs["role"] == "PRO"
            return SimpleNamespace(
                output_ref=output_ref,
                invocation=SimpleNamespace(result=SimpleNamespace(status="SUCCEEDED")),
            )

    handler = EvidenceBranchWorkHandler(
        role="PRO",
        records=_Records({parent_ref: parent}),
        debate=cast(DebateService, _Debate()),
        calls=calls,
        evidence_committed=lambda parent, output: joined.append((parent, output)),
    )

    result = await handler.execute(context)

    assert result.output_refs == (output_ref,)
    assert calls.requests == [("PRO", "COLLECT_SUPPORT", (debate_ref,))]
    assert joined == [(parent_ref, output_ref)]


@pytest.mark.asyncio
async def test_verification_handler_runs_parent_owned_debate_before_synthesis() -> None:
    """Catches missing children, serial branch handling, or guessed generation input."""
    context, records, bundle, parent_inputs = _verification_fixture()
    runner = _VerificationRunner(context.work, records)
    debate = _Debate(records)
    verification = _Verification(records)
    non_dynamic = _NonDynamic(context.work, records)
    calls = _Calls()
    scope = _ref("budget_profile_binding", "scope")

    def budget_scope(analysis_id: str) -> StoredDataRef:
        if analysis_id != "a1":
            raise LookupError(analysis_id)
        return scope

    handler = VerificationWorkHandler(
        records=records,
        runner=cast(WorkflowRunner, runner),
        verification=cast(VerificationService, verification),
        debate=cast(DebateService, debate),
        non_dynamic=cast(NonDynamicCompletionPort, non_dynamic),
        dynamic=cast(DynamicVerificationPort, _NoDynamic()),
        calls=calls,
        verification_identity_ref=_ref("role_identity", "verification"),
        budget_scope=budget_scope,
    )

    result = await handler.execute(context)

    assert result.output_refs == (non_dynamic.output_ref,)
    assert runner.events == [
        ("enqueue", "PRO_EVIDENCE"),
        ("enqueue", "CON_EVIDENCE"),
        ("activate", "PRO_EVIDENCE"),
        ("activate", "CON_EVIDENCE"),
    ]
    assert len(debate.requests) == 1
    debate_request = debate.requests[0]
    assert debate_request["verification_work"] == context.work
    assert debate_request["public_input_refs"] == parent_inputs
    pro_call = cast(AuthorizedLLMCall, debate_request["pro_call"])
    con_call = cast(AuthorizedLLMCall, debate_request["con_call"])
    assert pro_call.work.parent_work_ref == reference(context.work)
    assert con_call.work.parent_work_ref == reference(context.work)
    assert pro_call.work.work_id != con_call.work.work_id
    generation = verification.generations[0]
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    assert generation.work_id == context.work.work_id
    assert generation.generation == context.work.work_generation
    assert generation.hypothesis_ref == parent_inputs[0]
    assert generation.policy_ref == parent_inputs[2]
    assert generation.playbook_ref == parent_inputs[3]
    assert generation.evidence_ref == bundle_ref
    assert generation.application_ref == parent_inputs[5]
    assert generation.pro_ref == debate.pro_ref
    assert generation.con_ref == debate.con_ref
    assert generation.location == bundle.locations[0]
    assert generation.falsification_question_ids == (
        "hypothesis-question",
        "playbook-question",
    )
    assert generation.validation_ids == ("validation-check",)
    initial_sources = (
        parent_inputs[0],
        parent_inputs[2],
        parent_inputs[3],
        parent_inputs[5],
        debate.pro_ref,
        debate.con_ref,
        bundle_ref,
    )
    assert calls.requests[:3] == [
        ("PRO", "COLLECT_SUPPORT", parent_inputs),
        ("CON", "COLLECT_COUNTEREVIDENCE", parent_inputs),
        ("VERIFICATION", "ASSESS_INITIAL", initial_sources),
    ]
    assert calls.requests[3][0:2] == ("VERIFICATION", "FINAL_VERDICT")
    assert calls.requests[3][2][:-1] == initial_sources
    assert calls.requests[3][2][-1].data_kind == "verification_initial_assessment"
    assert [item[1] for item in calls.settled] == [
        debate.pro_invocation,
        debate.con_invocation,
        verification.invocation,
        non_dynamic.invocation,
    ]


@pytest.mark.asyncio
async def test_resumed_verification_reuses_prior_evidence_without_new_debate() -> None:
    context, records, _bundle, parent_inputs = _verification_fixture()
    runner = _VerificationRunner(context.work, records)
    debate = _Debate(records)
    dynamic = _ResumedDynamic()
    calls = _Calls()
    handler = VerificationWorkHandler(
        records=records,
        runner=cast(WorkflowRunner, runner),
        verification=cast(VerificationService, _Verification(records)),
        debate=cast(DebateService, debate),
        non_dynamic=cast(NonDynamicCompletionPort, _NonDynamic(context.work, records)),
        dynamic=cast(DynamicVerificationPort, dynamic),
        calls=calls,
        verification_identity_ref=_ref("role_identity", "verification"),
        budget_scope=lambda _analysis_id: _ref("budget_profile_binding", "scope"),
    )

    result = await handler.execute(context)

    assert result.output_refs == (dynamic.output_ref,)
    assert dynamic.calls == [{"context": context, "public_input_refs": parent_inputs}]
    assert runner.events == []
    assert debate.requests == []
    assert calls.requests == []


@pytest.mark.asyncio
async def test_verification_handler_branch_failure_never_reaches_a_verdict() -> None:
    """Catches converting an incomplete debate into FALSE/HOLD or leaking reserves."""
    context, records, _bundle, parent_inputs = _verification_fixture()
    runner = _VerificationRunner(context.work, records)
    debate = _Debate(records, fail_one_branch=True)
    verification = _Verification(records)
    calls = _Calls()
    handler = VerificationWorkHandler(
        records=records,
        runner=cast(WorkflowRunner, runner),
        verification=cast(VerificationService, verification),
        debate=cast(DebateService, debate),
        non_dynamic=cast(NonDynamicCompletionPort, _NonDynamic(context.work, records)),
        dynamic=cast(DynamicVerificationPort, _NoDynamic()),
        calls=calls,
        verification_identity_ref=_ref("role_identity", "verification"),
        budget_scope=lambda _analysis_id: _ref("budget_profile_binding", "scope"),
    )

    with pytest.raises(DebateIncompleteError):
        await handler.execute(context)

    assert calls.requests == [
        ("PRO", "COLLECT_SUPPORT", parent_inputs),
        ("CON", "COLLECT_COUNTEREVIDENCE", parent_inputs),
    ]
    assert [item[1] for item in calls.settled] == [
        debate.pro_invocation,
        debate.con_invocation,
    ]
    assert verification.generations == []


@pytest.mark.asyncio
async def test_verification_handler_requires_exact_static_parent_input() -> None:
    """Catches accepting a forged static ref that resolves to another revision."""
    context, records, bundle, parent_inputs = _verification_fixture()
    exact_bundle_ref = reference(bundle)
    assert isinstance(exact_bundle_ref, StoredDataRef)
    wrong_bundle_ref = exact_bundle_ref.model_copy(update={"content_hash": "f" * 64})
    wrong_inputs = tuple(
        wrong_bundle_ref if ref == exact_bundle_ref else ref for ref in parent_inputs
    )
    bad_context = _context(
        WorkType.VERIFICATION,
        wrong_inputs,
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
    )
    records.values[wrong_bundle_ref] = bundle
    runner = _VerificationRunner(bad_context.work, records)
    debate = _Debate(records)
    handler = VerificationWorkHandler(
        records=records,
        runner=cast(WorkflowRunner, runner),
        verification=cast(VerificationService, _Verification(records)),
        debate=cast(DebateService, debate),
        non_dynamic=cast(
            NonDynamicCompletionPort, _NonDynamic(bad_context.work, records)
        ),
        dynamic=cast(DynamicVerificationPort, _NoDynamic()),
        calls=_Calls(),
        verification_identity_ref=_ref("role_identity", "verification"),
        budget_scope=lambda _analysis_id: _ref("budget_profile_binding", "scope"),
    )

    with pytest.raises(ValueError, match="VERIFICATION_PARENT_INPUT_MISMATCH"):
        await handler.execute(bad_context)

    assert runner.events == []
    assert debate.requests == []
