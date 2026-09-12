from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from typing import Any

import pytest

from sastsimi.agents.cwe_labeling import CWELabelingAgent
from sastsimi.agents.technical_gate import TechnicalGateAgent
from sastsimi.contracts._domain import DomainRecord
from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionCheck,
    ActionDecision,
    ActionRequest,
    CheckResult,
    SessionMode,
)
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import DynamicReproductionResult, PoCBundle
from sastsimi.contracts.gates import CWELabel, TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VerificationAssignment,
)
from sastsimi.contracts.ids import (
    AnalysisId,
    AttemptId,
    CommitId,
    HypothesisId,
    LogicalRecordId,
    RecordId,
    StoredDataId,
    WorkId,
    WorkspaceId,
)
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
)
from sastsimi.contracts.records import RecordMeta, validate_revision
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import PlaybookApplication, VerificationResult
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.verification_registration import VerificationRegistration
from sastsimi.reporting.cwe_workflow import CWELabelingService, GateCallRefs
from sastsimi.reporting.technical_gate_workflow import (
    TechnicalGateService,
    TechnicalRevisionReconciler,
)
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.runtime.llm_invocation_provenance import (
    validate_llm_invocation_provenance,
)
from tests.contract.domain.success_fixture import dynamic_success

NOW = datetime(2026, 9, 12, tzinfo=UTC)
ANALYSIS = AnalysisId("a1")
WORKSPACE = WorkspaceId("ws1")
COMMIT = CommitId("c1")
HYPOTHESIS = HypothesisId("h1")


def _meta(kind: str, suffix: str, attempt: str | None = None) -> RecordMeta:
    return RecordMeta(
        record_id=RecordId(f"{kind}-{suffix}"),
        logical_record_id=LogicalRecordId(f"{kind}-logical"),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=NOW,
        analysis_id=ANALYSIS,
        workspace_id=WORKSPACE,
        commit_id=COMMIT,
        hypothesis_id=HYPOTHESIS,
        attempt_id=AttemptId(attempt) if attempt else None,
    )


class _Records:
    def __init__(self) -> None:
        self.values: dict[RecordRef, object] = {}

    def add(self, value: object) -> StoredDataRef:
        ref = reference(value)  # type: ignore[arg-type]
        assert isinstance(ref, StoredDataRef)
        self.values[ref] = value
        return ref

    def get_exact(self, ref: RecordRef) -> object:
        return self.values[ref]

    def is_revision_descendant(
        self, earlier_ref: RecordRef, later_ref: RecordRef
    ) -> bool:
        earlier = self.get_exact(earlier_ref)
        current = self.get_exact(later_ref)
        assert hasattr(earlier, "meta") and hasattr(current, "meta")
        while current.meta.record_id != earlier.meta.record_id:
            previous = next(
                (
                    value
                    for value in self.values.values()
                    if hasattr(value, "meta")
                    and value.meta.record_id == current.meta.previous_record_id
                ),
                None,
            )
            if previous is None:
                return False
            validate_revision(previous.meta, current.meta)
            current = previous
        return reference(current) == earlier_ref

    def stage_record(self, record: object) -> StoredDataRef:
        return self.add(record)


class _Artifacts:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def add(self, payload: object) -> StoredDataRef:
        data = canonical_bytes(payload)
        digest = content_hash(payload)
        self.values[digest] = data
        return StoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            workspace_id=WORKSPACE,
            commit_id=COMMIT,
            record_id=None,
        )

    def open_verified(self, ref: StoredDataRef) -> BytesIO:
        return BytesIO(self.values[ref.content_hash])


class _LLM:
    def __init__(self) -> None:
        self.outcomes: list[PersistedLLMInvocation] = []
        self.calls = 0

    async def invoke(self, **_: object) -> PersistedLLMInvocation:
        self.calls += 1
        return self.outcomes.pop(0)


class _Publisher:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.completed_work: WorkExecutionState | None = None

    def complete(
        self,
        work: WorkExecutionState,
        identity: StoredDataRef,
        role: str,
        outputs: tuple[object, ...],
        *,
        status: str = "SUCCEEDED",
        cause: str = "COMPLETED",
        error_ids: tuple[str, ...] = (),
        gap_ids: tuple[str, ...] = (),
        action_input_refs: tuple[RecordRef, ...] | None = None,
    ) -> WorkExecutionState:
        self.calls.append(
            dict(
                work=work,
                identity=identity,
                role=role,
                outputs=outputs,
                status=status,
                action_input_refs=action_input_refs,
            )
        )
        refs = tuple(reference(value) for value in outputs)  # type: ignore[arg-type]
        completed = work.model_copy(
            update={
                "status": status,
                "active_attempt_id": None,
                "output_refs": refs,
                "finished_at": NOW if status in {"SUCCEEDED", "FAILED"} else None,
            }
        )
        self.completed_work = completed
        return completed


class _Ready:
    def __init__(self, records: _Records) -> None:
        self.records = records
        self.calls: list[dict[str, object]] = []

    def enqueue_registered(
        self,
        registered: WorkExecutionState,
        scope: StoredDataRef,
        identity: StoredDataRef,
        *,
        role: str = "ORCHESTRATION",
    ) -> WorkExecutionState:
        assert registered.status == WorkStatus.PENDING
        self.calls.append(dict(scope=scope, identity=identity, role=role))
        self.records.add(registered)
        ready_meta = registered.meta.model_copy(
            update={
                "record_id": RecordId(f"{registered.meta.record_id}-ready"),
                "revision_number": registered.meta.revision_number + 1,
                "previous_record_id": registered.meta.record_id,
            }
        )
        ready = registered.model_copy(
            update={
                "meta": ready_meta,
                "status": WorkStatus.READY,
                "state_version": registered.state_version + 1,
            }
        )
        self.records.add(ready)
        return ready


class _Current:
    def __init__(
        self,
        *,
        works: tuple[object, ...],
        processes: tuple[object, ...] = (),
        assignments: tuple[object, ...] = (),
    ) -> None:
        self.works = works
        self.processes = processes
        self.assignments = assignments

    def current_records(self, analysis_id: str, kind: str) -> tuple[object, ...]:
        assert analysis_id == str(ANALYSIS)
        return {
            "work_execution_state": self.works,
            "hypothesis_process_state": self.processes,
            "verification_assignment": self.assignments,
        }[kind]


class _Revision:
    def __init__(
        self, assignment_ref: StoredDataRef, *, fail_before_start_once: bool = False
    ) -> None:
        self.assignment_ref = assignment_ref
        self.calls: list[dict[str, object]] = []
        self.fail_before_start_once = fail_before_start_once
        self.registration: VerificationRegistration | None = None

    def start_new_generation(self, **kwargs: object) -> VerificationRegistration:
        self.calls.append(dict(kwargs))
        if self.fail_before_start_once:
            self.fail_before_start_once = False
            raise RuntimeError("simulated crash before revision registration")
        if self.registration is not None:
            return VerificationRegistration(
                work=self.registration.work.model_copy(
                    update={"status": WorkStatus.READY}
                ),
                application=self.registration.application,
                assignment_ref=self.registration.assignment_ref,
                process_ref=self.registration.process_ref,
            )
        old_work = kwargs["old_work"] if "old_work" in kwargs else None
        del old_work
        work = WorkExecutionState.model_construct(
            meta=_meta("work_execution_state", "revision-work"),
            work_id=WorkId("verification-work-2"),
            parent_work_ref=None,
            work_type=WorkType.VERIFICATION,
            subject_type=SubjectType.HYPOTHESIS,
            subject_id=HYPOTHESIS,
            work_generation=2,
            status=WorkStatus.PENDING,
            state_version=1,
            last_transition_ref=None,
            last_transition_commit_ref=None,
            active_attempt_id=None,
            input_hash=content_hash((kwargs["technical_review_ref"],)),
            dedupe_key=content_hash(("revision-work", 2)),
            trigger_primitive_ref=None,
            input_refs=(kwargs["technical_review_ref"],),
            output_refs=(),
            gap_ids=(),
            error_ids=(),
            waiting_for=(),
            stop_reason=None,
            started_at=None,
            finished_at=None,
            elapsed_ms=0,
        )
        application = PlaybookApplication.model_construct(
            meta=_meta("playbook_application", "revision-app"),
            verification_work_id=work.work_id,
            verification_generation=2,
        )
        self.registration = VerificationRegistration(
            work=work,
            application=application,
            assignment_ref=self.assignment_ref,
            process_ref=kwargs["expected_process_ref"],  # type: ignore[arg-type]
        )
        return self.registration


@dataclass(frozen=True)
class _T10:
    revision: _Revision


@dataclass
class _Fixture:
    records: _Records
    artifacts: _Artifacts
    llm: _LLM
    publisher: _Publisher
    ready: _Ready
    verification: VerificationResult
    verification_ref: StoredDataRef
    dynamic: DynamicReproductionResult
    dynamic_ref: StoredDataRef
    poc: PoCBundle
    poc_ref: StoredDataRef
    process: HypothesisProcessState
    process_ref: StoredDataRef
    assignment: VerificationAssignment
    assignment_ref: StoredDataRef
    application: PlaybookApplication
    evidence_ref: StoredDataRef
    cwe_identity: StoredDataRef
    technical_identity: StoredDataRef
    orchestration_identity: StoredDataRef
    budget_ref: StoredDataRef

    def work(self, kind: WorkType, suffix: str) -> WorkExecutionState:
        return WorkExecutionState.model_construct(
            meta=_meta("work_execution_state", suffix),
            work_id=WorkId(f"{suffix}-work"),
            parent_work_ref=None,
            work_type=kind,
            subject_type=SubjectType.HYPOTHESIS,
            subject_id=HYPOTHESIS,
            work_generation=1,
            status=WorkStatus.RUNNING,
            state_version=2,
            last_transition_ref=None,
            last_transition_commit_ref=None,
            active_attempt_id=AttemptId(f"{suffix}-attempt"),
            input_hash="a" * 64,
            dedupe_key="b" * 64,
            trigger_primitive_ref=None,
            input_refs=(
                self.verification_ref,
                self.dynamic_ref,
                self.poc_ref,
                self.process_ref,
                self.assignment_ref,
                self.budget_ref,
            ),
            output_refs=(),
            gap_ids=(),
            error_ids=(),
            waiting_for=(),
            stop_reason=None,
            started_at=NOW,
            finished_at=None,
            elapsed_ms=0,
        )


def _opaque(records: _Records, kind: str, suffix: str) -> StoredDataRef:
    return records.add(DomainRecord.model_construct(meta=_meta(kind, suffix)))


def _fixture() -> _Fixture:
    records = _Records()
    artifacts = _Artifacts()
    chain = dynamic_success()
    poc = chain["poc"]
    poc_ref = records.add(poc)
    dynamic = chain["result"].model_copy(update={"poc_ref": poc_ref})
    dynamic_ref = records.add(dynamic)
    evidence = poc.evidence_refs[0]
    request_ref = dynamic.request_ref
    hypothesis_ref = _opaque(records, "vulnerability_hypothesis", "hypothesis")
    proposal_ref = _opaque(records, "hypothesis_proposal", "proposal")
    policy_ref = _opaque(records, "playbook_policy", "policy")
    playbook_ref = _opaque(records, "verification_playbook", "playbook")
    application = PlaybookApplication.model_construct(
        meta=_meta("playbook_application", "application"),
        verification_work_id=WorkId("verification-work-1"),
        verification_generation=1,
        hypothesis_ref=hypothesis_ref,
        proposal_ref=proposal_ref,
        policy_ref=policy_ref,
        playbook_ref=playbook_ref,
        selection="COMMON",
        selected_type=None,
        selection_reason="NO_TYPE",
        questions=(),
    )
    application_ref = records.add(application)
    verification = VerificationResult.model_construct(
        meta=_meta("verification_result", "verification", "verification-attempt"),
        playbook_ref=playbook_ref,
        playbook_application_ref=application_ref,
        verification_mode="ALWAYS_DEBATE",
        debate_triggers=(),
        debate_skip_reason=None,
        debate_input_hash="c" * 64,
        pro_evidence_ref=_opaque(records, "pro_evidence_result", "pro"),
        con_evidence_ref=_opaque(records, "con_evidence_result", "con"),
        supporting_evidence=(),
        counter_evidence=(),
        falsification_results=(),
        validation_results=(),
        initial_verdict="TRUE",
        dynamic_request_ref=request_ref,
        dynamic_result_ref=dynamic_ref,
        poc_ref=poc_ref,
        verdict="TRUE",
        verdict_rationale="Validated dynamic evidence supports the hypothesis",
        restrictions=(),
        bypass_candidates=(),
        required_primitive_candidates=(),
        provided_primitive_candidates=(),
        impact_escalation_candidates=(),
        material_child_proposals=(),
        unresolved_conditions=(),
        metrics=None,
        errors=(),
    )
    verification_ref = records.add(verification)
    owner = _opaque(records, "execution_identity", "owner")
    assignment = VerificationAssignment.model_construct(
        meta=_meta("verification_assignment", "assignment"),
        assignment_id="assignment-1",
        owner_identity_ref=owner,
        assignment_generation=1,
        status="ACTIVE",
        previous_assignment_ref=None,
        assigned_at=NOW,
    )
    assignment_ref = records.add(assignment)
    process = HypothesisProcessState.model_construct(
        meta=_meta("hypothesis_process_state", "process"),
        proposal_ref=proposal_ref,
        status="TERMINAL",
        verification_assignment_ref=assignment_ref,
        verification_generation=1,
        verification_work_ref=None,
        verification_result_ref=verification_ref,
        started_at=NOW,
        finished_at=NOW,
        elapsed_ms=0,
    )
    process_ref = records.add(process)
    return _Fixture(
        records=records,
        artifacts=artifacts,
        llm=_LLM(),
        publisher=_Publisher(),
        ready=_Ready(records),
        verification=verification,
        verification_ref=verification_ref,
        dynamic=dynamic,
        dynamic_ref=dynamic_ref,
        poc=poc,
        poc_ref=poc_ref,
        process=process,
        process_ref=process_ref,
        assignment=assignment,
        assignment_ref=assignment_ref,
        application=application,
        evidence_ref=evidence,
        cwe_identity=_opaque(records, "execution_identity", "cwe"),
        technical_identity=_opaque(records, "execution_identity", "technical"),
        orchestration_identity=_opaque(records, "execution_identity", "orchestration"),
        budget_ref=_opaque(records, "budget_profile_binding", "budget"),
    )


def _gate_call(
    fixture: _Fixture,
    work: WorkExecutionState,
    *,
    role: str,
    task: str,
    requested_by: str,
    requester: StoredDataRef,
    action_type: str,
    context: tuple[StoredDataRef, ...],
    payload: object,
) -> GateCallRefs:
    provider_ref = _opaque(fixture.records, "provider_profile", task)
    prompt_registry_entry_ref = _opaque(fixture.records, "prompt_registry_entry", task)
    prompt_template_ref = _opaque(fixture.records, "prompt_template", task)
    prompt_payload_ref = _opaque(fixture.records, "prompt_payload", task)
    execution_limits_ref = _opaque(fixture.records, "execution_limits", task)
    retry_policy_ref = _opaque(fixture.records, "retry_policy", task)
    tool_policy_ref = _opaque(fixture.records, "tool_policy", task)
    redaction_policy_ref = _opaque(fixture.records, "redaction_policy", task)
    semantic_validator_ref = _opaque(fixture.records, "semantic_validator", task)
    output_schema_ref = _opaque(fixture.records, "output_schema", task)
    spec = LLMCallSpec.model_construct(
        meta=_meta("llm_call_spec", task, str(work.active_attempt_id)),
        llm_call_id=f"{task}-call",
        agent_role=role,
        task_kind=task,
        purpose="PRODUCTION",
        provider_profile_ref=provider_ref,
        model="test-model",
        session_policy="NEW",
        parent_session_ref=None,
        context_refs=context,
        prompt_registry_entry_ref=prompt_registry_entry_ref,
        prompt_key=f"{role.lower()}.test",
        prompt_template_ref=prompt_template_ref,
        prompt_template_version="1.0.0",
        prompt_payload_ref=prompt_payload_ref,
        execution_limits_ref=execution_limits_ref,
        retry_policy_ref=retry_policy_ref,
        tool_policy_ref=tool_policy_ref,
        redaction_policy_ref=redaction_policy_ref,
        semantic_validator_ref=semantic_validator_ref,
        output_schema_ref=output_schema_ref,
        output_schema="test.schema.v1",
        token_budget=100,
        timeout_ms=1_000,
    )
    call_spec_ref = fixture.records.add(spec)
    action = ActionRequest.model_construct(
        meta=_meta("action_request", f"{task}-action", str(work.active_attempt_id)),
        action_id=f"{task}-action",
        requested_by=requested_by,
        requester_identity_ref=requester,
        action_type=action_type,
        work_ref=reference(work),
        expected_state_version=work.state_version,
        expected_verification_generation=None,
        generation_restart_reason=None,
        generation_restart_basis_refs=(),
        input_refs=context,
        dynamic_request_ref=None,
        reproduction_plan_ref=None,
        result_kind=None,
        candidate_result_ref=None,
        llm_call_spec_ref=call_spec_ref,
        tool_name=None,
        file_paths=(),
        provider_profile_ref=provider_ref,
        session_mode=SessionMode.NEW,
        sandbox_profile_ref=None,
        resource_profile_ref=None,
        run_policy_state_ref=None,
        image_digest=None,
        network_targets=(),
        resource_limits=None,
        reason="Run the authorized gate prompt",
        requested_at=NOW,
    )
    action_ref = fixture.records.add(action)
    required_checks = tuple(REQUIRED_CHECKS[action.action_type])
    check_results = tuple(
        ActionCheck(
            check_type=check,
            result=CheckResult.PASS,
            reason_code="APPROVED",
            safe_message="Approved",
        )
        for check in required_checks
    )
    decision = ActionDecision.model_construct(
        meta=_meta("action_decision", f"{task}-decision", str(work.active_attempt_id)),
        decision_id=f"{task}-decision",
        action_ref=action_ref,
        decision="ALLOW",
        required_checks=required_checks,
        check_results=check_results,
        checked_state_version=work.state_version,
        checked_config_refs=(),
        valid_until=NOW,
        error_ids=(),
        use_status="UNUSED",
        used_at=None,
        expired_at=None,
        expire_reason=None,
        outcome_refs=(),
        decided_at=NOW,
    )
    decision_ref = fixture.records.add(decision)
    claimed_meta = decision.meta.model_copy(
        update={
            "record_id": f"{task}-claimed",
            "revision_number": 2,
            "previous_record_id": decision.meta.record_id,
        }
    )
    claimed = ActionDecision.model_construct(
        meta=claimed_meta,
        decision_id=f"{task}-decision",
        action_ref=action_ref,
        decision="ALLOW",
        required_checks=required_checks,
        check_results=check_results,
        checked_state_version=work.state_version,
        checked_config_refs=(),
        valid_until=NOW,
        error_ids=(),
        use_status="USED",
        used_at=NOW,
        expired_at=None,
        expire_reason=None,
        outcome_refs=(),
        decided_at=NOW,
    )
    claimed_ref = fixture.records.add(claimed)
    output_ref = fixture.artifacts.add(payload)
    request = LLMInvocationRequest.model_construct(
        meta=_meta("llm_invocation_request", task, str(work.active_attempt_id)),
        llm_call_id=spec.llm_call_id,
        action_decision_ref=claimed_ref,
        call_spec_ref=call_spec_ref,
        agent_role=role,
        task_kind=task,
        purpose="PRODUCTION",
        provider_profile_ref=spec.provider_profile_ref,
        model=spec.model,
        session_policy=spec.session_policy,
        parent_session_ref=spec.parent_session_ref,
        context_refs=spec.context_refs,
        prompt_registry_entry_ref=spec.prompt_registry_entry_ref,
        prompt_key=spec.prompt_key,
        prompt_template_ref=spec.prompt_template_ref,
        prompt_template_version=spec.prompt_template_version,
        prompt_payload_ref=spec.prompt_payload_ref,
        execution_limits_ref=spec.execution_limits_ref,
        retry_policy_ref=spec.retry_policy_ref,
        tool_policy_ref=spec.tool_policy_ref,
        redaction_policy_ref=spec.redaction_policy_ref,
        semantic_validator_ref=spec.semantic_validator_ref,
        output_schema_ref=spec.output_schema_ref,
        output_schema=spec.output_schema,
        token_budget=spec.token_budget,
        timeout_ms=spec.timeout_ms,
    )
    result = LLMInvocationResult.model_construct(
        meta=_meta("llm_invocation_result", task, str(work.active_attempt_id)),
        llm_call_id=request.llm_call_id,
        purpose="PRODUCTION",
        status="SUCCEEDED",
        provider="test",
        model="test-model",
        actual_session_mode="NEW",
        session_ref=f"{task}-session",
        parsed_output_ref=output_ref,
        response_ref=output_ref,
        usage=None,
        started_at=NOW,
        finished_at=NOW,
        elapsed_ms=1,
        safe_error=None,
    )
    request_ref = fixture.records.add(request)
    result_ref = fixture.records.add(result)
    exposed_request_ref = fixture.artifacts.add({"request": task})
    log = LLMInvocationLog.model_construct(
        meta=_meta("llm_invocation_log", task, str(work.active_attempt_id)),
        llm_call_id=spec.llm_call_id,
        action_decision_ref=claimed_ref,
        call_spec_ref=call_spec_ref,
        agent_role=spec.agent_role,
        task_kind=spec.task_kind,
        purpose=spec.purpose,
        provider_profile_ref=spec.provider_profile_ref,
        provider=result.provider,
        model=spec.model,
        session_policy=spec.session_policy,
        session_ref=result.session_ref,
        parent_session_ref=spec.parent_session_ref,
        prompt_registry_entry_ref=spec.prompt_registry_entry_ref,
        prompt_key=spec.prompt_key,
        prompt_template_ref=spec.prompt_template_ref,
        prompt_template_version=spec.prompt_template_version,
        prompt_payload_ref=spec.prompt_payload_ref,
        execution_limits_ref=spec.execution_limits_ref,
        retry_policy_ref=spec.retry_policy_ref,
        tool_policy_ref=spec.tool_policy_ref,
        redaction_policy_ref=spec.redaction_policy_ref,
        semantic_validator_ref=spec.semantic_validator_ref,
        output_schema_ref=spec.output_schema_ref,
        context_refs=spec.context_refs,
        retrieved_code_locations=(),
        exposed_request_ref=exposed_request_ref,
        exposed_response_ref=result.response_ref,
        parsed_output_ref=result.parsed_output_ref,
        tool_calls=(),
        status=result.status,
        usage=result.usage,
        safe_error=result.safe_error,
        started_at=result.started_at,
        finished_at=result.finished_at,
        elapsed_ms=result.elapsed_ms,
        retry_count=0,
        validation_errors=(),
        repair_attempts=0,
        retry_of_llm_call_id=None,
        failover_from_llm_call_id=None,
        redaction_result="NOT_REQUIRED",
    )
    log_ref = fixture.records.add(log)
    reservation = BudgetReservation.model_construct(
        meta=_meta("budget_reservation", task, str(work.active_attempt_id)),
        reservation_id=f"{task}-reservation",
        budget_binding_ref=fixture.budget_ref,
        action_ref=action_ref,
        work_ref=reference(work),
        requested_units=None,
        status="RESERVED",
        ledger_entry_ref=None,
        reserved_at=NOW,
        finalized_at=None,
    )
    reservation_ref = fixture.records.add(reservation)
    fixture.llm.outcomes.append(
        PersistedLLMInvocation(request, result, log_ref, dispatch_state="RETURNED")
    )
    del request_ref, result_ref, log_ref, output_ref
    return GateCallRefs(
        decision_ref=decision_ref,
        reservation_ref=reservation_ref,
        call_spec_ref=call_spec_ref,
    )


def _metadata(
    source: RecordMeta, kind: str, attempt_id: AttemptId | None
) -> RecordMeta:
    return _meta(
        kind, f"output-{source.record_id}", str(attempt_id) if attempt_id else None
    )


@pytest.mark.asyncio
async def test_exact_final_true_is_labeled_then_technical_gate_accepts() -> None:
    fixture = _fixture()
    cwe_work = fixture.work(WorkType.CWE_LABEL, "cwe")
    cwe_context = (
        fixture.verification_ref,
        fixture.dynamic_ref,
        fixture.poc_ref,
        fixture.process_ref,
        fixture.evidence_ref,
    )
    cwe_call = _gate_call(
        fixture,
        cwe_work,
        role="CWE_LABELING",
        task="CLASSIFY_CWE",
        requested_by="CWE_LABELING",
        requester=fixture.cwe_identity,
        action_type="CALL_LLM",
        context=cwe_context,
        payload={
            "primary": "CWE-89",
            "alternatives": [],
            "rationale": "The validated SQL sink is the root cause",
            "evidence_indexes": [0],
            "uncertainty": None,
        },
    )
    cwe = CWELabelingService(
        agent=CWELabelingAgent(
            llm_calls=fixture.llm,
            records=fixture.records,
            artifacts=fixture.artifacts,
            metadata_factory=_metadata,
            provenance_validator=validate_llm_invocation_provenance,
        ),
        publisher=fixture.publisher,
        records=fixture.records,
        identity_ref=fixture.cwe_identity,
        taxonomy_version="CWE-4.17",
    )

    labeled = await cwe.label(
        work=cwe_work,
        process_ref=fixture.process_ref,
        verification_ref=fixture.verification_ref,
        dynamic_result_ref=fixture.dynamic_ref,
        poc_ref=fixture.poc_ref,
        call=cwe_call,
    )

    assert labeled.label.primary == "CWE-89"
    assert labeled.label.verification_result_ref == fixture.verification_ref
    assert labeled.completed_work.status == WorkStatus.SUCCEEDED
    assert fixture.publisher.calls[-1]["role"] == "CWE_LABELING"
    assert fixture.publisher.calls[-1]["identity"] == fixture.cwe_identity
    label_ref = reference(labeled.label)
    assert isinstance(label_ref, StoredDataRef)

    technical_work = fixture.work(WorkType.TECHNICAL_GATE, "technical")
    technical_work = technical_work.model_copy(
        update={"input_refs": (*technical_work.input_refs, label_ref)}
    )
    technical_context = (
        fixture.verification_ref,
        fixture.dynamic_ref,
        fixture.poc_ref,
        label_ref,
        fixture.process_ref,
        fixture.assignment_ref,
        fixture.evidence_ref,
    )
    technical_call = _gate_call(
        fixture,
        technical_work,
        role="TECHNICAL_GATE",
        task="REVIEW_TECHNICAL",
        requested_by="VERIFICATION",
        requester=fixture.assignment.owner_identity_ref,
        action_type="CALL_TECHNICAL_GATE",
        context=technical_context,
        payload={
            "status": "ACCEPT",
            "evidence_verdict_alignment": "The TRUE verdict matches the evidence",
            "code_flow_linkage": "The source reaches the SQL sink",
            "dynamic_linkage": "The validated PoC exercises that exact path",
            "cwe_assessment": "CWE-89 matches the root cause",
            "restriction_assessment": "No unresolved restriction blocks handoff",
            "revision_requests": [],
            "verification_requests": [],
            "rationale": "The exact evidence chain is internally consistent",
        },
    )
    revision = _Revision(fixture.assignment_ref)
    technical = TechnicalGateService(
        agent=TechnicalGateAgent(
            llm_calls=fixture.llm,
            records=fixture.records,
            artifacts=fixture.artifacts,
            metadata_factory=_metadata,
            provenance_validator=validate_llm_invocation_provenance,
        ),
        publisher=fixture.publisher,
        records=fixture.records,
        identity_ref=fixture.technical_identity,
        orchestration_identity_ref=fixture.orchestration_identity,
        t10_services=_T10(revision),
        ready_work=fixture.ready,
    )

    reviewed = await technical.review(
        work=technical_work,
        process_ref=fixture.process_ref,
        assignment_ref=fixture.assignment_ref,
        verification_ref=fixture.verification_ref,
        dynamic_result_ref=fixture.dynamic_ref,
        poc_ref=fixture.poc_ref,
        cwe_label_ref=label_ref,
        budget_binding_ref=fixture.budget_ref,
        call=technical_call,
    )

    assert reviewed.review.status == "ACCEPT"
    assert reviewed.review.handoff_readiness == "READY"
    assert reviewed.completed_work.status == WorkStatus.SUCCEEDED
    assert reviewed.revision_work is None
    assert revision.calls == []
    assert fixture.publisher.calls[-1]["role"] == "TECHNICAL_GATE"
    assert fixture.publisher.calls[-1]["identity"] == fixture.technical_identity


@pytest.mark.asyncio
async def test_revise_commits_review_then_readies_same_owner_new_generation() -> None:
    fixture = _fixture()
    label = CWELabel.model_construct(
        meta=_meta("cwe_label", "current"),
        verification_result_ref=fixture.verification_ref,
        verification_generation=1,
        cwe_labeling_work_id=WorkId("cwe-work"),
        llm_call_id="cwe-call",
        primary="CWE-89",
        alternatives=(),
        taxonomy_version="CWE-4.17",
        rationale="The SQL sink is the root cause",
        evidence_refs=(fixture.evidence_ref,),
        uncertainty=None,
    )
    label_ref = fixture.records.add(label)
    work = fixture.work(WorkType.TECHNICAL_GATE, "revise")
    work = work.model_copy(update={"input_refs": (*work.input_refs, label_ref)})
    context = (
        fixture.verification_ref,
        fixture.dynamic_ref,
        fixture.poc_ref,
        label_ref,
        fixture.process_ref,
        fixture.assignment_ref,
        fixture.evidence_ref,
    )
    call = _gate_call(
        fixture,
        work,
        role="TECHNICAL_GATE",
        task="REVIEW_TECHNICAL",
        requested_by="VERIFICATION",
        requester=fixture.assignment.owner_identity_ref,
        action_type="CALL_TECHNICAL_GATE",
        context=context,
        payload={
            "status": "REVISE",
            "evidence_verdict_alignment": "One linkage needs verification",
            "code_flow_linkage": "The sink is linked but one guard is unresolved",
            "dynamic_linkage": "The PoC supports the current path",
            "cwe_assessment": "The label remains plausible",
            "restriction_assessment": "A guard condition needs a new generation",
            "revision_requests": ["Recheck the guard condition"],
            "verification_requests": ["Collect guard-path evidence"],
            "rationale": "The same owner must re-verify the changed evidence need",
        },
    )
    revision = _Revision(fixture.assignment_ref)
    service = TechnicalGateService(
        agent=TechnicalGateAgent(
            llm_calls=fixture.llm,
            records=fixture.records,
            artifacts=fixture.artifacts,
            metadata_factory=_metadata,
            provenance_validator=validate_llm_invocation_provenance,
        ),
        publisher=fixture.publisher,
        records=fixture.records,
        identity_ref=fixture.technical_identity,
        orchestration_identity_ref=fixture.orchestration_identity,
        t10_services=_T10(revision),
        ready_work=fixture.ready,
    )

    result = await service.review(
        work=work,
        process_ref=fixture.process_ref,
        assignment_ref=fixture.assignment_ref,
        verification_ref=fixture.verification_ref,
        dynamic_result_ref=fixture.dynamic_ref,
        poc_ref=fixture.poc_ref,
        cwe_label_ref=label_ref,
        budget_binding_ref=fixture.budget_ref,
        call=call,
    )

    assert result.completed_work.status == WorkStatus.SUCCEEDED
    assert result.revision_work is not None
    assert result.revision_work.status == WorkStatus.READY
    assert result.revision_work.active_attempt_id is None
    assert (
        revision.calls[0]["owner_identity_ref"] == fixture.assignment.owner_identity_ref
    )
    assert revision.calls[0]["requester_identity_ref"] == fixture.orchestration_identity
    assert revision.calls[0]["policy_ref"] == fixture.application.policy_ref
    assert fixture.ready.calls == [
        {
            "scope": fixture.budget_ref,
            "identity": fixture.orchestration_identity,
            "role": "ORCHESTRATION",
        }
    ]


@pytest.mark.asyncio
async def test_committed_revise_is_reconciled_after_revision_start_crash() -> None:
    fixture = _fixture()
    label = CWELabel.model_construct(
        meta=_meta("cwe_label", "current"),
        verification_result_ref=fixture.verification_ref,
        verification_generation=1,
        cwe_labeling_work_id=WorkId("cwe-work"),
        llm_call_id="cwe-call",
        primary="CWE-89",
        alternatives=(),
        taxonomy_version="CWE-4.17",
        rationale="The SQL sink is the root cause",
        evidence_refs=(fixture.evidence_ref,),
        uncertainty=None,
    )
    label_ref = fixture.records.add(label)
    work = fixture.work(WorkType.TECHNICAL_GATE, "revise-recovery")
    work = work.model_copy(update={"input_refs": (*work.input_refs, label_ref)})
    context = (
        fixture.verification_ref,
        fixture.dynamic_ref,
        fixture.poc_ref,
        label_ref,
        fixture.process_ref,
        fixture.assignment_ref,
        fixture.evidence_ref,
    )
    call = _gate_call(
        fixture,
        work,
        role="TECHNICAL_GATE",
        task="REVIEW_TECHNICAL",
        requested_by="VERIFICATION",
        requester=fixture.assignment.owner_identity_ref,
        action_type="CALL_TECHNICAL_GATE",
        context=context,
        payload={
            "status": "REVISE",
            "evidence_verdict_alignment": "One linkage needs verification",
            "code_flow_linkage": "The sink is linked but one guard is unresolved",
            "dynamic_linkage": "The PoC supports the current path",
            "cwe_assessment": "The label remains plausible",
            "restriction_assessment": "A guard condition needs a new generation",
            "revision_requests": ["Recheck the guard condition"],
            "verification_requests": ["Collect guard-path evidence"],
            "rationale": "The same owner must re-verify the evidence need",
        },
    )
    revision = _Revision(
        fixture.assignment_ref,
        fail_before_start_once=True,
    )
    service = TechnicalGateService(
        agent=TechnicalGateAgent(
            llm_calls=fixture.llm,
            records=fixture.records,
            artifacts=fixture.artifacts,
            metadata_factory=_metadata,
            provenance_validator=validate_llm_invocation_provenance,
        ),
        publisher=fixture.publisher,
        records=fixture.records,
        identity_ref=fixture.technical_identity,
        orchestration_identity_ref=fixture.orchestration_identity,
        t10_services=_T10(revision),
        ready_work=fixture.ready,
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        await service.review(
            work=work,
            process_ref=fixture.process_ref,
            assignment_ref=fixture.assignment_ref,
            verification_ref=fixture.verification_ref,
            dynamic_result_ref=fixture.dynamic_ref,
            poc_ref=fixture.poc_ref,
            cwe_label_ref=label_ref,
            budget_binding_ref=fixture.budget_ref,
            call=call,
        )

    assert fixture.publisher.completed_work is not None
    current = _Current(
        works=(fixture.publisher.completed_work,),
        processes=(fixture.process,),
        assignments=(fixture.assignment,),
    )
    reconciler = TechnicalRevisionReconciler(
        service=service,
        current=current,
    )
    (recovered,) = reconciler.reconcile_pending(str(ANALYSIS))
    assert revision.registration is not None
    registered_work_ref = reference(revision.registration.work)
    assert isinstance(registered_work_ref, StoredDataRef)
    current_process_meta = fixture.process.meta.model_copy(
        update={
            "record_id": RecordId("hypothesis-process-current-revision"),
            "revision_number": fixture.process.meta.revision_number + 1,
            "previous_record_id": fixture.process.meta.record_id,
        }
    )
    current_process = fixture.process.model_copy(
        update={
            "meta": current_process_meta,
            "status": "VERIFYING",
            "verification_generation": 2,
            "verification_work_ref": registered_work_ref,
            "verification_result_ref": None,
            "finished_at": None,
        }
    )
    fixture.records.add(current_process)
    current.works = (fixture.publisher.completed_work, recovered)
    current.processes = (current_process,)
    (replayed,) = reconciler.reconcile_pending(str(ANALYSIS))

    assert recovered is not None
    assert recovered.status == WorkStatus.READY
    assert replayed == recovered
    assert len(fixture.publisher.calls) == 1
    assert fixture.llm.calls == 1
    assert len(revision.calls) == 2
    assert len(fixture.ready.calls) == 1
    assert (
        revision.calls[-1]["owner_identity_ref"]
        == fixture.assignment.owner_identity_ref
    )


def test_reconciler_rejects_successor_not_selected_by_current_process() -> None:
    fixture = _fixture()
    review = TechnicalEvidenceReview.model_construct(
        meta=_meta("technical_evidence_review", "wrong-successor", "gate-attempt"),
        action_decision_ref=_opaque(fixture.records, "action_decision", "review"),
        verification_result_ref=fixture.verification_ref,
        cwe_label_ref=_opaque(fixture.records, "cwe_label", "review"),
        status="REVISE",
        evidence_verdict_alignment="Needs revision",
        code_flow_linkage="Needs revision",
        dynamic_linkage="Needs revision",
        cwe_assessment="Needs revision",
        restriction_assessment="Needs revision",
        handoff_readiness="NOT_READY",
        revision_requests=("Revise the evidence",),
        verification_requests=("Verify the revised evidence",),
        rationale="A new verification generation is required",
    )
    review_ref = fixture.records.add(review)
    selected = fixture.work(WorkType.VERIFICATION, "selected-successor")
    selected = selected.model_copy(
        update={
            "work_generation": 2,
            "status": WorkStatus.PENDING,
            "state_version": 1,
            "active_attempt_id": None,
            "input_hash": content_hash((review_ref, "selected")),
            "dedupe_key": content_hash(("selected", 2)),
            "input_refs": (review_ref,),
            "started_at": None,
        }
    )
    selected_ref = fixture.records.add(selected)
    current_process_meta = fixture.process.meta.model_copy(
        update={
            "record_id": RecordId("hypothesis-process-wrong-successor"),
            "revision_number": fixture.process.meta.revision_number + 1,
            "previous_record_id": fixture.process.meta.record_id,
        }
    )
    current_process = fixture.process.model_copy(
        update={
            "meta": current_process_meta,
            "status": "VERIFYING",
            "verification_generation": 2,
            "verification_work_ref": selected_ref,
            "verification_result_ref": None,
            "finished_at": None,
        }
    )
    fixture.records.add(current_process)
    completed = fixture.work(WorkType.TECHNICAL_GATE, "wrong-successor")
    completed = completed.model_copy(
        update={
            "status": WorkStatus.SUCCEEDED,
            "active_attempt_id": None,
            "output_refs": (review_ref,),
            "finished_at": NOW,
            "stop_reason": "COMPLETED",
        }
    )
    wrong = selected.model_copy(
        update={
            "meta": _meta("work_execution_state", "unselected-successor"),
            "work_id": WorkId("unselected-successor"),
            "input_hash": content_hash((review_ref, "wrong")),
            "dedupe_key": content_hash(("wrong", 2)),
        }
    )
    service = TechnicalGateService(
        agent=TechnicalGateAgent(
            llm_calls=fixture.llm,
            records=fixture.records,
            artifacts=fixture.artifacts,
            metadata_factory=_metadata,
            provenance_validator=validate_llm_invocation_provenance,
        ),
        publisher=fixture.publisher,
        records=fixture.records,
        identity_ref=fixture.technical_identity,
        orchestration_identity_ref=fixture.orchestration_identity,
        t10_services=_T10(_Revision(fixture.assignment_ref)),
        ready_work=fixture.ready,
    )
    reconciler = TechnicalRevisionReconciler(
        service=service,
        current=_Current(
            works=(completed, wrong),
            processes=(current_process,),
            assignments=(fixture.assignment,),
        ),
    )

    with pytest.raises(ValueError, match="TECHNICAL_REVISE_CLOSURE_MISMATCH"):
        reconciler.reconcile_pending(str(ANALYSIS))
