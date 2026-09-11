from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from typing import Any

import pytest

from sastsimi.agents.cwe_labeling import CWELabelingAgent
from sastsimi.agents.technical_gate import TechnicalGateAgent
from sastsimi.contracts._domain import DomainRecord
from sastsimi.contracts.actions import ActionDecision, ActionRequest, SessionMode
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import DynamicReproductionResult, PoCBundle
from sastsimi.contracts.gates import CWELabel
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
from sastsimi.contracts.llm import LLMInvocationRequest, LLMInvocationResult
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import PlaybookApplication, VerificationResult
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.gates.cwe_service import CWELabelingService, GateCallRefs
from sastsimi.gates.technical_service import TechnicalGateService
from sastsimi.ports.verification_registration import VerificationRegistration
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
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
        return work.model_copy(
            update={
                "status": status,
                "active_attempt_id": None,
                "output_refs": refs,
                "finished_at": NOW if status in {"SUCCEEDED", "FAILED"} else None,
            }
        )


class _Ready:
    def __init__(self) -> None:
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
        return registered.model_copy(update={"status": WorkStatus.READY})


class _Revision:
    def __init__(self, assignment_ref: StoredDataRef) -> None:
        self.assignment_ref = assignment_ref
        self.calls: list[dict[str, object]] = []

    def start_new_generation(self, **kwargs: object) -> VerificationRegistration:
        self.calls.append(dict(kwargs))
        old_work = kwargs["old_work"] if "old_work" in kwargs else None
        del old_work
        work = WorkExecutionState.model_construct(
            meta=_meta("work_execution_state", "revision-work"),
            work_id=WorkId("verification-work-2"),
            work_type=WorkType.VERIFICATION,
            work_generation=2,
            status=WorkStatus.PENDING,
            active_attempt_id=None,
            input_refs=(),
        )
        application = PlaybookApplication.model_construct(
            meta=_meta("playbook_application", "revision-app"),
            verification_work_id=work.work_id,
            verification_generation=2,
        )
        return VerificationRegistration(
            work=work,
            application=application,
            assignment_ref=self.assignment_ref,
            process_ref=kwargs["expected_process_ref"],  # type: ignore[arg-type]
        )


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
        ready=_Ready(),
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
    call_spec_ref = _opaque(fixture.records, "llm_call_spec", task)
    provider_ref = _opaque(fixture.records, "provider_profile", task)
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
        session_mode=SessionMode.AUTO,
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
    decision = ActionDecision.model_construct(
        meta=_meta("action_decision", f"{task}-decision", str(work.active_attempt_id)),
        decision_id=f"{task}-decision",
        action_ref=action_ref,
        decision="ALLOW",
        required_checks=(),
        check_results=(),
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
    claimed = ActionDecision.model_construct(
        meta=_meta("action_decision", f"{task}-claimed", str(work.active_attempt_id)),
        decision_id=f"{task}-decision",
        action_ref=action_ref,
        decision="ALLOW",
        required_checks=(),
        check_results=(),
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
        llm_call_id=f"{task}-call",
        action_decision_ref=claimed_ref,
        call_spec_ref=call_spec_ref,
        agent_role=role,
        task_kind=task,
        purpose="PRODUCTION",
        provider_profile_ref=provider_ref,
        model="test-model",
        session_policy="NEW",
        parent_session_ref=None,
        context_refs=context,
        prompt_registry_entry_ref=_opaque(
            fixture.records, "prompt_registry_entry", task
        ),
        prompt_key=f"{role.lower()}.test",
        prompt_template_ref=_opaque(fixture.records, "prompt_template", task),
        prompt_template_version="1.0.0",
        prompt_payload_ref=_opaque(fixture.records, "prompt_payload", task),
        execution_limits_ref=_opaque(fixture.records, "execution_limits", task),
        retry_policy_ref=_opaque(fixture.records, "retry_policy", task),
        tool_policy_ref=_opaque(fixture.records, "tool_policy", task),
        redaction_policy_ref=_opaque(fixture.records, "redaction_policy", task),
        semantic_validator_ref=_opaque(fixture.records, "semantic_validator", task),
        output_schema_ref=_opaque(fixture.records, "output_schema", task),
        output_schema="test.schema.v1",
        token_budget=100,
        timeout_ms=1_000,
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
    log_ref = _opaque(fixture.records, "llm_invocation_log", task)
    fixture.llm.outcomes.append(
        PersistedLLMInvocation(request, result, log_ref, dispatch_state="RETURNED")
    )
    del request_ref, result_ref, log_ref, output_ref
    return GateCallRefs(
        decision_ref=decision_ref,
        reservation_ref=_opaque(fixture.records, "budget_reservation", task),
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
