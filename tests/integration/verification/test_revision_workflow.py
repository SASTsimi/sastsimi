from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.gates import TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VerificationAssignment,
)
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    HypothesisId,
    LogicalRecordId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import (
    AppliedPlaybookQuestion,
    PlaybookApplication,
    VerificationResult,
)
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.verification_registration import VerificationRegistration
from sastsimi.verification.revision_workflow import RevisionWorkflow
from tests.contract.domain.canonical_fixtures import make

NOW = datetime(2026, 9, 11, tzinfo=UTC)


def _meta(kind: str, suffix: str, *, attempt: str | None = None) -> RecordMeta:
    record_id = RecordId(f"{kind}-{suffix}")
    return RecordMeta(
        record_id=record_id,
        logical_record_id=LogicalRecordId(str(record_id)),
        record_type=kind,
        schema_version="1.0.0",
        analysis_id=AnalysisId("a1"),
        revision_number=1,
        previous_record_id=None,
        created_at=NOW,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        hypothesis_id=HypothesisId("h1"),
        attempt_id=attempt,
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


class _Registrar:
    def __init__(self, registration: VerificationRegistration) -> None:
        self.registration = registration
        self.calls = 0

    def revise(self, **_: object) -> VerificationRegistration:
        self.calls += 1
        return self.registration


def _fixture(
    *, reuse_old_application: bool = False
) -> tuple[RevisionWorkflow, dict[str, StoredDataRef]]:
    records = _Records()
    old_application = PlaybookApplication.model_validate(
        {
            "meta": _meta("playbook_application", "old"),
            "verification_work_id": "work-old",
            "verification_generation": 1,
            "hypothesis_ref": _record_ref("vulnerability_hypothesis", "hypothesis"),
            "proposal_ref": _record_ref("hypothesis_proposal", "proposal"),
            "policy_ref": _record_ref("playbook_policy", "policy"),
            "playbook_ref": _record_ref("verification_playbook", "playbook"),
            "selection": "COMMON",
            "selected_type": None,
            "selection_reason": "TYPE_NOT_ALLOWED",
            "questions": (
                AppliedPlaybookQuestion(
                    template_key="old", question="Old question", question_id="q-old"
                ),
            ),
        }
    )
    old_application_ref = records.add(old_application)
    verification_payload = make("VerificationResult")
    verification_payload["playbook_application_ref"] = old_application_ref.model_dump(
        mode="json"
    )
    old_result = VerificationResult.model_validate_json(
        canonical_bytes(verification_payload)
    )
    old_result_ref = records.add(old_result)
    assignment = VerificationAssignment.model_validate(
        {
            "meta": _meta("verification_assignment", "assignment"),
            "assignment_id": "assignment-1",
            "owner_identity_ref": _record_ref("identity", "owner"),
            "assignment_generation": 1,
            "status": "ACTIVE",
            "previous_assignment_ref": None,
            "assigned_at": NOW,
        }
    )
    assignment_ref = records.add(assignment)
    old_process = HypothesisProcessState.model_validate(
        {
            "meta": _meta("hypothesis_process_state", "old"),
            "proposal_ref": _record_ref("hypothesis_proposal", "proposal"),
            "status": "TERMINAL",
            "verification_assignment_ref": assignment_ref,
            "verification_generation": 1,
            "verification_work_ref": None,
            "verification_result_ref": old_result_ref,
            "started_at": NOW,
            "finished_at": NOW,
            "elapsed_ms": 1,
        }
    )
    old_process_ref = records.add(old_process)
    review = TechnicalEvidenceReview.model_validate(
        {
            "meta": _meta("technical_evidence_review", "review", attempt="gate"),
            "action_decision_ref": _record_ref("action_decision", "gate"),
            "verification_result_ref": old_result_ref,
            "cwe_label_ref": _record_ref("cwe_label", "label"),
            "status": "REVISE",
            "evidence_verdict_alignment": "More verification is required",
            "code_flow_linkage": "Path needs a fresh check",
            "dynamic_linkage": "Prior generation is not reusable",
            "cwe_assessment": "Recheck after verification",
            "restriction_assessment": "No restriction dropped",
            "handoff_readiness": "NOT_READY",
            "revision_requests": ("Re-run the named question",),
            "verification_requests": ("Collect fresh Pro and Con",),
            "rationale": "The same owner must start a fresh generation",
        }
    )
    review_ref = records.add(review)
    new_application = (
        old_application
        if reuse_old_application
        else PlaybookApplication.model_validate(
            old_application.model_dump()
            | {
                "meta": _meta("playbook_application", "new"),
                "verification_work_id": "work-new",
                "verification_generation": 2,
                "questions": (
                    AppliedPlaybookQuestion(
                        template_key="old",
                        question="Old question",
                        question_id="q-new",
                    ),
                ),
            }
        )
    )
    new_application_ref = records.add(new_application)
    work = WorkExecutionState.model_validate(
        {
            "meta": _meta("work_execution_state", "new"),
            "work_id": "work-new",
            "parent_work_ref": None,
            "work_type": WorkType.VERIFICATION,
            "subject_type": SubjectType.HYPOTHESIS,
            "subject_id": "h1",
            "work_generation": 2,
            "status": WorkStatus.PENDING,
            "state_version": 1,
            "last_transition_ref": None,
            "last_transition_commit_ref": None,
            "active_attempt_id": None,
            "input_hash": content_hash([review_ref, new_application_ref]),
            "dedupe_key": content_hash(["revise", 2]),
            "trigger_primitive_ref": None,
            "input_refs": (review_ref, new_application_ref),
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "waiting_for": (),
            "stop_reason": None,
            "started_at": None,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )
    work_ref = records.add(work)
    new_process = HypothesisProcessState.model_validate(
        old_process.model_dump()
        | {
            "meta": _meta("hypothesis_process_state", "new"),
            "status": "VERIFYING",
            "verification_generation": 2,
            "verification_work_ref": work_ref,
            "verification_result_ref": None,
            "finished_at": None,
        }
    )
    new_process_ref = records.add(new_process)
    registrar = _Registrar(
        VerificationRegistration(
            work=work,
            application=new_application,
            assignment_ref=assignment_ref,
            process_ref=new_process_ref,
        )
    )
    refs = {
        "review": review_ref,
        "process": old_process_ref,
        "owner": assignment.owner_identity_ref,
        "assignment": assignment_ref,
        "old_application": old_application_ref,
        "new_application": new_application_ref,
        "hypothesis": old_application.hypothesis_ref,
        "proposal": old_application.proposal_ref,
        "policy": old_application.policy_ref,
        "playbook": old_application.playbook_ref,
        "budget": _record_ref("execution_budget_profile", "budget"),
    }
    return RevisionWorkflow(registrar=registrar, records=records), refs


def _record_ref(kind: str, suffix: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"{kind}-{suffix}"),
        data_kind=kind,
        content_hash=content_hash([kind, suffix]),
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=RecordId(f"{kind}-{suffix}"),
    )


def _start(
    workflow: RevisionWorkflow, refs: dict[str, StoredDataRef]
) -> VerificationRegistration:
    return workflow.start_new_generation(
        technical_review_ref=refs["review"],
        hypothesis_ref=refs["hypothesis"],
        proposal_ref=refs["proposal"],
        policy_ref=refs["policy"],
        playbook_ref=refs["playbook"],
        expected_process_ref=refs["process"],
        owner_identity_ref=refs["owner"],
        requester_identity_ref=refs["owner"],
        budget_binding_ref=refs["budget"],
    )


def test_revise_returns_to_same_owner_with_fresh_generation() -> None:
    workflow, refs = _fixture()

    registration = _start(workflow, refs)

    assert registration.work.work_generation == 2
    assert registration.assignment_ref == refs["assignment"]
    assert reference(registration.application) != refs["old_application"]
    assert {item.question_id for item in registration.application.questions} == {
        "q-new"
    }


def test_revise_rejects_reused_application() -> None:
    workflow, refs = _fixture(reuse_old_application=True)

    with pytest.raises(ValueError, match="TECHNICAL_REVISE_CLOSURE_MISMATCH"):
        _start(workflow, refs)
