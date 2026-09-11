from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
from typing import Literal

import pytest

from sastsimi.agents.verification import VerificationAgent, VerificationCallRefs
from sastsimi.contracts._domain import DomainRecord
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.hypothesis import (
    FalsificationQuestion,
    HypothesisProposal,
    ValidationCheck,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.ids import (
    AnalysisId,
    AttemptId,
    CommitId,
    HypothesisId,
    LogicalRecordId,
    ProposalId,
    RecordId,
    StoredDataId,
    WorkId,
    WorkspaceId,
)
from sastsimi.contracts.llm import LLMInvocationRequest, LLMInvocationResult
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeLocation
from sastsimi.contracts.verification import (
    AppliedPlaybookQuestion,
    ConEvidenceResult,
    EvidenceClaim,
    PlaybookApplication,
    ProEvidenceResult,
)
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.dto import StagedArtifact
from sastsimi.ports.verification_assembly import VerificationGenerationInputs
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.verification.service import VerificationService

NOW = datetime(2026, 9, 11, tzinfo=UTC)
ANALYSIS_ID = AnalysisId("analysis-1")
WORKSPACE_ID = WorkspaceId("workspace-1")
COMMIT_ID = CommitId("commit-1")
HYPOTHESIS_ID = HypothesisId("hypothesis-1")
ATTEMPT_ID = AttemptId("verification-attempt-1")
WORK_ID = WorkId("verification-work-1")


def _meta(kind: str, *, suffix: str, attempt: AttemptId | None) -> RecordMeta:
    record_id = RecordId(f"{kind}-{suffix}")
    return RecordMeta(
        record_id=record_id,
        logical_record_id=LogicalRecordId(str(record_id)),
        record_type=kind,
        schema_version="1.0.0",
        analysis_id=ANALYSIS_ID,
        revision_number=1,
        previous_record_id=None,
        created_at=NOW,
        workspace_id=WORKSPACE_ID,
        commit_id=COMMIT_ID,
        hypothesis_id=HYPOTHESIS_ID,
        attempt_id=attempt,
    )


class _MemoryArtifacts:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        return StagedArtifact(data, media_type)

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        digest = content_hash_from_bytes(staged.data)
        self.values[digest] = staged.data
        return StoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            workspace_id=WORKSPACE_ID,
            commit_id=COMMIT_ID,
            record_id=None,
        )

    def open_verified(self, ref: StoredDataRef) -> BytesIO:
        data = self.values[ref.content_hash]
        if (
            ref.data_kind != "artifact"
            or ref.record_id is not None
            or str(ref.stored_data_id) != ref.content_hash
            or (ref.workspace_id, ref.commit_id) != (WORKSPACE_ID, COMMIT_ID)
            or content_hash_from_bytes(data) != ref.content_hash
        ):
            raise ValueError("HASH_MISMATCH")
        return BytesIO(data)

    def add_json(self, payload: object) -> StoredDataRef:
        return self.commit(
            self.stage_bytes(canonical_bytes(payload), "application/json")
        )


def content_hash_from_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


class _MemoryRecords:
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


class _QueuedLLM:
    def __init__(self) -> None:
        self.outcomes: list[PersistedLLMInvocation] = []

    async def invoke(self, **_: object) -> PersistedLLMInvocation:
        return self.outcomes.pop(0)


class _MetaFactory:
    def __init__(self) -> None:
        self.index = 0

    def __call__(
        self, source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta:
        self.index += 1
        return _meta(record_type, suffix=f"runtime-{self.index}", attempt=attempt_id)


def _evidence(
    role: Literal["PRO", "CON"], evidence_ref: StoredDataRef
) -> ProEvidenceResult | ConEvidenceResult:
    model = ProEvidenceResult if role == "PRO" else ConEvidenceResult
    return model.model_validate(
        {
            "meta": _meta(
                f"{role.lower()}_evidence_result",
                suffix=role.lower(),
                attempt=AttemptId(f"{role.lower()}-attempt"),
            ),
            "role": role,
            "parent_work_id": WORK_ID,
            "evidence_work_id": f"{role.lower()}-work",
            "verification_generation": 1,
            "llm_call_id": f"{role.lower()}-call",
            "debate_input_hash": "b" * 64,
            "evidence": (
                EvidenceClaim(
                    claim_id=f"{role.lower()}-claim",
                    statement=f"{role} checked the exact path",
                    source_role=role,
                    evidence_refs=(evidence_ref,),
                    code_locations=(
                        CodeLocation(
                            workspace_id=WORKSPACE_ID,
                            commit_id=COMMIT_ID,
                            file_path="src/app.py",
                            start_line=1,
                            end_line=2,
                            start_column=None,
                            end_column=None,
                        ),
                    ),
                    limitations=(),
                ),
            ),
            "summary": f"{role} complete",
            "limitations": (),
        }
    )


class _Fixture:
    def __init__(self) -> None:
        self.artifacts = _MemoryArtifacts()
        self.records = _MemoryRecords()
        self.llm = _QueuedLLM()
        self.evidence_ref = self.artifacts.add_json({"evidence": "code path"})
        proposal = HypothesisProposal.model_construct(
            meta=_meta("hypothesis_proposal", suffix="proposal", attempt=None),
            proposal_id=ProposalId("proposal-1"),
            proposal_state="HYPOTHESIS_ONLY",
            assertion_mode="NON_FINAL",
            statement="Input may reach SQL execution",
            origin="INITIAL",
            vulnerability_type_candidates=("CWE-89",),
            target_entities=(),
            target_locations=(
                CodeLocation(
                    workspace_id=WORKSPACE_ID,
                    commit_id=COMMIT_ID,
                    file_path="src/app.py",
                    start_line=1,
                    end_line=2,
                    start_column=None,
                    end_column=None,
                ),
            ),
            suspected_path=(),
            observed_facts=(),
            assumptions=(),
            restrictions=(),
            falsification_questions=(
                FalsificationQuestion(
                    question_id="question-hypothesis", question="Is input constant?"
                ),
            ),
            validation_checks=(
                ValidationCheck(
                    validation_id="validation-reachability",
                    instruction="Check reachability",
                ),
            ),
            parent_hypothesis_ids=(),
            source_primitive_match_id=None,
        )
        self.proposal_ref = self.records.add(proposal)
        hypothesis = VulnerabilityHypothesis.model_validate(
            {
                "meta": _meta(
                    "vulnerability_hypothesis", suffix="hypothesis", attempt=None
                ),
                "proposal_ref": self.proposal_ref,
                "statement": "Input may reach SQL execution",
                "origin": "INITIAL",
                "target_entities": (),
                "target_locations": proposal.target_locations,
                "suspected_path": (),
                "falsification_questions": proposal.falsification_questions,
                "validation_checks": proposal.validation_checks,
                "parent_hypothesis_ids": (),
                "source_primitive_match_id": None,
            }
        )
        self.hypothesis_ref = self.records.add(hypothesis)
        self.policy_ref = self._opaque_record("playbook_policy", "policy")
        self.playbook_ref = self._opaque_record("verification_playbook", "playbook")
        application = PlaybookApplication.model_validate(
            {
                "meta": _meta("playbook_application", suffix="app", attempt=None),
                "verification_work_id": WORK_ID,
                "verification_generation": 1,
                "hypothesis_ref": self.hypothesis_ref,
                "proposal_ref": self.proposal_ref,
                "policy_ref": self.policy_ref,
                "playbook_ref": self.playbook_ref,
                "selection": "COMMON",
                "selected_type": None,
                "selection_reason": "TYPE_NOT_ALLOWED",
                "questions": (
                    AppliedPlaybookQuestion(
                        template_key="constant-input",
                        question="Is the input constant?",
                        question_id="question-playbook",
                    ),
                ),
            }
        )
        self.application_ref = self.records.add(application)
        self.pro = _evidence("PRO", self.evidence_ref)
        self.con = _evidence("CON", self.evidence_ref)
        self.pro_ref = self.records.add(self.pro)
        self.con_ref = self.records.add(self.con)
        self.work = WorkExecutionState.model_construct(
            meta=_meta("work_execution_state", suffix="work", attempt=ATTEMPT_ID),
            work_id=WORK_ID,
            work_type=WorkType.VERIFICATION,
            work_generation=1,
            status=WorkStatus.RUNNING,
            active_attempt_id=ATTEMPT_ID,
            input_refs=(
                self.hypothesis_ref,
                self.proposal_ref,
                self.policy_ref,
                self.playbook_ref,
                self.application_ref,
            ),
        )
        self.generation = VerificationGenerationInputs(
            work_id=WORK_ID,
            generation=1,
            hypothesis_ref=self.hypothesis_ref,
            policy_ref=self.policy_ref,
            playbook_ref=self.playbook_ref,
            application_ref=self.application_ref,
            pro_ref=self.pro_ref,
            con_ref=self.con_ref,
            debate_input_hash="b" * 64,
            evidence_ref=self.evidence_ref,
            location=self.pro.evidence[0].code_locations[0],
            falsification_question_ids=(
                "question-hypothesis",
                "question-playbook",
            ),
            validation_ids=("validation-reachability",),
        )
        self.agent = VerificationAgent(
            llm_calls=self.llm,
            records=self.records,
            artifacts=self.artifacts,
            metadata_factory=_MetaFactory(),
            work_resolver=lambda work_id: self.work if work_id == WORK_ID else None,
            evidence_session_resolver=lambda call_id, _analysis_id: (
                (f"session-{call_id}", "NEW")
            ),
        )
        self.service = VerificationService(self.agent)

    def _opaque_record(self, kind: str, suffix: str) -> StoredDataRef:
        value = DomainRecord.model_construct(
            meta=_meta(kind, suffix=suffix, attempt=None)
        )
        return self.records.add(value)

    def queue(
        self,
        payload: object,
        *,
        task_kind: str,
        context_refs: tuple[StoredDataRef, ...],
        status: str = "SUCCEEDED",
    ) -> None:
        output_ref = self.artifacts.add_json(payload) if status == "SUCCEEDED" else None
        decision_ref = self._opaque_record("action_decision", f"decision-{task_kind}")
        call_spec_ref = self._opaque_record("llm_call_spec", f"call-{task_kind}")
        request = LLMInvocationRequest.model_construct(
            meta=_meta(
                "llm_invocation_request",
                suffix=f"request-{task_kind}",
                attempt=ATTEMPT_ID,
            ),
            llm_call_id=f"llm-{task_kind}",
            action_decision_ref=decision_ref,
            call_spec_ref=call_spec_ref,
            agent_role="VERIFICATION",
            task_kind=task_kind,
            purpose="PRODUCTION",
            context_refs=context_refs,
        )
        result = LLMInvocationResult.model_construct(
            meta=_meta(
                "llm_invocation_result",
                suffix=f"result-{task_kind}",
                attempt=ATTEMPT_ID,
            ),
            llm_call_id=request.llm_call_id,
            purpose="PRODUCTION",
            status=status,
            parsed_output_ref=output_ref,
            response_ref=output_ref,
            usage=None,
            elapsed_ms=3,
        )
        self.llm.outcomes.append(
            PersistedLLMInvocation(request=request, result=result, log_ref=decision_ref)
        )
        self.call = VerificationCallRefs(
            decision_ref=decision_ref,
            reservation_ref=decision_ref,
            call_spec_ref=call_spec_ref,
        )

    def assessment_context(self) -> tuple[StoredDataRef, ...]:
        return (
            self.hypothesis_ref,
            self.policy_ref,
            self.playbook_ref,
            self.application_ref,
            self.pro_ref,
            self.con_ref,
            self.evidence_ref,
        )

    def assessment_payload(
        self,
        verdict: str = "FALSE",
        *,
        next_step: str = "FINALIZE_WITHOUT_DYNAMIC",
        unresolved: tuple[str, ...] = (),
    ) -> dict[str, object]:
        return {
            "next_step": next_step,
            "proposed_verdict": verdict,
            "rationale": "The exact named checks were assessed",
            "evidence_refs": [self.evidence_ref.model_dump(mode="json")],
            "unresolved_conditions": list(unresolved),
        }

    def final_payload(
        self,
        verdict: str = "FALSE",
        *,
        outcome: str = "DISPROVED",
        unresolved: tuple[str, ...] = (),
    ) -> dict[str, object]:
        return {
            "verdict": verdict,
            "verdict_rationale": "The exact named checks determine the result",
            "falsification_results": [
                {
                    "question_id": question_id,
                    "outcome": outcome,
                    "evidence_refs": [self.evidence_ref.model_dump(mode="json")],
                    "rationale": "The exact question was checked",
                }
                for question_id in ("question-hypothesis", "question-playbook")
            ],
            "validation_results": [
                {
                    "validation_id": "validation-reachability",
                    "completion": "COMPLETE",
                    "evidence_refs": [self.evidence_ref.model_dump(mode="json")],
                    "summary": "Reachability checked",
                }
            ],
            "unresolved_conditions": list(unresolved),
        }


@pytest.mark.asyncio
async def test_false_requires_named_disproof_and_complete_checks() -> None:
    fixture = _Fixture()
    fixture.queue(
        fixture.assessment_payload(),
        task_kind="ASSESS_INITIAL",
        context_refs=fixture.assessment_context(),
    )
    assessment = await fixture.service.assess_initial(
        generation=fixture.generation,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )
    assessment_ref = reference(assessment)
    assert isinstance(assessment_ref, StoredDataRef)
    fixture.queue(
        fixture.final_payload(),
        task_kind="FINAL_VERDICT",
        context_refs=(*fixture.assessment_context(), assessment_ref),
    )

    result = await fixture.service.finalize_without_dynamic(
        generation=fixture.generation,
        assessment_ref=assessment_ref,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )

    assert result.verdict == "FALSE"
    assert any(item.outcome == "DISPROVED" for item in result.falsification_results)
    assert all(item.completion == "COMPLETE" for item in result.validation_results)
    assert result.meta.attempt_id == ATTEMPT_ID


@pytest.mark.asyncio
async def test_false_without_named_disproof_is_rejected() -> None:
    fixture = _Fixture()
    fixture.queue(
        fixture.assessment_payload(),
        task_kind="ASSESS_INITIAL",
        context_refs=fixture.assessment_context(),
    )
    assessment = await fixture.service.assess_initial(
        generation=fixture.generation,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )
    assessment_ref = reference(assessment)
    assert isinstance(assessment_ref, StoredDataRef)
    fixture.queue(
        fixture.final_payload(outcome="NOT_DISPROVED"),
        task_kind="FINAL_VERDICT",
        context_refs=(*fixture.assessment_context(), assessment_ref),
    )

    with pytest.raises(ValueError, match="FALSIFICATION_VERDICT_MISMATCH"):
        await fixture.service.finalize_without_dynamic(
            generation=fixture.generation,
            assessment_ref=assessment_ref,
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )


@pytest.mark.asyncio
async def test_hold_without_unresolved_condition_is_rejected() -> None:
    fixture = _Fixture()
    fixture.queue(
        fixture.assessment_payload("HOLD", unresolved=("Reachability",)),
        task_kind="ASSESS_INITIAL",
        context_refs=fixture.assessment_context(),
    )
    assessment = await fixture.service.assess_initial(
        generation=fixture.generation,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )
    assessment_ref = reference(assessment)
    assert isinstance(assessment_ref, StoredDataRef)
    fixture.queue(
        fixture.final_payload("HOLD", outcome="INCONCLUSIVE"),
        task_kind="FINAL_VERDICT",
        context_refs=(*fixture.assessment_context(), assessment_ref),
    )

    with pytest.raises(ValueError, match="HOLD_CONDITIONS_REQUIRED"):
        await fixture.service.finalize_without_dynamic(
            generation=fixture.generation,
            assessment_ref=assessment_ref,
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )


@pytest.mark.asyncio
async def test_initial_hold_without_unresolved_condition_is_rejected() -> None:
    fixture = _Fixture()
    fixture.queue(
        fixture.assessment_payload("HOLD"),
        task_kind="ASSESS_INITIAL",
        context_refs=fixture.assessment_context(),
    )

    with pytest.raises(ValueError, match="HOLD_CONDITIONS_REQUIRED"):
        await fixture.service.assess_initial(
            generation=fixture.generation,
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )


@pytest.mark.asyncio
async def test_authorized_work_input_can_be_in_synthesis_context() -> None:
    fixture = _Fixture()
    fixture.queue(
        fixture.assessment_payload(),
        task_kind="ASSESS_INITIAL",
        context_refs=(*fixture.assessment_context(), fixture.proposal_ref),
    )

    assessment = await fixture.service.assess_initial(
        generation=fixture.generation,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )

    assert assessment.proposed_verdict == "FALSE"


@pytest.mark.asyncio
async def test_unregistered_extra_context_is_rejected() -> None:
    fixture = _Fixture()
    foreign = fixture._opaque_record("verification_result", "foreign-generation")
    fixture.queue(
        fixture.assessment_payload(),
        task_kind="ASSESS_INITIAL",
        context_refs=(*fixture.assessment_context(), foreign),
    )

    with pytest.raises(ValueError, match="VERIFICATION_INVOCATION_CLOSURE_MISMATCH"):
        await fixture.service.assess_initial(
            generation=fixture.generation,
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )


@pytest.mark.asyncio
async def test_provider_failure_creates_no_assessment_or_verdict() -> None:
    fixture = _Fixture()
    fixture.queue(
        {},
        task_kind="ASSESS_INITIAL",
        context_refs=fixture.assessment_context(),
        status="AUTH_REQUIRED",
    )

    with pytest.raises(ValueError, match="LLM_INVOCATION_NOT_SUCCEEDED"):
        await fixture.service.assess_initial(
            generation=fixture.generation,
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )
    assert not any(
        ref.data_kind in {"verification_initial_assessment", "verification_result"}
        for ref in fixture.records.values
    )


@pytest.mark.asyncio
async def test_initial_true_waits_for_t11_instead_of_creating_final_true() -> None:
    fixture = _Fixture()
    fixture.queue(
        fixture.assessment_payload("TRUE", next_step="POC_CONFIRMATION"),
        task_kind="ASSESS_INITIAL",
        context_refs=fixture.assessment_context(),
    )
    assessment = await fixture.service.assess_initial(
        generation=fixture.generation,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )
    assessment_ref = reference(assessment)
    assert isinstance(assessment_ref, StoredDataRef)

    with pytest.raises(ValueError, match="T11_OUTPUT_REQUIRED"):
        await fixture.service.finalize_without_dynamic(
            generation=fixture.generation,
            assessment_ref=assessment_ref,
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )
    assert fixture.llm.outcomes == []
