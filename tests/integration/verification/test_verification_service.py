from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
from typing import Literal

import pytest

from sastsimi.agents.verification import VerificationAgent, VerificationCallRefs
from sastsimi.contracts._domain import DomainRecord
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import DynamicReproductionResult
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
from sastsimi.contracts.static import CodeLocation, CodeSymbol
from sastsimi.contracts.verification import (
    AppliedPlaybookQuestion,
    ConEvidenceResult,
    EvidenceClaim,
    PlaybookApplication,
    ProEvidenceResult,
)
from sastsimi.contracts.work import (
    TransitionCommit,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.dto import Record, StagedArtifact, TransitionCommitRequest
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.verification_assembly import VerificationGenerationInputs
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.verification.service import VerificationService
from tests.contract.domain.success_fixture import dynamic_success

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


class _MemoryRecords(RecordStore):
    def __init__(self) -> None:
        self.values: dict[RecordRef, Record] = {}

    def add(self, value: Record) -> StoredDataRef:
        ref = reference(value)
        assert isinstance(ref, StoredDataRef)
        self.values[ref] = value
        return ref

    def get_exact(self, ref: RecordRef) -> Record:
        return self.values[ref]

    def is_revision_descendant(
        self, earlier_ref: RecordRef, later_ref: RecordRef
    ) -> bool:
        earlier = self.get_exact(earlier_ref)
        current = self.get_exact(later_ref)
        if (
            type(earlier.meta) is not type(current.meta)
            or earlier.meta.logical_record_id != current.meta.logical_record_id
            or earlier.meta.record_type != current.meta.record_type
            or current.meta.revision_number < earlier.meta.revision_number
        ):
            return False
        by_record_id = {
            record.meta.record_id: record for record in self.values.values()
        }
        visited = set()
        while current.meta.record_id != earlier.meta.record_id:
            if (
                current.meta.record_id in visited
                or current.meta.previous_record_id is None
            ):
                return False
            visited.add(current.meta.record_id)
            predecessor = by_record_id.get(current.meta.previous_record_id)
            if predecessor is None:
                return False
            current = predecessor
        return True

    def stage_record(self, record: Record) -> StoredDataRef:
        return self.add(record)

    def commit_transition(self, request: TransitionCommitRequest) -> TransitionCommit:
        del request
        raise AssertionError("verification fixtures do not commit transitions")


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


class _DraftIdFactory:
    def __init__(self) -> None:
        self.index = 0

    def __call__(self) -> str:
        self.index += 1
        return f"runtime-draft-{self.index}"


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
        self.entity = CodeSymbol(
            symbol_id="route-handler",
            symbol_kind="CALLABLE",
            native_kind="function",
            name="handle_request",
            location=CodeLocation(
                workspace_id=WORKSPACE_ID,
                commit_id=COMMIT_ID,
                file_path="src/app.py",
                start_line=1,
                end_line=2,
                start_column=None,
                end_column=None,
            ),
        )
        proposal = HypothesisProposal.model_construct(
            meta=_meta("hypothesis_proposal", suffix="proposal", attempt=None),
            proposal_id=ProposalId("proposal-1"),
            proposal_state="HYPOTHESIS_ONLY",
            assertion_mode="NON_FINAL",
            statement="Input may reach SQL execution",
            origin="INITIAL",
            vulnerability_type_candidates=("CWE-89",),
            target_entities=(self.entity,),
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
                "target_entities": (self.entity,),
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
            draft_id_factory=_DraftIdFactory(),
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
            PersistedLLMInvocation(
                request=request,
                result=result,
                log_ref=decision_ref,
                dispatch_state="RETURNED",
            )
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
        required: tuple[dict[str, object], ...] = (),
        provided: tuple[dict[str, object], ...] | None = None,
    ) -> dict[str, object]:
        actual_provided = provided
        if actual_provided is None:
            actual_provided = (
                (self.primitive_content("Validated capability"),)
                if verdict == "TRUE"
                else ()
            )
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
            "required_primitive_candidates": list(required),
            "provided_primitive_candidates": list(actual_provided),
            "unresolved_conditions": list(unresolved),
        }

    def primitive_content(
        self,
        description: str,
        *,
        entity: CodeSymbol | None = None,
        evidence_ref: StoredDataRef | None = None,
    ) -> dict[str, object]:
        return {
            "entity_refs": [
                (entity or self.entity).model_dump(mode="json")
            ],
            "privilege_level": None,
            "evidence_refs": [
                (evidence_ref or self.evidence_ref).model_dump(mode="json")
            ],
            "description": description,
        }

    def install_dynamic_success(self) -> dict[str, StoredDataRef]:
        """Re-scope the canonical executed-PoC chain to this Verification fixture."""
        base = dynamic_success()
        dynamic_attempt = AttemptId("dynamic-attempt-1")

        def dynamic_meta(kind: str) -> RecordMeta:
            return _meta(kind, suffix="dynamic", attempt=dynamic_attempt)

        assignment_ref = self._opaque_record("verification_assignment", "dynamic")
        sandbox_ref = self._opaque_record("sandbox_profile", "dynamic")
        request = base["request"].model_copy(
            update={
                "meta": _meta(
                    "dynamic_reproduction_request",
                    suffix="dynamic",
                    attempt=ATTEMPT_ID,
                ),
                "verification_assignment_ref": assignment_ref,
                "verification_generation": self.generation.generation,
                "hypothesis_ref": self.hypothesis_ref,
                "sandbox_profile_ref": sandbox_ref,
                "code_refs": (self.evidence_ref,),
                "static_evidence_refs": (self.evidence_ref,),
                "pro_evidence_ref": self.pro_ref,
                "con_evidence_ref": self.con_ref,
            }
        )
        request_ref = self.records.add(request)
        requirements = base["requirements"].model_copy(
            update={
                "meta": dynamic_meta("environment_requirements"),
                "request_ref": request_ref,
            }
        )
        requirements_ref = self.records.add(requirements)
        plan = base["plan"].model_copy(
            update={
                "meta": dynamic_meta("reproduction_plan"),
                "request_ref": request_ref,
                "hypothesis_ref": self.hypothesis_ref,
                "environment_requirements_ref": requirements_ref,
                "sandbox_profile_ref": sandbox_ref,
            }
        )
        plan_ref = self.records.add(plan)
        recipe = base["recipe"].model_copy(
            update={
                "meta": dynamic_meta("environment_recipe"),
                "request_ref": request_ref,
                "environment_requirements_ref": requirements_ref,
                "recipe_source_ref": self.evidence_ref,
                "source_refs": (self.evidence_ref,),
            }
        )
        recipe_ref = self.records.add(recipe)
        environment = base["environment"].model_copy(
            update={
                "meta": dynamic_meta("sandbox_environment"),
                "request_ref": request_ref,
                "reproduction_plan_ref": plan_ref,
                "environment_recipe_ref": recipe_ref,
                "requirements_ref": requirements_ref,
            }
        )
        environment_ref = self.records.add(environment)
        policy = base["policy"].model_copy(
            update={
                "meta": dynamic_meta("sandbox_policy_decision"),
                "request_ref": request_ref,
                "sandbox_profile_ref": sandbox_ref,
            }
        )
        policy_ref = self.records.add(policy)
        candidate = base["candidate"].model_copy(
            update={
                "meta": dynamic_meta("poc_candidate"),
                "request_ref": request_ref,
                "reproduction_plan_ref": plan_ref,
                "content_ref": self.evidence_ref,
                "content_digest": self.evidence_ref.content_hash,
            }
        )
        candidate_ref = self.records.add(candidate)
        tool = base["tool_requests"][0].model_copy(
            update={
                "meta": dynamic_meta("dynamic_reproduction_tool_request"),
                "request_ref": request_ref,
                "reproduction_plan_ref": plan_ref,
                "environment_ref": environment_ref,
            }
        )
        tool_ref = self.records.add(tool)
        command = base["command_records"][0].model_copy(
            update={
                "meta": dynamic_meta("sandbox_command_record"),
                "request_ref": request_ref,
                "reproduction_plan_ref": plan_ref,
                "environment_recipe_ref": recipe_ref,
                "environment_ref": environment_ref,
                "tool_request_ref": tool_ref,
            }
        )
        command_ref = self.records.add(command)
        events = tuple(
            event.model_copy(
                update={
                    "environment_ref": (
                        environment_ref if event.environment_ref is not None else None
                    ),
                    "environment_recipe_ref": (
                        recipe_ref if event.environment_recipe_ref is not None else None
                    ),
                    "poc_candidate_ref": (
                        candidate_ref if event.poc_candidate_ref is not None else None
                    ),
                    "tool_request_ref": (
                        tool_ref if event.tool_request_ref is not None else None
                    ),
                    "command_ref": (
                        command_ref if event.command_ref is not None else None
                    ),
                    "command_digest": (
                        command.command_digest
                        if event.command_digest is not None
                        else None
                    ),
                    "input_refs": (
                        (policy_ref,)
                        if event.event_type == "SESSION_STARTED"
                        else (
                            (candidate.content_ref,)
                            if event.event_type.startswith("POC_EXECUTION_")
                            else event.input_refs
                        )
                    ),
                    "output_refs": (
                        (self.evidence_ref,)
                        if event.event_type == "POC_EXECUTION_FINISHED"
                        else event.output_refs
                    ),
                }
            )
            for event in base["log"].events
        )
        log = base["log"].model_copy(
            update={
                "meta": dynamic_meta("agent_log"),
                "request_ref": request_ref,
                "events": events,
            }
        )
        log_ref = self.records.add(log)
        conclusion = base["conclusion"].model_copy(
            update={
                "meta": dynamic_meta("dynamic_reproduction_conclusion"),
                "request_ref": request_ref,
                "reproduction_plan_ref": plan_ref,
                "environment_ref": environment_ref,
                "poc_candidate_ref": candidate_ref,
                "observation_refs": (self.evidence_ref,),
                "hypothesis_evidence_refs": (self.evidence_ref,),
            }
        )
        conclusion_ref = self.records.add(conclusion)
        poc = base["poc"].model_copy(
            update={
                "meta": dynamic_meta("poc_bundle"),
                "request_ref": request_ref,
                "reproduction_plan_ref": plan_ref,
                "environment_recipe_ref": recipe_ref,
                "environment_ref": environment_ref,
                "agent_log_ref": log_ref,
                "candidate_ref": candidate_ref,
                "candidate_digest": candidate.content_digest,
                "evidence_refs": (self.evidence_ref,),
            }
        )
        poc_ref = self.records.add(poc)
        cleanup = base["cleanup"].model_copy(
            update={
                "meta": dynamic_meta("cleanup_result"),
                "request_ref": request_ref,
                "environment_refs": (environment_ref,),
            }
        )
        cleanup_ref = self.records.add(cleanup)
        result = base["result"].model_copy(
            update={
                "meta": dynamic_meta("dynamic_reproduction_result"),
                "request_ref": request_ref,
                "reproduction_plan_ref": plan_ref,
                "policy_decision_ref": policy_ref,
                "agent_log_ref": log_ref,
                "agent_conclusion_ref": conclusion_ref,
                "environment_recipe_ref": recipe_ref,
                "environment_ref": environment_ref,
                "poc_candidate_ref": candidate_ref,
                "poc_ref": poc_ref,
                "observation_refs": (self.evidence_ref,),
                "hypothesis_evidence_refs": (self.evidence_ref,),
                "cleanup_ref": cleanup_ref,
            }
        )
        result_ref = self.records.add(result)
        return {"request": request_ref, "result": result_ref, "poc": poc_ref}

    def dynamic_context(
        self,
        assessment_ref: StoredDataRef,
        refs: dict[str, StoredDataRef],
    ) -> tuple[StoredDataRef, ...]:
        return (
            *self.assessment_context(),
            assessment_ref,
            refs["request"],
            refs["result"],
            refs["poc"],
        )


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
async def test_hold_preserves_required_primitive_content_with_trusted_id() -> None:
    fixture = _Fixture()
    fixture.queue(
        fixture.assessment_payload("HOLD", unresolved=("Need authenticated caller",)),
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
        fixture.final_payload(
            "HOLD",
            outcome="INCONCLUSIVE",
            unresolved=("Need authenticated caller",),
            required=(fixture.primitive_content("Authenticated caller required"),),
        ),
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

    assert result.required_primitive_candidates[0].description == (
        "Authenticated caller required"
    )
    assert result.required_primitive_candidates[0].draft_id == "runtime-draft-1"
    assert result.provided_primitive_candidates == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("forgery", "message"),
    [
        ("entity", "VERIFICATION_PRIMITIVE_ENTITY_CLOSURE_MISMATCH"),
        ("entity_scope", "VERIFICATION_PRIMITIVE_ENTITY_CLOSURE_MISMATCH"),
        ("evidence", "VERIFICATION_EVIDENCE_CLOSURE_MISMATCH"),
        ("evidence_scope", "VERIFICATION_EVIDENCE_CLOSURE_MISMATCH"),
        ("draft_id", "OUTPUT_RUNTIME_AUTHORITY_DENIED"),
    ],
)
async def test_primitive_content_forgery_is_rejected(
    forgery: str, message: str
) -> None:
    fixture = _Fixture()
    fixture.queue(
        fixture.assessment_payload("HOLD", unresolved=("Need capability",)),
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
    primitive = fixture.primitive_content("Capability required")
    if forgery.startswith("entity"):
        entity_location = fixture.entity.location
        if forgery == "entity_scope":
            entity_location = entity_location.model_copy(
                update={"workspace_id": WorkspaceId("foreign-workspace")}
            )
        primitive["entity_refs"] = [
            CodeSymbol(
                symbol_id="fabricated-handler",
                symbol_kind="CALLABLE",
                native_kind="function",
                name="fabricated_handler",
                location=entity_location,
            ).model_dump(mode="json")
        ]
    elif forgery.startswith("evidence"):
        evidence_ref = fixture.artifacts.add_json({"forged": "evidence"})
        if forgery == "evidence_scope":
            evidence_ref = evidence_ref.model_copy(
                update={"workspace_id": WorkspaceId("foreign-workspace")}
            )
        primitive["evidence_refs"] = [
            evidence_ref.model_dump(mode="json")
        ]
    else:
        primitive["draft_id"] = "caller-controlled-id"
    fixture.queue(
        fixture.final_payload(
            "HOLD",
            outcome="INCONCLUSIVE",
            unresolved=("Need capability",),
            required=(primitive,),
        ),
        task_kind="FINAL_VERDICT",
        context_refs=(*fixture.assessment_context(), assessment_ref),
    )

    with pytest.raises(ValueError, match=message):
        await fixture.service.finalize_without_dynamic(
            generation=fixture.generation,
            assessment_ref=assessment_ref,
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("verdict", "candidate_field", "message"),
    [
        ("FALSE", "required", "FALSE_PRIMITIVE_FORBIDDEN"),
        ("HOLD", "provided", "HOLD_PROVIDED_PRIMITIVE_FORBIDDEN"),
        ("TRUE", "none", "TRUE_PROVIDED_PRIMITIVE_REQUIRED"),
    ],
)
async def test_primitive_candidates_follow_final_verdict_shape(
    verdict: str, candidate_field: str, message: str
) -> None:
    fixture = _Fixture()
    dynamic_verdict = verdict == "TRUE"
    unresolved = ("Need capability",) if verdict == "HOLD" else ()
    fixture.queue(
        fixture.assessment_payload(
            verdict,
            next_step=(
                "POC_CONFIRMATION" if dynamic_verdict else "FINALIZE_WITHOUT_DYNAMIC"
            ),
            unresolved=unresolved,
        ),
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
    candidate = fixture.primitive_content("Candidate")
    required = (candidate,) if candidate_field == "required" else ()
    provided = (candidate,) if candidate_field == "provided" else ()
    dynamic = fixture.install_dynamic_success() if dynamic_verdict else None
    fixture.queue(
        fixture.final_payload(
            verdict,
            outcome={"FALSE": "DISPROVED", "HOLD": "INCONCLUSIVE"}.get(
                verdict, "NOT_DISPROVED"
            ),
            unresolved=unresolved,
            required=required,
            provided=provided,
        ),
        task_kind="FINAL_VERDICT",
        context_refs=(
            fixture.dynamic_context(assessment_ref, dynamic)
            if dynamic is not None
            else (*fixture.assessment_context(), assessment_ref)
        ),
    )

    with pytest.raises(ValueError, match=message):
        if dynamic is None:
            await fixture.service.finalize_without_dynamic(
                generation=fixture.generation,
                assessment_ref=assessment_ref,
                pro_ref=fixture.pro_ref,
                con_ref=fixture.con_ref,
                call=fixture.call,
            )
        else:
            await fixture.service.finalize_with_dynamic(
                generation=fixture.generation,
                assessment_ref=assessment_ref,
                dynamic_request_ref=dynamic["request"],
                dynamic_result_ref=dynamic["result"],
                poc_ref=dynamic["poc"],
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


@pytest.mark.asyncio
async def test_dynamic_supported_produces_true_with_exact_validated_poc() -> None:
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
    dynamic = fixture.install_dynamic_success()
    fixture.queue(
        fixture.final_payload(
            "TRUE",
            outcome="NOT_DISPROVED",
            required=(fixture.primitive_content("Attacker-controlled input"),),
            provided=(fixture.primitive_content("Validated sink execution"),),
        ),
        task_kind="FINAL_VERDICT",
        context_refs=fixture.dynamic_context(assessment_ref, dynamic),
    )

    outcome = await fixture.service.finalize_with_dynamic_with_invocation(
        generation=fixture.generation,
        assessment_ref=assessment_ref,
        dynamic_request_ref=dynamic["request"],
        dynamic_result_ref=dynamic["result"],
        poc_ref=dynamic["poc"],
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )

    assert outcome.record.verdict == "TRUE"
    assert outcome.record.poc_ref == dynamic["poc"]
    assert [
        item.description for item in outcome.record.required_primitive_candidates
    ] == ["Attacker-controlled input"]
    assert [
        item.description for item in outcome.record.provided_primitive_candidates
    ] == ["Validated sink execution"]
    assert [
        item.draft_id
        for item in (
            *outcome.record.required_primitive_candidates,
            *outcome.record.provided_primitive_candidates,
        )
    ] == ["runtime-draft-1", "runtime-draft-2"]
    assert outcome.invocation.request.llm_call_id == "llm-FINAL_VERDICT"


@pytest.mark.asyncio
async def test_dynamic_operational_failure_creates_no_final_verdict() -> None:
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
    dynamic = fixture.install_dynamic_success()
    successful = fixture.records.get_exact(dynamic["result"])
    assert isinstance(successful, DynamicReproductionResult)
    failed = successful.model_copy(
        update={
            "meta": _meta(
                "dynamic_reproduction_result",
                suffix="failed",
                attempt=successful.meta.attempt_id,
            ),
            "status": "FAILED",
            "failure_category": "EXECUTION",
            "failure_reason": "Sandbox command failed",
            "hypothesis_outcome": "INCONCLUSIVE",
            "poc_ref": None,
        }
    )
    failed_ref = fixture.records.add(failed)

    with pytest.raises(ValueError, match="EXECUTION_FAILURE_IS_NOT_VERDICT"):
        await fixture.service.finalize_with_dynamic(
            generation=fixture.generation,
            assessment_ref=assessment_ref,
            dynamic_request_ref=dynamic["request"],
            dynamic_result_ref=failed_ref,
            poc_ref=None,
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )

    assert fixture.llm.outcomes == []
    assert not any(
        ref.data_kind == "verification_result" for ref in fixture.records.values
    )


@pytest.mark.asyncio
async def test_changed_dynamic_result_reference_is_rejected_before_llm() -> None:
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
    dynamic = fixture.install_dynamic_success()
    changed_ref = dynamic["result"].model_copy(update={"content_hash": "f" * 64})

    with pytest.raises((KeyError, ValueError)):
        await fixture.service.finalize_with_dynamic(
            generation=fixture.generation,
            assessment_ref=assessment_ref,
            dynamic_request_ref=dynamic["request"],
            dynamic_result_ref=changed_ref,
            poc_ref=dynamic["poc"],
            pro_ref=fixture.pro_ref,
            con_ref=fixture.con_ref,
            call=fixture.call,
        )

    assert fixture.llm.outcomes == []
