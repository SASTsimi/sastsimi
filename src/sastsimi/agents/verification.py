"""Trusted finalization for Verification LLM output artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import BinaryIO, Literal, Protocol

from sastsimi.contracts.actions import SessionMode
from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.hypothesis import HypothesisProposal, VulnerabilityHypothesis
from sastsimi.contracts.ids import AttemptId, WorkId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import (
    ConEvidenceResult,
    EvidenceAgentResult,
    FalsificationResult,
    PlaybookApplication,
    ProEvidenceResult,
    ValidationCheckResult,
    VerificationInitialAssessment,
    VerificationMetrics,
    VerificationResult,
    validate_evidence_pair,
    validate_evidence_sessions,
    validate_verification_closure,
)
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.dto import Record
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.verification_assembly import VerificationGenerationInputs


@dataclass(frozen=True)
class VerificationCallRefs:
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef


@dataclass(frozen=True)
class VerificationAgentOutcome[T]:
    """Trusted domain proposal plus the exact LLM invocation that produced it."""

    record: T
    invocation: PersistedLLMInvocation


class WorkResolver(Protocol):
    def __call__(self, work_id: WorkId) -> WorkExecutionState | None: ...


class EvidenceSessionResolver(Protocol):
    def __call__(
        self, llm_call_id: str, analysis_id: str
    ) -> tuple[str, Literal["NEW", "RESUME"]]: ...


class MetadataFactory(Protocol):
    def __call__(
        self, source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta: ...


class LLMCallInvoker(Protocol):
    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation: ...


class VerificationRecordStore(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...

    def stage_record(self, record: Record) -> RecordRef: ...


class VerificationArtifactReader(Protocol):
    def open_verified(self, ref: StoredDataRef) -> BinaryIO: ...


class _InitialContent(ContractModel):
    next_step: Literal[
        "POC_CONFIRMATION", "VERDICT_EVIDENCE", "FINALIZE_WITHOUT_DYNAMIC"
    ]
    proposed_verdict: Literal["TRUE", "FALSE", "HOLD"]
    rationale: NonEmptyStr
    evidence_refs: tuple[StoredDataRef, ...]
    unresolved_conditions: tuple[NonEmptyStr, ...]


class _FalsificationContent(ContractModel):
    question_id: NonEmptyStr
    outcome: Literal["DISPROVED", "NOT_DISPROVED", "INCONCLUSIVE"]
    evidence_refs: tuple[StoredDataRef, ...]
    rationale: NonEmptyStr


class _ValidationContent(ContractModel):
    validation_id: NonEmptyStr
    completion: Literal["COMPLETE", "INCOMPLETE"]
    evidence_refs: tuple[StoredDataRef, ...]
    summary: NonEmptyStr


class _FinalContent(ContractModel):
    verdict: Literal["TRUE", "FALSE", "HOLD"]
    verdict_rationale: NonEmptyStr
    falsification_results: tuple[_FalsificationContent, ...]
    validation_results: tuple[_ValidationContent, ...]
    unresolved_conditions: tuple[NonEmptyStr, ...]


class VerificationAgent:
    """Invoke Verification prompts and convert content into trusted records."""

    def __init__(
        self,
        *,
        llm_calls: LLMCallInvoker,
        records: VerificationRecordStore,
        artifacts: VerificationArtifactReader,
        metadata_factory: MetadataFactory,
        work_resolver: WorkResolver,
        evidence_session_resolver: EvidenceSessionResolver,
    ) -> None:
        self._llm_calls = llm_calls
        self._records = records
        self._artifacts = artifacts
        self._metadata = metadata_factory
        self._work = work_resolver
        self._evidence_session = evidence_session_resolver

    async def assess_initial(
        self,
        *,
        generation: VerificationGenerationInputs,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationInitialAssessment:
        outcome = await self.assess_initial_with_invocation(
            generation=generation,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )
        return outcome.record

    async def assess_initial_with_invocation(
        self,
        *,
        generation: VerificationGenerationInputs,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationAgentOutcome[VerificationInitialAssessment]:
        work, hypothesis, _proposal, application, pro, con = self._generation_records(
            generation, pro_ref, con_ref
        )
        invocation = await self._llm_calls.invoke(
            work=work,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )
        payload = self._successful_payload(
            invocation,
            work=work,
            call=call,
            task_kind="ASSESS_INITIAL",
            required_context=self._initial_context(generation, pro_ref, con_ref),
        )
        content = _InitialContent.model_validate_json(canonical_bytes(payload))
        if content.proposed_verdict == "HOLD" and not content.unresolved_conditions:
            raise ValueError("HOLD_CONDITIONS_REQUIRED")
        self._require_allowed_evidence(content.evidence_refs, generation, pro, con)
        meta = self._trusted_meta(work, "verification_initial_assessment")
        assessment = VerificationInitialAssessment.model_validate(
            {
                "meta": meta,
                "verification_work_id": generation.work_id,
                "verification_generation": generation.generation,
                "hypothesis_ref": generation.hypothesis_ref,
                "policy_ref": generation.policy_ref,
                "playbook_ref": generation.playbook_ref,
                "playbook_application_ref": generation.application_ref,
                "pro_evidence_ref": pro_ref,
                "con_evidence_ref": con_ref,
                "next_step": content.next_step,
                "proposed_verdict": content.proposed_verdict,
                "rationale": content.rationale,
                "evidence_refs": content.evidence_refs,
                "unresolved_conditions": content.unresolved_conditions,
                "llm_call_id": invocation.request.llm_call_id,
            }
        )
        self._require_assessment_closure(
            assessment, generation, hypothesis, application, pro, con
        )
        self._stage_exact(assessment)
        return VerificationAgentOutcome(assessment, invocation)

    async def finalize_without_dynamic(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationResult:
        outcome = await self.finalize_without_dynamic_with_invocation(
            generation=generation,
            assessment_ref=assessment_ref,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )
        return outcome.record

    async def finalize_without_dynamic_with_invocation(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationAgentOutcome[VerificationResult]:
        work, hypothesis, proposal, application, pro, con = self._generation_records(
            generation, pro_ref, con_ref
        )
        assessment = self._exact(assessment_ref, VerificationInitialAssessment)
        self._require_assessment_closure(
            assessment, generation, hypothesis, application, pro, con
        )
        if assessment.next_step != "FINALIZE_WITHOUT_DYNAMIC":
            raise ValueError("T11_OUTPUT_REQUIRED")
        invocation = await self._llm_calls.invoke(
            work=work,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )
        payload = self._successful_payload(
            invocation,
            work=work,
            call=call,
            task_kind="FINAL_VERDICT",
            required_context=(
                *self._initial_context(generation, pro_ref, con_ref),
                assessment_ref,
            ),
        )
        content = _FinalContent.model_validate_json(canonical_bytes(payload))
        if content.verdict == "TRUE":
            raise ValueError("T11_OUTPUT_REQUIRED")
        for falsification in content.falsification_results:
            self._require_allowed_evidence(
                falsification.evidence_refs, generation, pro, con
            )
        for validation in content.validation_results:
            self._require_allowed_evidence(
                validation.evidence_refs, generation, pro, con
            )
        result = VerificationResult.model_validate(
            {
                "meta": self._trusted_meta(work, "verification_result"),
                "playbook_ref": generation.playbook_ref,
                "playbook_application_ref": generation.application_ref,
                "verification_mode": "ALWAYS_DEBATE",
                "debate_triggers": (),
                "debate_skip_reason": None,
                "debate_input_hash": generation.debate_input_hash,
                "pro_evidence_ref": pro_ref,
                "con_evidence_ref": con_ref,
                "supporting_evidence": pro.evidence,
                "counter_evidence": con.evidence,
                "falsification_results": tuple(
                    FalsificationResult.model_validate(item.model_dump())
                    for item in content.falsification_results
                ),
                "validation_results": tuple(
                    ValidationCheckResult.model_validate(item.model_dump())
                    for item in content.validation_results
                ),
                "initial_verdict": assessment.proposed_verdict,
                "dynamic_request_ref": None,
                "dynamic_result_ref": None,
                "poc_ref": None,
                "verdict": content.verdict,
                "verdict_rationale": content.verdict_rationale,
                "restrictions": proposal.restrictions,
                "bypass_candidates": (),
                "required_primitive_candidates": (),
                "provided_primitive_candidates": (),
                "impact_escalation_candidates": (),
                "material_child_proposals": (),
                "unresolved_conditions": content.unresolved_conditions,
                "metrics": VerificationMetrics(
                    pro_tokens=None,
                    con_tokens=None,
                    synthesis_tokens=(
                        invocation.result.usage.total_tokens
                        if invocation.result.usage is not None
                        else None
                    ),
                    elapsed_ms=invocation.result.elapsed_ms,
                    verdict_changed_after_debate=(
                        assessment.proposed_verdict != content.verdict
                    ),
                    hold_resolved=(
                        assessment.proposed_verdict == "HOLD"
                        and content.verdict != "HOLD"
                    ),
                    false_positive_reduction_candidate=content.verdict == "FALSE",
                    new_bypass_count=0,
                    new_restriction_count=0,
                    new_falsification_count=0,
                ),
                "errors": (),
            }
        )
        validate_verification_closure(
            result,
            hypothesis,
            proposal,
            application,
            pro,
            con,
            current_work_id=generation.work_id,
            current_generation=generation.generation,
            purpose=invocation.request.purpose,
        )
        self._stage_exact(result)
        return VerificationAgentOutcome(result, invocation)

    def _generation_records(
        self,
        generation: VerificationGenerationInputs,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
    ) -> tuple[
        WorkExecutionState,
        VulnerabilityHypothesis,
        HypothesisProposal,
        PlaybookApplication,
        ProEvidenceResult,
        ConEvidenceResult,
    ]:
        work = self._work(generation.work_id)
        if (
            work is None
            or not isinstance(work.meta, RecordMeta)
            or work.work_type != WorkType.VERIFICATION
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or work.work_generation != generation.generation
            or work.meta.hypothesis_id is None
        ):
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        hypothesis = self._exact(generation.hypothesis_ref, VulnerabilityHypothesis)
        proposal = self._exact(hypothesis.proposal_ref, HypothesisProposal)
        application = self._exact(generation.application_ref, PlaybookApplication)
        pro = self._exact(pro_ref, ProEvidenceResult)
        con = self._exact(con_ref, ConEvidenceResult)
        if (pro_ref, con_ref) != (generation.pro_ref, generation.con_ref):
            raise ValueError("STALE_RESULT")
        if (
            application.hypothesis_ref != generation.hypothesis_ref
            or application.proposal_ref != hypothesis.proposal_ref
            or application.policy_ref != generation.policy_ref
            or application.playbook_ref != generation.playbook_ref
            or application.verification_work_id != generation.work_id
            or application.verification_generation != generation.generation
            or generation.debate_input_hash != pro.debate_input_hash
        ):
            raise ValueError("STALE_RESULT")
        expected_questions = (
            *(item.question_id for item in hypothesis.falsification_questions),
            *(item.question_id for item in application.questions),
        )
        if (
            len(generation.falsification_question_ids) != len(expected_questions)
            or set(generation.falsification_question_ids) != set(expected_questions)
            or len(generation.validation_ids) != len(hypothesis.validation_checks)
            or set(generation.validation_ids)
            != {item.validation_id for item in hypothesis.validation_checks}
        ):
            raise ValueError("STALE_RESULT")
        validate_evidence_pair(
            pro,
            con,
            parent_work_id=generation.work_id,
            generation=generation.generation,
            debate_input_hash=generation.debate_input_hash,
        )
        analysis_id = str(work.meta.analysis_id)
        pro_session, pro_mode = self._evidence_session(pro.llm_call_id, analysis_id)
        con_session, con_mode = self._evidence_session(con.llm_call_id, analysis_id)
        validate_evidence_sessions(
            pro,
            con,
            pro_session_id=pro_session,
            con_session_id=con_session,
            pro_mode=SessionMode(pro_mode),
            con_mode=SessionMode(con_mode),
        )
        return work, hypothesis, proposal, application, pro, con

    def _successful_payload(
        self,
        invocation: PersistedLLMInvocation,
        *,
        work: WorkExecutionState,
        call: VerificationCallRefs,
        task_kind: str,
        required_context: tuple[StoredDataRef, ...],
    ) -> object:
        request, result = invocation.request, invocation.result
        if (
            result.status != "SUCCEEDED"
            or result.parsed_output_ref is None
            or result.response_ref != result.parsed_output_ref
        ):
            raise ValueError("LLM_INVOCATION_NOT_SUCCEEDED")
        if (
            not isinstance(work.meta, RecordMeta)
            or not isinstance(request.meta, RecordMeta)
            or not isinstance(result.meta, RecordMeta)
        ):
            raise ValueError("VERIFICATION_INVOCATION_CLOSURE_MISMATCH")
        if (
            request.agent_role != "VERIFICATION"
            or request.task_kind != task_kind
            or request.call_spec_ref != call.call_spec_ref
            or request.action_decision_ref.data_kind != "action_decision"
            or request.action_decision_ref.workspace_id != work.meta.workspace_id
            or request.action_decision_ref.commit_id != work.meta.commit_id
            or request.llm_call_id != result.llm_call_id
            or request.meta.attempt_id != work.active_attempt_id
            or result.meta.attempt_id != work.active_attempt_id
            or request.meta.analysis_id != work.meta.analysis_id
            or request.meta.workspace_id != work.meta.workspace_id
            or request.meta.commit_id != work.meta.commit_id
            or request.meta.hypothesis_id != work.meta.hypothesis_id
            or result.meta.analysis_id != work.meta.analysis_id
            or result.meta.workspace_id != work.meta.workspace_id
            or result.meta.commit_id != work.meta.commit_id
            or result.meta.hypothesis_id != work.meta.hypothesis_id
            or not self._context_is_exactly_authorized(
                request.context_refs, required_context, work
            )
        ):
            raise ValueError("VERIFICATION_INVOCATION_CLOSURE_MISMATCH")
        try:
            with self._artifacts.open_verified(result.parsed_output_ref) as stream:
                raw = stream.read()
            payload = json.loads(raw)
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("VERIFICATION_OUTPUT_ARTIFACT_INVALID") from error
        if not isinstance(payload, dict) or canonical_bytes(payload) != raw:
            raise ValueError("VERIFICATION_OUTPUT_ARTIFACT_INVALID")
        return payload

    @staticmethod
    def _context_is_exactly_authorized(
        actual: tuple[StoredDataRef, ...],
        required: tuple[StoredDataRef, ...],
        work: WorkExecutionState,
    ) -> bool:
        if len(actual) != len(set(actual)) or len(required) != len(set(required)):
            return False
        required_set = set(required)
        allowed = required_set | {
            ref for ref in work.input_refs if isinstance(ref, StoredDataRef)
        }
        actual_set = set(actual)
        return required_set.issubset(actual_set) and actual_set.issubset(allowed)

    def _require_assessment_closure(
        self,
        assessment: VerificationInitialAssessment,
        generation: VerificationGenerationInputs,
        hypothesis: VulnerabilityHypothesis,
        application: PlaybookApplication,
        pro: ProEvidenceResult,
        con: ConEvidenceResult,
    ) -> None:
        if (
            assessment.verification_work_id != generation.work_id
            or assessment.verification_generation != generation.generation
            or assessment.hypothesis_ref != generation.hypothesis_ref
            or assessment.policy_ref != generation.policy_ref
            or assessment.playbook_ref != generation.playbook_ref
            or assessment.playbook_application_ref != generation.application_ref
            or assessment.pro_evidence_ref != generation.pro_ref
            or assessment.con_evidence_ref != generation.con_ref
            or application.hypothesis_ref != reference(hypothesis)
            or reference(pro) != generation.pro_ref
            or reference(con) != generation.con_ref
        ):
            raise ValueError("INITIAL_ASSESSMENT_CLOSURE_MISMATCH")

    @staticmethod
    def _initial_context(
        generation: VerificationGenerationInputs,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
    ) -> tuple[StoredDataRef, ...]:
        return (
            generation.hypothesis_ref,
            generation.policy_ref,
            generation.playbook_ref,
            generation.application_ref,
            pro_ref,
            con_ref,
            generation.evidence_ref,
        )

    @staticmethod
    def _require_allowed_evidence(
        refs: tuple[StoredDataRef, ...],
        generation: VerificationGenerationInputs,
        pro: EvidenceAgentResult,
        con: EvidenceAgentResult,
    ) -> None:
        allowed = {
            generation.evidence_ref,
            *(
                ref
                for claim in (*pro.evidence, *con.evidence)
                for ref in claim.evidence_refs
            ),
        }
        if not refs or any(ref not in allowed for ref in refs):
            raise ValueError("VERIFICATION_EVIDENCE_CLOSURE_MISMATCH")

    def _trusted_meta(self, work: WorkExecutionState, kind: str) -> RecordMeta:
        assert isinstance(work.meta, RecordMeta)
        meta = self._metadata(work.meta, kind, work.active_attempt_id)
        if (
            meta.record_type != kind
            or meta.attempt_id != work.active_attempt_id
            or meta.analysis_id != work.meta.analysis_id
            or meta.workspace_id != work.meta.workspace_id
            or meta.commit_id != work.meta.commit_id
            or meta.hypothesis_id != work.meta.hypothesis_id
        ):
            raise ValueError("RUNTIME_METADATA_SCOPE_MISMATCH")
        return meta

    def _stage_exact(self, record: Record) -> None:
        expected = reference(record)
        actual = self._records.stage_record(record)
        if actual != expected:
            raise ValueError("DOMAIN_RECORD_STAGE_MISMATCH")

    def _exact[T](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:  # type: ignore[arg-type]
            raise ValueError("RECORD_REVISION_MISMATCH")
        return value


__all__ = ["VerificationAgent", "VerificationAgentOutcome", "VerificationCallRefs"]
