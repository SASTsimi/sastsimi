"""Trusted finalization for Verification LLM output artifacts."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import BinaryIO, Literal, Protocol, cast

from sastsimi.contracts.actions import SessionMode
from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.domain import DomainRecord, walk
from sastsimi.contracts.dynamic import (
    AgentLog,
    CleanupResult,
    DynamicReproductionConclusion,
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionToolRequest,
    EnvironmentRecipe,
    EnvironmentRequirements,
    PoCBundle,
    PoCCandidate,
    ReproductionPlan,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPolicyDecision,
    validate_dynamic_closure,
)
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
    validate_dynamic_verdict,
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


@dataclass(frozen=True)
class _DynamicClosureRecords:
    request: DynamicReproductionRequest
    result: DynamicReproductionResult
    log: AgentLog
    plan: ReproductionPlan | None
    recipe: EnvironmentRecipe | None
    environment: SandboxEnvironment | None
    candidate: PoCCandidate | None
    poc: PoCBundle | None
    conclusion: DynamicReproductionConclusion | None
    policy: SandboxPolicyDecision | None
    cleanup: CleanupResult | None


class WorkResolver(Protocol):
    def __call__(self, work_id: WorkId) -> WorkExecutionState | None: ...


class EvidenceSessionResolver(Protocol):
    def __call__(
        self, llm_call_id: str, analysis_id: str
    ) -> tuple[str, Literal["NEW", "RESUME"]]: ...


class _EvidenceRefsCarrier(Protocol):
    evidence_refs: tuple[StoredDataRef, ...]


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

    async def finalize_with_dynamic(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        dynamic_request_ref: StoredDataRef,
        dynamic_result_ref: StoredDataRef,
        poc_ref: StoredDataRef | None,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationResult:
        outcome = await self.finalize_with_dynamic_with_invocation(
            generation=generation,
            assessment_ref=assessment_ref,
            dynamic_request_ref=dynamic_request_ref,
            dynamic_result_ref=dynamic_result_ref,
            poc_ref=poc_ref,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )
        return outcome.record

    async def finalize_with_dynamic_with_invocation(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        dynamic_request_ref: StoredDataRef,
        dynamic_result_ref: StoredDataRef,
        poc_ref: StoredDataRef | None,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationAgentOutcome[VerificationResult]:
        """Finalize only an exact, completed R7 result for this R6 generation."""
        work, hypothesis, proposal, application, pro, con = self._generation_records(
            generation, pro_ref, con_ref
        )
        assessment = self._exact(assessment_ref, VerificationInitialAssessment)
        self._require_assessment_closure(
            assessment, generation, hypothesis, application, pro, con
        )
        if assessment.next_step == "FINALIZE_WITHOUT_DYNAMIC":
            raise ValueError("DYNAMIC_OUTPUT_NOT_EXPECTED")

        dynamic = self._dynamic_closure_records(
            dynamic_request_ref=dynamic_request_ref,
            dynamic_result_ref=dynamic_result_ref,
            poc_ref=poc_ref,
        )
        if (
            dynamic.request.verification_generation != generation.generation
            or dynamic.request.hypothesis_ref != generation.hypothesis_ref
            or dynamic.request.pro_evidence_ref != pro_ref
            or dynamic.request.con_evidence_ref != con_ref
            or dynamic.request.purpose != assessment.next_step
            or dynamic.request.initial_verdict != assessment.proposed_verdict
            or dynamic.result.request_ref != dynamic_request_ref
        ):
            raise ValueError("STALE_RESULT")
        if dynamic.result.status not in {"SUCCEEDED", "PARTIAL"}:
            raise ValueError("EXECUTION_FAILURE_IS_NOT_VERDICT")

        self._validate_dynamic_closure(
            dynamic,
            generation=generation.generation,
        )
        invocation = await self._llm_calls.invoke(
            work=work,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )
        required_context = (
            *self._initial_context(generation, pro_ref, con_ref),
            assessment_ref,
            dynamic_request_ref,
            dynamic_result_ref,
            *((poc_ref,) if poc_ref is not None else ()),
        )
        payload = self._successful_payload(
            invocation,
            work=work,
            call=call,
            task_kind="FINAL_VERDICT",
            required_context=required_context,
        )
        content = _FinalContent.model_validate_json(canonical_bytes(payload))
        expected_verdict = {
            "SUPPORTED": "TRUE",
            "DISPROVED": "FALSE",
            "INCONCLUSIVE": "HOLD",
        }[dynamic.result.hypothesis_outcome]
        if content.verdict != expected_verdict:
            raise ValueError("DYNAMIC_VERDICT_MISMATCH")

        allowed_dynamic = {
            *dynamic.result.observation_refs,
            *dynamic.result.hypothesis_evidence_refs,
            *dynamic.result.disproof_evidence_refs,
        }
        for falsification in content.falsification_results:
            self._require_allowed_evidence(
                falsification.evidence_refs,
                generation,
                pro,
                con,
                additional=allowed_dynamic,
            )
        for validation in content.validation_results:
            self._require_allowed_evidence(
                validation.evidence_refs,
                generation,
                pro,
                con,
                additional=allowed_dynamic,
            )
        if dynamic.result.hypothesis_outcome == "DISPROVED":
            named_disproof_refs = {
                ref
                for item in content.falsification_results
                if item.outcome == "DISPROVED"
                for ref in item.evidence_refs
            }
            if not set(dynamic.result.disproof_evidence_refs) <= named_disproof_refs:
                raise ValueError("DYNAMIC_DISPROOF_NOT_NAMED")

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
                "dynamic_request_ref": dynamic_request_ref,
                "dynamic_result_ref": dynamic_result_ref,
                "poc_ref": poc_ref,
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
        validate_dynamic_verdict(
            result,
            dynamic.request,
            dynamic.result,
            dynamic.poc,
            generation=generation.generation,
        )
        self._stage_exact(result)
        return VerificationAgentOutcome(result, invocation)

    def _dynamic_closure_records(
        self,
        *,
        dynamic_request_ref: StoredDataRef,
        dynamic_result_ref: StoredDataRef,
        poc_ref: StoredDataRef | None,
    ) -> _DynamicClosureRecords:
        request = self._exact(dynamic_request_ref, DynamicReproductionRequest)
        result = self._exact(dynamic_result_ref, DynamicReproductionResult)
        if result.request_ref != dynamic_request_ref or result.poc_ref != poc_ref:
            raise ValueError("DYNAMIC_CLOSURE_MISSING")
        return _DynamicClosureRecords(
            request=request,
            result=result,
            log=self._exact(result.agent_log_ref, AgentLog),
            plan=self._optional_exact(result.reproduction_plan_ref, ReproductionPlan),
            recipe=self._optional_exact(
                result.environment_recipe_ref, EnvironmentRecipe
            ),
            environment=self._optional_exact(
                result.environment_ref, SandboxEnvironment
            ),
            candidate=self._optional_exact(result.poc_candidate_ref, PoCCandidate),
            poc=self._optional_exact(result.poc_ref, PoCBundle),
            conclusion=self._optional_exact(
                result.agent_conclusion_ref, DynamicReproductionConclusion
            ),
            policy=self._optional_exact(
                result.policy_decision_ref, SandboxPolicyDecision
            ),
            cleanup=self._optional_exact(result.cleanup_ref, CleanupResult),
        )

    def _validate_dynamic_closure(
        self,
        dynamic: _DynamicClosureRecords,
        *,
        generation: int,
    ) -> None:
        event_command_refs = self._unique_refs(
            event.command_ref
            for event in dynamic.log.events
            if event.command_ref is not None
        )
        event_tool_refs = self._unique_refs(
            event.tool_request_ref
            for event in dynamic.log.events
            if event.tool_request_ref is not None
        )
        event_environment_refs = self._unique_refs(
            event.environment_ref
            for event in dynamic.log.events
            if event.environment_ref is not None
            and event.environment_ref != dynamic.result.environment_ref
        )
        event_recipe_refs = self._unique_refs(
            event.environment_recipe_ref
            for event in dynamic.log.events
            if event.environment_recipe_ref is not None
            and event.environment_recipe_ref != dynamic.result.environment_recipe_ref
        )
        requirements = (
            self._exact(
                dynamic.plan.environment_requirements_ref, EnvironmentRequirements
            )
            if dynamic.plan is not None
            else None
        )
        evidence_roots = (
            *dynamic.result.observation_refs,
            *dynamic.result.hypothesis_evidence_refs,
            *dynamic.result.disproof_evidence_refs,
            *(dynamic.poc.evidence_refs if dynamic.poc is not None else ()),
        )
        validate_dynamic_closure(
            dynamic.result,
            dynamic.request,
            dynamic.log,
            generation=generation,
            plan=dynamic.plan,
            recipe=dynamic.recipe,
            environment=dynamic.environment,
            candidate=dynamic.candidate,
            poc=dynamic.poc,
            conclusion=dynamic.conclusion,
            policy=dynamic.policy,
            cleanup=dynamic.cleanup,
            resolved_evidence=self._resolve_evidence(evidence_roots),
            command_records=tuple(
                self._exact(ref, SandboxCommandRecord) for ref in event_command_refs
            ),
            tool_requests=tuple(
                self._exact(ref, DynamicReproductionToolRequest)
                for ref in event_tool_refs
            ),
            attempt_environments=tuple(
                self._exact(ref, SandboxEnvironment) for ref in event_environment_refs
            ),
            attempt_recipes=tuple(
                self._exact(ref, EnvironmentRecipe) for ref in event_recipe_refs
            ),
            requirements=requirements,
            attempt_resource_refs=(
                dynamic.cleanup.resource_refs if dynamic.cleanup is not None else ()
            ),
        )

    def _resolve_evidence(
        self, roots: tuple[StoredDataRef, ...]
    ) -> dict[StoredDataRef, DomainRecord]:
        resolved: dict[StoredDataRef, DomainRecord] = {}
        pending = list(roots)
        while pending:
            ref = pending.pop()
            if ref.record_id is None or ref in resolved:
                continue
            record = self._exact(ref, DomainRecord)
            resolved[ref] = record
            for value in walk(record):
                if (
                    isinstance(value, ContractModel)
                    and "evidence_refs" in type(value).model_fields
                ):
                    pending.extend(cast(_EvidenceRefsCarrier, value).evidence_refs)
        return resolved

    @staticmethod
    def _unique_refs(refs: Iterable[StoredDataRef]) -> tuple[StoredDataRef, ...]:
        return tuple(dict.fromkeys(refs))

    def _optional_exact[T](self, ref: StoredDataRef | None, model: type[T]) -> T | None:
        return self._exact(ref, model) if ref is not None else None

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
        *,
        additional: set[StoredDataRef] | None = None,
    ) -> None:
        allowed = {
            generation.evidence_ref,
            *(
                ref
                for claim in (*pro.evidence, *con.evidence)
                for ref in claim.evidence_refs
            ),
            *(additional or set()),
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
