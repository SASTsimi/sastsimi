"""Claimed-work adapters for the production T10 LLM slice.

The adapters deliberately do not poll another work item.  Pro and Con run as
independent claimed works; their completion hook may make a pending
Verification parent READY, but it must return immediately.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, Protocol, cast

from sastsimi.agents.dynamic_reproduction import DynamicAgentInvocation
from sastsimi.agents.verification import (
    VerificationAgentOutcome,
    VerificationCallRefs,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.domain import same_scope
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    ReproductionPlan,
    SandboxEnvironment,
)
from sastsimi.contracts.hypothesis import VulnerabilityHypothesis
from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    LLMRole,
)
from sastsimi.contracts.prompt_redaction import redact_untrusted_text
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    ReferencedRecord,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import CodeContextResponse, StaticFactBundle
from sastsimi.contracts.verification import (
    PlaybookApplication,
    PlaybookPolicy,
    VerificationInitialAssessment,
    VerificationPlaybook,
)
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.authorized_llm_call import AuthorizedLLMCall
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.verification_assembly import VerificationGenerationInputs
from sastsimi.runtime.claimed_context import require_claimed_context
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.verification.completion import VerificationCompletion
from sastsimi.verification.debate_service import (
    DebateIncompleteError,
    DebateResult,
    DebateService,
)
from sastsimi.verification.service import VerificationService

type EvidenceRole = Literal["PRO", "CON"]
type BudgetScopeResolver = Callable[[str], BudgetScopeRef]


class ProductionCallPort(Protocol):
    def resolve(
        self,
        *,
        work: WorkExecutionState,
        role: LLMRole,
        task_kind: str,
        source_refs: tuple[StoredDataRef, ...],
    ) -> AuthorizedLLMCall: ...

    def settle(
        self, call: AuthorizedLLMCall, invocation: PersistedLLMInvocation
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ProductionDynamicStageCallResolver:
    """Resolve and settle one exact R7 LLM call at the stage boundary."""

    calls: ProductionCallPort
    max_execute_turns: int
    records: RecordStore | None = None
    artifacts: ArtifactStore | None = None
    _pending: dict[StoredDataRef, AuthorizedLLMCall] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if isinstance(self.max_execute_turns, bool) or self.max_execute_turns < 1:
            raise ValueError("DYNAMIC_EXECUTE_TURN_LIMIT_INVALID")

    def resolve(
        self,
        *,
        work: WorkExecutionState,
        task_kind: str,
        context_refs: tuple[StoredDataRef, ...],
    ) -> DynamicAgentInvocation:
        resolved_context_refs = (
            self._candidate_context_refs(work, context_refs)
            if task_kind == "CREATE_POC_CANDIDATE"
            else context_refs
        )
        call = self.calls.resolve(
            work=work,
            role="DYNAMIC_REPRODUCTION",
            task_kind=task_kind,
            source_refs=resolved_context_refs,
        )
        if call.call_spec_ref in self._pending:
            raise ValueError("DYNAMIC_LLM_CALL_ALREADY_PENDING")
        self._pending[call.call_spec_ref] = call
        return DynamicAgentInvocation(
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
            context_refs=resolved_context_refs,
        )

    def _candidate_context_refs(
        self,
        work: WorkExecutionState,
        context_refs: tuple[StoredDataRef, ...],
    ) -> tuple[StoredDataRef, ...]:
        if self.records is None or self.artifacts is None:
            raise ValueError("DYNAMIC_CANDIDATE_CONTEXT_MISMATCH")
        if (
            not isinstance(work.meta, RecordMeta)
            or work.active_attempt_id is None
            or len(context_refs) != 3
            or tuple(ref.data_kind for ref in context_refs)
            != (
                "dynamic_reproduction_request",
                "reproduction_plan",
                "sandbox_environment",
            )
        ):
            raise ValueError("DYNAMIC_CANDIDATE_CONTEXT_MISMATCH")
        request_ref, plan_ref, environment_ref = context_refs
        try:
            request = self.records.get_exact(request_ref)
            plan = self.records.get_exact(plan_ref)
            environment = self.records.get_exact(environment_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("DYNAMIC_CANDIDATE_CONTEXT_MISMATCH") from error
        if (
            not isinstance(request, DynamicReproductionRequest)
            or reference(request) != request_ref
            or not isinstance(plan, ReproductionPlan)
            or reference(plan) != plan_ref
            or not isinstance(environment, SandboxEnvironment)
            or reference(environment) != environment_ref
            or work.input_refs != (request_ref,)
            or request.meta.analysis_id != work.meta.analysis_id
            or request.meta.workspace_id != work.meta.workspace_id
            or request.meta.commit_id != work.meta.commit_id
            or request.meta.hypothesis_id != work.meta.hypothesis_id
            or plan.meta.analysis_id != work.meta.analysis_id
            or plan.meta.workspace_id != work.meta.workspace_id
            or plan.meta.commit_id != work.meta.commit_id
            or plan.meta.hypothesis_id != work.meta.hypothesis_id
            or environment.meta.analysis_id != work.meta.analysis_id
            or environment.meta.workspace_id != work.meta.workspace_id
            or environment.meta.commit_id != work.meta.commit_id
            or environment.meta.hypothesis_id != work.meta.hypothesis_id
            or plan.meta.attempt_id != work.active_attempt_id
            or environment.meta.attempt_id != work.active_attempt_id
            or plan.request_ref != request_ref
            or plan.purpose != request.purpose
            or plan.hypothesis_ref != request.hypothesis_ref
            or plan.sandbox_profile_ref != request.sandbox_profile_ref
            or environment.request_ref != request_ref
            or environment.reproduction_plan_ref != plan_ref
            or environment.requirements_ref != plan.environment_requirements_ref
            or environment.status != "READY"
        ):
            raise ValueError("DYNAMIC_CANDIDATE_CONTEXT_MISMATCH")
        response_refs = request.code_refs
        if not response_refs or len(response_refs) != len(set(response_refs)):
            raise ValueError("DYNAMIC_CANDIDATE_CONTEXT_MISMATCH")
        fragment_refs: list[StoredDataRef] = []
        for response_ref in response_refs:
            try:
                response = self.records.get_exact(response_ref)
            except (LookupError, ValueError) as error:
                raise ValueError("DYNAMIC_CANDIDATE_CONTEXT_MISMATCH") from error
            if (
                response_ref.data_kind != CodeContextResponse.KIND
                or not isinstance(response, CodeContextResponse)
                or reference(response) != response_ref
                or response.meta.analysis_id != work.meta.analysis_id
                or response.meta.workspace_id != work.meta.workspace_id
                or response.meta.commit_id != work.meta.commit_id
                or response.meta.hypothesis_id != work.meta.hypothesis_id
                or not response.code_fragment_refs
            ):
                raise ValueError("DYNAMIC_CANDIDATE_CONTEXT_MISMATCH")
            returned_bytes = 0
            for fragment_ref in response.code_fragment_refs:
                if (
                    fragment_ref.record_id is not None
                    or fragment_ref.data_kind != "artifact"
                    or fragment_ref.workspace_id != work.meta.workspace_id
                    or fragment_ref.commit_id != work.meta.commit_id
                    or str(fragment_ref.stored_data_id) != fragment_ref.content_hash
                ):
                    raise ValueError("DYNAMIC_CANDIDATE_CONTEXT_MISMATCH")
                try:
                    with self.artifacts.open_verified(fragment_ref) as stream:
                        raw = stream.read()
                    redact_untrusted_text(raw)
                except (OSError, TypeError, ValueError) as error:
                    raise ValueError("DYNAMIC_CANDIDATE_CODE_UNAVAILABLE") from error
                returned_bytes += len(raw)
                fragment_refs.append(fragment_ref)
            if returned_bytes != response.returned_bytes:
                raise ValueError("DYNAMIC_CANDIDATE_CONTEXT_MISMATCH")
        if len(fragment_refs) != len(set(fragment_refs)):
            raise ValueError("DYNAMIC_CANDIDATE_CONTEXT_MISMATCH")
        return (*context_refs, *response_refs, *fragment_refs)

    def settle(
        self,
        authorization: DynamicAgentInvocation,
        invocation: PersistedLLMInvocation,
    ) -> None:
        call = self._pending.pop(authorization.call_spec_ref, None)
        if (
            call is None
            or call.decision_ref != authorization.decision_ref
            or call.reservation_ref != authorization.reservation_ref
            or invocation.request.call_spec_ref != authorization.call_spec_ref
            or invocation.request.action_decision_ref != authorization.decision_ref
            or invocation.request.agent_role != "DYNAMIC_REPRODUCTION"
        ):
            raise ValueError("DYNAMIC_LLM_SETTLEMENT_MISMATCH")
        self.calls.settle(call, invocation)


class HypothesisWorkflowPort(Protocol):
    async def run(self, **kwargs: object) -> object: ...


class HypothesesCommittedPort(Protocol):
    """Register downstream Verification only after proposal commit succeeds."""

    def __call__(self, proposal_refs: tuple[StoredDataRef, ...]) -> None: ...


@dataclass(frozen=True, slots=True)
class HypothesisProposalWorkHandler:
    """Run the initial, analysis-scoped Hypothesis Agent call."""

    records: RecordStore
    workflow: HypothesisWorkflowPort
    calls: ProductionCallPort
    orchestration_identity_ref: BudgetScopeRef
    hypotheses_committed: HypothesesCommittedPort

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        require_claimed_context(context, WorkType.HYPOTHESIS_PROPOSAL)
        work = context.work
        if (
            work.subject_type != SubjectType.ANALYSIS
            or str(work.subject_id) != str(work.meta.analysis_id)
            or not isinstance(work.meta, RecordMeta)
            or work.meta.hypothesis_id is not None
        ):
            raise ValueError("HYPOTHESIS_INITIAL_WORK_SCOPE_MISMATCH")
        static_refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == StaticFactBundle.KIND
        )
        if len(work.input_refs) != 1 or len(static_refs) != 1:
            raise ValueError("HYPOTHESIS_STATIC_CLOSURE_MISMATCH")
        bundle_ref = static_refs[0]
        try:
            bundle = self.records.get_exact(bundle_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("HYPOTHESIS_STATIC_CLOSURE_MISMATCH") from error
        if (
            not isinstance(bundle, StaticFactBundle)
            or reference(bundle) != bundle_ref
            or bundle.meta.hypothesis_id is not None
        ):
            raise ValueError("HYPOTHESIS_STATIC_CLOSURE_MISMATCH")
        same_scope(work.meta, bundle.meta, hypothesis=False)
        call = self.calls.resolve(
            work=work,
            role="HYPOTHESIS",
            task_kind="GENERATE_INITIAL",
            source_refs=(bundle_ref,),
        )
        result = await self.workflow.run(
            work=work,
            orchestration_identity_ref=self.orchestration_identity_ref,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
            static_bundle=bundle,
            static_bundle_ref=bundle_ref,
        )
        outcome = getattr(result, "outcome", None)
        invocation = getattr(outcome, "invocation", None)
        if not isinstance(invocation, PersistedLLMInvocation):
            # Runtime tests may use a structural invocation double; production
            # still validates it inside HypothesisWorkflow before completion.
            if invocation is None:
                raise ValueError("HYPOTHESIS_INVOCATION_MISSING")
        self.calls.settle(call, invocation)
        completed = getattr(result, "completed_work", None)
        if (
            not isinstance(completed, WorkExecutionState)
            or completed.status != WorkStatus.SUCCEEDED
            or completed.active_attempt_id is not None
        ):
            raise ValueError("HYPOTHESIS_PROVIDER_CALL_FAILED")
        proposal_refs = tuple(
            ref
            for ref in completed.output_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == "hypothesis_proposal"
        )
        if len(proposal_refs) != len(completed.output_refs):
            raise ValueError("HYPOTHESIS_OUTPUT_CLOSURE_MISMATCH")
        self.hypotheses_committed(proposal_refs)
        return WorkHandlerResult(completed.output_refs)


class EvidenceCommittedPort(Protocol):
    def __call__(
        self, parent_work_ref: StoredDataRef, evidence_ref: StoredDataRef
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class EvidenceBranchWorkHandler:
    """Execute one independently claimed Pro or Con branch and return."""

    role: EvidenceRole
    records: RecordStore
    debate: DebateService
    calls: ProductionCallPort
    evidence_committed: EvidenceCommittedPort

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        expected = (
            WorkType.PRO_EVIDENCE if self.role == "PRO" else WorkType.CON_EVIDENCE
        )
        task_kind = (
            "COLLECT_SUPPORT" if self.role == "PRO" else "COLLECT_COUNTEREVIDENCE"
        )
        require_claimed_context(context, expected)
        work = context.work
        parent_ref = work.parent_work_ref
        if not isinstance(parent_ref, StoredDataRef):
            raise ValueError("EVIDENCE_PARENT_WORK_SCOPE_MISMATCH")
        try:
            parent = self.records.get_exact(parent_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("EVIDENCE_PARENT_WORK_SCOPE_MISMATCH") from error
        source_refs = tuple(
            ref for ref in work.input_refs if isinstance(ref, StoredDataRef)
        )
        normalized = tuple(sorted(source_refs, key=canonical_bytes))
        if (
            not isinstance(parent, WorkExecutionState)
            or reference(parent) != parent_ref
            or len(source_refs) != len(work.input_refs)
            or not source_refs
            or source_refs != normalized
        ):
            raise ValueError("EVIDENCE_PARENT_WORK_SCOPE_MISMATCH")
        call = self.calls.resolve(
            work=work,
            role=self.role,
            task_kind=task_kind,
            source_refs=normalized,
        )
        result = await self.debate.run_branch(
            parent_work=parent,
            public_input_refs=normalized,
            call=call,
            role=self.role,
        )
        self.calls.settle(call, result.invocation)
        self.evidence_committed(parent_ref, result.output_ref)
        return WorkHandlerResult((result.output_ref,))


@dataclass(frozen=True, slots=True)
class VerificationClaim:
    generation: VerificationGenerationInputs
    initial_source_refs: tuple[StoredDataRef, ...]


class VerificationClaimResolver(Protocol):
    def __call__(self, context: WorkContext) -> VerificationClaim: ...


@dataclass(frozen=True, slots=True)
class _VerificationParentInputs:
    public_refs: tuple[StoredDataRef, ...]
    hypothesis_ref: StoredDataRef
    hypothesis: VulnerabilityHypothesis
    policy_ref: StoredDataRef
    playbook_ref: StoredDataRef
    application_ref: StoredDataRef
    application: PlaybookApplication
    evidence_ref: StoredDataRef
    bundle: StaticFactBundle


class NonDynamicCompletionPort(Protocol):
    async def complete_without_dynamic(
        self, **kwargs: object
    ) -> VerificationCompletion: ...


class DynamicVerificationPort(Protocol):
    """Exact T10-to-T11 handoff boundary.

    A production implementation must publish the same-attempt
    ``DynamicReproductionRequest``, register a separate ``DYNAMIC_REPRO`` child,
    and move the parent out of ``RUNNING`` before returning.  It must not execute,
    wait for, or poll that child; a child-terminal CAS/reconciliation hook owns
    resuming the parent for final synthesis.
    """

    async def complete_dynamic(
        self,
        *,
        context: WorkContext,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
    ) -> WorkHandlerResult: ...

    async def resume_dynamic(
        self,
        *,
        context: WorkContext,
        public_input_refs: tuple[StoredDataRef, ...],
    ) -> WorkHandlerResult | None: ...


@dataclass(frozen=True, slots=True)
class VerificationWorkHandler:
    """Own one claimed Verification debate and synthesize only after both branches."""

    records: RecordStore
    runner: WorkflowRunner
    verification: VerificationService
    debate: DebateService
    non_dynamic: NonDynamicCompletionPort
    dynamic: DynamicVerificationPort
    calls: ProductionCallPort
    verification_identity_ref: BudgetScopeRef
    budget_scope: BudgetScopeResolver

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        require_claimed_context(context, WorkType.VERIFICATION)
        work = context.work
        parent_inputs = self._parent_inputs(work)
        resumed = await self.dynamic.resume_dynamic(
            context=context,
            public_input_refs=parent_inputs.public_refs,
        )
        if resumed is not None:
            return resumed
        scope = self.budget_scope(str(work.meta.analysis_id))
        if not isinstance(scope, (RunStoredDataRef, StoredDataRef)):
            raise ValueError("VERIFICATION_BUDGET_SCOPE_REQUIRED")
        pro_work, con_work = self._start_evidence_children(
            work, parent_inputs.public_refs, scope
        )
        pro_call = self.calls.resolve(
            work=pro_work,
            role="PRO",
            task_kind="COLLECT_SUPPORT",
            source_refs=parent_inputs.public_refs,
        )
        con_call = self.calls.resolve(
            work=con_work,
            role="CON",
            task_kind="COLLECT_COUNTEREVIDENCE",
            source_refs=parent_inputs.public_refs,
        )
        try:
            debate = await self.debate.run(
                verification_work=work,
                public_input_refs=parent_inputs.public_refs,
                pro_call=pro_call,
                con_call=con_call,
            )
        except DebateIncompleteError as error:
            self._settle_evidence_calls(
                pro_call,
                con_call,
                error.pro_invocation,
                error.con_invocation,
            )
            raise
        self._settle_evidence_calls(
            pro_call,
            con_call,
            debate.pro_invocation,
            debate.con_invocation,
        )
        generation, initial_source_refs = self._generation_inputs(
            work, parent_inputs, debate
        )
        initial_call = self.calls.resolve(
            work=work,
            role="VERIFICATION",
            task_kind="ASSESS_INITIAL",
            source_refs=initial_source_refs,
        )
        initial = await self.verification.assess_initial_with_invocation(
            generation=generation,
            pro_ref=generation.pro_ref,
            con_ref=generation.con_ref,
            call=_verification_call_refs(initial_call),
        )
        self.calls.settle(initial_call, initial.invocation)
        assessment_ref = self._publish_assessment(work, initial, initial_call)
        if initial.record.next_step != "FINALIZE_WITHOUT_DYNAMIC":
            return await self.dynamic.complete_dynamic(
                context=context,
                generation=generation,
                assessment_ref=assessment_ref,
            )

        final_call = self.calls.resolve(
            work=work,
            role="VERIFICATION",
            task_kind="FINAL_VERDICT",
            source_refs=(*initial_source_refs, assessment_ref),
        )
        completion = await self.non_dynamic.complete_without_dynamic(
            generation=generation,
            assessment_ref=assessment_ref,
            pro_ref=generation.pro_ref,
            con_ref=generation.con_ref,
            call=_verification_call_refs(final_call),
        )
        self.calls.settle(final_call, completion.outcome.invocation)
        return WorkHandlerResult(completion.completed_work.output_refs)

    def _parent_inputs(self, work: WorkExecutionState) -> _VerificationParentInputs:
        if (
            not isinstance(work.meta, RecordMeta)
            or any(not isinstance(ref, StoredDataRef) for ref in work.input_refs)
            or len(work.input_refs) != len(set(work.input_refs))
        ):
            raise ValueError("VERIFICATION_PARENT_INPUT_MISMATCH")
        public_refs = cast(tuple[StoredDataRef, ...], tuple(work.input_refs))
        hypothesis_ref, hypothesis = self._exact_parent_input(
            work, VulnerabilityHypothesis.KIND, VulnerabilityHypothesis
        )
        policy_ref, _policy = self._exact_parent_input(
            work, PlaybookPolicy.KIND, PlaybookPolicy
        )
        playbook_ref, _playbook = self._exact_parent_input(
            work, VerificationPlaybook.KIND, VerificationPlaybook
        )
        application_ref, application = self._exact_parent_input(
            work, PlaybookApplication.KIND, PlaybookApplication
        )
        evidence_ref, bundle = self._exact_parent_input(
            work, StaticFactBundle.KIND, StaticFactBundle
        )
        if (
            work.subject_type != SubjectType.HYPOTHESIS
            or str(work.subject_id) != str(work.meta.hypothesis_id)
            or hypothesis.meta.hypothesis_id != work.meta.hypothesis_id
            or application.hypothesis_ref != hypothesis_ref
            or application.proposal_ref != hypothesis.proposal_ref
            or application.policy_ref != policy_ref
            or application.playbook_ref != playbook_ref
            or application.verification_work_id != work.work_id
            or application.verification_generation != work.work_generation
            or not hypothesis.target_locations
            or public_refs
            != (
                hypothesis_ref,
                hypothesis.proposal_ref,
                policy_ref,
                playbook_ref,
                evidence_ref,
                application_ref,
            )
        ):
            raise ValueError("VERIFICATION_PARENT_INPUT_MISMATCH")
        return _VerificationParentInputs(
            public_refs,
            hypothesis_ref,
            hypothesis,
            policy_ref,
            playbook_ref,
            application_ref,
            application,
            evidence_ref,
            bundle,
        )

    def _exact_parent_input[T: ReferencedRecord](
        self,
        work: WorkExecutionState,
        kind: str,
        model: type[T],
    ) -> tuple[StoredDataRef, T]:
        refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == kind
        )
        if len(refs) != 1:
            raise ValueError("VERIFICATION_PARENT_INPUT_MISMATCH")
        ref = refs[0]
        try:
            value = self.records.get_exact(ref)
        except (LookupError, ValueError) as error:
            raise ValueError("VERIFICATION_PARENT_INPUT_MISMATCH") from error
        meta = getattr(value, "meta", None)
        if (
            not isinstance(value, model)
            or not isinstance(meta, RecordMeta)
            or reference(value) != ref
        ):
            raise ValueError("VERIFICATION_PARENT_INPUT_MISMATCH")
        try:
            same_scope(
                cast(RecordMeta, work.meta),
                meta,
                hypothesis=getattr(model, "HYPOTHESIS", None) is True,
            )
        except ValueError as error:
            raise ValueError("VERIFICATION_PARENT_INPUT_MISMATCH") from error
        return ref, value

    def _start_evidence_children(
        self,
        work: WorkExecutionState,
        public_refs: tuple[StoredDataRef, ...],
        scope: BudgetScopeRef,
    ) -> tuple[WorkExecutionState, WorkExecutionState]:
        parent_ref = reference(work)
        if not isinstance(parent_ref, StoredDataRef):
            raise ValueError("EVIDENCE_PARENT_WORK_SCOPE_MISMATCH")
        ready = tuple(
            self.runner.enqueue(
                scope,
                work.meta,
                work_type,
                work.subject_type,
                str(work.subject_id),
                self.verification_identity_ref,
                role="VERIFICATION",
                generation=work.work_generation,
                inputs=public_refs,
                parent=parent_ref,
            )
            for work_type in (WorkType.PRO_EVIDENCE, WorkType.CON_EVIDENCE)
        )
        running = tuple(
            self.runner.activate(
                child,
                scope,
                self.verification_identity_ref,
                role="VERIFICATION",
            )
            for child in ready
        )
        pro_work, con_work = running
        if (
            pro_work.work_type != WorkType.PRO_EVIDENCE
            or con_work.work_type != WorkType.CON_EVIDENCE
            or pro_work.status != WorkStatus.RUNNING
            or con_work.status != WorkStatus.RUNNING
            or pro_work.parent_work_ref != parent_ref
            or con_work.parent_work_ref != parent_ref
            or pro_work.input_refs != public_refs
            or con_work.input_refs != public_refs
            or pro_work.work_generation != work.work_generation
            or con_work.work_generation != work.work_generation
        ):
            raise ValueError("EVIDENCE_WORK_SCOPE_MISMATCH")
        return pro_work, con_work

    def _settle_evidence_calls(
        self,
        pro_call: AuthorizedLLMCall,
        con_call: AuthorizedLLMCall,
        pro_invocation: PersistedLLMInvocation | None,
        con_invocation: PersistedLLMInvocation | None,
    ) -> None:
        for call, invocation in (
            (pro_call, pro_invocation),
            (con_call, con_invocation),
        ):
            if invocation is not None:
                self.calls.settle(call, invocation)

    @staticmethod
    def _generation_inputs(
        work: WorkExecutionState,
        parent: _VerificationParentInputs,
        debate: DebateResult,
    ) -> tuple[VerificationGenerationInputs, tuple[StoredDataRef, ...]]:
        generation = VerificationGenerationInputs(
            work_id=work.work_id,
            generation=work.work_generation,
            hypothesis_ref=parent.hypothesis_ref,
            policy_ref=parent.policy_ref,
            playbook_ref=parent.playbook_ref,
            application_ref=parent.application_ref,
            pro_ref=debate.pro_ref,
            con_ref=debate.con_ref,
            debate_input_hash=debate.pro.debate_input_hash,
            evidence_ref=parent.evidence_ref,
            location=parent.hypothesis.target_locations[0],
            falsification_question_ids=tuple(
                str(item.question_id)
                for item in parent.hypothesis.falsification_questions
            )
            + tuple(str(item.question_id) for item in parent.application.questions),
            validation_ids=tuple(
                str(item.validation_id) for item in parent.hypothesis.validation_checks
            ),
        )
        initial_source_refs = (
            generation.hypothesis_ref,
            generation.policy_ref,
            generation.playbook_ref,
            generation.application_ref,
            generation.pro_ref,
            generation.con_ref,
            generation.evidence_ref,
        )
        return generation, initial_source_refs

    def _publish_assessment(
        self,
        work: WorkExecutionState,
        outcome: VerificationAgentOutcome[VerificationInitialAssessment],
        call: AuthorizedLLMCall,
    ) -> StoredDataRef:
        refs = _invocation_refs(self.records, outcome.invocation)
        published = self.runner.publish_intermediate(
            work,
            self.verification_identity_ref,
            "VERIFICATION",
            (outcome.record,),
            action_input_refs=_unique_refs(
                (
                    *work.input_refs,
                    call.decision_ref,
                    call.reservation_ref,
                    call.call_spec_ref,
                    *refs,
                )
            ),
        )
        expected = reference(outcome.record)
        if published != (expected,) or not isinstance(expected, StoredDataRef):
            raise ValueError("VERIFICATION_ASSESSMENT_COMMIT_MISMATCH")
        return expected


def _verification_call_refs(call: AuthorizedLLMCall) -> VerificationCallRefs:
    return VerificationCallRefs(
        decision_ref=call.decision_ref,
        reservation_ref=call.reservation_ref,
        call_spec_ref=call.call_spec_ref,
    )


def _invocation_refs(
    records: RecordStore, invocation: PersistedLLMInvocation
) -> tuple[StoredDataRef, ...]:
    request_ref = reference(invocation.request)
    result_ref = reference(invocation.result)
    if not isinstance(request_ref, StoredDataRef) or not isinstance(
        result_ref, StoredDataRef
    ):
        raise ValueError("VERIFICATION_INVOCATION_PROVENANCE_MISMATCH")
    request = records.get_exact(request_ref)
    result = records.get_exact(result_ref)
    log = records.get_exact(invocation.log_ref)
    if (
        not isinstance(request, LLMInvocationRequest)
        or not isinstance(result, LLMInvocationResult)
        or not isinstance(log, LLMInvocationLog)
        or request != invocation.request
        or result != invocation.result
        or reference(log) != invocation.log_ref
    ):
        raise ValueError("VERIFICATION_INVOCATION_PROVENANCE_MISMATCH")
    return request_ref, result_ref, invocation.log_ref


def _unique_refs(refs: tuple[RecordRef, ...]) -> tuple[RecordRef, ...]:
    return tuple(dict.fromkeys(refs))


__all__ = [
    "DynamicVerificationPort",
    "EvidenceBranchWorkHandler",
    "HypothesesCommittedPort",
    "HypothesisProposalWorkHandler",
    "ProductionDynamicStageCallResolver",
    "ProductionCallPort",
    "VerificationClaim",
    "VerificationClaimResolver",
    "VerificationWorkHandler",
]
