"""Claimed-work adapters for the production T10 LLM slice.

The adapters deliberately do not poll another work item.  Pro and Con run as
independent claimed works; their completion hook may make a pending
Verification parent READY, but it must return immediately.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, Protocol, cast

from pydantic import BaseModel

from sastsimi.agents.dynamic_reproduction import DynamicAgentInvocation
from sastsimi.agents.verification import (
    VerificationAgentOutcome,
    VerificationCallRefs,
)
from sastsimi.chaining.work_handlers import require_claimed_context
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.domain import same_scope
from sastsimi.contracts.hypothesis import VulnerabilityHypothesis
from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    PromptInputSlot,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    ReferencedRecord,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import StaticFactBundle
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
from sastsimi.ports.dto import Record, WorkContext, WorkHandlerResult
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.verification_assembly import VerificationGenerationInputs
from sastsimi.prompts.builder import PromptSource
from sastsimi.prompts.production import (
    ApprovedProductionRoute,
    PreparedProductionCall,
    ProductionLLMConfigurationService,
    ProductionRoute,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.verification.completion import VerificationCompletion
from sastsimi.verification.debate_service import (
    AuthorizedLLMCall,
    DebateIncompleteError,
    DebateResult,
    DebateService,
)
from sastsimi.verification.service import VerificationService

type LLMRole = Literal[
    "HYPOTHESIS", "PRO", "CON", "VERIFICATION", "DYNAMIC_REPRODUCTION"
]
type EvidenceRole = Literal["PRO", "CON"]
type BudgetScopeResolver = Callable[[str], BudgetScopeRef]


class ProductionRouteLookup(Protocol):
    """Resolve an analysis-owned route and its exact approval graph."""

    def __call__(
        self, analysis_id: str, role: LLMRole, task_kind: str
    ) -> tuple[ProductionRoute, ApprovedProductionRoute]: ...


class PreparedCallAuthorizer(Protocol):
    """Attach budget and action authority after prompt preparation."""

    def authorize(
        self, *, work: WorkExecutionState, prepared: PreparedProductionCall
    ) -> AuthorizedLLMCall: ...

    def settle(
        self, call: AuthorizedLLMCall, invocation: PersistedLLMInvocation
    ) -> None: ...


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
class ConfiguredProductionCallResolver:
    """Build a call from the exact route selected for this analysis.

    The route lookup is keyed by ``analysis_id``.  Consequently a handler
    cannot silently reuse another analysis's prompt approval, Provider, or
    model.  The configuration service additionally verifies their exact refs.
    """

    configuration: ProductionLLMConfigurationService
    records: RecordStore
    route_lookup: ProductionRouteLookup
    authorizer: PreparedCallAuthorizer

    def resolve(
        self,
        *,
        work: WorkExecutionState,
        role: LLMRole,
        task_kind: str,
        source_refs: tuple[StoredDataRef, ...],
    ) -> AuthorizedLLMCall:
        if (
            not isinstance(work.meta, RecordMeta)
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or not source_refs
            or len(source_refs) != len(set(source_refs))
        ):
            raise ValueError("PRODUCTION_LLM_CALL_SCOPE_MISMATCH")
        route, approval = self.route_lookup(str(work.meta.analysis_id), role, task_kind)
        if route.role != role or route.task_kind != task_kind:
            raise ValueError("PRODUCTION_LLM_ROUTE_MISMATCH")
        resolved = self.configuration.resolve_route(route=route, approval=approval)
        sources = self._sources(work.meta, resolved.entry.input_slots, source_refs)
        prepared = self.configuration.prepare_call(
            route=route,
            approval=approval,
            work=work,
            sources=sources,
        )
        if (
            prepared.call_spec.agent_role != role
            or prepared.call_spec.task_kind != task_kind
            or prepared.call_spec.model != route.model
            or prepared.call_spec.provider_profile_ref != resolved.provider_ref
            or prepared.call_spec.context_refs != source_refs
        ):
            raise ValueError("PRODUCTION_LLM_CALL_SCOPE_MISMATCH")
        call = self.authorizer.authorize(work=work, prepared=prepared)
        if call.work != work or call.call_spec_ref != prepared.call_spec_ref:
            raise ValueError("PRODUCTION_LLM_AUTHORIZATION_MISMATCH")
        return call

    def settle(
        self, call: AuthorizedLLMCall, invocation: PersistedLLMInvocation
    ) -> None:
        self.authorizer.settle(call, invocation)

    def _sources(
        self,
        work_meta: RecordMeta,
        slots: tuple[PromptInputSlot, ...],
        refs: tuple[StoredDataRef, ...],
    ) -> tuple[PromptSource, ...]:
        # PromptInputSlot is deliberately consumed structurally so this adapter
        # does not introduce another prompt-contract model.
        slot_by_kind: dict[str, PromptInputSlot] = {}
        for slot in slots:
            kind = str(slot.data_kind)
            if not kind or kind in slot_by_kind:
                raise ValueError("PRODUCTION_PROMPT_SOURCE_AMBIGUOUS")
            slot_by_kind[kind] = slot
        sources: list[PromptSource] = []
        counts: dict[str, int] = {}
        for ref in refs:
            candidate_slot = slot_by_kind.get(ref.data_kind)
            try:
                value = self.records.get_exact(ref)
            except (LookupError, ValueError) as error:
                raise ValueError("PRODUCTION_PROMPT_SOURCE_NOT_EXACT") from error
            meta = getattr(value, "meta", None)
            if (
                candidate_slot is None
                or not isinstance(value, BaseModel)
                or not isinstance(meta, RecordMeta)
                or reference(cast(Record, value)) != ref
            ):
                raise ValueError("PRODUCTION_PROMPT_SOURCE_NOT_EXACT")
            if (
                meta.analysis_id != work_meta.analysis_id
                or meta.workspace_id != work_meta.workspace_id
                or meta.commit_id != work_meta.commit_id
                or (
                    meta.hypothesis_id is not None
                    and meta.hypothesis_id != work_meta.hypothesis_id
                )
            ):
                raise ValueError("PRODUCTION_PROMPT_SOURCE_SCOPE_MISMATCH")
            name = str(candidate_slot.slot)
            sources.append(PromptSource(name, ref, value))
            counts[name] = counts.get(name, 0) + 1
        for slot in slots:
            name = str(slot.slot)
            cardinality = str(slot.cardinality)
            count = counts.get(name, 0)
            if (
                cardinality == "REQUIRED_ONE"
                and count != 1
                or cardinality == "OPTIONAL_ONE"
                and count > 1
                or cardinality == "REQUIRED_MANY"
                and count < 1
            ):
                raise ValueError("PROMPT_CARDINALITY_MISMATCH")
        return tuple(sources)


@dataclass(frozen=True, slots=True)
class ProductionDynamicStageCallResolver:
    """Resolve and settle one exact R7 LLM call at the stage boundary."""

    calls: ProductionCallPort
    max_execute_turns: int
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
        call = self.calls.resolve(
            work=work,
            role="DYNAMIC_REPRODUCTION",
            task_kind=task_kind,
            source_refs=context_refs,
        )
        if call.call_spec_ref in self._pending:
            raise ValueError("DYNAMIC_LLM_CALL_ALREADY_PENDING")
        self._pending[call.call_spec_ref] = call
        return DynamicAgentInvocation(
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )

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
    "ConfiguredProductionCallResolver",
    "DynamicVerificationPort",
    "EvidenceBranchWorkHandler",
    "HypothesesCommittedPort",
    "HypothesisProposalWorkHandler",
    "ProductionDynamicStageCallResolver",
    "PreparedCallAuthorizer",
    "ProductionCallPort",
    "ProductionRouteLookup",
    "VerificationClaim",
    "VerificationClaimResolver",
    "VerificationWorkHandler",
]
