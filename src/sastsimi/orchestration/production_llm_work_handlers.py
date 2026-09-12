"""Claimed-work adapters for the production T10 LLM slice.

The adapters deliberately do not poll another work item.  Pro and Con run as
independent claimed works; their completion hook may make a pending
Verification parent READY, but it must return immediately.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, cast

from pydantic import BaseModel

from sastsimi.agents.verification import (
    VerificationAgentOutcome,
    VerificationCallRefs,
)
from sastsimi.chaining.work_handlers import require_claimed_context
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.domain import same_scope
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
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.verification import VerificationInitialAssessment
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
    DebateService,
)
from sastsimi.verification.service import VerificationService

type LLMRole = Literal["HYPOTHESIS", "PRO", "CON", "VERIFICATION"]
type EvidenceRole = Literal["PRO", "CON"]


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
        route, approval = self.route_lookup(
            str(work.meta.analysis_id), role, task_kind
        )
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
            if isinstance(ref, StoredDataRef)
            and ref.data_kind == StaticFactBundle.KIND
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
            if isinstance(ref, StoredDataRef)
            and ref.data_kind == "hypothesis_proposal"
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


class NonDynamicCompletionPort(Protocol):
    async def complete_without_dynamic(
        self, **kwargs: object
    ) -> VerificationCompletion: ...


class DynamicVerificationPort(Protocol):
    """Direct T11 continuation; implementations must not poll child work."""

    async def complete_dynamic(
        self,
        *,
        context: WorkContext,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
    ) -> WorkHandlerResult: ...


@dataclass(frozen=True, slots=True)
class VerificationWorkHandler:
    """Synthesize one claimed Verification generation using T10 services."""

    records: RecordStore
    runner: WorkflowRunner
    verification: VerificationService
    non_dynamic: NonDynamicCompletionPort
    dynamic: DynamicVerificationPort
    resolve_claim: VerificationClaimResolver
    calls: ProductionCallPort
    verification_identity_ref: BudgetScopeRef

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        require_claimed_context(context, WorkType.VERIFICATION)
        claim = self.resolve_claim(context)
        generation = claim.generation
        work = context.work
        if (
            generation.work_id != work.work_id
            or generation.generation != work.work_generation
            or generation.pro_ref not in claim.initial_source_refs
            or generation.con_ref not in claim.initial_source_refs
            or len(claim.initial_source_refs) != len(set(claim.initial_source_refs))
        ):
            raise ValueError("VERIFICATION_CLAIM_SCOPE_MISMATCH")
        initial_call = self.calls.resolve(
            work=work,
            role="VERIFICATION",
            task_kind="ASSESS_INITIAL",
            source_refs=claim.initial_source_refs,
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
            source_refs=(*claim.initial_source_refs, assessment_ref),
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
    "PreparedCallAuthorizer",
    "ProductionCallPort",
    "ProductionRouteLookup",
    "VerificationClaim",
    "VerificationClaimResolver",
    "VerificationWorkHandler",
]
