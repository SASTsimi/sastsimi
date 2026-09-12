"""Primitive admission and exact-snapshot chaining workflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, cast

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import (
    ChainingResult,
    NoMatchReason,
    Primitive,
    PrimitiveAdmissionDecision,
    PrimitiveIndexState,
    PrimitiveMatchCandidate,
    validate_chaining_closure,
)
from sastsimi.contracts.hypothesis import (
    FalsificationQuestion,
    HypothesisProposal,
    ValidationCheck,
)
from sastsimi.contracts.ids import AttemptId, ProposalId, RecordId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeSymbol, Restriction
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState, WorkStatus
from sastsimi.ports.chaining import (
    ChainingAgentInput,
    ChainingAgentPort,
    ChainingChildHandoffPort,
    ChainingComparison,
    ChainingDecision,
    ChainingEvidence,
    ChainingLineagePort,
    ChainingPoolHistoryPort,
    ChainingPrimitive,
    ChainingPrimitiveInput,
    ChainingPrimitiveResult,
    ChainingResultPublisherPort,
    PinnedChainingUniverse,
)
from sastsimi.ports.dto import WorkContext
from sastsimi.ports.fake_workflow import NoMatchBuilder, ProviderInvoker, ProviderProber
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.llm_invocation import InvocationMetadataFactory
from sastsimi.ports.record_store import RecordStore
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_llm_invocation import (
    invoke_fake_provider,
    persist_fake_invocation,
)
from sastsimi.runtime.fake_support import (
    ANALYSIS_ID,
    COMMIT_ID,
    WORKSPACE_ID,
    FakeClock,
    FakeEvidence,
    FakeRecordFactory,
)
from sastsimi.runtime.llm_invocation_provenance import llm_invocation_save_refs
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .lineage import (
    LineageNode,
    LineageResolver,
    SuccessfulMatchPair,
    expected_lineage_exclusions,
    retain_deepest_successful_matches,
)
from .matching import (
    DirectionalComparison,
    PrimitiveEntry,
    directional_comparisons,
    owns_pair,
)


@dataclass(frozen=True)
class ChainingDependencies:
    runtime: RuntimeServices
    runner: WorkflowRunner
    clock: FakeClock
    evidence: FakeEvidence
    records: FakeRecordFactory
    provider_invoke: ProviderInvoker
    provider_probe: ProviderProber
    no_match_builder: NoMatchBuilder


@dataclass(frozen=True)
class ChainingOutcome:
    primitive_ref: StoredDataRef | None
    stopped: bool


class ChainingService:
    """Own admission, Primitive publication and pinned-index Chaining."""

    def __init__(self, dependencies: ChainingDependencies) -> None:
        self.runtime = dependencies.runtime
        self.runner = dependencies.runner
        self.clock = dependencies.clock
        self.evidence = dependencies.evidence
        self.provider_invoke = dependencies.provider_invoke
        self.provider_probe = dependencies.provider_probe
        self.no_match_builder = dependencies.no_match_builder
        self._record_meta = dependencies.records.record_meta
        self._artifact = dependencies.records.artifact
        self._stored_artifact = dependencies.records.stored_artifact

    def run(
        self,
        *,
        verification: VerificationResult,
        scope: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        generation: int,
        verification_ref: StoredDataRef,
        technical_ref: StoredDataRef,
        collection_ref: StoredDataRef,
        review_ref: StoredDataRef,
        label_ref: StoredDataRef,
        observation: StoredDataRef,
        admission_decision: Literal["ALLOW", "DENY"],
        publish_denied_primitive: bool,
        stop_after_chaining: bool,
    ) -> ChainingOutcome:
        hypothesis_id = str(verification.meta.hypothesis_id)
        primitive_work = self.runner.start(
            scope,
            verification.meta,
            "PRIMITIVE_UPDATE",
            "HYPOTHESIS",
            hypothesis_id,
            orchestrator_ref,
            inputs=(verification_ref, technical_ref, collection_ref, review_ref),
            generation=generation,
        )
        primitive_identity = self.evidence.identity(
            RequesterRole.PRIMITIVE_ADMISSION_RUNTIME
        )
        admission = PrimitiveAdmissionDecision.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        primitive_work.meta,
                        "primitive_admission_decision",
                        attempt_id=primitive_work.active_attempt_id,
                    ),
                    verification_result_ref=verification_ref,
                    technical_review_ref=technical_ref,
                    policy_collection_result_ref=collection_ref,
                    rule_scope_review_ref=review_ref,
                    testing_restriction_compliance=(
                        "PASS" if admission_decision == "ALLOW" else "FAIL"
                    ),
                    decision=admission_decision,
                    reason_code=(
                        "TESTING_RESTRICTION_PASSED"
                        if admission_decision == "ALLOW"
                        else "TESTING_RESTRICTION_VIOLATION"
                    ),
                    decided_at=self.clock.now(),
                )
            )
        )
        admission_ref = reference(admission)
        assert isinstance(admission_ref, StoredDataRef)
        primitive = Primitive.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        primitive_work.meta,
                        "primitive",
                        attempt_id=primitive_work.active_attempt_id,
                    ),
                    primitive_id="fake-primitive",
                    workspace_id=WORKSPACE_ID,
                    commit_id=COMMIT_ID,
                    inputs=verification.required_primitive_candidates,
                    result=verification.provided_primitive_candidates[0],
                    restrictions=verification.restrictions,
                    source_hypothesis_id=verification.meta.hypothesis_id,
                    source_verification_ref=verification_ref,
                    technical_review_ref=technical_ref,
                    admission_decision_ref=admission_ref,
                    evidence_refs=(observation,),
                    description="Deterministic validated primitive",
                )
            )
        )
        primitive_ref = reference(primitive)
        assert isinstance(primitive_ref, StoredDataRef)
        outputs = (
            (admission, primitive)
            if admission_decision == "ALLOW" or publish_denied_primitive
            else (admission,)
        )
        self.runner.complete(
            primitive_work,
            primitive_identity,
            "PRIMITIVE_ADMISSION_RUNTIME",
            outputs,
        )
        if admission_decision == "DENY":
            return ChainingOutcome(None, True)

        indexes = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "primitive_index_state"
            )
            if isinstance(item, PrimitiveIndexState)
            and item.meta.hypothesis_id == verification.meta.hypothesis_id
        )
        if len(indexes) != 1:
            raise LookupError("EXACT_PRIMITIVE_INDEX_NOT_FOUND")
        primitive_index = indexes[0]
        primitive_index_ref = reference(primitive_index)
        assert isinstance(primitive_index_ref, StoredDataRef)
        chaining_work = self.runner.start(
            scope,
            verification.meta,
            "CHAINING",
            "ANALYSIS",
            str(ANALYSIS_ID),
            orchestrator_ref,
            inputs=(primitive_index_ref, *primitive_index.primitive_refs),
            trigger_primitive_ref=primitive_ref,
            generation=generation,
        )
        chaining_identity = self.evidence.identity(RequesterRole.CHAINING)
        candidate = self.no_match_builder(
            meta=self.runner.metadata(
                chaining_work.meta,
                "chaining_result",
                attempt_id=chaining_work.active_attempt_id,
            ),
            primitive_refs=primitive_index.primitive_refs,
        )
        call_ref, provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            work=chaining_work,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role="CHAINING",
            result_kind="chaining_result",
            context_refs=tuple(
                ref
                for ref in chaining_work.input_refs
                if isinstance(ref, StoredDataRef)
            ),
        )
        record, invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=chaining_work,
            scope=scope,
            identity=chaining_identity,
            action_role=RequesterRole.CHAINING,
            action_type="CALL_LLM",
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: candidate,
            provider_invoke=self.provider_invoke,
        )
        assert isinstance(record, ChainingResult)
        persist_fake_invocation(self.runtime, invocation)
        self.runner.complete(chaining_work, chaining_identity, "CHAINING", (record,))
        return ChainingOutcome(primitive_ref, stop_after_chaining)


class ChainingCallRefs(Protocol):
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef


@dataclass(frozen=True, slots=True)
class ChainingWorkflowOutcome:
    result: ChainingResult
    completed_work: WorkExecutionState
    child_works: tuple[WorkExecutionState, ...]


class ChainingWorkflowService:
    """Run one claimed batch and hand off only atomically published children.

    The publisher owns ChainingResult publication and match-identity reservation
    in one transaction.  This service must never reserve matches separately.
    """

    def __init__(
        self,
        *,
        agent: ChainingAgentPort,
        records: RecordStore,
        pools: ChainingPoolHistoryPort,
        lineage: ChainingLineagePort,
        publisher: ChainingResultPublisherPort,
        children: ChainingChildHandoffPort,
        ids: IdGenerator,
        metadata_factory: InvocationMetadataFactory,
        requester_identity_ref: BudgetScopeRef,
    ) -> None:
        self._agent = agent
        self._records = records
        self._pools = pools
        self._lineage = lineage
        self._publisher = publisher
        self._children = children
        self._ids = ids
        self._metadata = metadata_factory
        self._identity = requester_identity_ref

    async def execute(
        self,
        *,
        context: WorkContext,
        call: ChainingCallRefs,
    ) -> ChainingWorkflowOutcome:
        work = context.work
        work_ref = reference(work)
        if not isinstance(work_ref, StoredDataRef):
            raise ValueError("CHAINING_WORK_CONTEXT_MISMATCH")
        history = self._pools.get_for_trigger(work_ref)
        universe = history.universe
        if (
            history.trigger_work_ref != work_ref
            or universe.trigger_primitive_ref != work.trigger_primitive_ref
            or len(work.input_refs)
            != len((*universe.index_refs, *universe.considered_primitive_refs))
            or set(work.input_refs)
            != set((*universe.index_refs, *universe.considered_primitive_refs))
        ):
            raise ValueError("CHAINING_PINNED_UNIVERSE_MISMATCH")
        entries = tuple(
            PrimitiveEntry(ref=ref, primitive=self._exact_primitive(ref))
            for ref in universe.considered_primitive_refs
        )
        comparisons = self._owned_comparisons(universe, entries)
        prompt = self._prompt(entries, comparisons)
        outcome = await self._agent.match(
            context=context,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
            content=prompt.content,
        )
        if outcome.content is None:
            raise ValueError("CHAINING_AGENT_FAILED")
        result = self._finalize(
            work=work,
            universe=universe,
            entries=entries,
            comparisons=comparisons,
            prompt=prompt,
            decisions=outcome.content.decisions,
        )
        action_refs = llm_invocation_save_refs(
            records=self._records,
            work=work,
            issued_decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
            invocation=outcome.invocation,
        )
        completed = self._publisher.publish(
            context=context,
            result=result,
            action_input_refs=action_refs,
        )
        result_ref = reference(result)
        if (
            completed.status != WorkStatus.SUCCEEDED
            or completed.active_attempt_id is not None
            or not isinstance(result_ref, StoredDataRef)
            or tuple(ref for ref in completed.output_refs if ref == result_ref)
            != (result_ref,)
        ):
            raise ValueError("CHAINING_RESULT_NOT_COMMITTED")
        children = tuple(
            self._children.enqueue_ready(
                source_result_ref=result_ref,
                proposal_id=proposal.proposal_id,
                requester_identity_ref=self._identity,
            )
            for proposal in result.chained_hypothesis_proposals
        )
        for proposal, child in zip(
            result.chained_hypothesis_proposals, children, strict=True
        ):
            if (
                child.status != WorkStatus.READY
                or child.active_attempt_id is not None
                or child.output_refs
                or str(child.subject_id) != str(proposal.proposal_id)
            ):
                raise ValueError("CHAINING_CHILD_NOT_READY")
        return ChainingWorkflowOutcome(result, completed, children)

    def _owned_comparisons(
        self,
        universe: PinnedChainingUniverse,
        entries: tuple[PrimitiveEntry, ...],
    ) -> tuple[DirectionalComparison, ...]:
        trigger = universe.trigger_primitive_ref
        owned: set[StoredDataRef] = set()
        for entry in entries:
            if entry.ref == trigger:
                continue
            history = self._pools.get_for_primitive(entry.ref)
            if history.universe.trigger_primitive_ref != entry.ref:
                raise ValueError("CHAINING_POOL_HISTORY_MISMATCH")
            if owns_pair(
                trigger,
                entry.ref,
                trigger_pool=universe.considered_primitive_refs,
                other_trigger_pool=history.universe.considered_primitive_refs,
            ):
                owned.add(entry.ref)
        return tuple(
            comparison
            for comparison in directional_comparisons(trigger, entries)
            if (
                comparison.downstream_ref
                if comparison.upstream_ref == trigger
                else comparison.upstream_ref
            )
            in owned
        )

    def _prompt(
        self,
        entries: tuple[PrimitiveEntry, ...],
        comparisons: tuple[DirectionalComparison, ...],
    ) -> _TrustedPrompt:
        primitive_keys = {
            entry.ref: f"primitive-{index}"
            for index, entry in enumerate(entries, start=1)
        }
        evidence: list[ChainingEvidence] = []
        evidence_refs: dict[str, tuple[StoredDataRef, ...]] = {}
        evidence_owners: dict[str, set[StoredDataRef]] = {}
        primitive_evidence: dict[StoredDataRef, tuple[str, ...]] = {}
        entity_keys: dict[tuple[StoredDataRef, bytes], str] = {}
        entity_counter = 0

        def add_evidence(
            key: str,
            kind: str,
            summary: str,
            refs: tuple[StoredDataRef, ...],
            owner: StoredDataRef,
        ) -> None:
            evidence.append(ChainingEvidence(key, kind, summary))  # type: ignore[arg-type]
            evidence_refs[key] = refs
            evidence_owners[key] = {owner}

        for entry_index, entry in enumerate(entries, start=1):
            local_keys: list[str] = []
            for evidence_index, ref in enumerate(
                entry.primitive.evidence_refs, start=1
            ):
                key = f"evidence-{entry_index}-{evidence_index}"
                add_evidence(
                    key,
                    "VERIFICATION",
                    f"Evidence supporting {entry.primitive.description}",
                    (ref,),
                    entry.ref,
                )
                local_keys.append(key)
            primitive_evidence[entry.ref] = tuple(local_keys)
            drafts = (
                *entry.primitive.inputs,
                *((entry.primitive.result,) if entry.primitive.result else ()),
            )
            for draft in drafts:
                for entity in draft.entity_refs:
                    identity = (entry.ref, canonical_bytes(entity))
                    if identity in entity_keys:
                        continue
                    entity_counter += 1
                    key = f"entity-{entity_counter}"
                    entity_keys[identity] = key
                    add_evidence(
                        key,
                        "ENTITY",
                        _entity_summary(entity),
                        entry.primitive.evidence_refs,
                        entry.ref,
                    )

        primitives: list[ChainingPrimitive] = []
        input_keys: dict[tuple[StoredDataRef, str], str] = {}
        for entry_index, entry in enumerate(entries, start=1):
            primitive = entry.primitive
            inputs: list[ChainingPrimitiveInput] = []
            for input_index, draft in enumerate(primitive.inputs, start=1):
                input_key = f"input-{entry_index}-{input_index}"
                input_keys[(entry.ref, str(draft.draft_id))] = input_key
                inputs.append(
                    ChainingPrimitiveInput(
                        input_key=input_key,
                        description=str(draft.description),
                        entity_keys=tuple(
                            entity_keys[(entry.ref, canonical_bytes(entity))]
                            for entity in draft.entity_refs
                        ),
                        privilege_level=draft.privilege_level,
                        evidence_keys=primitive_evidence[entry.ref],
                    )
                )
            result = primitive.result
            primitives.append(
                ChainingPrimitive(
                    primitive_key=primitive_keys[entry.ref],
                    description=str(primitive.description),
                    inputs=tuple(inputs),
                    result=(
                        ChainingPrimitiveResult(
                            description=str(result.description),
                            entity_keys=tuple(
                                entity_keys[(entry.ref, canonical_bytes(entity))]
                                for entity in result.entity_refs
                            ),
                            privilege_level=result.privilege_level,
                            evidence_keys=primitive_evidence[entry.ref],
                        )
                        if result is not None
                        else None
                    ),
                    restrictions=tuple(
                        str(restriction.statement)
                        for restriction in primitive.restrictions
                    ),
                )
            )
        prompt_comparisons = tuple(
            ChainingComparison(
                comparison_key=item.comparison_key,
                upstream_key=primitive_keys[item.upstream_ref],
                downstream_key=primitive_keys[item.downstream_ref],
                input_key=input_keys[(item.downstream_ref, item.matched_input_id)],
            )
            for item in comparisons
        )
        return _TrustedPrompt(
            content=ChainingAgentInput(
                evidence=tuple(evidence),
                primitives=tuple(primitives),
                comparisons=prompt_comparisons,
            ),
            evidence_refs=evidence_refs,
            evidence_owners={
                key: frozenset(owners) for key, owners in evidence_owners.items()
            },
        )

    def _finalize(
        self,
        *,
        work: WorkExecutionState,
        universe: PinnedChainingUniverse,
        entries: tuple[PrimitiveEntry, ...],
        comparisons: tuple[DirectionalComparison, ...],
        prompt: _TrustedPrompt,
        decisions: tuple[ChainingDecision, ...],
    ) -> ChainingResult:
        if not isinstance(work.meta, RecordMeta) or work.active_attempt_id is None:
            raise ValueError("CHAINING_WORK_CONTEXT_MISMATCH")
        by_key = {item.comparison_key: item for item in comparisons}
        decision_keys = tuple(decision.comparison_key for decision in decisions)
        if len(decision_keys) != len(set(decision_keys)) or set(decision_keys) != set(
            by_key
        ):
            raise ValueError("CHAINING_DECISION_COVERAGE_MISMATCH")
        by_ref = {entry.ref: entry.primitive for entry in entries}
        successful: list[SuccessfulMatchPair] = []
        successful_pair_keys: set[tuple[StoredDataRef, StoredDataRef]] = set()
        for decision in decisions:
            comparison = by_key.get(decision.comparison_key)
            if comparison is None:
                raise ValueError("CHAINING_DECISION_COVERAGE_MISMATCH")
            pair = (comparison.upstream_ref, comparison.downstream_ref)
            if decision.outcome == "MATCH":
                if pair not in successful_pair_keys:
                    successful.append(SuccessfulMatchPair(*pair))
                    successful_pair_keys.add(pair)
        resolve = self._lineage_resolver(universe, work.meta)
        retained_pairs = retain_deepest_successful_matches(
            considered_refs=universe.considered_primitive_refs,
            trigger_ref=universe.trigger_primitive_ref,
            successful_match_pairs=tuple(successful),
            resolve=resolve,
            analysis_id=str(work.meta.analysis_id),
        )
        retained_keys = {
            (pair.upstream_ref, pair.downstream_ref) for pair in retained_pairs
        }
        exclusions = expected_lineage_exclusions(
            considered_refs=universe.considered_primitive_refs,
            trigger_ref=universe.trigger_primitive_ref,
            successful_match_pairs=retained_pairs,
            resolve=resolve,
            analysis_id=str(work.meta.analysis_id),
        )
        excluded = {item.excluded_primitive_ref for item in exclusions}
        matches: list[PrimitiveMatchCandidate] = []
        proposals: list[HypothesisProposal] = []
        no_matches: list[NoMatchReason] = []
        for decision in decisions:
            comparison = by_key[decision.comparison_key]
            candidate_ref = (
                comparison.downstream_ref
                if comparison.upstream_ref == universe.trigger_primitive_ref
                else comparison.upstream_ref
            )
            if candidate_ref in excluded:
                continue
            pair_key = (comparison.upstream_ref, comparison.downstream_ref)
            if decision.outcome == "MATCH":
                if pair_key not in retained_keys:
                    continue
                match, proposal = self._match_and_proposal(
                    meta=work.meta,
                    attempt_id=work.active_attempt_id,
                    comparison=comparison,
                    decision=decision,
                    upstream=by_ref[comparison.upstream_ref],
                    downstream=by_ref[comparison.downstream_ref],
                    evidence_map=prompt.evidence_refs,
                    evidence_owners=prompt.evidence_owners,
                )
                matches.append(match)
                proposals.append(proposal)
            else:
                reason_code = decision.reason_code
                if reason_code is None:
                    raise ValueError("CHAINING_NO_MATCH_REASON_REQUIRED")
                no_matches.append(
                    NoMatchReason(
                        upstream_result_ref=comparison.upstream_ref,
                        downstream_input_ref=comparison.downstream_ref,
                        checked_input_id=comparison.matched_input_id,
                        reason_code=reason_code,
                        detail=decision.detail,
                    )
                )
        source_refs = _source_refs(tuple(matches), by_ref)
        input_refs = _unique_refs(
            tuple(
                ref
                for match in matches
                for ref in (match.upstream_result_ref, match.downstream_input_ref)
            )
        )
        result = ChainingResult(
            meta=self._metadata(work.meta, "chaining_result", work.active_attempt_id),
            source_result_refs=source_refs,
            considered_primitive_refs=universe.considered_primitive_refs,
            input_primitive_refs=input_refs,
            primitive_match_candidates=tuple(matches),
            chained_hypothesis_proposals=tuple(proposals),
            excluded_lineage_refs=exclusions,
            no_match_reasons=tuple(no_matches),
            errors=(),
        )
        validate_chaining_closure(
            result,
            tuple(entry.primitive for entry in entries),
            universe.considered_primitive_refs,
            exclusions,
        )
        return result

    def _match_and_proposal(
        self,
        *,
        meta: RecordMeta,
        attempt_id: AttemptId,
        comparison: DirectionalComparison,
        decision: ChainingDecision,
        upstream: Primitive,
        downstream: Primitive,
        evidence_map: dict[str, tuple[StoredDataRef, ...]],
        evidence_owners: dict[str, frozenset[StoredDataRef]],
    ) -> tuple[PrimitiveMatchCandidate, HypothesisProposal]:
        pair_refs = {comparison.upstream_ref, comparison.downstream_ref}
        if any(
            not evidence_owners.get(key)
            or not evidence_owners[key] <= pair_refs
            for key in decision.evidence_keys
        ):
            raise ValueError("CHAINING_MATCH_EVIDENCE_SCOPE_MISMATCH")
        evidence = _unique_refs(
            tuple(
                ref
                for key in decision.evidence_keys
                for ref in evidence_map.get(str(key), ())
            )
        )
        if not evidence:
            raise ValueError("CHAINING_MATCH_EVIDENCE_REQUIRED")
        match_id = str(self._ids.new(RecordId))
        parents = _unique_values(
            (upstream.source_hypothesis_id, downstream.source_hypothesis_id)
        )
        parent_verifications = _unique_refs(
            (upstream.source_verification_ref, downstream.source_verification_ref)
        )
        match = PrimitiveMatchCandidate(
            primitive_match_id=match_id,
            upstream_result_ref=comparison.upstream_ref,
            downstream_input_ref=comparison.downstream_ref,
            matched_input_id=comparison.matched_input_id,
            parent_hypothesis_ids=parents,
            parent_verification_refs=parent_verifications,
            workspace_id=meta.workspace_id,
            commit_id=meta.commit_id,
            evidence_refs=evidence,
            candidate_state="UNVALIDATED",
        )
        content = decision.child
        if content is None:
            raise ValueError("CHAINING_MATCH_CHILD_REQUIRED")
        remaining = (
            *upstream.inputs,
            *(
                draft
                for draft in downstream.inputs
                if str(draft.draft_id) != comparison.matched_input_id
            ),
        )
        entities = _unique_values(
            tuple(
                entity
                for draft in (
                    *upstream.inputs,
                    *downstream.inputs,
                    *((upstream.result,) if upstream.result else ()),
                    *((downstream.result,) if downstream.result else ()),
                )
                for entity in draft.entity_refs
            )
        )
        locations = _unique_values(tuple(entity.location for entity in entities))
        restrictions = _merged_restrictions(upstream, downstream)
        proposal = HypothesisProposal(
            meta=self._metadata(meta, "hypothesis_proposal", attempt_id),
            proposal_id=self._ids.new(ProposalId),
            proposal_state="HYPOTHESIS_ONLY",
            assertion_mode="NON_FINAL",
            statement=str(content.statement),
            origin="CHAINING",
            vulnerability_type_candidates=tuple(content.vulnerability_type_candidates),
            target_entities=entities,
            target_locations=locations,
            suspected_path=locations,
            observed_facts=(),
            assumptions=tuple(str(draft.description) for draft in remaining),
            restrictions=restrictions,
            falsification_questions=tuple(
                FalsificationQuestion(
                    question_id=str(self._ids.new(RecordId)),
                    question=str(question),
                )
                for question in content.falsification_questions
            ),
            validation_checks=tuple(
                ValidationCheck(
                    validation_id=str(self._ids.new(RecordId)),
                    instruction=str(instruction),
                )
                for instruction in content.validation_checks
            ),
            parent_hypothesis_ids=parents,
            source_primitive_match_id=match_id,
        )
        return match, proposal

    def _lineage_resolver(
        self, universe: PinnedChainingUniverse, meta: RecordMeta
    ) -> LineageResolver:
        def resolve(ref: StoredDataRef) -> LineageNode:
            return LineageNode(
                primitive_ref=ref,
                parent_primitive_refs=self._lineage.ancestors(
                    primitive_ref=ref,
                    universe=universe,
                ),
                analysis_id=str(meta.analysis_id),
                workspace_id=str(meta.workspace_id),
                commit_id=str(meta.commit_id),
                committed=True,
            )

        return cast(LineageResolver, resolve)

    def _exact_primitive(self, ref: StoredDataRef) -> Primitive:
        value = self._records.get_exact(ref)
        if not isinstance(value, Primitive) or reference(value) != ref:
            raise ValueError("CHAINING_PINNED_UNIVERSE_MISMATCH")
        return value


@dataclass(frozen=True, slots=True)
class _TrustedPrompt:
    content: ChainingAgentInput
    evidence_refs: dict[str, tuple[StoredDataRef, ...]]
    evidence_owners: dict[str, frozenset[StoredDataRef]]


def _entity_summary(entity: CodeSymbol) -> str:
    location = entity.location
    prefix = f"{entity.symbol_kind} {entity.name}"
    return f"{prefix} at {location.file_path}:{location.start_line}"


def _unique_refs[T: StoredDataRef](values: tuple[T, ...]) -> tuple[T, ...]:
    return tuple(dict.fromkeys(values))


def _unique_values[T](values: tuple[T, ...]) -> tuple[T, ...]:
    unique: list[T] = []
    for value in values:
        if value not in unique:
            unique.append(value)
    return tuple(unique)


def _merged_restrictions(
    upstream: Primitive, downstream: Primitive
) -> tuple[Restriction, ...]:
    by_id: dict[str, Restriction] = {}
    for restriction in (*upstream.restrictions, *downstream.restrictions):
        key = str(restriction.restriction_id)
        if key in by_id and by_id[key] != restriction:
            raise ValueError("RESTRICTION_ID_CONFLICT")
        by_id[key] = restriction
    return tuple(by_id.values())


def _source_refs(
    matches: tuple[PrimitiveMatchCandidate, ...],
    primitives: dict[StoredDataRef, Primitive],
) -> tuple[StoredDataRef, ...]:
    refs: list[StoredDataRef] = []
    for match in matches:
        for ref in (match.upstream_result_ref, match.downstream_input_ref):
            primitive = primitives[ref]
            refs.append(primitive.source_verification_ref)
            if primitive.technical_review_ref is not None:
                refs.append(primitive.technical_review_ref)
    return _unique_refs(tuple(refs))
