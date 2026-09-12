"""Deterministic post-commit handoffs for the production T10--T12 graph."""

from __future__ import annotations

from dataclasses import dataclass

from sastsimi.bootstrap import T12Services
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.chaining import PrimitiveIndexState
from sastsimi.contracts.domain import DomainRecord
from sastsimi.contracts.dynamic import DynamicReproductionResult, PoCBundle
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VerificationAssignment,
)
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.reporting import Finding, FindingIndexState, evidence_closure
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import (
    TERMINAL_WORK_STATUSES,
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.orchestration.primitive_handoff import PrimitiveHandoffRefs
from sastsimi.orchestration.production_composition import ProductionInstallationContext
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.work_handler import WorkHandler
from sastsimi.reporting.rule_scope_gate_workflow import (
    expected_rule_scope_evidence,
)


@dataclass(frozen=True, slots=True)
class RoutedWorkHandler:
    """Run a self-committing handler, then enqueue only from its durable state."""

    delegate: WorkHandler
    router: ProductionStageRouter

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        result = await self.delegate.execute(context)
        current = self.router.context.runtime.work.get(str(context.work.work_id))
        self.router.after(current)
        return result


@dataclass(frozen=True, slots=True)
class ProductionStageRouter:
    """Create the next exact work only after the previous output is committed."""

    context: ProductionInstallationContext
    t12: T12Services

    def after(self, work: WorkExecutionState) -> None:
        if work.status != WorkStatus.SUCCEEDED and not (
            work.work_type == WorkType.POLICY_FETCH
            and work.status in TERMINAL_WORK_STATUSES
        ):
            return
        routes = {
            WorkType.VERIFICATION: self._after_verification,
            WorkType.DYNAMIC_REPRO: self._after_dynamic,
            WorkType.CWE_LABEL: self._after_cwe,
            WorkType.POLICY_FETCH: self._after_policy,
            WorkType.TECHNICAL_GATE: self._after_technical,
            WorkType.RULE_SCOPE_GATE: self._after_rule_scope,
            WorkType.FINDING_NORMALIZE: self._after_finding,
        }
        route = routes.get(work.work_type)
        if route is not None:
            route(work)

    def _after_dynamic(self, work: WorkExecutionState) -> None:
        if work.parent_work_ref is None:
            raise ValueError("DYNAMIC_PARENT_REQUIRED")
        parent = self.context.runtime.unit_of_work.records.get_exact(
            work.parent_work_ref
        )
        if not isinstance(parent, WorkExecutionState):
            raise ValueError("DYNAMIC_PARENT_REQUIRED")
        current = self.context.runtime.work.get(str(parent.work_id))
        if current.status == WorkStatus.SUCCEEDED:
            self._after_verification(current)

    def _after_verification(self, work: WorkExecutionState) -> None:
        verification_ref, verification = self._one_output(
            work, VerificationResult.KIND, VerificationResult
        )
        if verification.verdict != "TRUE":
            return
        if verification.dynamic_result_ref is None or verification.poc_ref is None:
            raise ValueError("VALIDATED_POC_REQUIRED")
        process_ref, _process = self._current(
            work, HypothesisProcessState.KIND, HypothesisProcessState
        )
        dynamic = self._exact(
            verification.dynamic_result_ref, DynamicReproductionResult
        )
        poc = self._exact(verification.poc_ref, PoCBundle)
        evidence = _allowed_dynamic_evidence(verification, dynamic, poc)
        self._enqueue(
            work,
            WorkType.CWE_LABEL,
            (
                verification_ref,
                verification.dynamic_result_ref,
                verification.poc_ref,
                process_ref,
                *evidence,
            ),
            parent=self._work_ref(work),
        )

    def _after_cwe(self, work: WorkExecutionState) -> None:
        label_ref, _label = self._one_output(work, CWELabel.KIND, CWELabel)
        verification_ref, verification = self._one_input(
            work, VerificationResult.KIND, VerificationResult
        )
        process_ref, _process = self._current(
            work, HypothesisProcessState.KIND, HypothesisProcessState
        )
        assignment_ref, _assignment = self._current(
            work, VerificationAssignment.KIND, VerificationAssignment
        )
        if verification.dynamic_result_ref is None or verification.poc_ref is None:
            raise ValueError("VALIDATED_POC_REQUIRED")
        dynamic = self._exact(
            verification.dynamic_result_ref, DynamicReproductionResult
        )
        poc = self._exact(verification.poc_ref, PoCBundle)
        self._enqueue(
            work,
            WorkType.TECHNICAL_GATE,
            (
                verification_ref,
                verification.dynamic_result_ref,
                verification.poc_ref,
                label_ref,
                process_ref,
                assignment_ref,
                self._scope(work),
                *_allowed_dynamic_evidence(verification, dynamic, poc),
            ),
        )

    def _after_technical(self, work: WorkExecutionState) -> None:
        _ref, review = self._one_output(
            work, TechnicalEvidenceReview.KIND, TechnicalEvidenceReview
        )
        if review.status == "ACCEPT":
            self._join_policy(work)

    def _after_policy(self, work: WorkExecutionState) -> None:
        work_for_run = getattr(self.context.scheduler_store, "work_for_run", None)
        if not callable(work_for_run):
            raise ValueError("PRODUCTION_WORK_QUERY_REQUIRED")
        for candidate in work_for_run(str(work.meta.analysis_id)):
            if (
                candidate.work_type == WorkType.TECHNICAL_GATE
                and candidate.status == WorkStatus.SUCCEEDED
            ):
                _ref, review = self._one_output(
                    candidate,
                    TechnicalEvidenceReview.KIND,
                    TechnicalEvidenceReview,
                )
                if review.status == "ACCEPT":
                    self._join_policy(candidate)

    def _join_policy(self, work: WorkExecutionState) -> None:
        technical_ref, technical = self._one_output(
            work, TechnicalEvidenceReview.KIND, TechnicalEvidenceReview
        )
        verification_ref, verification = self._one_input(
            work, VerificationResult.KIND, VerificationResult
        )
        label_ref, label = self._one_input(work, CWELabel.KIND, CWELabel)
        run = self.context.runtime.budget_registry.current_state(
            str(work.meta.analysis_id)
        )
        state_ref = run.run_policy_state_ref
        if not isinstance(state_ref, StoredDataRef):
            return
        state = self._exact(state_ref, RunPolicyState)
        if state.status in {"PREPARING", "BLOCKED"}:
            return
        collection_ref = state.collection_result_ref
        if not isinstance(collection_ref, StoredDataRef):
            raise ValueError("POLICY_COLLECTION_RESULT_REQUIRED")
        collection = self._exact(collection_ref, PolicyCollectionResult)
        if state.status == "FAILED":
            if collection.status != "COLLECTION_FAILED":
                raise ValueError("POLICY_FAILURE_STATE_MISMATCH")
            self._enqueue_primitive_without_rule(
                work,
                technical_ref=technical_ref,
                verification_ref=verification_ref,
                verification=verification,
                label_ref=label_ref,
                state_ref=state_ref,
                collection_ref=collection_ref,
            )
            return
        policy = (
            self._exact(state.policy_record_ref, ProgramPolicyRecord)
            if state.policy_record_ref is not None
            else None
        )
        source_refs = (
            tuple(collection.official_source_refs)
            if collection.status == "FOUND"
            else ()
        )
        evidence = expected_rule_scope_evidence(
            verification=verification,
            label=label,
            state=state,
            policy=policy,
            source_refs=source_refs,
        )
        base = (
            verification_ref,
            label_ref,
            technical_ref,
            state_ref,
            collection_ref,
            *((state.policy_record_ref,) if state.policy_record_ref else ()),
            *evidence,
        )
        self._enqueue(work, WorkType.RULE_SCOPE_GATE, _unique(base))

    def _enqueue_primitive_without_rule(
        self,
        work: WorkExecutionState,
        *,
        technical_ref: StoredDataRef,
        verification_ref: StoredDataRef,
        verification: VerificationResult,
        label_ref: StoredDataRef,
        state_ref: StoredDataRef,
        collection_ref: StoredDataRef,
    ) -> None:
        process_ref, _process = self._current(
            work, HypothesisProcessState.KIND, HypothesisProcessState
        )
        index_ref, _index = self._current(
            work, PrimitiveIndexState.KIND, PrimitiveIndexState
        )
        if (
            verification.dynamic_request_ref is None
            or verification.dynamic_result_ref is None
            or verification.poc_ref is None
        ):
            raise ValueError("VALIDATED_POC_REQUIRED")
        self.t12.primitive_handoff.enqueue_true(
            refs=PrimitiveHandoffRefs(
                process_ref=process_ref,
                verification_ref=verification_ref,
                dynamic_request_ref=verification.dynamic_request_ref,
                dynamic_result_ref=verification.dynamic_result_ref,
                poc_ref=verification.poc_ref,
                cwe_label_ref=label_ref,
                technical_review_ref=technical_ref,
                run_policy_state_ref=state_ref,
                collection_ref=collection_ref,
                primitive_index_ref=index_ref,
            ),
            scope=self._scope(work),
            metadata=work.meta,
            identity=self.context.role_identity_refs[RequesterRole.ORCHESTRATION],
        )

    def _after_rule_scope(self, work: WorkExecutionState) -> None:
        review_ref, review = self._one_output(
            work, RuleScopeImpactReview.KIND, RuleScopeImpactReview
        )
        verification_ref, verification = self._one_input(
            work, VerificationResult.KIND, VerificationResult
        )
        label_ref, _label = self._one_input(work, CWELabel.KIND, CWELabel)
        technical_ref, _technical = self._one_input(
            work, TechnicalEvidenceReview.KIND, TechnicalEvidenceReview
        )
        process_ref, _process = self._current(
            work, HypothesisProcessState.KIND, HypothesisProcessState
        )
        index_ref, _index = self._current(
            work, PrimitiveIndexState.KIND, PrimitiveIndexState
        )
        if (
            verification.dynamic_request_ref is None
            or verification.dynamic_result_ref is None
            or verification.poc_ref is None
        ):
            raise ValueError("VALIDATED_POC_REQUIRED")
        handoff = PrimitiveHandoffRefs(
            process_ref=process_ref,
            verification_ref=verification_ref,
            dynamic_request_ref=verification.dynamic_request_ref,
            dynamic_result_ref=verification.dynamic_result_ref,
            poc_ref=verification.poc_ref,
            cwe_label_ref=label_ref,
            technical_review_ref=technical_ref,
            run_policy_state_ref=review.run_policy_state_ref,
            collection_ref=review.policy_collection_result_ref,
            primitive_index_ref=index_ref,
            policy_ref=review.policy_record_ref,
            rule_scope_review_ref=review_ref,
        )
        self.t12.primitive_handoff.enqueue_true(
            refs=handoff,
            scope=self._scope(work),
            metadata=work.meta,
            identity=self.context.role_identity_refs[RequesterRole.ORCHESTRATION],
        )
        if not review.report_ready():
            return
        resolved = _published_domain_records(self.context, work)
        evidence = evidence_closure(verification, resolved)
        inputs = _unique(
            (
                process_ref,
                verification_ref,
                verification.dynamic_result_ref,
                verification.poc_ref,
                label_ref,
                technical_ref,
                review_ref,
                review.run_policy_state_ref,
                review.policy_collection_result_ref,
                *((review.policy_record_ref,) if review.policy_record_ref else ()),
                *evidence,
            )
        )
        self._enqueue(
            work,
            WorkType.FINDING_NORMALIZE,
            inputs,
            parent=self._work_ref(work),
        )

    def _after_finding(self, work: WorkExecutionState) -> None:
        finding_ref, finding = self._one_output(work, Finding.KIND, Finding)
        index_ref, index = self._current(
            work, FindingIndexState.KIND, FindingIndexState
        )
        if index.finding_ref != finding_ref:
            raise ValueError("FINDING_INDEX_NOT_CURRENT")
        inputs = _unique(
            (
                finding_ref,
                index_ref,
                finding.verification_result_ref,
                finding.dynamic_result_ref,
                finding.poc_ref,
                finding.cwe_label_ref,
                finding.technical_review_ref,
                finding.rule_scope_impact_review_ref,
                self._exact(
                    finding.rule_scope_impact_review_ref, RuleScopeImpactReview
                ).run_policy_state_ref,
                *((finding.policy_record_ref,) if finding.policy_record_ref else ()),
                *(source.source_ref for source in finding.condition_sources),
            )
        )
        self._enqueue(work, WorkType.REPORT_DRAFT, inputs)

    def _enqueue(
        self,
        source: WorkExecutionState,
        kind: WorkType,
        inputs: tuple[StoredDataRef, ...],
        *,
        parent: StoredDataRef | None = None,
    ) -> WorkExecutionState:
        meta = _next_meta(self.context, source, kind)
        source_meta = _record_meta(source)
        return self.context.runner.ensure_enqueue(
            self._scope(source),
            meta,
            kind,
            SubjectType.HYPOTHESIS,
            str(source_meta.hypothesis_id),
            self.context.role_identity_refs[RequesterRole.ORCHESTRATION],
            stable_key=(
                "production-stage:"
                + kind.value
                + ":"
                + str(source.work_generation)
                + ":"
                + content_hash(inputs)
            ),
            inputs=inputs,
            parent=parent,
            generation=source.work_generation,
        )

    def _scope(self, work: WorkExecutionState) -> StoredDataRef:
        value = self.context.runtime.budget_registry.current_state(
            str(work.meta.analysis_id)
        ).budget_binding_ref
        if not isinstance(value, StoredDataRef):
            raise ValueError("CURRENT_BUDGET_SCOPE_REQUIRED")
        return value

    def _current[T: DomainRecord](
        self, work: WorkExecutionState, kind: str, model: type[T]
    ) -> tuple[StoredDataRef, T]:
        work_meta = _record_meta(work)
        matches = tuple(
            item
            for item in self.context.runtime.queries.current_records(
                str(work.meta.analysis_id), kind
            )
            if isinstance(item, model)
            and item.meta.hypothesis_id == work_meta.hypothesis_id
        )
        if len(matches) != 1:
            raise ValueError("CURRENT_STAGE_INPUT_REQUIRED")
        ref = reference(matches[0])
        if not isinstance(ref, StoredDataRef):
            raise ValueError("CURRENT_STAGE_INPUT_REQUIRED")
        return ref, matches[0]

    def _one_output[T: DomainRecord](
        self, work: WorkExecutionState, kind: str, model: type[T]
    ) -> tuple[StoredDataRef, T]:
        refs = tuple(
            ref
            for ref in work.output_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == kind
        )
        if len(refs) != 1:
            raise ValueError("STAGE_OUTPUT_REQUIRED")
        return refs[0], self._exact(refs[0], model)

    def _one_input[T: DomainRecord](
        self, work: WorkExecutionState, kind: str, model: type[T]
    ) -> tuple[StoredDataRef, T]:
        refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == kind
        )
        if len(refs) != 1:
            raise ValueError("STAGE_INPUT_REQUIRED")
        return refs[0], self._exact(refs[0], model)

    def _exact[T: DomainRecord](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self.context.runtime.unit_of_work.records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:
            raise ValueError("STAGE_EXACT_REFERENCE_REQUIRED")
        return value

    @staticmethod
    def _work_ref(work: WorkExecutionState) -> StoredDataRef:
        value = reference(work)
        if not isinstance(value, StoredDataRef):
            raise ValueError("STAGE_WORK_REFERENCE_REQUIRED")
        return value


def _allowed_dynamic_evidence(
    verification: VerificationResult,
    dynamic: DynamicReproductionResult,
    poc: PoCBundle,
) -> tuple[StoredDataRef, ...]:
    return _unique(
        (
            *(
                ref
                for claim in (
                    *verification.supporting_evidence,
                    *verification.counter_evidence,
                )
                for ref in claim.evidence_refs
            ),
            *dynamic.observation_refs,
            *dynamic.hypothesis_evidence_refs,
            *dynamic.disproof_evidence_refs,
            *poc.evidence_refs,
        )
    )


def _published_domain_records(
    context: ProductionInstallationContext, work: WorkExecutionState
) -> dict[bytes, DomainRecord]:
    values = context.runtime.queries.published_records(str(work.meta.analysis_id))
    return {
        canonical_bytes(ref): item
        for item in values
        if isinstance(item, DomainRecord)
        and isinstance((ref := reference(item)), StoredDataRef)
    }


def _next_meta(
    context: ProductionInstallationContext,
    source: WorkExecutionState,
    kind: WorkType,
) -> RecordMeta:
    source_meta = _record_meta(source)
    raw = context.runner.metadata(source_meta, kind.value.casefold())
    raw["hypothesis_id"] = source_meta.hypothesis_id
    raw["attempt_id"] = None
    return RecordMeta.model_validate(raw)


def _unique(values: tuple[StoredDataRef, ...]) -> tuple[StoredDataRef, ...]:
    return tuple(dict.fromkeys(values))


def _record_meta(work: WorkExecutionState) -> RecordMeta:
    if not isinstance(work.meta, RecordMeta) or work.meta.hypothesis_id is None:
        raise ValueError("HYPOTHESIS_STAGE_SCOPE_REQUIRED")
    return work.meta


__all__ = ["ProductionStageRouter", "RoutedWorkHandler"]
