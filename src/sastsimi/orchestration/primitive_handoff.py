"""Fail-closed, ready-only handoff from accepted Gate results to T13."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from sastsimi.contracts.chaining import PrimitiveIndexState
from sastsimi.contracts.domain import DomainRecord, exact, same_scope
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    PoCBundle,
)
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
    validate_rule_scope_gate,
    validate_technical_gate,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.records import RecordMetadata
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.ready_work import ReadyWorkPort
from sastsimi.ports.runtime_query import RuntimeQueryPort


class ExactRecordReader(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


@dataclass(frozen=True, slots=True)
class PrimitiveHandoffRefs:
    process_ref: StoredDataRef
    verification_ref: StoredDataRef
    dynamic_request_ref: StoredDataRef
    dynamic_result_ref: StoredDataRef
    poc_ref: StoredDataRef
    cwe_label_ref: StoredDataRef
    technical_review_ref: StoredDataRef
    run_policy_state_ref: StoredDataRef
    collection_ref: StoredDataRef
    primitive_index_ref: StoredDataRef
    policy_ref: StoredDataRef | None = None
    rule_scope_review_ref: StoredDataRef | None = None

    def work_inputs(self) -> tuple[StoredDataRef, ...]:
        return (
            self.process_ref,
            self.verification_ref,
            self.dynamic_request_ref,
            self.dynamic_result_ref,
            self.poc_ref,
            self.cwe_label_ref,
            self.technical_review_ref,
            self.run_policy_state_ref,
            self.collection_ref,
            *((self.policy_ref,) if self.policy_ref is not None else ()),
            *((self.rule_scope_review_ref,) if self.rule_scope_review_ref else ()),
            self.primitive_index_ref,
        )


class PrimitiveUpdateHandoff:
    """Validate the committed Gate closure and enqueue, but never run, T13 work."""

    def __init__(
        self,
        *,
        records: ExactRecordReader,
        current: RuntimeQueryPort,
        ready_work: ReadyWorkPort,
    ) -> None:
        self._records = records
        self._current = current
        self._ready = ready_work

    def enqueue_true(
        self,
        *,
        refs: PrimitiveHandoffRefs,
        scope: BudgetScopeRef,
        metadata: RecordMetadata,
        identity: BudgetScopeRef,
    ) -> WorkExecutionState:
        process = self._exact(refs.process_ref, HypothesisProcessState)
        verification = self._exact(refs.verification_ref, VerificationResult)
        request = self._exact(refs.dynamic_request_ref, DynamicReproductionRequest)
        dynamic = self._exact(refs.dynamic_result_ref, DynamicReproductionResult)
        poc = self._exact(refs.poc_ref, PoCBundle)
        cwe = self._exact(refs.cwe_label_ref, CWELabel)
        technical = self._exact(refs.technical_review_ref, TechnicalEvidenceReview)
        policy_state = self._exact(refs.run_policy_state_ref, RunPolicyState)
        collection = self._exact(refs.collection_ref, PolicyCollectionResult)
        index = self._exact(refs.primitive_index_ref, PrimitiveIndexState)
        policy = (
            self._exact(refs.policy_ref, ProgramPolicyRecord)
            if refs.policy_ref is not None
            else None
        )
        rule_scope = (
            self._exact(refs.rule_scope_review_ref, RuleScopeImpactReview)
            if refs.rule_scope_review_ref is not None
            else None
        )
        self._validate_current(refs, process, policy_state, index)
        self._validate_gate_chain(
            refs=refs,
            process=process,
            verification=verification,
            request=request,
            dynamic=dynamic,
            poc=poc,
            cwe=cwe,
            technical=technical,
            policy_state=policy_state,
            collection=collection,
            policy=policy,
            rule_scope=rule_scope,
        )
        inputs = refs.work_inputs()
        if len(inputs) != len(set(inputs)):
            raise ValueError("PRIMITIVE_HANDOFF_DUPLICATE_INPUT")
        return self._ready.enqueue(
            scope,
            metadata,
            "PRIMITIVE_UPDATE",
            "HYPOTHESIS",
            str(verification.meta.hypothesis_id),
            identity,
            role="ORCHESTRATION",
            generation=process.verification_generation,
            inputs=cast(tuple[RecordRef, ...], inputs),
        )

    def _validate_current(
        self,
        refs: PrimitiveHandoffRefs,
        process: HypothesisProcessState,
        policy_state: RunPolicyState,
        index: PrimitiveIndexState,
    ) -> None:
        if (
            process.status != "TERMINAL"
            or process.verification_result_ref != refs.verification_ref
            or process.verification_work_ref is not None
            or index.current_verification_ref != refs.verification_ref
        ):
            raise ValueError("STALE_RESULT")
        self._require_current(refs.process_ref, process)
        self._require_current(refs.run_policy_state_ref, policy_state)
        self._require_current(refs.primitive_index_ref, index)

    def _require_current(
        self, expected_ref: StoredDataRef, value: DomainRecord
    ) -> None:
        matches = tuple(
            item
            for item in self._current.current_records(
                str(value.meta.analysis_id), value.meta.record_type
            )
            if isinstance(item, type(value))
            and getattr(item.meta, "hypothesis_id", None)
            == getattr(value.meta, "hypothesis_id", None)
        )
        if len(matches) != 1 or reference(matches[0]) != expected_ref:
            raise ValueError("STALE_RESULT")

    @staticmethod
    def _validate_gate_chain(
        *,
        refs: PrimitiveHandoffRefs,
        process: HypothesisProcessState,
        verification: VerificationResult,
        request: DynamicReproductionRequest,
        dynamic: DynamicReproductionResult,
        poc: PoCBundle,
        cwe: CWELabel,
        technical: TechnicalEvidenceReview,
        policy_state: RunPolicyState,
        collection: PolicyCollectionResult,
        policy: ProgramPolicyRecord | None,
        rule_scope: RuleScopeImpactReview | None,
    ) -> None:
        for value in (request, dynamic, poc, cwe, technical, collection, policy_state):
            same_scope(verification.meta, value.meta, hypothesis=False)
        same_scope(verification.meta, process.meta)
        same_scope(verification.meta, cwe.meta)
        same_scope(verification.meta, technical.meta)
        if rule_scope is not None:
            same_scope(verification.meta, rule_scope.meta)
        if policy is not None:
            same_scope(verification.meta, policy.meta, hypothesis=False)
        if verification.dynamic_request_ref is None:
            raise ValueError("DYNAMIC_VERIFICATION_CLOSURE_MISMATCH")
        for request_ref in (
            verification.dynamic_request_ref,
            dynamic.request_ref,
            poc.request_ref,
        ):
            exact(request_ref, request, verification.meta)
        validate_technical_gate(
            technical,
            verification,
            cwe,
            dynamic,
            poc,
            current_generation=process.verification_generation,
        )
        if technical.status != "ACCEPT":
            raise ValueError("TECHNICAL_GATE_NOT_ACCEPTED")
        if (
            policy_state.collection_result_ref != refs.collection_ref
            or policy_state.policy_record_ref != refs.policy_ref
            or collection.policy_record_ref != refs.policy_ref
        ):
            raise ValueError("GATE_POLICY_CLOSURE_MISMATCH")
        if collection.status == "COLLECTION_FAILED":
            if (
                policy_state.status not in {"BLOCKED", "FAILED"}
                or policy is not None
                or rule_scope is not None
            ):
                raise ValueError("POLICY_COLLECTION_FAILED_HANDOFF_MISMATCH")
            return
        if rule_scope is None:
            raise ValueError("RULE_SCOPE_REVIEW_REQUIRED")
        validate_rule_scope_gate(
            rule_scope, technical, policy_state, collection, policy
        )

    def _exact[T: DomainRecord](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model):
            raise ValueError("RECORD_REVISION_MISMATCH")
        exact(ref, value, value.meta)
        return value


__all__ = ["PrimitiveHandoffRefs", "PrimitiveUpdateHandoff"]
