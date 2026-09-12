"""Trusted, non-LLM admission of exact final Verification capabilities."""

from __future__ import annotations

from typing import Literal, Protocol

from sastsimi.contracts.chaining import (
    Primitive,
    PrimitiveAdmissionDecision,
    PrimitiveIndexState,
    validate_admission,
    validate_primitive_source,
)
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
from sastsimi.contracts.ids import HypothesisId, LogicalRecordId, RecordId
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import PrimitiveDraft, VerificationResult
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import Record
from sastsimi.ports.id_generator import IdGenerator

Admission = Literal["ALLOW", "DENY"]
AdmissionReason = Literal[
    "TESTING_RESTRICTION_PASSED",
    "TESTING_RESTRICTION_UNCERTAIN",
    "POLICY_COLLECTION_FAILED",
    "TESTING_RESTRICTION_VIOLATION",
]


def decide_primitive_admission(
    *,
    collection_status: str,
    testing_restriction_compliance: str | None,
) -> tuple[Admission, AdmissionReason]:
    """Apply the one approved policy axis; this is not another policy Gate."""

    if collection_status == "COLLECTION_FAILED":
        if testing_restriction_compliance is not None:
            raise ValueError("ADMISSION_COLLECTION_FAILED_MISMATCH")
        return "ALLOW", "POLICY_COLLECTION_FAILED"
    if collection_status not in {"FOUND", "ABSENT_CONFIRMED"}:
        raise ValueError("ADMISSION_COLLECTION_STATUS_INVALID")
    if testing_restriction_compliance == "PASS":
        return "ALLOW", "TESTING_RESTRICTION_PASSED"
    if testing_restriction_compliance == "UNCERTAIN":
        return "ALLOW", "TESTING_RESTRICTION_UNCERTAIN"
    if testing_restriction_compliance == "FAIL":
        return "DENY", "TESTING_RESTRICTION_VIOLATION"
    raise ValueError("ADMISSION_REVIEW_REQUIRED")


class ExactRecordStore(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


class CurrentRecordQuery(Protocol):
    def current_records(self, analysis_id: str, kind: str) -> tuple[Record, ...]: ...


class AtomicAdmissionPublisher(Protocol):
    """Commit outputs and their PrimitiveIndex projection in one transaction."""

    def complete(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        role: str,
        outputs: tuple[Record, ...],
        *,
        status: str = "SUCCEEDED",
        cause: str = "COMPLETED",
        error_ids: tuple[str, ...] = (),
        gap_ids: tuple[str, ...] = (),
        action_input_refs: tuple[RecordRef, ...] | None = None,
    ) -> WorkExecutionState: ...


class PrimitiveAdmissionRuntime:
    """Resolve only pinned work input and atomically publish eligible Primitives."""

    _COMMON_KINDS = frozenset(
        {"hypothesis_process_state", "verification_result", "primitive_index_state"}
    )
    _TRUE_KINDS = frozenset(
        {
            *_COMMON_KINDS,
            "dynamic_reproduction_request",
            "dynamic_reproduction_result",
            "poc_bundle",
            "cwe_label",
            "technical_evidence_review",
            "run_policy_state",
            "policy_collection_result",
            "program_policy_record",
            "rule_scope_impact_review",
        }
    )

    def __init__(
        self,
        *,
        records: ExactRecordStore,
        current: CurrentRecordQuery,
        publisher: AtomicAdmissionPublisher,
        identity_ref: BudgetScopeRef,
        clock: Clock,
        ids: IdGenerator,
    ) -> None:
        self._records = records
        self._current = current
        self._publisher = publisher
        self._identity_ref = identity_ref
        self._clock = clock
        self._ids = ids

    def admit(self, work: WorkExecutionState) -> WorkExecutionState:
        self._require_running(work)
        refs = self._indexed_inputs(work)
        verification_ref = self._required_ref(refs, "verification_result")
        verification = self._exact(verification_ref, VerificationResult)

        if verification.verdict == "FALSE" or (
            verification.verdict == "HOLD"
            and not verification.required_primitive_candidates
        ):
            self._require_exact_kinds(refs, self._COMMON_KINDS)
            self._current_closure(refs, verification_ref, verification)
            raise ValueError("PRIMITIVE_UPDATE_NOT_REQUIRED")
        if verification.verdict == "HOLD":
            self._require_exact_kinds(refs, self._COMMON_KINDS)
            process, index = self._current_closure(refs, verification_ref, verification)
            del process, index
            primitive = self._hold_primitive(work, verification, verification_ref)
            return self._complete(work, (primitive,))

        self._require_exact_kinds(
            refs,
            self._TRUE_KINDS,
            optional=frozenset(
                {
                    "policy_collection_result",
                    "program_policy_record",
                    "rule_scope_impact_review",
                }
            ),
        )
        process, _ = self._current_closure(refs, verification_ref, verification)
        policy_state_ref = self._required_ref(refs, "run_policy_state")
        policy_state = self._exact(policy_state_ref, RunPolicyState)
        same_scope(verification.meta, policy_state.meta, hypothesis=False)
        self._require_current(policy_state_ref, policy_state)
        collection_ref = refs.get("policy_collection_result")
        if policy_state.collection_result_ref is None:
            if any(
                refs.get(kind) is not None
                for kind in (
                    "policy_collection_result",
                    "program_policy_record",
                    "rule_scope_impact_review",
                )
            ):
                raise ValueError("GATE_POLICY_CLOSURE_MISMATCH")
            raise ValueError("PRIMITIVE_UPDATE_NOT_REQUIRED")
        if collection_ref is None:
            raise ValueError("GATE_POLICY_CLOSURE_MISMATCH")
        collection = self._exact(collection_ref, PolicyCollectionResult)
        decision, primitives = self._admit_true(
            work=work,
            refs=refs,
            process=process,
            verification=verification,
            verification_ref=verification_ref,
            policy_state=policy_state,
            collection=collection,
        )
        outputs: tuple[Record, ...] = (decision, *primitives)
        return self._complete(work, outputs)

    def _admit_true(
        self,
        *,
        work: WorkExecutionState,
        refs: dict[str, StoredDataRef],
        process: HypothesisProcessState,
        verification: VerificationResult,
        verification_ref: StoredDataRef,
        policy_state: RunPolicyState,
        collection: PolicyCollectionResult,
    ) -> tuple[PrimitiveAdmissionDecision, tuple[Primitive, ...]]:
        request = self._exact(
            self._required_ref(refs, "dynamic_reproduction_request"),
            DynamicReproductionRequest,
        )
        dynamic = self._exact(
            self._required_ref(refs, "dynamic_reproduction_result"),
            DynamicReproductionResult,
        )
        poc = self._exact(self._required_ref(refs, "poc_bundle"), PoCBundle)
        cwe = self._exact(self._required_ref(refs, "cwe_label"), CWELabel)
        technical_ref = self._required_ref(refs, "technical_evidence_review")
        technical = self._exact(technical_ref, TechnicalEvidenceReview)
        for value in (request, dynamic, poc):
            same_scope(verification.meta, value.meta)
        for request_ref in (
            verification.dynamic_request_ref,
            dynamic.request_ref,
            poc.request_ref,
        ):
            if request_ref is None:
                raise ValueError("DYNAMIC_VERIFICATION_CLOSURE_MISMATCH")
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
        collection_ref = self._required_ref(refs, "policy_collection_result")
        if (
            policy_state.collection_result_ref != collection_ref
            or policy_state.policy_record_ref != refs.get("program_policy_record")
            or collection.policy_record_ref != refs.get("program_policy_record")
        ):
            raise ValueError("GATE_POLICY_CLOSURE_MISMATCH")
        policy = self._optional_exact(
            refs.get("program_policy_record"), ProgramPolicyRecord
        )
        review = self._optional_exact(
            refs.get("rule_scope_impact_review"), RuleScopeImpactReview
        )
        testing: str | None
        review_ref: StoredDataRef | None
        if collection.status == "COLLECTION_FAILED":
            if (
                policy_state.status not in {"BLOCKED", "FAILED"}
                or policy is not None
                or review is not None
            ):
                raise ValueError("POLICY_COLLECTION_FAILED_HANDOFF_MISMATCH")
            testing = None
            review_ref = None
        else:
            if review is None:
                raise ValueError("RULE_SCOPE_REVIEW_REQUIRED")
            validate_rule_scope_gate(
                review, technical, policy_state, collection, policy
            )
            testing = review.testing_restriction_compliance
            review_ref = self._required_ref(refs, "rule_scope_impact_review")
        decision_value, reason = decide_primitive_admission(
            collection_status=collection.status,
            testing_restriction_compliance=testing,
        )
        decision = PrimitiveAdmissionDecision(
            meta=self._meta(work, "primitive_admission_decision"),
            verification_result_ref=verification_ref,
            technical_review_ref=technical_ref,
            policy_collection_result_ref=collection_ref,
            rule_scope_review_ref=review_ref,
            testing_restriction_compliance=testing or "NOT_EVALUATED",
            decision=decision_value,
            reason_code=reason,
            decided_at=self._clock.now(),
        )
        validate_admission(
            decision, verification, technical, collection, policy_state, review
        )
        if decision.decision == "DENY":
            return decision, ()
        if not verification.provided_primitive_candidates:
            raise ValueError("TRUE_PROVIDED_PRIMITIVE_REQUIRED")
        decision_ref = reference(decision)
        if not isinstance(decision_ref, StoredDataRef):
            raise ValueError("PRIMITIVE_WORK_SCOPE_REQUIRED")
        primitives = tuple(
            self._true_primitive(
                work,
                verification,
                verification_ref,
                technical,
                technical_ref,
                decision,
                decision_ref,
                result,
            )
            for result in verification.provided_primitive_candidates
        )
        return decision, primitives

    def _hold_primitive(
        self,
        work: WorkExecutionState,
        verification: VerificationResult,
        verification_ref: StoredDataRef,
    ) -> Primitive:
        primitive = Primitive(
            meta=self._meta(work, "primitive"),
            primitive_id=str(self._ids.new(RecordId)),
            workspace_id=verification.meta.workspace_id,
            commit_id=verification.meta.commit_id,
            inputs=verification.required_primitive_candidates,
            result=None,
            restrictions=verification.restrictions,
            source_hypothesis_id=self._hypothesis_id(verification),
            source_verification_ref=verification_ref,
            technical_review_ref=None,
            admission_decision_ref=None,
            evidence_refs=self._evidence(verification.required_primitive_candidates),
            description=verification.verdict_rationale,
        )
        validate_primitive_source(primitive, verification)
        return primitive

    def _true_primitive(
        self,
        work: WorkExecutionState,
        verification: VerificationResult,
        verification_ref: StoredDataRef,
        technical: TechnicalEvidenceReview,
        technical_ref: StoredDataRef,
        decision: PrimitiveAdmissionDecision,
        decision_ref: StoredDataRef,
        result: PrimitiveDraft,
    ) -> Primitive:
        primitive = Primitive(
            meta=self._meta(work, "primitive"),
            primitive_id=str(self._ids.new(RecordId)),
            workspace_id=verification.meta.workspace_id,
            commit_id=verification.meta.commit_id,
            inputs=verification.required_primitive_candidates,
            result=result,
            restrictions=verification.restrictions,
            source_hypothesis_id=self._hypothesis_id(verification),
            source_verification_ref=verification_ref,
            technical_review_ref=technical_ref,
            admission_decision_ref=decision_ref,
            evidence_refs=self._evidence(
                (*verification.required_primitive_candidates, result)
            ),
            description=result.description,
        )
        validate_primitive_source(primitive, verification, technical, decision)
        return primitive

    @staticmethod
    def _evidence(drafts: tuple[PrimitiveDraft, ...]) -> tuple[StoredDataRef, ...]:
        refs: list[StoredDataRef] = []
        for draft in drafts:
            refs.extend(draft.evidence_refs)
        return tuple(dict.fromkeys(refs))

    @staticmethod
    def _hypothesis_id(verification: VerificationResult) -> HypothesisId:
        hypothesis_id = verification.meta.hypothesis_id
        if hypothesis_id is None:
            raise ValueError("PRIMITIVE_WORK_SCOPE_REQUIRED")
        return hypothesis_id

    def _current_closure(
        self,
        refs: dict[str, StoredDataRef],
        verification_ref: StoredDataRef,
        verification: VerificationResult,
    ) -> tuple[HypothesisProcessState, PrimitiveIndexState]:
        process_ref = self._required_ref(refs, "hypothesis_process_state")
        process = self._exact(process_ref, HypothesisProcessState)
        index_ref = self._required_ref(refs, "primitive_index_state")
        index = self._exact(index_ref, PrimitiveIndexState)
        same_scope(verification.meta, process.meta)
        same_scope(verification.meta, index.meta)
        if (
            process.status != "TERMINAL"
            or process.verification_result_ref != verification_ref
            or process.verification_work_ref is not None
            or index.current_verification_ref != verification_ref
        ):
            raise ValueError("STALE_RESULT")
        self._require_current(process_ref, process)
        self._require_current(index_ref, index)
        return process, index

    def _require_current(
        self, expected_ref: StoredDataRef, value: DomainRecord
    ) -> None:
        candidates = tuple(
            item
            for item in self._current.current_records(
                str(value.meta.analysis_id), value.meta.record_type
            )
            if isinstance(item, type(value))
            and getattr(item.meta, "hypothesis_id", None)
            == getattr(value.meta, "hypothesis_id", None)
        )
        if len(candidates) != 1 or reference(candidates[0]) != expected_ref:
            raise ValueError("STALE_RESULT")

    def _complete(
        self, work: WorkExecutionState, outputs: tuple[Record, ...]
    ) -> WorkExecutionState:
        completed = self._publisher.complete(
            work,
            self._identity_ref,
            "PRIMITIVE_ADMISSION_RUNTIME",
            outputs,
            action_input_refs=work.input_refs,
        )
        if (
            completed.status != WorkStatus.SUCCEEDED
            or completed.last_transition_commit_ref is None
        ):
            raise ValueError("PRIMITIVE_COMMIT_REQUIRED")
        return completed

    def _meta(self, work: WorkExecutionState, kind: str) -> RecordMeta:
        if not isinstance(work.meta, RecordMeta) or work.meta.hypothesis_id is None:
            raise ValueError("PRIMITIVE_WORK_SCOPE_REQUIRED")
        record_id = self._ids.new(RecordId)
        meta = RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            schema_version=work.meta.schema_version,
            analysis_id=work.meta.analysis_id,
            revision_number=1,
            previous_record_id=None,
            created_at=self._clock.now(),
            workspace_id=work.meta.workspace_id,
            commit_id=work.meta.commit_id,
            hypothesis_id=work.meta.hypothesis_id,
            attempt_id=work.active_attempt_id,
        )
        return meta

    def _indexed_inputs(self, work: WorkExecutionState) -> dict[str, StoredDataRef]:
        refs: dict[str, StoredDataRef] = {}
        for item in work.input_refs:
            if not isinstance(item, StoredDataRef) or item.data_kind in refs:
                raise ValueError("PRIMITIVE_EXACT_INPUT_REQUIRED")
            refs[item.data_kind] = item
        return refs

    @staticmethod
    def _required_ref(refs: dict[str, StoredDataRef], kind: str) -> StoredDataRef:
        try:
            return refs[kind]
        except KeyError as error:
            raise ValueError("PRIMITIVE_EXACT_INPUT_REQUIRED") from error

    @staticmethod
    def _require_exact_kinds(
        refs: dict[str, StoredDataRef],
        allowed: frozenset[str],
        *,
        optional: frozenset[str] = frozenset(),
    ) -> None:
        actual = frozenset(refs)
        if not actual <= allowed or not allowed - optional <= actual:
            raise ValueError("PRIMITIVE_EXACT_INPUT_REQUIRED")

    def _optional_exact[T: DomainRecord](
        self, ref: StoredDataRef | None, model: type[T]
    ) -> T | None:
        return self._exact(ref, model) if ref is not None else None

    def _exact[T: DomainRecord](self, ref: StoredDataRef, model: type[T]) -> T:
        try:
            value = self._records.get_exact(ref)
        except (KeyError, LookupError) as error:
            raise ValueError("RECORD_REVISION_MISMATCH") from error
        if not isinstance(value, model):
            raise ValueError("RECORD_REVISION_MISMATCH")
        exact(ref, value, value.meta)
        return value

    @staticmethod
    def _require_running(work: WorkExecutionState) -> None:
        if (
            work.work_type != WorkType.PRIMITIVE_UPDATE
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
        ):
            raise ValueError("ATTEMPT_NOT_ACTIVE")


__all__ = [
    "AtomicAdmissionPublisher",
    "PrimitiveAdmissionRuntime",
    "decide_primitive_admission",
]
