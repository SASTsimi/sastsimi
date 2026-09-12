"""Public, non-persisted seams for Primitive admission and Chaining.

The LLM-facing values in this module contain prompt-local keys and explanatory
content only.  Exact references, record metadata, and runtime-owned identifiers
remain on trusted runtime/storage seams.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.ids import ProposalId
from sastsimi.contracts.records import RecordMeta, RecordMetadata
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    StoredDataRef,
    reference,
    require_record_ref,
)
from sastsimi.contracts.work import SubjectType, WorkExecutionState, WorkType

from .dto import WorkContext
from .llm_invocation import PersistedLLMInvocation


def _require_kind(value: StoredDataRef, kind: str, code: str) -> None:
    try:
        require_record_ref(value, kind)
    except ValueError as error:
        raise ValueError(code) from error


def _require_non_empty(value: str, code: str) -> None:
    if not value.strip():
        raise ValueError(code)


def _require_unique[T](values: tuple[T, ...], code: str) -> None:
    if any(value in values[:index] for index, value in enumerate(values)):
        raise ValueError(code)


@dataclass(frozen=True, slots=True)
class HoldPrimitiveAdmissionClosure:
    """Exact final HOLD state needed before admission can be requested."""

    verification_ref: StoredDataRef
    hypothesis_process_ref: StoredDataRef
    expected_primitive_index_ref: StoredDataRef

    def __post_init__(self) -> None:
        for value, kind in (
            (self.verification_ref, "verification_result"),
            (self.hypothesis_process_ref, "hypothesis_process_state"),
            (self.expected_primitive_index_ref, "primitive_index_state"),
        ):
            _require_kind(value, kind, "PRIMITIVE_ADMISSION_REF_KIND")
        _require_unique(self.input_refs(), "PRIMITIVE_ADMISSION_REF_DUPLICATE")

    def input_refs(self) -> tuple[StoredDataRef, ...]:
        return (
            self.verification_ref,
            self.hypothesis_process_ref,
            self.expected_primitive_index_ref,
        )


@dataclass(frozen=True, slots=True)
class TruePrimitiveAdmissionClosure:
    """Exact accepted-TRUE proof and frozen-policy chain for admission."""

    hypothesis_process_ref: StoredDataRef
    verification_ref: StoredDataRef
    dynamic_request_ref: StoredDataRef
    dynamic_result_ref: StoredDataRef
    poc_ref: StoredDataRef
    cwe_label_ref: StoredDataRef
    technical_review_ref: StoredDataRef
    run_policy_state_ref: StoredDataRef
    collection_ref: StoredDataRef
    expected_primitive_index_ref: StoredDataRef
    policy_ref: StoredDataRef | None = None
    rule_scope_review_ref: StoredDataRef | None = None

    def __post_init__(self) -> None:
        for value, kind in (
            (self.hypothesis_process_ref, "hypothesis_process_state"),
            (self.verification_ref, "verification_result"),
            (self.dynamic_request_ref, "dynamic_reproduction_request"),
            (self.dynamic_result_ref, "dynamic_reproduction_result"),
            (self.poc_ref, "poc_bundle"),
            (self.cwe_label_ref, "cwe_label"),
            (self.technical_review_ref, "technical_evidence_review"),
            (self.run_policy_state_ref, "run_policy_state"),
            (self.collection_ref, "policy_collection_result"),
            (self.expected_primitive_index_ref, "primitive_index_state"),
        ):
            _require_kind(value, kind, "PRIMITIVE_ADMISSION_REF_KIND")
        for optional_value, kind in (
            (self.policy_ref, "program_policy_record"),
            (self.rule_scope_review_ref, "rule_scope_impact_review"),
        ):
            if optional_value is not None:
                _require_kind(optional_value, kind, "PRIMITIVE_ADMISSION_REF_KIND")
        _require_unique(self.input_refs(), "PRIMITIVE_ADMISSION_REF_DUPLICATE")

    def input_refs(self) -> tuple[StoredDataRef, ...]:
        return (
            self.hypothesis_process_ref,
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
            self.expected_primitive_index_ref,
        )


type PrimitiveAdmissionClosure = (
    HoldPrimitiveAdmissionClosure | TruePrimitiveAdmissionClosure
)


class PrimitiveAdmissionSourcePort(Protocol):
    """Resolve only the exact closure pinned by a claimed current work."""

    def resolve(self, context: WorkContext) -> PrimitiveAdmissionClosure: ...


class PrimitiveAdmissionPort(Protocol):
    """Finalize one already-claimed Primitive update, without scheduling children."""

    def admit(self, context: WorkContext) -> WorkExecutionState: ...


@dataclass(frozen=True, slots=True)
class PrimitiveUpdateOutcome:
    """Committed admission/index outcome; no mutable projection is exposed."""

    source_work_ref: StoredDataRef
    transition_commit_ref: StoredDataRef
    admission_decision_ref: StoredDataRef | None
    primitive_refs: tuple[StoredDataRef, ...]
    primitive_index_ref: StoredDataRef | None

    def __post_init__(self) -> None:
        _require_kind(
            self.source_work_ref,
            "work_execution_state",
            "PRIMITIVE_UPDATE_OUTCOME_REF_KIND",
        )
        _require_kind(
            self.transition_commit_ref,
            "transition_commit",
            "PRIMITIVE_UPDATE_OUTCOME_REF_KIND",
        )
        if self.admission_decision_ref is not None:
            _require_kind(
                self.admission_decision_ref,
                "primitive_admission_decision",
                "PRIMITIVE_UPDATE_OUTCOME_REF_KIND",
            )
        for value in self.primitive_refs:
            _require_kind(value, "primitive", "PRIMITIVE_UPDATE_OUTCOME_REF_KIND")
        if self.primitive_index_ref is not None:
            _require_kind(
                self.primitive_index_ref,
                "primitive_index_state",
                "PRIMITIVE_UPDATE_OUTCOME_REF_KIND",
            )
        _require_unique(self.primitive_refs, "PRIMITIVE_UPDATE_REF_DUPLICATE")
        if bool(self.primitive_refs) != (self.primitive_index_ref is not None):
            raise ValueError("PRIMITIVE_UPDATE_INDEX_MISMATCH")
        if not self.primitive_refs and self.admission_decision_ref is None:
            raise ValueError("PRIMITIVE_UPDATE_EMPTY_OUTCOME")


@dataclass(frozen=True, slots=True)
class PinnedChainingUniverse:
    """Complete immutable comparison universe captured before work readiness."""

    trigger_primitive_ref: StoredDataRef
    index_refs: tuple[StoredDataRef, ...]
    considered_primitive_refs: tuple[StoredDataRef, ...]

    def __post_init__(self) -> None:
        _require_kind(
            self.trigger_primitive_ref,
            "primitive",
            "CHAINING_PINNED_REF_KIND",
        )
        for value in self.index_refs:
            _require_kind(value, "primitive_index_state", "CHAINING_PINNED_REF_KIND")
        for value in self.considered_primitive_refs:
            _require_kind(value, "primitive", "CHAINING_PINNED_REF_KIND")
        if not self.index_refs or not self.considered_primitive_refs:
            raise ValueError("CHAINING_PINNED_UNIVERSE_EMPTY")
        _require_unique(self.index_refs, "CHAINING_PINNED_REF_DUPLICATE")
        _require_unique(self.considered_primitive_refs, "CHAINING_PINNED_REF_DUPLICATE")
        if self.considered_primitive_refs.count(self.trigger_primitive_ref) != 1:
            raise ValueError("CHAINING_TRIGGER_NOT_PINNED")


@dataclass(frozen=True, slots=True)
class ChainingPoolHistory:
    """Historical pool for one exact trigger work, never a current lookup."""

    trigger_work_ref: StoredDataRef
    universe: PinnedChainingUniverse

    def __post_init__(self) -> None:
        _require_kind(
            self.trigger_work_ref,
            "work_execution_state",
            "CHAINING_POOL_WORK_REF_KIND",
        )


class ChainingPoolHistoryPort(Protocol):
    """Read one immutable work-time pool by its exact trigger-work ref."""

    def get_for_trigger(
        self, trigger_work_ref: StoredDataRef
    ) -> ChainingPoolHistory: ...

    def get_for_primitive(
        self, trigger_primitive_ref: StoredDataRef
    ) -> ChainingPoolHistory: ...


@dataclass(frozen=True, slots=True)
class ChainingCohortMember:
    work: WorkExecutionState
    pool: ChainingPoolHistory


@dataclass(frozen=True, slots=True)
class ChainingCohortRegistration:
    """One complete sibling cohort with a uniform visibility state."""

    source_update_ref: StoredDataRef
    members: tuple[ChainingCohortMember, ...]
    status: Literal["PENDING", "READY"]

    def __post_init__(self) -> None:
        _require_kind(
            self.source_update_ref,
            "transition_commit",
            "CHAINING_COHORT_SOURCE_KIND",
        )
        if not self.members:
            raise ValueError("CHAINING_COHORT_EMPTY")
        work_ids = tuple(str(member.work.work_id) for member in self.members)
        trigger_refs = tuple(
            member.pool.universe.trigger_primitive_ref for member in self.members
        )
        _require_unique(work_ids, "CHAINING_COHORT_MEMBER_DUPLICATE")
        _require_unique(trigger_refs, "CHAINING_COHORT_MEMBER_DUPLICATE")
        first = self.members[0].work
        if not isinstance(first.meta, RecordMeta):
            raise ValueError("CHAINING_COHORT_SCOPE_MISMATCH")
        for member in self.members:
            work = member.work
            if work.status != self.status:
                raise ValueError("CHAINING_COHORT_PARTIAL_VISIBILITY")
            if not isinstance(work.meta, RecordMeta) or any(
                (
                    work.work_type != WorkType.CHAINING,
                    work.subject_type != SubjectType.ANALYSIS,
                    work.meta.analysis_id != first.meta.analysis_id,
                    work.meta.workspace_id != first.meta.workspace_id,
                    work.meta.commit_id != first.meta.commit_id,
                    work.work_generation != first.work_generation,
                    self.source_update_ref.workspace_id != work.meta.workspace_id,
                    self.source_update_ref.commit_id != work.meta.commit_id,
                )
            ):
                raise ValueError("CHAINING_COHORT_SCOPE_MISMATCH")
            work_ref = reference(work)
            expected_inputs = (
                *member.pool.universe.index_refs,
                *member.pool.universe.considered_primitive_refs,
            )
            if (
                not isinstance(work_ref, StoredDataRef)
                or member.pool.trigger_work_ref != work_ref
                or work.trigger_primitive_ref
                != member.pool.universe.trigger_primitive_ref
                or len(work.input_refs) != len(expected_inputs)
                or any(value not in work.input_refs for value in expected_inputs)
                or any(value not in expected_inputs for value in work.input_refs)
            ):
                raise ValueError("CHAINING_COHORT_POOL_MISMATCH")


class ChainingCohortPort(Protocol):
    """Pin one committed Primitive update and register its sibling cohort.

    The caller supplies the exact committed update outcome, never a universe
    assembled from a mutable/current read.  The implementation resolves the
    outcome's exact ``primitive_index_ref`` and builds every immutable sibling
    universe from that index inside the registration transaction.
    """

    def register_pending(
        self,
        *,
        outcome: PrimitiveUpdateOutcome,
        scope: BudgetScopeRef,
        requester_identity_ref: BudgetScopeRef,
        metadata: RecordMetadata,
        generation: int,
    ) -> ChainingCohortRegistration: ...

    def promote_ready(
        self,
        *,
        registration: ChainingCohortRegistration,
        scope: BudgetScopeRef,
        requester_identity_ref: BudgetScopeRef,
    ) -> ChainingCohortRegistration: ...


@dataclass(frozen=True, slots=True)
class ChainingEvidence:
    evidence_key: str
    kind: Literal[
        "CODE_FLOW", "ENTITY", "PRIVILEGE", "ORDER", "RESTRICTION", "VERIFICATION"
    ]
    summary: str

    def __post_init__(self) -> None:
        _require_non_empty(self.evidence_key, "CHAINING_CONTENT_EMPTY")
        _require_non_empty(self.summary, "CHAINING_CONTENT_EMPTY")


@dataclass(frozen=True, slots=True)
class ChainingPrimitiveInput:
    input_key: str
    description: str
    entity_keys: tuple[str, ...]
    privilege_level: str | None
    evidence_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChainingPrimitiveResult:
    description: str
    entity_keys: tuple[str, ...]
    privilege_level: str | None
    evidence_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChainingPrimitive:
    primitive_key: str
    description: str
    inputs: tuple[ChainingPrimitiveInput, ...]
    result: ChainingPrimitiveResult | None
    restrictions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChainingComparison:
    comparison_key: str
    upstream_key: str
    downstream_key: str
    input_key: str


@dataclass(frozen=True, slots=True)
class ChainingAgentInput:
    """Prompt payload with no stored references or runtime-owned identifiers."""

    evidence: tuple[ChainingEvidence, ...]
    primitives: tuple[ChainingPrimitive, ...]
    comparisons: tuple[ChainingComparison, ...]

    def __post_init__(self) -> None:
        evidence_keys = tuple(item.evidence_key for item in self.evidence)
        primitive_keys = tuple(item.primitive_key for item in self.primitives)
        comparison_keys = tuple(item.comparison_key for item in self.comparisons)
        for values in (evidence_keys, primitive_keys, comparison_keys):
            _require_unique(values, "CHAINING_PROMPT_KEY_DUPLICATE")
        primitives = {item.primitive_key: item for item in self.primitives}
        for comparison in self.comparisons:
            upstream = primitives.get(comparison.upstream_key)
            downstream = primitives.get(comparison.downstream_key)
            if (
                upstream is None
                or upstream.result is None
                or downstream is None
                or comparison.upstream_key == comparison.downstream_key
                or comparison.input_key
                not in {item.input_key for item in downstream.inputs}
            ):
                raise ValueError("CHAINING_PROMPT_COMPARISON_MISMATCH")


@dataclass(frozen=True, slots=True)
class ChainedHypothesisContent:
    statement: str
    vulnerability_type_candidates: tuple[str, ...]
    falsification_questions: tuple[str, ...]
    validation_checks: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_non_empty(self.statement, "CHAINING_CHILD_CONTENT_EMPTY")
        if not self.falsification_questions or not self.validation_checks:
            raise ValueError("CHAINING_CHILD_CHECKS_REQUIRED")


@dataclass(frozen=True, slots=True)
class ChainingDecision:
    comparison_key: str
    outcome: Literal["MATCH", "NO_MATCH"]
    reason_code: (
        Literal[
            "ENTITY_UNRELATED",
            "PRIVILEGE_UNSATISFIED",
            "ORDER_INVALID",
            "RESTRICTION_CONFLICT",
            "NO_CODE_EVIDENCE",
        ]
        | None
    )
    detail: str
    evidence_keys: tuple[str, ...]
    child: ChainedHypothesisContent | None

    def __post_init__(self) -> None:
        _require_non_empty(self.comparison_key, "CHAINING_CONTENT_EMPTY")
        _require_non_empty(self.detail, "CHAINING_CONTENT_EMPTY")
        if self.outcome == "MATCH":
            if self.child is None:
                raise ValueError("CHAINING_MATCH_CHILD_REQUIRED")
            if self.reason_code is not None or not self.evidence_keys:
                raise ValueError("CHAINING_MATCH_CONTENT_MISMATCH")
        elif self.child is not None or self.reason_code is None:
            raise ValueError("CHAINING_NO_MATCH_CONTENT_MISMATCH")


@dataclass(frozen=True, slots=True)
class ChainingAgentOutput:
    """Untrusted content to be finalized with trusted refs and IDs."""

    decisions: tuple[ChainingDecision, ...]

    def __post_init__(self) -> None:
        _require_unique(
            tuple(item.comparison_key for item in self.decisions),
            "CHAINING_DECISION_DUPLICATE",
        )


@dataclass(frozen=True, slots=True)
class ChainingAgentOutcome:
    invocation: PersistedLLMInvocation
    content: ChainingAgentOutput | None

    def __post_init__(self) -> None:
        succeeded = (
            self.invocation.dispatch_state == "RETURNED"
            and self.invocation.result.status == "SUCCEEDED"
        )
        if succeeded != (self.content is not None):
            raise ValueError("CHAINING_INVOCATION_OUTCOME_MISMATCH")


class ChainingAgentPort(Protocol):
    async def match(
        self,
        *,
        context: WorkContext,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
        content: ChainingAgentInput,
    ) -> ChainingAgentOutcome: ...


class ChainingResultPublisherPort(Protocol):
    """Atomically publish one trusted result through its claimed work."""

    def publish(
        self,
        *,
        context: WorkContext,
        result: ChainingResult,
        action_input_refs: tuple[RecordRef, ...],
    ) -> WorkExecutionState: ...


class ChainingLineagePort(Protocol):
    """Resolve committed ancestors inside one exact pinned universe."""

    def ancestors(
        self,
        *,
        primitive_ref: StoredDataRef,
        universe: PinnedChainingUniverse,
    ) -> tuple[StoredDataRef, ...]: ...


@dataclass(frozen=True, slots=True)
class ChainingMatchIdentity:
    """Trusted result-finalization identity reserved atomically by storage."""

    primitive_match_id: str
    upstream_result_ref: StoredDataRef
    downstream_input_ref: StoredDataRef
    matched_input_id: str

    def __post_init__(self) -> None:
        _require_non_empty(self.primitive_match_id, "CHAINING_MATCH_ID_EMPTY")
        _require_non_empty(self.matched_input_id, "CHAINING_INPUT_ID_EMPTY")
        for value in (self.upstream_result_ref, self.downstream_input_ref):
            _require_kind(value, "primitive", "CHAINING_MATCH_REF_KIND")
        if self.upstream_result_ref == self.downstream_input_ref:
            raise ValueError("CHAINING_SELF_MATCH")


class ChainingMatchReservationPort(Protocol):
    """Reserve every identity inside the same transaction as the result."""

    def reserve_for_result(
        self,
        *,
        source_result_ref: StoredDataRef,
        identities: tuple[ChainingMatchIdentity, ...],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class PrimitiveUpdateReconciliationRequest:
    source_update_ref: StoredDataRef

    def __post_init__(self) -> None:
        _require_kind(
            self.source_update_ref,
            "transition_commit",
            "RECONCILIATION_SOURCE_KIND",
        )


@dataclass(frozen=True, slots=True)
class ChainingResultReconciliationRequest:
    source_result_ref: StoredDataRef

    def __post_init__(self) -> None:
        _require_kind(
            self.source_result_ref,
            "chaining_result",
            "RECONCILIATION_SOURCE_KIND",
        )


class ChainingReconciliationPort(Protocol):
    def reconcile_primitive_update(
        self,
        request: PrimitiveUpdateReconciliationRequest,
    ) -> ChainingCohortRegistration | None: ...

    def reconcile_chaining_result(
        self,
        request: ChainingResultReconciliationRequest,
    ) -> tuple[WorkExecutionState, ...]: ...


class ChainingCommittedSourcePort(Protocol):
    """Rebuild post-commit handoffs from exact committed source records only."""

    def primitive_update(
        self, source_update_ref: StoredDataRef
    ) -> PrimitiveUpdateOutcome: ...

    def chaining_result(self, source_result_ref: StoredDataRef) -> ChainingResult: ...


class ChainingChildHandoffPort(Protocol):
    """Enqueue one nested proposal as READY without claiming or executing it."""

    def enqueue_ready(
        self,
        *,
        source_result_ref: StoredDataRef,
        proposal_id: ProposalId,
        requester_identity_ref: BudgetScopeRef,
    ) -> WorkExecutionState: ...


@dataclass(frozen=True, slots=True)
class ChainingProposalRegistration:
    """Exact projected child records and its not-yet-claimed Verification work."""

    source_result_ref: StoredDataRef
    proposal: HypothesisProposal
    proposal_ref: StoredDataRef
    hypothesis_ref: StoredDataRef
    process_ref: StoredDataRef
    verification_work: WorkExecutionState

    def __post_init__(self) -> None:
        _require_kind(
            self.source_result_ref, "chaining_result", "CHAINING_CHILD_REF_KIND"
        )
        for value, kind in (
            (self.proposal_ref, "hypothesis_proposal"),
            (self.hypothesis_ref, "vulnerability_hypothesis"),
            (self.process_ref, "hypothesis_process_state"),
        ):
            _require_kind(value, kind, "CHAINING_CHILD_REF_KIND")
        if (
            reference(self.proposal) != self.proposal_ref
            or self.proposal.origin != "CHAINING"
            or self.verification_work.work_type != WorkType.VERIFICATION
            or self.verification_work.subject_type != SubjectType.HYPOTHESIS
            or self.verification_work.status != "READY"
            or self.verification_work.active_attempt_id is not None
            or self.proposal_ref not in self.verification_work.input_refs
        ):
            raise ValueError("CHAINING_CHILD_REGISTRATION_MISMATCH")


class ChainingProposalRegistrationPort(Protocol):
    """Commit one claimed child proposal and enqueue Verification as READY."""

    def register_claimed(
        self,
        *,
        context: WorkContext,
        source_result_ref: StoredDataRef,
        proposal_id: ProposalId,
        requester_identity_ref: BudgetScopeRef,
    ) -> ChainingProposalRegistration: ...


__all__ = [
    "ChainedHypothesisContent",
    "ChainingAgentInput",
    "ChainingAgentOutcome",
    "ChainingAgentOutput",
    "ChainingAgentPort",
    "ChainingChildHandoffPort",
    "ChainingCommittedSourcePort",
    "ChainingCohortMember",
    "ChainingCohortPort",
    "ChainingCohortRegistration",
    "ChainingComparison",
    "ChainingDecision",
    "ChainingEvidence",
    "ChainingLineagePort",
    "ChainingMatchIdentity",
    "ChainingMatchReservationPort",
    "ChainingPoolHistory",
    "ChainingPoolHistoryPort",
    "ChainingProposalRegistration",
    "ChainingProposalRegistrationPort",
    "ChainingPrimitive",
    "ChainingPrimitiveInput",
    "ChainingPrimitiveResult",
    "ChainingReconciliationPort",
    "ChainingResultPublisherPort",
    "ChainingResultReconciliationRequest",
    "HoldPrimitiveAdmissionClosure",
    "PinnedChainingUniverse",
    "PrimitiveAdmissionClosure",
    "PrimitiveAdmissionPort",
    "PrimitiveAdmissionSourcePort",
    "PrimitiveUpdateOutcome",
    "PrimitiveUpdateReconciliationRequest",
    "TruePrimitiveAdmissionClosure",
]
