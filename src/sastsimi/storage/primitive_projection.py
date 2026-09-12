"""Exact primitive admission closure and append-only current index projection."""

from collections import Counter

from sqlalchemy import Connection

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import (
    Primitive,
    PrimitiveAdmissionDecision,
    PrimitiveIndexState,
    validate_admission,
    validate_primitive_index_revision,
    validate_primitive_source,
)
from sastsimi.contracts.domain import exact, same_scope
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    PoCBundle,
)
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
    validate_technical_gate,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.policy import PolicyCollectionResult, RunPolicyState
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record

from .codec import reference
from .records import next_meta
from .run_states import get_run
from .stage_policy import resolved
from .verification_projection import current_scoped
from .work_service import WorkService


def validate_primitive_outputs(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
) -> tuple[Primitive, ...]:
    admissions = [
        item for item in outputs if isinstance(item, PrimitiveAdmissionDecision)
    ]
    primitives = [item for item in outputs if isinstance(item, Primitive)]
    if not admissions and not primitives:
        if work.work_type == "PRIMITIVE_UPDATE" and outputs:
            raise ValueError("PRIMITIVE_EXACT_OUTPUT_REQUIRED")
        return ()
    if work.work_type != "PRIMITIVE_UPDATE" or len(admissions) > 1:
        raise ValueError("PRIMITIVE_EXACT_OUTPUT_REQUIRED")
    if len(outputs) != len(primitives) + len(admissions):
        raise ValueError("PRIMITIVE_EXACT_OUTPUT_REQUIRED")
    if admissions:
        admission = admissions[0]
        verification_ref = admission.verification_result_ref
    else:
        if len(primitives) != 1:
            raise ValueError("PRIMITIVE_EXACT_OUTPUT_REQUIRED")
        admission = None
        verification_ref = primitives[0].source_verification_ref
    if _pinned_ref(work, "verification_result") != verification_ref:
        raise ValueError("PRIMITIVE_EXACT_INPUT_REQUIRED")
    verification = resolved(
        works.records,
        connection,
        verification_ref,
        VerificationResult,
    )
    process_ref = _pinned_ref(work, "hypothesis_process_state")
    process = resolved(works.records, connection, process_ref, HypothesisProcessState)
    index_ref = _pinned_ref(work, "primitive_index_state")
    index = resolved(works.records, connection, index_ref, PrimitiveIndexState)
    processes = current_scoped(
        works, connection, work, "hypothesis_process_state", HypothesisProcessState
    )
    indexes = current_scoped(
        works, connection, work, "primitive_index_state", PrimitiveIndexState
    )
    if (
        len(processes) != 1
        or len(indexes) != 1
        or reference(processes[0]) != process_ref
        or reference(indexes[0]) != index_ref
    ):
        raise ValueError("STALE_RESULT: current Verification required")
    if admission is None:
        return validate_resolved_primitive_outputs(
            work=work,
            outputs=outputs,
            verification=verification,
            process=process,
            index=index,
        )
    if (
        _pinned_ref(work, "technical_evidence_review") != admission.technical_review_ref
        or _pinned_ref(work, "policy_collection_result")
        != admission.policy_collection_result_ref
    ):
        raise ValueError("PRIMITIVE_EXACT_INPUT_REQUIRED")
    if admission.rule_scope_review_ref is not None and (
        _pinned_ref(work, "rule_scope_impact_review") != admission.rule_scope_review_ref
    ):
        raise ValueError("PRIMITIVE_EXACT_INPUT_REQUIRED")
    technical = resolved(
        works.records,
        connection,
        admission.technical_review_ref,
        TechnicalEvidenceReview,
    )
    request_ref = _pinned_ref(work, "dynamic_reproduction_request")
    dynamic_ref = _pinned_ref(work, "dynamic_reproduction_result")
    poc_ref = _pinned_ref(work, "poc_bundle")
    cwe_ref = _pinned_ref(work, "cwe_label")
    request = resolved(
        works.records, connection, request_ref, DynamicReproductionRequest
    )
    dynamic = resolved(
        works.records, connection, dynamic_ref, DynamicReproductionResult
    )
    poc = resolved(works.records, connection, poc_ref, PoCBundle)
    cwe = resolved(works.records, connection, cwe_ref, CWELabel)
    collection = resolved(
        works.records,
        connection,
        admission.policy_collection_result_ref,
        PolicyCollectionResult,
    )
    review = (
        resolved(
            works.records,
            connection,
            admission.rule_scope_review_ref,
            RuleScopeImpactReview,
        )
        if admission.rule_scope_review_ref is not None
        else None
    )
    state_ref = _pinned_ref(work, "run_policy_state")
    state = resolved(works.records, connection, state_ref, RunPolicyState)
    run = get_run(connection, str(work.meta.analysis_id))
    if run.run_policy_state_ref != state_ref:
        raise ValueError("FROZEN_POLICY_REQUIRED")
    return validate_resolved_primitive_outputs(
        work=work,
        outputs=outputs,
        verification=verification,
        process=process,
        index=index,
        request=request,
        dynamic=dynamic,
        poc=poc,
        cwe=cwe,
        technical=technical,
        admission=admission,
        collection=collection,
        state=state,
        review=review,
    )


def validate_resolved_primitive_outputs(
    *,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
    verification: VerificationResult,
    process: HypothesisProcessState,
    index: PrimitiveIndexState,
    request: DynamicReproductionRequest | None = None,
    dynamic: DynamicReproductionResult | None = None,
    poc: PoCBundle | None = None,
    cwe: CWELabel | None = None,
    technical: TechnicalEvidenceReview | None = None,
    admission: PrimitiveAdmissionDecision | None = None,
    collection: PolicyCollectionResult | None = None,
    state: RunPolicyState | None = None,
    review: RuleScopeImpactReview | None = None,
) -> tuple[Primitive, ...]:
    """Validate a fully resolved batch before its one atomic transition commit."""

    primitives = tuple(item for item in outputs if isinstance(item, Primitive))
    decisions = tuple(
        item for item in outputs if isinstance(item, PrimitiveAdmissionDecision)
    )
    if (
        work.work_type != "PRIMITIVE_UPDATE"
        or len(outputs) != len(primitives) + len(decisions)
        or len(decisions) != (1 if admission is not None else 0)
        or (admission is not None and decisions != (admission,))
    ):
        raise ValueError("PRIMITIVE_EXACT_OUTPUT_REQUIRED")
    verification_ref = _stored_reference(verification)
    process_ref = _stored_reference(process)
    index_ref = _stored_reference(index)
    same_scope(verification.meta, process.meta)
    same_scope(verification.meta, index.meta)
    if (
        process.status != "TERMINAL"
        or process.verification_result_ref != verification_ref
        or process.verification_work_ref is not None
        or index.current_verification_ref != verification_ref
    ):
        raise ValueError("STALE_RESULT: current Verification required")
    base_refs = (process_ref, verification_ref, index_ref)
    if admission is None:
        _exact_work_inputs(work, base_refs)
        if (
            verification.verdict != "HOLD"
            or not verification.required_primitive_candidates
            or len(primitives) != 1
        ):
            raise ValueError("HOLD_PRIMITIVE_MISMATCH")
        validate_primitive_source(primitives[0], verification)
        return primitives
    if (
        request is None
        or dynamic is None
        or poc is None
        or cwe is None
        or technical is None
        or collection is None
        or state is None
    ):
        raise ValueError("PRIMITIVE_ADMISSION_REQUIRED")
    if verification.dynamic_request_ref is None:
        raise ValueError("DYNAMIC_VERIFICATION_CLOSURE_MISMATCH")
    exact(verification.dynamic_request_ref, request, verification.meta)
    same_scope(verification.meta, request.meta)
    validate_technical_gate(
        technical,
        verification,
        cwe,
        dynamic,
        poc,
        current_generation=process.verification_generation,
    )
    validate_admission(admission, verification, technical, collection, state, review)
    expected_refs: list[StoredDataRef] = [
        *base_refs,
        admission.technical_review_ref,
        admission.policy_collection_result_ref,
        _stored_reference(state),
        technical.cwe_label_ref,
    ]
    for ref in (
        verification.dynamic_request_ref,
        verification.dynamic_result_ref,
        verification.poc_ref,
        state.policy_record_ref,
        admission.rule_scope_review_ref,
    ):
        if ref is not None:
            expected_refs.append(ref)
    if not all(isinstance(ref, StoredDataRef) for ref in expected_refs):
        raise ValueError("PRIMITIVE_EXACT_INPUT_REQUIRED")
    _exact_work_inputs(work, tuple(expected_refs))
    if admission.decision == "DENY":
        if primitives:
            raise ValueError("PRIMITIVE_DENY_MUST_NOT_PUBLISH")
        return ()
    if not primitives:
        raise ValueError("PRIMITIVE_ALLOW_REQUIRES_PRIMITIVE")
    admission_ref = _stored_reference(admission)
    for primitive in primitives:
        if primitive.admission_decision_ref != admission_ref:
            raise ValueError("PRIMITIVE_ADMISSION_REQUIRED")
        validate_primitive_source(primitive, verification, technical, admission)
    if Counter(canonical_bytes(item.result) for item in primitives) != Counter(
        canonical_bytes(item) for item in verification.provided_primitive_candidates
    ):
        raise ValueError("PRIMITIVE_RESULT_CLOSURE_MISMATCH")
    return primitives


def _pinned_ref(work: WorkExecutionState, kind: str) -> StoredDataRef:
    refs = tuple(
        ref
        for ref in work.input_refs
        if isinstance(ref, StoredDataRef) and ref.data_kind == kind
    )
    if len(refs) != 1:
        raise ValueError("PRIMITIVE_EXACT_INPUT_REQUIRED")
    return refs[0]


def _stored_reference(record: Record) -> StoredDataRef:
    result = reference(record)
    if not isinstance(result, StoredDataRef):
        raise ValueError("PRIMITIVE_EXACT_INPUT_REQUIRED")
    return result


def _exact_work_inputs(
    work: WorkExecutionState, expected: tuple[StoredDataRef, ...]
) -> None:
    if len(work.input_refs) != len(expected) or set(work.input_refs) != set(expected):
        raise ValueError("PRIMITIVE_EXACT_INPUT_REQUIRED")


def primitive_index_projection(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    primitives: tuple[Primitive, ...],
) -> PrimitiveIndexState | None:
    if not primitives:
        return None
    indexes = current_scoped(
        works, connection, work, "primitive_index_state", PrimitiveIndexState
    )
    if len(indexes) != 1:
        raise ValueError("PRIMITIVE_INDEX_CONFLICT")
    previous = indexes[0]
    current = PrimitiveIndexState.model_validate(
        previous.model_dump()
        | dict(
            meta=next_meta(previous.meta, works.clock, works.ids),
            primitive_refs=(
                *previous.primitive_refs,
                *(reference(primitive) for primitive in primitives),
            ),
            updated_at=works.clock.now(),
        )
    )
    validate_primitive_index_revision(previous, current)
    return current
