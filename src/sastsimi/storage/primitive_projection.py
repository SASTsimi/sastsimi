"""Exact primitive admission closure and append-only current index projection."""

from sqlalchemy import Connection

from sastsimi.contracts.chaining import (
    Primitive,
    PrimitiveAdmissionDecision,
    PrimitiveIndexState,
    validate_admission,
    validate_primitive_index_revision,
    validate_primitive_source,
)
from sastsimi.contracts.gates import RuleScopeImpactReview, TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.policy import PolicyCollectionResult, RunPolicyState
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
        return ()
    if (
        work.work_type != "PRIMITIVE_UPDATE"
        or len(admissions) != 1
        or not primitives
        or len(outputs) != len(primitives) + 1
    ):
        raise ValueError("PRIMITIVE_EXACT_OUTPUT_REQUIRED")
    admission = admissions[0]
    verification = resolved(
        works.records,
        connection,
        admission.verification_result_ref,
        VerificationResult,
    )
    technical = resolved(
        works.records,
        connection,
        admission.technical_review_ref,
        TechnicalEvidenceReview,
    )
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
    run = get_run(connection, str(work.meta.analysis_id))
    if run.run_policy_state_ref is None:
        raise ValueError("FROZEN_POLICY_REQUIRED")
    state = resolved(
        works.records, connection, run.run_policy_state_ref, RunPolicyState
    )
    processes = current_scoped(
        works, connection, work, "hypothesis_process_state", HypothesisProcessState
    )
    indexes = current_scoped(
        works, connection, work, "primitive_index_state", PrimitiveIndexState
    )
    if (
        len(processes) != 1
        or len(indexes) != 1
        or processes[0].status != "TERMINAL"
        or processes[0].verification_result_ref != reference(verification)
        or indexes[0].current_verification_ref != reference(verification)
    ):
        raise ValueError("STALE_RESULT: current Verification required")
    validate_admission(admission, verification, technical, collection, state, review)
    admission_ref = reference(admission)
    for primitive in primitives:
        if primitive.admission_decision_ref != admission_ref:
            raise ValueError("PRIMITIVE_ADMISSION_REQUIRED")
        validate_primitive_source(primitive, verification, technical, admission)
    return tuple(primitives)


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
