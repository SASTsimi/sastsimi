"""Deterministic READ_CODE orchestration through public runtime services."""

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.records import RecordMetadata
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import (
    CodeContextResponse,
    CodeLocation,
    ContextRetrievalLimits,
)
from sastsimi.runtime.fake_support import FakeEvidence
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner


def retrieve_fake_context(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    evidence: FakeEvidence,
    scope: StoredDataRef,
    identity: StoredDataRef,
    service_identity: StoredDataRef,
    metadata: RecordMetadata,
    hypothesis_id: str,
    generation: int,
    inputs: tuple[StoredDataRef, ...],
    location: CodeLocation,
    fragment_ref: StoredDataRef,
) -> tuple[CodeContextResponse, StoredDataRef]:
    evidence.bind_identity(identity, RequesterRole.VERIFICATION)
    work = runner.start(
        scope,
        metadata,
        "CONTEXT_RETRIEVAL",
        "HYPOTHESIS",
        hypothesis_id,
        identity,
        role="VERIFICATION",
        inputs=inputs,
        generation=generation,
    )

    action = runner.action(
        work,
        identity,
        "VERIFICATION",
        "READ_CODE",
        file_paths=(str(location.file_path),),
    )
    units = runner.units(elapsed_ms=1, cost_minor_units=1)
    reservation = runner.reserve(work, scope, action, units)
    decision = runner.authorize(work, action, reservation)
    used = runtime.validator.claim_external(
        str(work.work_id), decision, reference(reservation)
    )
    evidence.bind_identity(service_identity, RequesterRole.CONTEXT_RETRIEVAL_SERVICE)
    request = runtime.context.bind(
        str(work.work_id),
        used,
        requested_entities=(),
        requested_locations=(location,),
        relation_query=("CALLERS", "CALLEES"),
        limits=ContextRetrievalLimits(
            max_depth=1,
            max_fragments=1,
            max_bytes=4096,
            max_requests_per_hypothesis=1,
            timeout_ms=1000,
        ),
    )
    runtime.validator.mark_dispatched(decision, idempotency_key=str(action.action_id))
    runtime.validator.mark_returned(decision)
    runner.account(reservation, units)
    response = CodeContextResponse.model_validate_json(
        canonical_bytes(
            dict(
                meta=runner.metadata(
                    work.meta,
                    "code_context_response",
                    attempt_id=work.active_attempt_id,
                ),
                code_request_id=request.code_request_id,
                entities=(),
                locations=(location,),
                code_fragment_refs=(fragment_ref,),
                discovered_relations=(),
                gaps=(),
                errors=(),
                truncated=False,
                returned_fragment_count=1,
                returned_bytes=len(
                    runtime.unit_of_work.artifacts.open_verified(fragment_ref).read()
                ),
                consumed_token_estimate=1,
            )
        )
    )
    completed = runner.complete(
        work, service_identity, "CONTEXT_RETRIEVAL_SERVICE", (response,)
    )
    output_ref = completed.output_refs[0]
    if not isinstance(output_ref, StoredDataRef) or output_ref != reference(response):
        raise ValueError("FAKE_CONTEXT_OUTPUT_MISMATCH")
    return response, output_ref
