"""Context requests are bound to durable READ_CODE claims, not caller IDs."""

from pathlib import Path

import pytest

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import (
    CodeContextResponse,
    CodeLocation,
    ContextRetrievalLimits,
)
from sastsimi.ports.context import ContextReadPlan, ContextRetrievalIntent
from sastsimi.static_analysis.context_retrieval import context_intent_hash
from tests.integration.storage.test_intermediate_publication import (
    prepared_policy_parser,
)


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        "request",
        "scope",
        "owner",
        "unused",
        "other-work",
        "revoked-reader",
        "revoked-service",
        "unbound-dispatch",
    ],
)
def test_context_service_binds_used_read_then_commits_its_response(
    tmp_path: Path, invalid: str | None
) -> None:
    h, runtime, runner, policy_work, parser, _ = prepared_policy_parser(
        tmp_path, context=True
    )
    identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    runner.complete(policy_work, identity, "POLICY_PARSER", (parser,))
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    service_identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.CONTEXT_RETRIEVAL_SERVICE
    )
    meta = RecordMeta.model_validate_json(
        canonical_bytes(
            parser.meta.model_dump()
            | dict(
                hypothesis_id="h1",
                attempt_id=None,
            )
        )
    )
    limits = ContextRetrievalLimits(
        max_depth=1,
        max_fragments=1,
        max_bytes=4096,
        max_requests_per_hypothesis=2,
        timeout_ms=100,
    )
    location = CodeLocation(
        workspace_id=meta.workspace_id,
        commit_id=meta.commit_id,
        file_path="src/app.py",
        start_line=1,
        start_column=None,
        end_line=1,
        end_column=None,
    )
    ceiling_ref = runtime.unit_of_work.artifacts.commit(
        runtime.unit_of_work.artifacts.stage_bytes(
            canonical_bytes(
                {
                    "kind": "context_ceiling_profile",
                    "schema_version": "1.0",
                    **limits.model_dump(),
                }
            ),
            "application/json",
        )
    )
    parser_ref = reference(parser)
    assert isinstance(parser_ref, StoredDataRef)
    work = runner.start(
        scope,
        meta,
        "CONTEXT_RETRIEVAL",
        "HYPOTHESIS",
        "h1",
        identity,
        inputs=(parser_ref, ceiling_ref),
    )
    intent = ContextRetrievalIntent(
        proposal_ref=parser_ref,
        bundle_ref=parser_ref,
        requested_entities=(),
        requested_locations=(location,),
        relation_query=(),
        reason="Read exact context",
        requested_limits=limits,
    )
    plan = ContextReadPlan(
        intent_hash=context_intent_hash(intent),
        workspace_id=str(meta.workspace_id),
        commit_id=str(meta.commit_id),
        proposal_ref=parser_ref,
        bundle_ref=parser_ref,
        ceiling_profile_ref=ceiling_ref,
        requested_limits=limits,
        entities=(),
        locations=(location,),
        relations=(),
        file_paths=("src/app.py",),
        lineage_refs=(),
    )
    plan_ref = runtime.unit_of_work.artifacts.commit(
        runtime.unit_of_work.artifacts.stage_bytes(
            canonical_bytes(plan), "application/json"
        )
    )
    h.evidence.identities[identity] = RequesterRole.PRO
    action = runner.action(
        work,
        identity,
        "PRO",
        "READ_CODE",
        input_refs=(*work.input_refs, plan_ref),
        file_paths=("src/app.py",),
        reason=intent.reason,
    )
    reservation = runner.reserve(
        work, scope, action, runner.units(elapsed_ms=1, cost_minor_units=1)
    )
    reservation_ref = h.records.stage_record(reservation)
    decision = runner.authorize(work, action, reservation)
    used_ref = runtime.validator.claim_external(
        str(work.work_id), decision, reservation_ref
    )
    assert used_ref is not None
    if invalid == "unbound-dispatch":
        with pytest.raises(ValueError, match="CONTEXT_REQUEST_REQUIRED"):
            runtime.validator.mark_dispatched(decision)
        return
    if invalid in {"unused", "other-work", "revoked-reader", "revoked-service"}:
        if invalid == "revoked-reader":
            h.evidence.identities[identity] = RequesterRole.CON
        if invalid == "revoked-service":
            h.evidence.identities[service_identity] = RequesterRole.PRO
        with pytest.raises(ValueError, match="CONTEXT_|AUTHORITY_DENIED"):
            runtime.context.bind(
                str(policy_work.work_id)
                if invalid == "other-work"
                else str(work.work_id),
                decision if invalid == "unused" else used_ref,
                requested_entities=(),
                requested_locations=(location,),
                relation_query=(),
                limits=limits,
            )
        return
    request = runtime.context.bind(
        str(work.work_id),
        used_ref,
        requested_entities=(),
        requested_locations=(location,),
        relation_query=(),
        limits=limits,
    )
    assert request.action_decision_ref == used_ref
    assert request.meta.attempt_id == work.active_attempt_id
    runtime.validator.mark_dispatched(decision)
    runtime.validator.mark_returned(decision)
    runner.account(reservation, runner.units(elapsed_ms=1, cost_minor_units=1))
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
                code_fragment_refs=(),
                discovered_relations=(),
                gaps=(),
                errors=(),
                truncated=False,
                returned_fragment_count=0,
                returned_bytes=0,
                consumed_token_estimate=None,
            )
        )
    )
    if invalid in {"request", "scope"}:
        data = response.model_dump(mode="json")
        if invalid == "request":
            data["code_request_id"] = "different-request"
        else:
            data["meta"]["workspace_id"] = "different-workspace"
        response = CodeContextResponse.model_validate_json(canonical_bytes(data))
    if invalid == "owner":
        h.evidence.identities[service_identity] = RequesterRole.PRO
    if invalid is not None:
        with pytest.raises(
            ValueError, match="CONTEXT_|AUTHORITY_DENIED|WORKSPACE_MISMATCH"
        ):
            runner.complete(
                work, service_identity, "CONTEXT_RETRIEVAL_SERVICE", (response,)
            )
        assert runtime.work.get(str(work.work_id)).status == "RUNNING"
        return
    completed = runner.complete(
        work, service_identity, "CONTEXT_RETRIEVAL_SERVICE", (response,)
    )
    assert completed.status == "SUCCEEDED"
    assert h.records.get_exact(completed.output_refs[0]) == response
