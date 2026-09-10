"""Bind one same-attempt Context request to a claimed, undispatched READ_CODE."""

from sqlalchemy import select

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef
from sastsimi.contracts.static import (
    CodeContextRequest,
    CodeLocation,
    CodeSymbol,
    ContextRetrievalLimits,
)
from sastsimi.ports.context import ContextRetrievalIntent
from sastsimi.static_analysis.context_retrieval import (
    context_intent_hash,
    decode_context_read_plan,
)

from . import models
from .action_context import check_owner
from .action_policy import check_role
from .codec import reference
from .context_policy import derived_context_requests, resolve_context_ceiling
from .current_inputs import check_current_input
from .transition_service import TransitionService


class ContextBindingService:
    def __init__(
        self, transitions: TransitionService, identity_ref: BudgetScopeRef | None
    ) -> None:
        self.transitions = transitions
        self.identity_ref = identity_ref

    def bind(
        self,
        work_id: str,
        used_decision_ref: RecordRef,
        *,
        requested_entities: tuple[CodeSymbol, ...],
        requested_locations: tuple[CodeLocation, ...],
        relation_query: tuple[str, ...],
        limits: ContextRetrievalLimits,
    ) -> CodeContextRequest:
        works = self.transitions.works
        records = works.records
        with records.database.write() as connection:
            if (
                self.identity_ref is None
                or records.evidence.identity_role(self.identity_ref)
                != "CONTEXT_RETRIEVAL_SERVICE"
            ):
                raise ValueError(
                    "CONTEXT_AUTHORITY_MISMATCH: trusted service identity required"
                )
            records.resolve(connection, self.identity_ref)
            work = works.get(work_id, connection)
            used = records.resolve(connection, used_decision_ref)
            if (
                not isinstance(used, ActionDecision)
                or used.decision != "ALLOW"
                or used.use_status != "USED"
            ):
                raise ValueError("CONTEXT_CLAIM_REQUIRED")
            action = records.resolve(connection, used.action_ref)
            if not isinstance(action, ActionRequest) or (
                action.action_type != "READ_CODE"
                or action.work_ref != reference(work)
                or work.work_type != "CONTEXT_RETRIEVAL"
                or work.status != "RUNNING"
                or work.active_attempt_id is None
                or getattr(action.meta, "attempt_id", None) != work.active_attempt_id
                or getattr(work.meta, "hypothesis_id", None) is None
            ):
                raise ValueError("CONTEXT_AUTHORITY_MISMATCH")
            check_role(
                action, records.evidence.identity_role(action.requester_identity_ref)
            )
            check_owner(records, connection, action, work)
            for input_ref in (*work.input_refs, *action.input_refs):
                check_current_input(records, connection, input_ref)
            receipt = connection.execute(
                select(models.action_decisions.c.payload).where(
                    models.action_decisions.c.action_id == str(action.action_id),
                )
            ).scalar()
            dispatch = (
                connection.execute(
                    select(models.external_dispatches).where(
                        models.external_dispatches.c.action_id == str(action.action_id),
                    )
                )
                .mappings()
                .one_or_none()
            )
            if (
                receipt != used.model_dump_json()
                and receipt != canonical_bytes(used).decode()
            ):
                raise ValueError("CONTEXT_CLAIM_REQUIRED: exact durable receipt")
            if (
                dispatch is None
                or dispatch["dispatched_at"] is not None
                or (
                    dispatch["attempt_id"] != str(work.active_attempt_id)
                    or dispatch["work_id"] != work_id
                )
            ):
                raise ValueError("CONTEXT_CLAIM_REQUIRED: before exact dispatch")
            if any(
                location.file_path not in action.file_paths
                for location in requested_locations
            ):
                raise ValueError("CONTEXT_PATH_MISMATCH")
            ceilings = resolve_context_ceiling(self.transitions.artifacts, work)
            plan_candidates = []
            for input_ref in action.input_refs:
                if (
                    not isinstance(input_ref, StoredDataRef)
                    or input_ref.record_id is not None
                    or input_ref == ceilings.ref
                ):
                    continue
                try:
                    with self.transitions.artifacts.open_verified(input_ref) as stream:
                        plan_raw = stream.read(limits.max_bytes + 1)
                    if len(plan_raw) > limits.max_bytes:
                        continue
                    plan_candidates.append(
                        (input_ref, decode_context_read_plan(plan_raw), plan_raw)
                    )
                except (OSError, ValueError):
                    continue
            if len(plan_candidates) != 1:
                raise ValueError("CONTEXT_PLAN_CHANGED")
            plan_ref, plan, _plan_raw = plan_candidates[0]
            expected_inputs = set(work.input_refs) | {plan_ref}
            if (
                len(action.input_refs) != len(set(action.input_refs))
                or set(action.input_refs) != expected_inputs
            ):
                raise ValueError("CONTEXT_PLAN_CHANGED")
            intent = ContextRetrievalIntent(
                proposal_ref=plan.proposal_ref,
                bundle_ref=plan.bundle_ref,
                requested_entities=requested_entities,
                requested_locations=requested_locations,
                relation_query=tuple(relation_query),  # type: ignore[arg-type]
                reason=action.reason,
                requested_limits=limits,
            )
            if (
                plan.ceiling_profile_ref != ceilings.ref
                or plan.requested_limits != limits
                or plan.entities != requested_entities
                or plan.locations != requested_locations
                or set(plan.file_paths) != set(action.file_paths)
                or len(plan.file_paths) != len(set(plan.file_paths))
                or plan.intent_hash != context_intent_hash(intent)
                or plan.proposal_ref not in work.input_refs
                or plan.bundle_ref not in work.input_refs
                or any(ref not in work.input_refs for ref in plan.lineage_refs)
            ):
                raise ValueError("CONTEXT_PLAN_CHANGED")
            bound_refs = tuple(
                ref
                for ref in used.outcome_refs
                if ref.data_kind == "code_context_request"
            )
            if bound_refs:
                if len(bound_refs) != 1:
                    raise ValueError("CONTEXT_REQUEST_ALREADY_BOUND")
                existing = records.resolve(connection, bound_refs[0])
                if not isinstance(existing, CodeContextRequest) or (
                    existing.action_decision_ref != used_decision_ref
                    or existing.requested_entities != requested_entities
                    or existing.requested_locations != requested_locations
                    or existing.relation_query != tuple(relation_query)
                    or existing.reason != action.reason
                    or existing.limits != limits
                ):
                    raise ValueError("CONTEXT_REQUEST_ALREADY_BOUND")
                return existing
            ledger = derived_context_requests(
                records,
                connection,
                analysis_id=str(work.meta.analysis_id),
                hypothesis_id=str(
                    work.meta.hypothesis_id if isinstance(work.meta, RecordMeta) else ""
                ),
            )
            if len(ledger) >= ceilings.limits.max_requests_per_hypothesis:
                raise ValueError("CONTEXT_REQUEST_LIMIT_EXCEEDED")
            record_id = works.ids.new(RecordId)
            request = CodeContextRequest.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=work.meta.model_dump()
                        | dict(
                            record_id=record_id,
                            logical_record_id=LogicalRecordId(str(record_id)),
                            record_type="code_context_request",
                            revision_number=1,
                            previous_record_id=None,
                            attempt_id=work.active_attempt_id,
                            created_at=works.clock.now(),
                        ),
                        code_request_id=str(works.ids.new(RecordId)),
                        action_decision_ref=used_decision_ref,
                        requested_entities=requested_entities,
                        requested_locations=requested_locations,
                        relation_query=relation_query,
                        reason=action.reason,
                        limits=limits,
                    )
                )
            )
            ref = records.stage(connection, request)
            records.publish(connection, ref)
            self.transitions.publish_pointer(connection, ref)
            works.validator.record_outcome(connection, used, (ref,))
            return request
