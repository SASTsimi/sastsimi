"""Bind one same-attempt Context request to a claimed, undispatched READ_CODE."""

from sqlalchemy import select

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef
from sastsimi.contracts.static import (
    CodeContextRequest,
    CodeLocation,
    CodeSymbol,
    ContextRetrievalLimits,
)

from . import models
from .action_context import check_owner
from .action_policy import check_role
from .codec import reference
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
            if any(
                ref.data_kind == "code_context_request" for ref in used.outcome_refs
            ):
                raise ValueError("CONTEXT_REQUEST_ALREADY_BOUND")
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
