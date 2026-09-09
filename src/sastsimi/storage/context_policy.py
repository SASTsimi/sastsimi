"""Resolve exact READ_CODE request provenance before Context response publication."""

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.static import CodeContextRequest, CodeContextResponse
from sastsimi.contracts.work import WorkExecutionState

from . import models
from .codec import reference
from .repositories import SQLiteRecordStore


def require_context_request(
    records: SQLiteRecordStore,
    connection: Connection,
    action: ActionRequest,
    work: WorkExecutionState,
) -> None:
    payload = connection.execute(
        select(models.action_decisions.c.payload).where(
            models.action_decisions.c.action_id == str(action.action_id),
        )
    ).scalar()
    if payload is None:
        raise ValueError("CONTEXT_REQUEST_REQUIRED")
    used = ActionDecision.model_validate_json(payload)
    refs = [ref for ref in used.outcome_refs if ref.data_kind == "code_context_request"]
    if len(refs) != 1:
        raise ValueError("CONTEXT_REQUEST_REQUIRED")
    request = records.resolve(connection, refs[0])
    if (
        not isinstance(request, CodeContextRequest)
        or request.meta.attempt_id != work.active_attempt_id
    ):
        raise ValueError("CONTEXT_REQUEST_REQUIRED")
    origin = records.resolve(connection, request.action_decision_ref)
    if (
        not isinstance(origin, ActionDecision)
        or origin.use_status != "USED"
        or (
            origin.action_ref != reference(action)
            or origin.decision_id != used.decision_id
        )
    ):
        raise ValueError("CONTEXT_REQUEST_REQUIRED")


def check_context_response(
    records: SQLiteRecordStore,
    connection: Connection,
    work: WorkExecutionState,
    response: CodeContextResponse,
) -> None:
    if (
        work.work_type != "CONTEXT_RETRIEVAL"
        or work.status != "RUNNING"
        or (
            work.active_attempt_id is None
            or response.meta.attempt_id != work.active_attempt_id
            or any(
                getattr(response.meta, name, None) != getattr(work.meta, name, None)
                for name in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                )
            )
        )
    ):
        raise ValueError("CONTEXT_RESPONSE_SCOPE_MISMATCH")
    matching = []
    for payload in connection.execute(
        select(models.action_decisions.c.payload)
    ).scalars():
        used = ActionDecision.model_validate_json(payload)
        if used.use_status != "USED" or used.decision != "ALLOW":
            continue
        action = records.resolve(connection, used.action_ref)
        if (
            not isinstance(action, ActionRequest)
            or action.action_type != "READ_CODE"
            or (
                action.work_ref != reference(work)
                or getattr(action.meta, "attempt_id", None) != work.active_attempt_id
            )
        ):
            continue
        dispatch = (
            connection.execute(
                select(models.external_dispatches).where(
                    models.external_dispatches.c.action_id == str(action.action_id),
                )
            )
            .mappings()
            .one_or_none()
        )
        if dispatch is None or dispatch["returned_at"] is None:
            continue
        for ref in used.outcome_refs:
            if ref.data_kind != "code_context_request":
                continue
            request = records.resolve(connection, ref)
            if (
                not isinstance(request, CodeContextRequest)
                or request.code_request_id != response.code_request_id
            ):
                continue
            origin = records.resolve(connection, request.action_decision_ref)
            if (
                not isinstance(origin, ActionDecision)
                or origin.use_status != "USED"
                or (
                    origin.action_ref != used.action_ref
                    or origin.decision_id != used.decision_id
                    or request.meta.attempt_id != work.active_attempt_id
                    or any(
                        getattr(request.meta, name, None)
                        != getattr(response.meta, name, None)
                        for name in (
                            "analysis_id",
                            "workspace_id",
                            "commit_id",
                            "hypothesis_id",
                        )
                    )
                )
            ):
                raise ValueError("CONTEXT_RESPONSE_REQUEST_MISMATCH")
            matching.append(request)
    if len(matching) != 1:
        raise ValueError(
            "CONTEXT_RESPONSE_REQUEST_MISMATCH: exact returned request required"
        )
