"""Resolve exact READ_CODE provenance and immutable Context policy artifacts."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any, cast

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import (
    CodeContextRequest,
    CodeContextResponse,
    ContextRetrievalLimits,
)
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.context import ContextCeilingProfile

from . import models
from .codec import reference
from .repositories import SQLiteRecordStore

_CEILING_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "max_depth",
        "max_fragments",
        "max_bytes",
        "max_requests_per_hypothesis",
        "timeout_ms",
    }
)


def decode_context_ceiling(
    artifacts: ArtifactStore, ref: StoredDataRef
) -> ContextCeilingProfile:
    """Decode the one closed, content-addressed context ceiling projection."""
    if (
        ref.data_kind != "artifact"
        or ref.record_id is not None
        or str(ref.stored_data_id) != ref.content_hash
    ):
        raise ValueError("CONTEXT_PROFILE_CHANGED")
    try:
        with artifacts.open_verified(ref) as stream:
            raw = stream.read()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("CONTEXT_PROFILE_CHANGED") from error
    if not isinstance(value, dict) or set(value) != _CEILING_FIELDS:
        raise ValueError("CONTEXT_PROFILE_CHANGED")
    item = cast(dict[str, Any], value)
    if item["kind"] != "context_ceiling_profile" or item["schema_version"] != "1.0":
        raise ValueError("CONTEXT_PROFILE_CHANGED")
    limits = ContextRetrievalLimits.model_validate(
        {name: item[name] for name in _CEILING_FIELDS - {"kind", "schema_version"}}
    )
    return ContextCeilingProfile(ref=ref, limits=limits)


def resolve_context_ceiling(
    artifacts: ArtifactStore, work: WorkExecutionState
) -> ContextCeilingProfile:
    """Find exactly one valid ceiling already pinned in the Context work."""
    candidates: list[ContextCeilingProfile] = []
    for ref in work.input_refs:
        if not isinstance(ref, StoredDataRef) or ref.record_id is not None:
            continue
        try:
            candidates.append(decode_context_ceiling(artifacts, ref))
        except ValueError:
            continue
    if len(candidates) != 1:
        raise ValueError("CONTEXT_PROFILE_CHANGED")
    return candidates[0]


def derived_context_requests(
    records: SQLiteRecordStore,
    connection: Connection,
    *,
    analysis_id: str,
    hypothesis_id: str,
) -> tuple[CodeContextRequest, ...]:
    """Derive the cross-generation request ledger from durable claim closures."""
    found: dict[str, CodeContextRequest] = {}
    for payload in connection.execute(
        select(models.action_decisions.c.payload)
    ).scalars():
        used = ActionDecision.model_validate_json(payload)
        if used.decision != "ALLOW" or used.use_status != "USED":
            continue
        action = records.resolve(connection, used.action_ref)
        if not isinstance(action, ActionRequest) or action.action_type != "READ_CODE":
            continue
        if not isinstance(action.meta, RecordMeta) or (
            str(action.meta.analysis_id) != analysis_id
            or str(action.meta.hypothesis_id) != hypothesis_id
        ):
            continue
        dispatch = (
            connection.execute(
                select(models.external_dispatches).where(
                    models.external_dispatches.c.action_id == str(action.action_id)
                )
            )
            .mappings()
            .one_or_none()
        )
        if dispatch is None:
            continue
        for ref in used.outcome_refs:
            if ref.data_kind != "code_context_request":
                continue
            request = records.resolve(connection, ref)
            if not isinstance(request, CodeContextRequest):
                raise ValueError("CONTEXT_REQUEST_REQUIRED")
            previous = found.get(str(request.code_request_id))
            if previous is not None and previous != request:
                raise ValueError("CONTEXT_REQUEST_LEDGER_CONFLICT")
            found[str(request.code_request_id)] = request
    return tuple(found[key] for key in sorted(found))


def require_exact_context_inputs(
    action: ActionRequest,
    work: WorkExecutionState,
    *,
    profile_ref: StoredDataRef,
    plan_ref: StoredDataRef,
    required_refs: Iterable[StoredDataRef],
    file_paths: Iterable[str],
) -> None:
    """Check the pre-authorized immutable READ_CODE input/path closure."""
    required = tuple(required_refs)
    action_refs = tuple(action.input_refs)
    if (
        action.action_type != "READ_CODE"
        or profile_ref not in work.input_refs
        or action_refs.count(profile_ref) != 1
        or action_refs.count(plan_ref) != 1
        or any(action_refs.count(ref) != 1 for ref in required)
        or set(action.file_paths) != set(file_paths)
        or len(action.file_paths) != len(set(action.file_paths))
    ):
        raise ValueError("CONTEXT_PLAN_CHANGED")


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
    requested_paths = {
        str(item.location.file_path) for item in request.requested_entities
    } | {str(item.file_path) for item in request.requested_locations}
    plan_refs = tuple(ref for ref in action.input_refs if ref not in work.input_refs)
    profile_refs = tuple(
        ref
        for ref in work.input_refs
        if isinstance(ref, StoredDataRef)
        and ref.data_kind == "artifact"
        and ref.record_id is None
    )
    if (
        action.reason != request.reason
        or set(action.file_paths) != requested_paths
        or len(action.file_paths) != len(set(action.file_paths))
        or len(plan_refs) != 1
        or not isinstance(plan_refs[0], StoredDataRef)
        or plan_refs[0].data_kind != "artifact"
        or plan_refs[0].record_id is not None
        or len(profile_refs) != 1
        or action.input_refs.count(profile_refs[0]) != 1
    ):
        raise ValueError("CONTEXT_PLAN_CHANGED")
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
