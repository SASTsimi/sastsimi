from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.contracts.dynamic import DynamicReproductionRequest
from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeContextResponse
from sastsimi.storage.llm_context import _dynamic_poc_context_refs
from tests.contract.domain.canonical_fixtures import make


def _meta(kind: str, name: str, *, attempt_id: str | None) -> RecordMeta:
    return RecordMeta.model_validate(
        make("WorkExecutionState")["meta"]
        | {
            "record_id": f"{name}-record",
            "logical_record_id": f"{name}-logical",
            "record_type": kind,
            "analysis_id": "a1",
            "workspace_id": "ws1",
            "commit_id": "c1",
            "hypothesis_id": "h1",
            "attempt_id": attempt_id,
            "created_at": datetime(2026, 9, 20, tzinfo=UTC),
        }
    )


def _ref(kind: str, name: str, *, record: bool = True) -> StoredDataRef:
    digest = hashlib.sha256(name.encode()).hexdigest()
    return StoredDataRef(
        stored_data_id=StoredDataId(f"{name}-stored" if record else digest),
        data_kind=kind,
        content_hash=digest,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=RecordId(f"{name}-record") if record else None,
    )


class _Records:
    def __init__(self, values: dict[RecordRef, object]) -> None:
        self.values = values

    def resolve(self, _connection: object, ref: RecordRef) -> object:
        return self.values[ref]


def _fixture() -> tuple[
    _Records, SimpleNamespace, SimpleNamespace, StoredDataRef, StoredDataRef
]:
    fragment_ref = _ref("artifact", "fragment", record=False)
    response_value = make("CodeContextResponse")
    for field in ("entities", "locations", "discovered_relations", "gaps", "errors"):
        response_value[field] = tuple(response_value[field])
    response = CodeContextResponse.model_validate(
        response_value
        | {
            "meta": _meta("code_context_response", "response", attempt_id="ctx-at"),
            "code_fragment_refs": (fragment_ref,),
            "returned_fragment_count": 1,
            "returned_bytes": 12,
        }
    )
    response_ref = cast(StoredDataRef, reference(response))
    request_value = make("DynamicReproductionRequest")
    request_value["environment_needs"] = tuple(request_value["environment_needs"])
    request_value["static_evidence_refs"] = tuple(request_value["static_evidence_refs"])
    request = DynamicReproductionRequest.model_validate(
        request_value
        | {
            "meta": _meta(
                "dynamic_reproduction_request", "request", attempt_id="verify-at"
            ),
            "verification_generation": 1,
            "code_refs": (response_ref,),
            "created_at": datetime(2026, 9, 20, tzinfo=UTC),
        }
    )
    request_ref = cast(StoredDataRef, reference(request))
    plan_ref = _ref("reproduction_plan", "plan")
    environment_ref = _ref("sandbox_environment", "environment")
    spec = SimpleNamespace(
        agent_role="DYNAMIC_REPRODUCTION",
        task_kind="CREATE_POC_CANDIDATE",
        context_refs=(
            request_ref,
            plan_ref,
            environment_ref,
            response_ref,
            fragment_ref,
        ),
    )
    work = SimpleNamespace(
        work_type="DYNAMIC_REPRO",
        input_refs=(request_ref,),
        meta=_meta("work_execution_state", "work", attempt_id=None),
        active_attempt_id="dynamic-at",
        work_generation=1,
    )
    return (
        _Records({request_ref: request, response_ref: response}),
        spec,
        work,
        response_ref,
        fragment_ref,
    )


def test_dynamic_poc_admits_only_request_pinned_code_closure() -> None:
    records, spec, work, response_ref, fragment_ref = _fixture()

    admitted = _dynamic_poc_context_refs(
        cast(Any, records),
        cast(Any, None),
        spec=cast(Any, spec),
        work=cast(Any, work),
    )

    assert admitted == {response_ref, fragment_ref}


def test_dynamic_poc_rejects_an_extra_code_fragment() -> None:
    records, spec, work, _, _ = _fixture()
    foreign_ref = _ref("artifact", "foreign", record=False)
    spec.context_refs = (*spec.context_refs, foreign_ref)

    with pytest.raises(ValueError, match="dynamic PoC context"):
        _dynamic_poc_context_refs(
            cast(Any, records),
            cast(Any, None),
            spec=cast(Any, spec),
            work=cast(Any, work),
        )
