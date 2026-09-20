from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.agents.chaining import _validated_chaining_context
from sastsimi.chaining.service import chaining_input_hash
from sastsimi.composition.production_feature_installer import _CallAdapters
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import (
    AnalysisId,
    AttemptId,
    CommitId,
    LogicalRecordId,
    RecordId,
    StoredDataId,
    WorkId,
    WorkspaceId,
)
from sastsimi.contracts.llm import LLMCallSpec, PromptContextBinding, PromptInputSlot
from sastsimi.contracts.prompt_redaction import render_provider_prompt
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.chaining import (
    ChainingAgentInput,
    ChainingComparison,
    ChainingEvidence,
    ChainingPrimitive,
    ChainingPrimitiveInput,
    ChainingPrimitiveResult,
)
from sastsimi.ports.dto import WorkContext
from sastsimi.prompts.local_catalog import LOCAL_EVALUATION_PROMPT_SPECS
from sastsimi.prompts.production import (
    REQUIRED_PRODUCTION_PROMPT_ROUTES,
    ProductionLLMConfigurationService,
)
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.llm_context import _chaining_prepared_input_refs

WORKSPACE_ID = WorkspaceId("workspace-one")
COMMIT_ID = CommitId("c" * 40)
ATTEMPT_ID = AttemptId("attempt-one")


class _Calls:
    def __init__(self) -> None:
        self.source_refs: tuple[StoredDataRef, ...] | None = None

    def resolve(self, **values: object) -> object:
        self.source_refs = cast(tuple[StoredDataRef, ...], values["source_refs"])
        return SimpleNamespace(
            decision_ref=_ref("decision", "action_decision"),
            reservation_ref=_ref("reservation", "budget_reservation"),
            call_spec_ref=_ref("call", "llm_call_spec"),
        )


def _ref(value: str, kind: str) -> StoredDataRef:
    digest = (value.encode("utf-8").hex() + "0" * 64)[:64]
    return StoredDataRef(
        stored_data_id=StoredDataId(value),
        data_kind=kind,
        content_hash=digest,
        workspace_id=WORKSPACE_ID,
        commit_id=COMMIT_ID,
        record_id=RecordId(value),
    )


def _artifact_ref(value: str) -> StoredDataRef:
    digest = (value.encode("utf-8").hex() + "0" * 64)[:64]
    return StoredDataRef(
        stored_data_id=StoredDataId(digest),
        data_kind="artifact",
        content_hash=digest,
        workspace_id=WORKSPACE_ID,
        commit_id=COMMIT_ID,
        record_id=None,
    )


def _context() -> WorkContext:
    meta = RecordMeta(
        record_id=RecordId("work-record"),
        logical_record_id=LogicalRecordId("work-logical"),
        record_type="work_execution_state",
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=datetime(2026, 9, 20, tzinfo=UTC),
        analysis_id=AnalysisId("analysis-one"),
        workspace_id=WORKSPACE_ID,
        commit_id=COMMIT_ID,
        hypothesis_id=None,
        attempt_id=None,
    )
    work = WorkExecutionState.model_construct(
        meta=meta,
        work_id=WorkId("work-one"),
        work_type="CHAINING",
        status="RUNNING",
        active_attempt_id=ATTEMPT_ID,
        input_refs=(
            _ref("index", "primitive_index_state"),
            _ref("primitive-a", "primitive"),
            _ref("primitive-b", "primitive"),
        ),
    )
    return WorkContext(work=work, attempt=cast(Any, object()))


def _content(*, description: str = "safe primitive") -> ChainingAgentInput:
    return ChainingAgentInput(
        evidence=(ChainingEvidence("evidence-1", "CODE_FLOW", "safe evidence"),),
        primitives=(
            ChainingPrimitive(
                "primitive-1",
                description,
                (),
                ChainingPrimitiveResult("result", (), None, ("evidence-1",)),
                (),
            ),
            ChainingPrimitive(
                "primitive-2",
                "downstream",
                (
                    ChainingPrimitiveInput(
                        "input-2-1", "input", (), None, ("evidence-1",)
                    ),
                ),
                None,
                (),
            ),
        ),
        comparisons=(
            ChainingComparison(
                "comparison-1", "primitive-1", "primitive-2", "input-2-1"
            ),
        ),
    )


def _chaining_slot() -> PromptInputSlot:
    return PromptInputSlot.model_validate(
        {
            "slot": "prepared_input",
            "data_kind": "artifact",
            "field_paths": ("/redacted_body",),
            "cardinality": "REQUIRED_ONE",
            "trust_class": "UNTRUSTED_DATA",
        }
    )


def test_chaining_call_persists_and_binds_exact_attempt_scoped_input(
    tmp_path: Path,
) -> None:
    calls = _Calls()
    artifacts = LocalArtifactStore(tmp_path / "artifacts", WORKSPACE_ID, COMMIT_ID)
    context = _context()
    content = _content()

    call, bound_hash = _CallAdapters(cast(Any, calls), artifacts).chaining(
        context, content
    )

    assert call.call_spec_ref == _ref("call", "llm_call_spec")
    assert bound_hash == chaining_input_hash(content)
    assert calls.source_refs is not None
    assert calls.source_refs[:-1] == context.work.input_refs
    prompt_ref = calls.source_refs[-1]
    assert prompt_ref.data_kind == "artifact"
    assert (prompt_ref.workspace_id, prompt_ref.commit_id) == (
        WORKSPACE_ID,
        COMMIT_ID,
    )
    with artifacts.open_verified(prompt_ref) as stream:
        bound = json.loads(stream.read())
    assert bound["scope"] == {
        "analysis_id": "analysis-one",
        "attempt_id": "attempt-one",
        "commit_id": "c" * 40,
        "hypothesis_id": None,
        "workspace_id": "workspace-one",
    }
    assert bound["content"]["comparisons"][0]["comparison_key"] == "comparison-1"
    assert bound["content"]["evidence"][0]["evidence_key"] == "evidence-1"


def test_chaining_call_rejects_content_that_still_requires_redaction(
    tmp_path: Path,
) -> None:
    artifacts = LocalArtifactStore(tmp_path / "artifacts", WORKSPACE_ID, COMMIT_ID)
    calls = _Calls()

    with pytest.raises(ValueError, match="CHAINING_PROMPT_REDACTION_REQUIRED"):
        _CallAdapters(cast(Any, calls), artifacts).chaining(
            _context(), _content(description="api_key=not-safe")
        )

    assert calls.source_refs is None


def test_rendered_chaining_input_allows_safe_nested_json_evidence() -> None:
    raw = canonical_bytes(
        {
            "redacted_body": canonical_bytes(
                {
                    "evidence_key": "evidence-1",
                    "summary": '{"locations":["src/app.py:1"]}',
                }
            ).decode("utf-8")
        }
    )

    rendered = render_provider_prompt(
        b"role=CHAINING\ntask=MATCH_PRIMITIVES",
        (("prepared_input", raw),),
    )

    assert b"evidence-1" in rendered
    assert b"src/app.py:1" in rendered

    with pytest.raises(ValueError, match="PROMPT_REDACTION_FAILED"):
        render_provider_prompt(rb"Load \\server\private\evidence.json", ())


def test_local_chaining_catalog_requires_exact_prepared_input_artifact() -> None:
    spec = next(
        item
        for item in LOCAL_EVALUATION_PROMPT_SPECS
        if (item.role, item.task_kind) == ("CHAINING", "MATCH_PRIMITIVES")
    )

    assert _chaining_slot() in spec.input_slots


def test_production_chaining_route_requires_exact_prepared_input_artifact() -> None:
    route = next(
        item
        for item in REQUIRED_PRODUCTION_PROMPT_ROUTES
        if (item.role, item.task_kind) == ("CHAINING", "MATCH_PRIMITIVES")
    )
    entry = cast(Any, SimpleNamespace(input_slots=(_chaining_slot(),)))

    ProductionLLMConfigurationService._require_route_input_contract(route, entry)

    with pytest.raises(ValueError, match="PRODUCTION_PROMPT_ROUTE_MISMATCH"):
        ProductionLLMConfigurationService._require_route_input_contract(
            route, cast(Any, SimpleNamespace(input_slots=()))
        )


def test_storage_admits_only_the_exact_chaining_prepared_input_binding() -> None:
    source = _artifact_ref("prepared")
    projected = _artifact_ref("projected")
    binding = PromptContextBinding(
        slot="prepared_input",
        data_kind="artifact",
        source_ref=source,
        projected_data_ref=projected,
        field_paths=("/redacted_body",),
        trust_class="UNTRUSTED_DATA",
    )

    allowed = _chaining_prepared_input_refs(
        payload=cast(Any, SimpleNamespace(context_bindings=(binding,))),
        spec=cast(
            Any,
            SimpleNamespace(
                agent_role="CHAINING",
                task_kind="MATCH_PRIMITIVES",
                context_refs=(*_context().work.input_refs, source),
            ),
        ),
        work=_context().work,
    )

    assert allowed == {source}

    foreign = source.model_copy(update={"workspace_id": WorkspaceId("other")})
    with pytest.raises(ValueError, match="LLM_CONTEXT_WORK_MISMATCH"):
        _chaining_prepared_input_refs(
            payload=cast(
                Any,
                SimpleNamespace(
                    context_bindings=(
                        binding.model_copy(update={"source_ref": foreign}),
                    )
                ),
            ),
            spec=cast(
                Any,
                SimpleNamespace(
                    agent_role="CHAINING",
                    task_kind="MATCH_PRIMITIVES",
                    context_refs=(*_context().work.input_refs, foreign),
                ),
            ),
            work=_context().work,
        )


def test_chaining_agent_requires_exact_prepared_content_in_call_context(
    tmp_path: Path,
) -> None:
    artifacts = LocalArtifactStore(tmp_path / "artifacts", WORKSPACE_ID, COMMIT_ID)
    calls = _Calls()
    context = _context()
    content = _content()
    _CallAdapters(cast(Any, calls), artifacts).chaining(context, content)
    assert calls.source_refs is not None
    spec = LLMCallSpec.model_construct(
        agent_role="CHAINING",
        task_kind="MATCH_PRIMITIVES",
        context_refs=calls.source_refs,
    )

    assert (
        _validated_chaining_context(
            spec=spec,
            context=context,
            content=content,
            artifacts=artifacts,
        )
        == calls.source_refs
    )

    with pytest.raises(ValueError, match="CHAINING_PROMPT_CONTENT_MISMATCH"):
        _validated_chaining_context(
            spec=spec,
            context=context,
            content=_content(description="different"),
            artifacts=artifacts,
        )

    mixed_attempt = WorkContext(
        work=context.work.model_copy(
            update={"active_attempt_id": AttemptId("attempt-other")}
        ),
        attempt=context.attempt,
    )
    with pytest.raises(ValueError, match="CHAINING_PROMPT_CONTENT_MISMATCH"):
        _validated_chaining_context(
            spec=spec,
            context=mixed_attempt,
            content=content,
            artifacts=artifacts,
        )
