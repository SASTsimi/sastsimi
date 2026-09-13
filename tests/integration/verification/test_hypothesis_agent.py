from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, cast

import pytest

from sastsimi.agents.hypothesis import HypothesisAgent
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import (
    AnalysisId,
    AttemptId,
    CommitId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.llm import (
    InvocationStatus,
    LLMInvocationRequest,
    LLMInvocationResult,
    PromptInputSlot,
    PromptRegistryEntry,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeLocation, StaticFactBundle
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.dto import StagedArtifact
from sastsimi.prompts.builder import PromptBuilder
from sastsimi.prompts.registry import LoadedPromptDefinition
from sastsimi.runtime.fake_support import FakeClock, FakeIds
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation

NOW = datetime(2026, 9, 11, tzinfo=UTC)


def metadata(
    kind: str,
    record_id: str,
    *,
    hypothesis_id: str | None = None,
    attempt_id: str | AttemptId | None = None,
) -> RecordMeta:
    return RecordMeta.model_validate(
        {
            "record_id": record_id,
            "logical_record_id": record_id,
            "record_type": kind,
            "schema_version": "1.0.0",
            "revision_number": 1,
            "previous_record_id": None,
            "created_at": NOW,
            "analysis_id": "a1",
            "workspace_id": "ws1",
            "commit_id": "c1",
            "hypothesis_id": hypothesis_id,
            "attempt_id": attempt_id,
        }
    )


def stored_ref(kind: str, name: str) -> StoredDataRef:
    digest = hashlib.sha256(f"{kind}:{name}".encode()).hexdigest()
    return StoredDataRef(
        stored_data_id=StoredDataId(name),
        data_kind=kind,
        content_hash=digest,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=RecordId(f"{name}-record"),
    )


class MemoryArtifacts:
    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        return StagedArtifact(data, media_type)

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        digest = hashlib.sha256(staged.data).hexdigest()
        self.data[digest] = staged.data
        return StoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            workspace_id=WorkspaceId("ws1"),
            commit_id=CommitId("c1"),
            record_id=None,
        )

    def commit_run(
        self, staged: StagedArtifact, analysis_id: AnalysisId
    ) -> RunStoredDataRef:
        digest = hashlib.sha256(staged.data).hexdigest()
        self.data[digest] = staged.data
        return RunStoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            analysis_id=analysis_id,
            record_id=None,
        )

    def open_verified(self, ref: StoredDataRef | RunStoredDataRef) -> BinaryIO:
        data = self.data[ref.content_hash]
        if hashlib.sha256(data).hexdigest() != ref.content_hash:
            raise ValueError("HASH_MISMATCH")
        return BytesIO(data)


def location() -> dict[str, object]:
    return {
        "workspace_id": "ws1",
        "commit_id": "c1",
        "file_path": "src/app.py",
        "start_line": 10,
        "start_column": 1,
        "end_line": 10,
        "end_column": 20,
    }


def _bundle() -> StaticFactBundle:
    return StaticFactBundle(
        meta=metadata("static_fact_bundle", "bundle-record"),
        entities=(),
        locations=(CodeLocation.model_validate(location()),),
        source_candidates=(),
        sink_candidates=(),
        sanitizer_candidates=(),
        validator_candidates=(),
        auth_and_permission_checks=(),
        other_facts=(),
        call_edges=(),
        data_flow_candidates=(),
        route_bindings=(),
        tool_runs=(),
        gaps=(),
        errors=(),
    )


def _definition(
    artifacts: MemoryArtifacts,
) -> tuple[LoadedPromptDefinition, StoredDataRef]:
    template = b"\n".join(
        f"# {name}\nfixture".encode()
        for name in (
            "ROLE_AND_SCOPE",
            "TASK",
            "TRUSTED_RULES",
            "INPUT_SLOTS",
            "UNTRUSTED_DATA_BOUNDARY",
            "DECISION_CRITERIA",
            "OUTPUT_SCHEMA",
            "UNCERTAINTY_AND_ERRORS",
            "FORBIDDEN_BEHAVIOR",
        )
    )
    template_ref = artifacts.commit(artifacts.stage_bytes(template, "text/markdown"))
    entry = PromptRegistryEntry(
        meta=metadata("prompt_registry_entry", "entry-record"),
        prompt_key="hypothesis.generate-initial.fixture-v1",
        agent_role="HYPOTHESIS",
        task_kind="GENERATE_INITIAL",
        purpose="EVALUATION",
        template_ref=template_ref,
        template_version="1.0.0",
        input_slots=(
            PromptInputSlot(
                slot="facts",
                data_kind="static_fact_bundle",
                field_paths=("/locations",),
                cardinality="REQUIRED_ONE",
                trust_class="UNTRUSTED_DATA",
            ),
        ),
        forbidden_context_kinds=("credential",),
        output_schema_ref=stored_ref("output_schema_spec", "schema"),
        session_policy="NEW",
        provider_profile_refs=(stored_ref("provider_profile", "provider"),),
        execution_limits_ref=stored_ref("execution_limits", "limits"),
        retry_policy_ref=stored_ref("llm_retry_policy", "retry"),
        semantic_validator_ref=stored_ref(
            "semantic_validator_spec", "semantic-validator"
        ),
        tool_policy_ref=stored_ref("llm_tool_policy", "tool-policy"),
        redaction_policy_ref=stored_ref("prompt_redaction_policy", "redaction-policy"),
        result_kind="hypothesis_proposal",
        status="ACTIVE",
        quality_evaluation_ref=None,
        owner_role="R1",
        reviewer_roles=("R3", "R4"),
    )
    definition = LoadedPromptDefinition.from_bytes(
        entry=entry,
        template_path=Path("hypothesis.md"),
        template=template,
    )
    entry_ref = reference(entry)
    assert isinstance(entry_ref, StoredDataRef)
    return definition, entry_ref


def _work(bundle_ref: StoredDataRef) -> WorkExecutionState:
    return WorkExecutionState.model_validate(
        {
            "meta": metadata(
                "work_execution_state",
                "hypothesis-work-record",
                hypothesis_id=None,
                attempt_id=None,
            ),
            "work_id": "hypothesis-work",
            "parent_work_ref": None,
            "work_type": WorkType.HYPOTHESIS_PROPOSAL,
            "subject_type": SubjectType.PROPOSAL,
            "subject_id": "proposal-batch",
            "work_generation": 1,
            "status": WorkStatus.RUNNING,
            "state_version": 2,
            "last_transition_ref": stored_ref("state_transition", "started"),
            "last_transition_commit_ref": None,
            "active_attempt_id": "hypothesis-attempt",
            "input_hash": "a" * 64,
            "dedupe_key": "b" * 64,
            "trigger_primitive_ref": None,
            "input_refs": (bundle_ref,),
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "waiting_for": (),
            "stop_reason": None,
            "started_at": metadata(
                "work_execution_state",
                "time-source",
                hypothesis_id=None,
                attempt_id=None,
            ).created_at,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )


def _invocation(
    artifacts: ArtifactStore,
    work: WorkExecutionState,
    bundle_ref: StoredDataRef,
    payload: object | None,
    *,
    status: InvocationStatus = "SUCCEEDED",
) -> PersistedLLMInvocation:
    assert isinstance(work.meta, RecordMeta)
    attempt_id = cast(AttemptId, work.active_attempt_id)
    request_meta = metadata(
        "llm_invocation_request",
        "hypothesis-request",
        hypothesis_id=None,
        attempt_id=attempt_id,
    )
    call_spec_ref = stored_ref("llm_call_spec", "hypothesis-call-spec")
    request = LLMInvocationRequest.model_validate(
        {
            "meta": request_meta,
            "llm_call_id": "hypothesis-call",
            "action_decision_ref": stored_ref("action_decision", "allow"),
            "call_spec_ref": call_spec_ref,
            "agent_role": "HYPOTHESIS",
            "task_kind": "GENERATE_INITIAL",
            "purpose": "EVALUATION",
            "provider_profile_ref": stored_ref("provider_profile", "provider"),
            "model": "fixture-model",
            "session_policy": "NEW",
            "parent_session_ref": None,
            "context_refs": (bundle_ref,),
            "prompt_registry_entry_ref": stored_ref(
                "prompt_registry_entry", "hypothesis-entry"
            ),
            "prompt_key": "hypothesis.generate-initial.fixture-v1",
            "prompt_template_ref": stored_ref("artifact", "template").model_copy(
                update={"data_kind": "artifact", "record_id": None}
            ),
            "prompt_template_version": "1.0.0",
            "prompt_payload_ref": stored_ref("prompt_payload", "payload"),
            "execution_limits_ref": stored_ref("execution_limits", "limits"),
            "retry_policy_ref": stored_ref("llm_retry_policy", "retry"),
            "tool_policy_ref": stored_ref("llm_tool_policy", "tools"),
            "redaction_policy_ref": stored_ref("prompt_redaction_policy", "redaction"),
            "semantic_validator_ref": stored_ref(
                "semantic_validator_spec", "validator"
            ),
            "output_schema_ref": stored_ref("output_schema_spec", "schema"),
            "output_schema": "{}",
            "token_budget": 100,
            "timeout_ms": 1_000,
        }
    )
    parsed_output_ref = None
    if status == "SUCCEEDED":
        data = canonical_bytes(payload)
        parsed_output_ref = artifacts.commit(
            artifacts.stage_bytes(data, "application/json")
        )
    result = LLMInvocationResult.model_validate(
        {
            "meta": metadata(
                "llm_invocation_result",
                "hypothesis-result",
                hypothesis_id=None,
                attempt_id=attempt_id,
            ),
            "llm_call_id": request.llm_call_id,
            "purpose": request.purpose,
            "status": status,
            "provider": "OPENAI",
            "model": request.model,
            "actual_session_mode": "NEW",
            "session_ref": "session-1" if status == "SUCCEEDED" else None,
            "response_ref": parsed_output_ref,
            "parsed_output_ref": parsed_output_ref,
            "usage": None,
            "started_at": request_meta.created_at,
            "finished_at": request_meta.created_at,
            "elapsed_ms": 0,
            "safe_error": None if status == "SUCCEEDED" else f"{status}: safe failure",
        }
    )
    return PersistedLLMInvocation(
        request=request,
        result=result,
        log_ref=stored_ref("llm_invocation_log", "hypothesis-log"),
        dispatch_state="RETURNED",
    )


@dataclass
class _Calls:
    invocation: PersistedLLMInvocation
    calls: int = 0

    async def invoke(self, **_: object) -> PersistedLLMInvocation:
        self.calls += 1
        return self.invocation


def _proposal(statement: str) -> dict[str, object]:
    return {
        "statement": statement,
        "vulnerability_type_candidates": ["SQL_INJECTION"],
        "target_entities": [],
        "target_locations": [location()],
        "suspected_path": [location()],
        "observed_facts": [],
        "assumptions": ["The route accepts attacker-controlled input"],
        "restrictions": [],
        "falsification_questions": [{"question": "Is the query always parameterized?"}],
        "validation_checks": [{"instruction": "Trace the exact input-to-query path"}],
    }


@pytest.mark.asyncio
async def test_hypothesis_output_is_finalized_with_runtime_owned_ids() -> None:
    artifacts = MemoryArtifacts()
    builder = PromptBuilder(artifacts)
    definition, entry_ref = _definition(artifacts)
    bundle = _bundle()
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    work = _work(bundle_ref)
    invocation = _invocation(
        artifacts,
        work,
        bundle_ref,
        [
            _proposal("Input may reach the first query"),
            _proposal("Input may reach the second query"),
        ],
    )
    calls = _Calls(invocation)
    ids = FakeIds()
    agent = HypothesisAgent(
        prompt_builder=builder,
        llm_calls=calls,
        artifacts=artifacts,
        ids=ids,
        clock=FakeClock(),
    )

    payload = agent.prepare_prompt(
        definition=definition,
        registry_entry_ref=entry_ref,
        work=work,
        static_bundle=bundle,
        static_bundle_ref=bundle_ref,
    )
    assert payload.context_bindings[0].source_ref == bundle_ref

    outcome = await agent.propose(
        work=work,
        decision_ref=invocation.request.action_decision_ref,
        reservation_ref=stored_ref("budget_reservation", "reservation"),
        call_spec_ref=invocation.request.call_spec_ref,
        static_bundle=bundle,
        static_bundle_ref=bundle_ref,
    )

    assert calls.calls == 1
    assert [item.statement for item in outcome.proposals] == [
        "Input may reach the first query",
        "Input may reach the second query",
    ]
    assert len({item.proposal_id for item in outcome.proposals}) == 2
    assert all(
        item.meta.record_type == "hypothesis_proposal" for item in outcome.proposals
    )
    assert all(item.meta.hypothesis_id is None for item in outcome.proposals)
    assert all(
        item.meta.attempt_id == work.active_attempt_id for item in outcome.proposals
    )
    assert (
        len(
            {
                question.question_id
                for item in outcome.proposals
                for question in item.falsification_questions
            }
        )
        == 2
    )
    assert (
        len(
            {
                check.validation_id
                for item in outcome.proposals
                for check in item.validation_checks
            }
        )
        == 2
    )


@pytest.mark.asyncio
async def test_provider_owned_ids_are_rejected_before_runtime_ids_are_issued() -> None:
    artifacts = MemoryArtifacts()
    bundle = _bundle()
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    work = _work(bundle_ref)
    forged = _proposal("Input may reach a query") | {
        "proposal_id": "provider-proposal",
        "falsification_questions": [
            {
                "question_id": "provider-question",
                "question": "Is the query parameterized?",
            }
        ],
    }
    invocation = _invocation(artifacts, work, bundle_ref, [forged])
    ids = FakeIds()
    agent = HypothesisAgent(
        prompt_builder=PromptBuilder(artifacts),
        llm_calls=_Calls(invocation),
        artifacts=artifacts,
        ids=ids,
        clock=FakeClock(),
    )

    with pytest.raises(ValueError, match="OUTPUT_RUNTIME_AUTHORITY_DENIED"):
        await agent.propose(
            work=work,
            decision_ref=invocation.request.action_decision_ref,
            reservation_ref=stored_ref("budget_reservation", "reservation"),
            call_spec_ref=invocation.request.call_spec_ref,
            static_bundle=bundle,
            static_bundle_ref=bundle_ref,
        )

    assert ids.index == 0


@pytest.mark.asyncio
async def test_empty_candidate_list_is_a_successful_no_proposal_result() -> None:
    artifacts = MemoryArtifacts()
    bundle = _bundle()
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    work = _work(bundle_ref)
    invocation = _invocation(artifacts, work, bundle_ref, [])
    agent = HypothesisAgent(
        prompt_builder=PromptBuilder(artifacts),
        llm_calls=_Calls(invocation),
        artifacts=artifacts,
        ids=FakeIds(),
        clock=FakeClock(),
    )

    outcome = await agent.propose(
        work=work,
        decision_ref=invocation.request.action_decision_ref,
        reservation_ref=stored_ref("budget_reservation", "reservation"),
        call_spec_ref=invocation.request.call_spec_ref,
        static_bundle=bundle,
        static_bundle_ref=bundle_ref,
    )

    assert outcome.invocation.result.status == "SUCCEEDED"
    assert outcome.proposals == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["AUTH_REQUIRED", "TIMED_OUT", "INVALID_OUTPUT"])
async def test_provider_failure_returns_no_proposal(status: InvocationStatus) -> None:
    artifacts = MemoryArtifacts()
    bundle = _bundle()
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    work = _work(bundle_ref)
    invocation = _invocation(artifacts, work, bundle_ref, None, status=status)
    agent = HypothesisAgent(
        prompt_builder=PromptBuilder(artifacts),
        llm_calls=_Calls(invocation),
        artifacts=artifacts,
        ids=FakeIds(),
        clock=FakeClock(),
    )

    outcome = await agent.propose(
        work=work,
        decision_ref=invocation.request.action_decision_ref,
        reservation_ref=stored_ref("budget_reservation", "reservation"),
        call_spec_ref=invocation.request.call_spec_ref,
        static_bundle=bundle,
        static_bundle_ref=bundle_ref,
    )

    assert outcome.proposals == ()
    assert outcome.invocation.result.status == status
