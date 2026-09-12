from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from typing import BinaryIO, Literal, cast

import pytest

from sastsimi.agents.dynamic_reproduction import (
    DynamicAgentInvocation,
    DynamicAgentOutcome,
    DynamicReproductionAgent,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import (
    AgentLog,
    DynamicReproductionConclusion,
    DynamicReproductionRequest,
    DynamicReproductionToolRequest,
    EnvironmentRequirements,
    PoCCandidate,
    ReproductionPlan,
    SandboxEnvironment,
)
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
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.dto import StagedArtifact, WorkHandlerResult
from sastsimi.reproduction.service import (
    DynamicOperationalError,
    DynamicReproductionWorkflowService,
    DynamicSandboxSession,
    DynamicStageAuthorizations,
)
from sastsimi.runtime.fake_support import FakeClock, FakeIds
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation

NOW = datetime(2026, 9, 11, tzinfo=UTC)


def metadata(kind: str, record_id: str, *, attempt_id: str | None) -> RecordMeta:
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
            "hypothesis_id": "h1",
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
        return BytesIO(self.data[ref.content_hash])


def dynamic_work(request_ref: StoredDataRef) -> WorkExecutionState:
    return WorkExecutionState.model_validate(
        {
            "meta": metadata(
                "work_execution_state", "dynamic-work-record", attempt_id=None
            ),
            "work_id": "dynamic-work",
            "parent_work_ref": stored_ref("work_execution_state", "verification-work"),
            "work_type": WorkType.DYNAMIC_REPRO,
            "subject_type": SubjectType.HYPOTHESIS,
            "subject_id": "h1",
            "work_generation": 1,
            "status": WorkStatus.RUNNING,
            "state_version": 2,
            "last_transition_ref": stored_ref("state_transition", "started"),
            "last_transition_commit_ref": None,
            "active_attempt_id": "dynamic-attempt",
            "input_hash": "a" * 64,
            "dedupe_key": "b" * 64,
            "trigger_primitive_ref": None,
            "input_refs": (request_ref,),
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "waiting_for": (),
            "stop_reason": None,
            "started_at": NOW,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )


def reproduction_request() -> DynamicReproductionRequest:
    return DynamicReproductionRequest.model_validate(
        {
            "meta": metadata(
                "dynamic_reproduction_request",
                "request-record",
                attempt_id="r6-attempt",
            ),
            "verification_assignment_ref": stored_ref(
                "verification_assignment", "assignment"
            ),
            "verification_generation": 1,
            "hypothesis_ref": stored_ref("vulnerability_hypothesis", "hypothesis"),
            "purpose": "POC_CONFIRMATION",
            "initial_verdict": "TRUE",
            "goal": "Demonstrate the exact unsafe query path",
            "environment_needs": (
                {
                    "need_id": "database",
                    "kind": "DATABASE",
                    "description": "A local SQLite database",
                    "required": True,
                    "source_refs": (stored_ref("static_fact_bundle", "facts"),),
                },
            ),
            "sandbox_profile_ref": stored_ref("sandbox_profile", "sandbox-profile"),
            "code_refs": (stored_ref("code_context_response", "code"),),
            "static_evidence_refs": (stored_ref("static_fact_bundle", "facts"),),
            "pro_evidence_ref": stored_ref("pro_evidence_result", "pro"),
            "con_evidence_ref": stored_ref("con_evidence_result", "con"),
            "created_at": NOW,
        }
    )


def invocation(
    artifacts: MemoryArtifacts,
    work: WorkExecutionState,
    *,
    task: str,
    contexts: tuple[StoredDataRef, ...],
    content: object | None,
    status: InvocationStatus = "SUCCEEDED",
    sequence: int,
) -> PersistedLLMInvocation:
    attempt = cast(AttemptId, work.active_attempt_id)
    call_ref = stored_ref("llm_call_spec", f"call-{sequence}")
    decision_ref = stored_ref("action_decision", f"decision-{sequence}")
    parent = (
        "dynamic-session" if task == "EXECUTE_REPRODUCTION" and sequence > 4 else None
    )
    request = LLMInvocationRequest.model_validate(
        {
            "meta": metadata(
                "llm_invocation_request",
                f"invocation-request-{sequence}",
                attempt_id=str(attempt),
            ),
            "llm_call_id": f"dynamic-call-{sequence}",
            "action_decision_ref": decision_ref,
            "call_spec_ref": call_ref,
            "agent_role": "DYNAMIC_REPRODUCTION",
            "task_kind": task,
            "purpose": "EVALUATION",
            "provider_profile_ref": stored_ref("provider_profile", "provider"),
            "model": "fixture-model",
            "session_policy": "AUTO" if task == "EXECUTE_REPRODUCTION" else "NEW",
            "parent_session_ref": parent,
            "context_refs": contexts,
            "prompt_registry_entry_ref": stored_ref(
                "prompt_registry_entry", f"entry-{sequence}"
            ),
            "prompt_key": f"dynamic.{task.lower()}.fixture-v1",
            "prompt_template_ref": artifacts.commit(
                artifacts.stage_bytes(f"template-{sequence}".encode(), "text/markdown")
            ),
            "prompt_template_version": "1.0.0",
            "prompt_payload_ref": stored_ref("prompt_payload", f"payload-{sequence}"),
            "execution_limits_ref": stored_ref("execution_limits", "limits"),
            "retry_policy_ref": stored_ref("llm_retry_policy", "retry"),
            "tool_policy_ref": stored_ref("llm_tool_policy", f"tools-{task}"),
            "redaction_policy_ref": stored_ref("prompt_redaction_policy", "redaction"),
            "semantic_validator_ref": stored_ref(
                "semantic_validator_spec", f"validator-{task}"
            ),
            "output_schema_ref": stored_ref("output_schema_spec", f"schema-{task}"),
            "output_schema": "{}",
            "token_budget": 100,
            "timeout_ms": 1_000,
        }
    )
    output_ref = None
    if status == "SUCCEEDED":
        output_ref = artifacts.commit(
            artifacts.stage_bytes(canonical_bytes(content), "application/json")
        )
    result = LLMInvocationResult.model_validate(
        {
            "meta": metadata(
                "llm_invocation_result",
                f"invocation-result-{sequence}",
                attempt_id=str(attempt),
            ),
            "llm_call_id": request.llm_call_id,
            "purpose": request.purpose,
            "status": status,
            "provider": "OPENAI",
            "model": request.model,
            "actual_session_mode": "RESUMED" if parent else "NEW",
            "session_ref": "dynamic-session" if status == "SUCCEEDED" else None,
            "response_ref": output_ref,
            "parsed_output_ref": output_ref,
            "usage": None,
            "started_at": NOW,
            "finished_at": NOW,
            "elapsed_ms": 0,
            "safe_error": None if status == "SUCCEEDED" else "safe provider failure",
        }
    )
    return PersistedLLMInvocation(
        request=request,
        result=result,
        log_ref=stored_ref("llm_invocation_log", f"log-{sequence}"),
        dispatch_state="RETURNED",
    )


@dataclass
class QueuedCalls:
    values: list[PersistedLLMInvocation]
    tasks: list[str]

    async def invoke(self, **_: object) -> PersistedLLMInvocation:
        value = self.values.pop(0)
        self.tasks.append(value.request.task_kind)
        return value


def auth(value: PersistedLLMInvocation) -> DynamicAgentInvocation:
    return DynamicAgentInvocation(
        decision_ref=value.request.action_decision_ref,
        reservation_ref=stored_ref(
            "budget_reservation", f"budget-{value.request.llm_call_id}"
        ),
        call_spec_ref=value.request.call_spec_ref,
    )


def environment(
    request_ref: StoredDataRef, plan_ref: StoredDataRef, requirements_ref: StoredDataRef
) -> SandboxEnvironment:
    return SandboxEnvironment.model_validate(
        {
            "meta": metadata(
                "sandbox_environment",
                "environment-record",
                attempt_id="dynamic-attempt",
            ),
            "request_ref": request_ref,
            "reproduction_plan_ref": plan_ref,
            "environment_recipe_ref": stored_ref("environment_recipe", "recipe"),
            "requirements_ref": requirements_ref,
            "container_instance_id": "container-1",
            "container_action": "CREATED",
            "container_reason": "INITIAL_CLEAN",
            "previous_environment_ref": None,
            "status": "READY",
            "checks": (),
            "limitations": (),
            "created_at": NOW,
        }
    )


def agent_log(request_ref: StoredDataRef) -> AgentLog:
    return AgentLog.model_validate(
        {
            "meta": metadata("agent_log", "log-record", attempt_id="dynamic-attempt"),
            "request_ref": request_ref,
            "events": (),
        }
    )


@pytest.mark.asyncio
async def test_only_execute_stage_can_request_sandbox_tools() -> None:
    artifacts = MemoryArtifacts()
    request = reproduction_request()
    request_ref = reference(request)
    assert isinstance(request_ref, StoredDataRef)
    work = dynamic_work(request_ref)

    derive = invocation(
        artifacts,
        work,
        task="DERIVE_ENVIRONMENT",
        contexts=(request_ref,),
        content={
            "items": [
                {
                    "source_need_index": 0,
                    "kind": "DATABASE",
                    "name": "sqlite",
                    "required": True,
                    "expected": "SQLite available in the isolated image",
                    "alternatives": [],
                }
            ]
        },
        sequence=1,
    )
    calls = QueuedCalls([derive], [])
    agent = DynamicReproductionAgent(
        llm_calls=calls,
        artifacts=artifacts,
        ids=FakeIds(),
        clock=FakeClock(),
    )
    requirements_outcome = await agent.derive_environment(
        work=work,
        authorization=auth(derive),
        request=request,
        request_ref=request_ref,
    )
    assert isinstance(requirements_outcome.record, EnvironmentRequirements)
    requirements = requirements_outcome.record
    requirements_ref = reference(requirements)
    assert isinstance(requirements_ref, StoredDataRef)
    assert requirements.request_ref == request_ref
    assert requirements.items[0].requirement_id == "database"

    plan_call = invocation(
        artifacts,
        work,
        task="PLAN_REPRODUCTION",
        contexts=(request_ref, requirements_ref),
        content={
            "strategy_summary": "Run the local fixture and observe the query result",
            "requested_evidence": ["admin row returned only for the payload"],
        },
        sequence=2,
    )
    calls.values.append(plan_call)
    plan_outcome = await agent.plan_reproduction(
        work=work,
        authorization=auth(plan_call),
        request=request,
        request_ref=request_ref,
        requirements=requirements,
        requirements_ref=requirements_ref,
    )
    assert isinstance(plan_outcome.record, ReproductionPlan)
    plan = plan_outcome.record
    plan_ref = reference(plan)
    assert isinstance(plan_ref, StoredDataRef)

    env = environment(request_ref, plan_ref, requirements_ref)
    env_ref = reference(env)
    assert isinstance(env_ref, StoredDataRef)
    candidate_call = invocation(
        artifacts,
        work,
        task="CREATE_POC_CANDIDATE",
        contexts=(request_ref, plan_ref, env_ref),
        content={"content": "print('safe test payload')"},
        sequence=3,
    )
    calls.values.append(candidate_call)
    candidate_outcome = await agent.create_poc_candidate(
        work=work,
        authorization=auth(candidate_call),
        request=request,
        request_ref=request_ref,
        plan=plan,
        plan_ref=plan_ref,
        environment=env,
        environment_ref=env_ref,
    )
    assert isinstance(candidate_outcome.record, PoCCandidate)
    candidate = candidate_outcome.record
    candidate_ref = reference(candidate)
    assert isinstance(candidate_ref, StoredDataRef)
    log = agent_log(request_ref)
    log_ref = reference(log)
    assert isinstance(log_ref, StoredDataRef)

    execute_call = invocation(
        artifacts,
        work,
        task="EXECUTE_REPRODUCTION",
        contexts=(
            request_ref,
            requirements_ref,
            plan_ref,
            env_ref,
            candidate_ref,
            log_ref,
        ),
        content={
            "action": "RUN_COMMAND",
            "command": {
                "executable": "python",
                "arguments": ["/workspace/poc.py"],
                "working_directory": "/workspace",
            },
            "recreate_reason": None,
            "rationale": "Run the candidate inside the approved container",
        },
        sequence=4,
    )
    calls.values.append(execute_call)
    tool_outcome = await agent.next_tool_request(
        work=work,
        authorization=auth(execute_call),
        request=request,
        request_ref=request_ref,
        requirements=requirements,
        requirements_ref=requirements_ref,
        plan=plan,
        plan_ref=plan_ref,
        environment=env,
        environment_ref=env_ref,
        candidate=candidate,
        candidate_ref=candidate_ref,
        log=log,
        log_ref=log_ref,
        prior_tool_refs=(),
        observation_refs=(),
        turn_number=1,
    )
    assert tool_outcome.record is not None
    assert tool_outcome.record.action == "RUN_COMMAND"
    assert tool_outcome.record.command is not None

    observation_ref = stored_ref("dynamic_observation", "observation")
    interpret_call = invocation(
        artifacts,
        work,
        task="INTERPRET_ATTEMPT",
        contexts=(
            request_ref,
            plan_ref,
            env_ref,
            candidate_ref,
            log_ref,
            observation_ref,
        ),
        content={
            "proposed_outcome": "SUPPORTED",
            "observation_indexes": [0],
            "hypothesis_evidence_indexes": [0],
            "hypothesis_linkage": "The recorded result reaches the described sink",
            "limitations": [],
        },
        sequence=5,
    )
    calls.values.append(interpret_call)
    conclusion = await agent.interpret_attempt(
        work=work,
        authorization=auth(interpret_call),
        request=request,
        request_ref=request_ref,
        plan=plan,
        plan_ref=plan_ref,
        environment=env,
        environment_ref=env_ref,
        candidate=candidate,
        candidate_ref=candidate_ref,
        log=log,
        log_ref=log_ref,
        observation_refs=(observation_ref,),
    )
    assert conclusion.record is not None
    assert conclusion.record.request_ref == request_ref
    assert conclusion.record.hypothesis_evidence_refs == (observation_ref,)
    assert calls.tasks == [
        "DERIVE_ENVIRONMENT",
        "PLAN_REPRODUCTION",
        "CREATE_POC_CANDIDATE",
        "EXECUTE_REPRODUCTION",
        "INTERPRET_ATTEMPT",
    ]


@pytest.mark.asyncio
async def test_runtime_owned_provider_fields_are_rejected() -> None:
    artifacts = MemoryArtifacts()
    request = reproduction_request()
    request_ref = cast(StoredDataRef, reference(request))
    work = dynamic_work(request_ref)
    forged = invocation(
        artifacts,
        work,
        task="DERIVE_ENVIRONMENT",
        contexts=(request_ref,),
        content={"meta": {"attempt_id": "provider-attempt"}, "items": []},
        sequence=1,
    )
    agent = DynamicReproductionAgent(
        llm_calls=QueuedCalls([forged], []),
        artifacts=artifacts,
        ids=FakeIds(),
        clock=FakeClock(),
    )

    with pytest.raises(ValueError, match="OUTPUT_RUNTIME_AUTHORITY_DENIED"):
        await agent.derive_environment(
            work=work,
            authorization=auth(forged),
            request=request,
            request_ref=request_ref,
        )


@dataclass
class FakeWorkflowPort:
    session: DynamicSandboxSession
    fail_on_tool: bool = False
    published: list[str] | None = None
    failure: object | None = None
    verdict_calls: int = 0
    gate_calls: int = 0
    cleanup_calls: int = 0

    def __post_init__(self) -> None:
        self.published = []

    def publish(
        self, record: object, invocation: PersistedLLMInvocation
    ) -> StoredDataRef:
        del invocation
        assert self.published is not None
        self.published.append(record.meta.record_type)  # type: ignore[attr-defined]
        return cast(StoredDataRef, reference(record))  # type: ignore[arg-type]

    async def open_session(self, **_: object) -> DynamicSandboxSession:
        return self.session

    async def apply_tool(self, **_: object) -> DynamicSandboxSession:
        if self.fail_on_tool:
            raise DynamicOperationalError(
                "FAILED", "EXECUTION", "sandbox command failed"
            )
        return self.session

    async def cleanup(self, session: DynamicSandboxSession) -> DynamicSandboxSession:
        self.cleanup_calls += 1
        return session

    def finalize(self, **_: object) -> WorkHandlerResult:
        return WorkHandlerResult((stored_ref("dynamic_reproduction_result", "result"),))

    def finalize_failure(self, *, failure: object, **_: object) -> WorkHandlerResult:
        self.failure = failure
        return WorkHandlerResult(
            (stored_ref("dynamic_reproduction_result", "failed-result"),)
        )


@dataclass
class BlockedFlowAgent:
    invocation: PersistedLLMInvocation

    async def derive_environment(
        self, **kwargs: object
    ) -> DynamicAgentOutcome[EnvironmentRequirements]:
        work = cast(WorkExecutionState, kwargs["work"])
        request = cast(DynamicReproductionRequest, kwargs["request"])
        request_ref = cast(StoredDataRef, kwargs["request_ref"])
        need = request.environment_needs[0]
        record = EnvironmentRequirements.model_validate(
            {
                "meta": metadata(
                    "environment_requirements",
                    "blocked-requirements",
                    attempt_id=str(work.active_attempt_id),
                ),
                "request_ref": request_ref,
                "items": (
                    {
                        "requirement_id": need.need_id,
                        "kind": need.kind,
                        "name": "sqlite",
                        "required": True,
                        "expected": "SQLite is available",
                        "expected_ref": None,
                        "alternatives": (),
                        "check_ref": None,
                        "secret_ref": None,
                        "source_refs": need.source_refs,
                    },
                ),
            }
        )
        return DynamicAgentOutcome(self.invocation, record)

    async def plan_reproduction(
        self, **kwargs: object
    ) -> DynamicAgentOutcome[ReproductionPlan]:
        work = cast(WorkExecutionState, kwargs["work"])
        request = cast(DynamicReproductionRequest, kwargs["request"])
        request_ref = cast(StoredDataRef, kwargs["request_ref"])
        requirements_ref = cast(StoredDataRef, kwargs["requirements_ref"])
        record = ReproductionPlan(
            meta=metadata(
                "reproduction_plan",
                "blocked-plan",
                attempt_id=str(work.active_attempt_id),
            ),
            request_ref=request_ref,
            purpose=request.purpose,
            hypothesis_ref=request.hypothesis_ref,
            environment_requirements_ref=requirements_ref,
            sandbox_profile_ref=request.sandbox_profile_ref,
            reproduction_goal=request.goal,
            strategy_summary="Run the isolated fixture",
            requested_evidence=(),
        )
        return DynamicAgentOutcome(self.invocation, record)

    async def create_poc_candidate(
        self, **_: object
    ) -> DynamicAgentOutcome[PoCCandidate]:
        raise AssertionError("policy denial must happen before candidate creation")

    async def next_tool_request(
        self, **_: object
    ) -> DynamicAgentOutcome[DynamicReproductionToolRequest]:
        raise AssertionError("policy denial must happen before tool execution")

    async def interpret_attempt(
        self, **_: object
    ) -> DynamicAgentOutcome[DynamicReproductionConclusion]:
        raise AssertionError("policy denial must happen before interpretation")


@dataclass
class FailingFlowAgent:
    category: Literal["AGENT", "TIMEOUT", "EXECUTION"]

    async def derive_environment(
        self, **_: object
    ) -> DynamicAgentOutcome[EnvironmentRequirements]:
        raise DynamicOperationalError(
            "FAILED", self.category, "safe operational failure"
        )

    async def plan_reproduction(
        self, **_: object
    ) -> DynamicAgentOutcome[ReproductionPlan]:
        raise AssertionError("failure must stop the workflow")

    async def create_poc_candidate(
        self, **_: object
    ) -> DynamicAgentOutcome[PoCCandidate]:
        raise AssertionError("failure must stop the workflow")

    async def next_tool_request(
        self, **_: object
    ) -> DynamicAgentOutcome[DynamicReproductionToolRequest]:
        raise AssertionError("failure must stop the workflow")

    async def interpret_attempt(
        self, **_: object
    ) -> DynamicAgentOutcome[DynamicReproductionConclusion]:
        raise AssertionError("failure must stop the workflow")


@dataclass
class UnexpectedAfterOpenAgent(BlockedFlowAgent):
    async def create_poc_candidate(
        self, **_: object
    ) -> DynamicAgentOutcome[PoCCandidate]:
        raise RuntimeError("TEST_ONLY_SECRET unexpected provider failure")


@dataclass
class CancelledAfterOpenAgent(BlockedFlowAgent):
    async def create_poc_candidate(
        self, **_: object
    ) -> DynamicAgentOutcome[PoCCandidate]:
        raise asyncio.CancelledError


@pytest.mark.asyncio
async def test_operational_failure_has_no_r6_verdict_or_gate() -> None:
    artifacts = MemoryArtifacts()
    request = reproduction_request()
    request_ref = cast(StoredDataRef, reference(request))
    work = dynamic_work(request_ref)
    derive = invocation(
        artifacts,
        work,
        task="DERIVE_ENVIRONMENT",
        contexts=(request_ref,),
        content={
            "items": [
                {
                    "source_need_index": 0,
                    "kind": "DATABASE",
                    "name": "sqlite",
                    "required": True,
                    "expected": "SQLite is available",
                    "alternatives": [],
                }
            ]
        },
        sequence=1,
    )
    plan_call = invocation(
        artifacts,
        work,
        task="PLAN_REPRODUCTION",
        contexts=(request_ref,),
        content={
            "strategy_summary": "Run the isolated fixture",
            "requested_evidence": [],
        },
        sequence=2,
    )
    agent = BlockedFlowAgent(derive)
    port = FakeWorkflowPort(
        DynamicSandboxSession.blocked(
            policy_ref=stored_ref("sandbox_policy_decision", "denied-policy"),
            log_ref=stored_ref("agent_log", "blocked-log"),
        )
    )
    service = DynamicReproductionWorkflowService(agent=agent, workflow=port)

    completed = await service.execute(
        work=work,
        request=request,
        request_ref=request_ref,
        authorizations=DynamicStageAuthorizations(
            derive=auth(derive),
            plan=auth(plan_call),
            candidate=None,
            execute=(),
            interpret=None,
        ),
    )

    assert completed.output_refs
    assert port.failure is not None
    assert port.failure.status == "BLOCKED"  # type: ignore[attr-defined]
    assert port.failure.failure_category == "POLICY_BLOCKED"  # type: ignore[attr-defined]
    assert port.failure.hypothesis_outcome == "INCONCLUSIVE"  # type: ignore[attr-defined]
    assert port.failure.poc_ref is None  # type: ignore[attr-defined]
    assert port.verdict_calls == 0
    assert port.gate_calls == 0


@pytest.mark.asyncio
async def test_unexpected_failure_is_cleaned_and_recorded_safely() -> None:
    artifacts = MemoryArtifacts()
    request = reproduction_request()
    request_ref = cast(StoredDataRef, reference(request))
    work = dynamic_work(request_ref)
    persisted_invocation = invocation(
        artifacts,
        work,
        task="DERIVE_ENVIRONMENT",
        contexts=(request_ref,),
        content={"items": []},
        sequence=1,
    )
    env = environment(
        request_ref,
        stored_ref("reproduction_plan", "allowed-plan"),
        stored_ref("environment_requirements", "allowed-requirements"),
    )
    log = agent_log(request_ref)
    port = FakeWorkflowPort(
        DynamicSandboxSession(
            allowed=True,
            policy_ref=stored_ref("sandbox_policy_decision", "allowed-policy"),
            log_ref=cast(StoredDataRef, reference(log)),
            environment=env,
            environment_ref=cast(StoredDataRef, reference(env)),
            log=log,
        )
    )
    service = DynamicReproductionWorkflowService(
        agent=UnexpectedAfterOpenAgent(persisted_invocation),
        workflow=port,
    )
    authorization = auth(persisted_invocation)

    completed = await service.execute(
        work=work,
        request=request,
        request_ref=request_ref,
        authorizations=DynamicStageAuthorizations(
            derive=authorization,
            plan=authorization,
            candidate=authorization,
            execute=(),
            interpret=None,
        ),
    )

    assert completed.output_refs
    assert port.cleanup_calls == 1
    assert port.failure is not None
    assert port.failure.failure_category == "INTERNAL"  # type: ignore[attr-defined]
    assert port.failure.failure_reason == (  # type: ignore[attr-defined]
        "Unexpected dynamic workflow failure"
    )


@pytest.mark.asyncio
async def test_cancellation_after_open_cleans_exact_session_resources() -> None:
    artifacts = MemoryArtifacts()
    request = reproduction_request()
    request_ref = cast(StoredDataRef, reference(request))
    work = dynamic_work(request_ref)
    persisted_invocation = invocation(
        artifacts,
        work,
        task="DERIVE_ENVIRONMENT",
        contexts=(request_ref,),
        content={"items": []},
        sequence=1,
    )
    env = environment(
        request_ref,
        stored_ref("reproduction_plan", "allowed-plan"),
        stored_ref("environment_requirements", "allowed-requirements"),
    )
    log = agent_log(request_ref)
    port = FakeWorkflowPort(
        DynamicSandboxSession(
            allowed=True,
            policy_ref=stored_ref("sandbox_policy_decision", "allowed-policy"),
            log_ref=cast(StoredDataRef, reference(log)),
            environment=env,
            environment_ref=cast(StoredDataRef, reference(env)),
            log=log,
        )
    )
    service = DynamicReproductionWorkflowService(
        agent=CancelledAfterOpenAgent(persisted_invocation),
        workflow=port,
    )
    authorization = auth(persisted_invocation)

    with pytest.raises(asyncio.CancelledError):
        await service.execute(
            work=work,
            request=request,
            request_ref=request_ref,
            authorizations=DynamicStageAuthorizations(
                derive=authorization,
                plan=authorization,
                candidate=authorization,
                execute=(),
                interpret=None,
            ),
        )

    assert port.cleanup_calls == 1
    assert port.failure is None


@pytest.mark.asyncio
@pytest.mark.parametrize("category", ["AGENT", "TIMEOUT", "EXECUTION"])
async def test_operational_errors_remain_inconclusive(category: str) -> None:
    request = reproduction_request()
    request_ref = cast(StoredDataRef, reference(request))
    work = dynamic_work(request_ref)
    port = FakeWorkflowPort(
        DynamicSandboxSession.blocked(
            policy_ref=stored_ref("sandbox_policy_decision", "unused-policy"),
            log_ref=stored_ref("agent_log", "unused-log"),
        )
    )
    authorization = DynamicAgentInvocation(
        decision_ref=stored_ref("action_decision", "unused-decision"),
        reservation_ref=stored_ref("budget_reservation", "unused-reservation"),
        call_spec_ref=stored_ref("llm_call_spec", "unused-spec"),
    )
    service = DynamicReproductionWorkflowService(
        agent=FailingFlowAgent(
            cast(Literal["AGENT", "TIMEOUT", "EXECUTION"], category)
        ),
        workflow=port,
    )

    await service.execute(
        work=work,
        request=request,
        request_ref=request_ref,
        authorizations=DynamicStageAuthorizations(
            derive=authorization,
            plan=authorization,
            candidate=None,
            execute=(),
            interpret=None,
        ),
    )

    assert port.failure is not None
    assert port.failure.failure_category == category  # type: ignore[attr-defined]
    assert port.failure.hypothesis_outcome == "INCONCLUSIVE"  # type: ignore[attr-defined]
    assert port.failure.poc_ref is None  # type: ignore[attr-defined]
    assert port.verdict_calls == 0
    assert port.gate_calls == 0
