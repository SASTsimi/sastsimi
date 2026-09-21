"""Deterministic dynamic-reproduction orchestration stages."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Literal, Protocol

from sastsimi.agents.dynamic_reproduction import (
    DynamicAgentInvocation,
    DynamicAgentOutcome,
    DynamicReproductionAgent,
)
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
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import (
    Record,
    WorkHandlerResult,
)
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation


@dataclass(frozen=True)
class DynamicStageAuthorizations:
    """Exact T09 call authorizations allocated by the trusted runtime."""

    derive: DynamicAgentInvocation
    plan: DynamicAgentInvocation
    candidate: DynamicAgentInvocation | None
    execute: tuple[DynamicAgentInvocation, ...]
    interpret: DynamicAgentInvocation | None


class DynamicStageCallResolver(Protocol):
    """Authorize each dynamic LLM call only after its exact inputs exist."""

    @property
    def max_execute_turns(self) -> int: ...

    def resolve(
        self,
        *,
        work: WorkExecutionState,
        task_kind: str,
        context_refs: tuple[StoredDataRef, ...],
    ) -> DynamicAgentInvocation: ...

    def settle(
        self,
        authorization: DynamicAgentInvocation,
        invocation: PersistedLLMInvocation,
    ) -> None: ...


@dataclass(frozen=True)
class DynamicSandboxSession:
    """The exact state returned by the Sandbox/Session-Manager adapter."""

    allowed: bool
    policy_ref: StoredDataRef
    log_ref: StoredDataRef
    environment: SandboxEnvironment | None
    environment_ref: StoredDataRef | None
    log: AgentLog | None
    observation_refs: tuple[StoredDataRef, ...] = ()
    prior_tools: tuple[DynamicReproductionToolRequest, ...] = ()
    prior_tool_refs: tuple[StoredDataRef, ...] = ()

    def __post_init__(self) -> None:
        present = self.environment is not None and self.log is not None
        if self.allowed != present or (self.environment is None) != (
            self.environment_ref is None
        ):
            raise ValueError("DYNAMIC_SESSION_SHAPE_MISMATCH")
        if self.log is not None and reference(self.log) != self.log_ref:
            raise ValueError("DYNAMIC_SESSION_LOG_MISMATCH")
        if (
            self.environment is not None
            and reference(self.environment) != self.environment_ref
        ):
            raise ValueError("DYNAMIC_SESSION_ENVIRONMENT_MISMATCH")
        if len(self.prior_tools) != len(self.prior_tool_refs) or any(
            reference(record) != ref
            for record, ref in zip(self.prior_tools, self.prior_tool_refs, strict=True)
        ):
            raise ValueError("DYNAMIC_SESSION_TOOL_HISTORY_MISMATCH")

    @classmethod
    def blocked(
        cls, *, policy_ref: StoredDataRef, log_ref: StoredDataRef
    ) -> DynamicSandboxSession:
        return cls(
            allowed=False,
            policy_ref=policy_ref,
            log_ref=log_ref,
            environment=None,
            environment_ref=None,
            log=None,
        )


@dataclass(frozen=True)
class DynamicWorkflowFailure:
    """Operational terminal data; deliberately has no R6 verdict or Gate field."""

    status: Literal["BLOCKED", "FAILED", "CANCELLED"]
    failure_category: Literal[
        "POLICY_BLOCKED",
        "EXTERNAL_CONFIGURATION",
        "PLAN",
        "ENVIRONMENT_SETUP",
        "DEPENDENCY",
        "AGENT",
        "EXECUTION",
        "OBSERVATION",
        "TIMEOUT",
        "RESOURCE_LIMIT",
        "RETRY_LIMIT",
        "INTERNAL",
    ]
    failure_reason: str
    hypothesis_outcome: Literal["INCONCLUSIVE"] = "INCONCLUSIVE"
    poc_ref: None = None


class DynamicOperationalError(Exception):
    """An actual operating failure, distinct from evidence that disproves a bug."""

    def __init__(
        self,
        status: Literal["BLOCKED", "FAILED", "CANCELLED"],
        failure_category: Literal[
            "POLICY_BLOCKED",
            "EXTERNAL_CONFIGURATION",
            "PLAN",
            "ENVIRONMENT_SETUP",
            "DEPENDENCY",
            "AGENT",
            "EXECUTION",
            "OBSERVATION",
            "TIMEOUT",
            "RESOURCE_LIMIT",
            "RETRY_LIMIT",
            "INTERNAL",
        ],
        safe_reason: str,
    ) -> None:
        super().__init__(safe_reason)
        self.failure = DynamicWorkflowFailure(
            status=status,
            failure_category=failure_category,
            failure_reason=safe_reason,
        )


class DynamicWorkflowPort(Protocol):
    """Adapter joining Controller, setup, Session Manager, and trusted storage."""

    def publish(
        self, record: Record, invocation: PersistedLLMInvocation
    ) -> StoredDataRef: ...

    async def open_session(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        requirements_ref: StoredDataRef,
        plan: ReproductionPlan,
        plan_ref: StoredDataRef,
    ) -> DynamicSandboxSession: ...

    async def apply_tool(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        requirements_ref: StoredDataRef,
        plan: ReproductionPlan,
        plan_ref: StoredDataRef,
        candidate: PoCCandidate,
        candidate_ref: StoredDataRef,
        tool: DynamicReproductionToolRequest,
        tool_ref: StoredDataRef,
        session: DynamicSandboxSession,
    ) -> DynamicSandboxSession: ...

    async def cleanup(
        self, session: DynamicSandboxSession
    ) -> DynamicSandboxSession: ...

    def finalize(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        requirements_ref: StoredDataRef,
        plan: ReproductionPlan,
        plan_ref: StoredDataRef,
        candidate: PoCCandidate,
        candidate_ref: StoredDataRef,
        conclusion: DynamicReproductionConclusion,
        conclusion_ref: StoredDataRef,
        session: DynamicSandboxSession,
    ) -> WorkHandlerResult: ...

    def finalize_failure(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        session: DynamicSandboxSession | None,
        failure: DynamicWorkflowFailure,
    ) -> WorkHandlerResult: ...


class DynamicAgentPort(Protocol):
    async def derive_environment(
        self, **kwargs: object
    ) -> DynamicAgentOutcome[EnvironmentRequirements]: ...
    async def plan_reproduction(
        self, **kwargs: object
    ) -> DynamicAgentOutcome[ReproductionPlan]: ...
    async def create_poc_candidate(
        self, **kwargs: object
    ) -> DynamicAgentOutcome[PoCCandidate]: ...
    async def next_tool_request(
        self, **kwargs: object
    ) -> DynamicAgentOutcome[DynamicReproductionToolRequest]: ...
    async def interpret_attempt(
        self, **kwargs: object
    ) -> DynamicAgentOutcome[DynamicReproductionConclusion]: ...


class DynamicReproductionWorkflowService:
    """Production stage ordering without taking verdict, Gate, or PoC authority."""

    def __init__(
        self,
        *,
        agent: DynamicReproductionAgent | DynamicAgentPort,
        workflow: DynamicWorkflowPort,
        call_resolver: DynamicStageCallResolver | None = None,
    ) -> None:
        self._agent = agent
        self._workflow = workflow
        self._call_resolver = call_resolver

    async def execute(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        authorizations: DynamicStageAuthorizations | None,
    ) -> WorkHandlerResult:
        session: DynamicSandboxSession | None = None
        try:
            restore = getattr(self._workflow, "restore_initial_stages", None)
            restored = (
                restore(work=work, request=request, request_ref=request_ref)
                if callable(restore)
                else None
            )
            if restored is None:
                derive_authorization = self._resolve_call(
                    work=work,
                    task_kind="DERIVE_ENVIRONMENT",
                    context_refs=(request_ref,),
                    fallback=(
                        authorizations.derive if authorizations is not None else None
                    ),
                )
                requirements_outcome = await self._agent.derive_environment(
                    work=work,
                    authorization=derive_authorization,
                    request=request,
                    request_ref=request_ref,
                )
                self._settle_call(derive_authorization, requirements_outcome.invocation)
                requirements = _require_stage_record(requirements_outcome, "AGENT")
                requirements_ref = self._workflow.publish(
                    requirements, requirements_outcome.invocation
                )

                plan_authorization = self._resolve_call(
                    work=work,
                    task_kind="PLAN_REPRODUCTION",
                    context_refs=(request_ref, requirements_ref),
                    fallback=(
                        authorizations.plan if authorizations is not None else None
                    ),
                )
                plan_outcome = await self._agent.plan_reproduction(
                    work=work,
                    authorization=plan_authorization,
                    request=request,
                    request_ref=request_ref,
                    requirements=requirements,
                    requirements_ref=requirements_ref,
                )
                self._settle_call(plan_authorization, plan_outcome.invocation)
                plan = _require_stage_record(plan_outcome, "PLAN")
                plan_ref = self._workflow.publish(plan, plan_outcome.invocation)
            else:
                requirements, requirements_ref, plan, plan_ref = restored

            session = await self._workflow.open_session(
                work=work,
                request=request,
                request_ref=request_ref,
                requirements=requirements,
                requirements_ref=requirements_ref,
                plan=plan,
                plan_ref=plan_ref,
            )
            if not session.allowed:
                raise DynamicOperationalError(
                    "BLOCKED", "POLICY_BLOCKED", "Sandbox boundary denied the request"
                )
            assert session.environment is not None
            assert session.environment_ref is not None
            assert session.log is not None
            if session.environment.status != "READY":
                raise DynamicOperationalError(
                    "BLOCKED",
                    "ENVIRONMENT_SETUP",
                    "Sandbox environment is not ready",
                )
            candidate_authorization = self._resolve_call(
                work=work,
                task_kind="CREATE_POC_CANDIDATE",
                context_refs=(request_ref, plan_ref, session.environment_ref),
                fallback=(
                    authorizations.candidate if authorizations is not None else None
                ),
            )
            candidate_outcome = await self._agent.create_poc_candidate(
                work=work,
                authorization=candidate_authorization,
                request=request,
                request_ref=request_ref,
                plan=plan,
                plan_ref=plan_ref,
                environment=session.environment,
                environment_ref=session.environment_ref,
            )
            self._settle_call(candidate_authorization, candidate_outcome.invocation)
            candidate = _require_stage_record(candidate_outcome, "AGENT")
            candidate_ref = self._workflow.publish(
                candidate, candidate_outcome.invocation
            )

            finished = False
            execute_turns = (
                self._call_resolver.max_execute_turns
                if self._call_resolver is not None
                else len(authorizations.execute)
                if authorizations is not None
                else 0
            )
            for turn_number in range(1, execute_turns + 1):
                assert session.environment is not None
                assert session.environment_ref is not None
                assert session.log is not None
                execute_context_refs = (
                    request_ref,
                    requirements_ref,
                    plan_ref,
                    session.environment_ref,
                    candidate_ref,
                    session.log_ref,
                    *session.prior_tool_refs,
                    *session.observation_refs,
                )
                authorization = self._resolve_call(
                    work=work,
                    task_kind="EXECUTE_REPRODUCTION",
                    context_refs=execute_context_refs,
                    fallback=(
                        authorizations.execute[turn_number - 1]
                        if authorizations is not None
                        else None
                    ),
                )
                tool_outcome = await self._agent.next_tool_request(
                    work=work,
                    authorization=authorization,
                    request=request,
                    request_ref=request_ref,
                    requirements=requirements,
                    requirements_ref=requirements_ref,
                    plan=plan,
                    plan_ref=plan_ref,
                    environment=session.environment,
                    environment_ref=session.environment_ref,
                    candidate=candidate,
                    candidate_ref=candidate_ref,
                    log=session.log,
                    log_ref=session.log_ref,
                    prior_tool_refs=session.prior_tool_refs,
                    observation_refs=session.observation_refs,
                    turn_number=turn_number,
                )
                self._settle_call(authorization, tool_outcome.invocation)
                tool = _require_stage_record(tool_outcome, "AGENT")
                tool_ref = self._workflow.publish(tool, tool_outcome.invocation)
                if tool.action == "FINISH":
                    finished = True
                    break
                session = await self._workflow.apply_tool(
                    work=work,
                    request=request,
                    request_ref=request_ref,
                    requirements=requirements,
                    requirements_ref=requirements_ref,
                    plan=plan,
                    plan_ref=plan_ref,
                    candidate=candidate,
                    candidate_ref=candidate_ref,
                    tool=tool,
                    tool_ref=tool_ref,
                    session=session,
                )
            if not finished:
                raise DynamicOperationalError(
                    "FAILED", "RETRY_LIMIT", "Dynamic reproduction turn limit exhausted"
                )
            assert session.environment is not None
            assert session.environment_ref is not None
            assert session.log is not None
            interpret_context_refs = (
                request_ref,
                plan_ref,
                session.environment_ref,
                candidate_ref,
                session.log_ref,
                *session.observation_refs,
            )
            interpret_authorization = self._resolve_call(
                work=work,
                task_kind="INTERPRET_ATTEMPT",
                context_refs=interpret_context_refs,
                fallback=(
                    authorizations.interpret if authorizations is not None else None
                ),
            )
            conclusion_outcome = await self._agent.interpret_attempt(
                work=work,
                authorization=interpret_authorization,
                request=request,
                request_ref=request_ref,
                plan=plan,
                plan_ref=plan_ref,
                environment=session.environment,
                environment_ref=session.environment_ref,
                candidate=candidate,
                candidate_ref=candidate_ref,
                log=session.log,
                log_ref=session.log_ref,
                observation_refs=session.observation_refs,
            )
            self._settle_call(interpret_authorization, conclusion_outcome.invocation)
            conclusion = _require_stage_record(conclusion_outcome, "AGENT")
            conclusion_ref = self._workflow.publish(
                conclusion, conclusion_outcome.invocation
            )
            session = await self._workflow.cleanup(session)
            return self._workflow.finalize(
                work=work,
                request=request,
                request_ref=request_ref,
                requirements=requirements,
                requirements_ref=requirements_ref,
                plan=plan,
                plan_ref=plan_ref,
                candidate=candidate,
                candidate_ref=candidate_ref,
                conclusion=conclusion,
                conclusion_ref=conclusion_ref,
                session=session,
            )
        except asyncio.CancelledError:
            if session is not None:
                await self._workflow.cleanup(session)
            raise
        except DynamicOperationalError as error:
            if session is not None and session.allowed:
                session = await self._workflow.cleanup(session)
            return self._workflow.finalize_failure(
                work=work,
                request=request,
                request_ref=request_ref,
                session=session,
                failure=error.failure,
            )
        except Exception as error:
            if session is not None and session.allowed:
                session = await self._workflow.cleanup(session)
            return self._workflow.finalize_failure(
                work=work,
                request=request,
                request_ref=request_ref,
                session=session,
                failure=DynamicWorkflowFailure(
                    status="FAILED",
                    failure_category="INTERNAL",
                    failure_reason=_safe_internal_failure_reason(error),
                ),
            )

    def _resolve_call(
        self,
        *,
        work: WorkExecutionState,
        task_kind: str,
        context_refs: tuple[StoredDataRef, ...],
        fallback: DynamicAgentInvocation | None,
    ) -> DynamicAgentInvocation:
        if self._call_resolver is not None:
            return self._call_resolver.resolve(
                work=work,
                task_kind=task_kind,
                context_refs=context_refs,
            )
        if fallback is None:
            raise DynamicOperationalError(
                "FAILED", "INTERNAL", "Dynamic LLM authorization is missing"
            )
        return fallback

    def _settle_call(
        self,
        authorization: DynamicAgentInvocation,
        invocation: PersistedLLMInvocation,
    ) -> None:
        if self._call_resolver is not None:
            self._call_resolver.settle(authorization, invocation)


def _require_stage_record[T](
    outcome: DynamicAgentOutcome[T], category: Literal["AGENT", "PLAN"]
) -> T:
    if outcome.record is None:
        raise DynamicOperationalError(
            "BLOCKED", category, "LLM stage did not produce a usable result"
        )
    return outcome.record


def _safe_internal_failure_reason(error: Exception) -> str:
    code = getattr(error, "code", None)
    if isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", code):
        return code
    message = str(error)
    if re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", message):
        return message
    return "Unexpected dynamic workflow failure"
