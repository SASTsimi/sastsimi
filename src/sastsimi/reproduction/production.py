"""Production bridge joining the dynamic Agent, Sandbox, and session manager."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from sastsimi.agents.dynamic_reproduction import DynamicReproductionAgent
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.budget import DynamicReproductionLifecycleProfile
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.dynamic import (
    AgentLog,
    AgentLogEvent,
    CleanupResult,
    DynamicReproductionConclusion,
    DynamicReproductionRequest,
    DynamicReproductionToolRequest,
    EnvironmentRecipe,
    EnvironmentRequirements,
    PoCCandidate,
    ReproductionPlan,
    SandboxCommandInput,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPolicyDecision,
    SandboxProfile,
)
from sastsimi.contracts.ids import ActionId, RecordId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import Record, WorkHandlerResult
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.sandbox.controller import SandboxController, SandboxRunSpec
from sastsimi.sandbox.docker_adapter import DockerCommandOutcome
from sastsimi.sandbox.session_manager import (
    DynamicFinalizationInput,
    ReproductionSessionManager,
)
from sastsimi.sandbox.setup_automation import (
    DockerLifecyclePort,
    PreparedSandbox,
    ReproductionSetupAutomation,
)

from .service import (
    DynamicAgentPort,
    DynamicOperationalError,
    DynamicReproductionWorkflowService,
    DynamicSandboxSession,
    DynamicStageAuthorizations,
    DynamicWorkflowFailure,
)


@dataclass(frozen=True)
class DynamicSandboxAuthorization:
    """Exact trusted RUN_SANDBOX inputs; this is not Agent output."""

    action: ActionRequest
    action_decision_ref: StoredDataRef
    sandbox_profile: SandboxProfile
    lifecycle_profile: DynamicReproductionLifecycleProfile
    run_policy_state_ref: StoredDataRef
    run_spec: SandboxRunSpec


type DynamicSandboxAuthorizationResolver = Callable[
    [
        WorkExecutionState,
        DynamicReproductionRequest,
        EnvironmentRequirements,
        ReproductionPlan,
    ],
    DynamicSandboxAuthorization,
]


class DynamicRecordSink(Protocol):
    def publish(
        self,
        *,
        work: WorkExecutionState,
        role: RequesterRole,
        record: Record,
        input_refs: tuple[StoredDataRef, ...],
    ) -> StoredDataRef: ...

    def finish(
        self,
        *,
        work: WorkExecutionState,
        result: Record,
        status: str,
        input_refs: tuple[StoredDataRef, ...],
    ) -> WorkHandlerResult: ...


@dataclass(frozen=True)
class RuntimeDynamicRecordSink:
    """Persist exact immutable records through the trusted runtime."""

    runner: WorkflowRunner
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef]

    def publish(
        self,
        *,
        work: WorkExecutionState,
        role: RequesterRole,
        record: Record,
        input_refs: tuple[StoredDataRef, ...],
    ) -> StoredDataRef:
        identity = self._identity(role)
        (stored,) = self.runner.publish_intermediate(
            work,
            identity,
            role.value,
            (record,),
            action_input_refs=input_refs,
        )
        if not isinstance(stored, StoredDataRef) or stored != reference(record):
            raise ValueError("DYNAMIC_PERSISTENCE_REFERENCE_MISMATCH")
        return stored

    def finish(
        self,
        *,
        work: WorkExecutionState,
        result: Record,
        status: str,
        input_refs: tuple[StoredDataRef, ...],
    ) -> WorkHandlerResult:
        self.runner.complete(
            work,
            self._identity(RequesterRole.REPRODUCTION_SESSION_MANAGER),
            RequesterRole.REPRODUCTION_SESSION_MANAGER.value,
            (result,),
            status=status,
            cause="COMPLETED" if status == "SUCCEEDED" else status,
            error_ids=(
                (f"dynamic-{content_hash(result)[:16]}",) if status == "FAILED" else ()
            ),
            action_input_refs=input_refs,
        )
        result_ref = reference(result)
        if not isinstance(result_ref, StoredDataRef):
            raise ValueError("DYNAMIC_PERSISTENCE_REFERENCE_MISMATCH")
        return WorkHandlerResult((result_ref,))

    def _identity(self, role: RequesterRole) -> BudgetScopeRef:
        value = self.role_identity_refs.get(role)
        if value is None:
            raise ValueError(f"{role.value}_IDENTITY_REQUIRED")
        return value


class ProductionDynamicWorkflow:
    """Attempt-local adapter over Controller, setup, Docker, and durable logs."""

    def __init__(
        self,
        *,
        work: WorkExecutionState,
        controller: SandboxController,
        setup: ReproductionSetupAutomation,
        docker: DockerLifecyclePort,
        sessions: ReproductionSessionManager,
        artifacts: ArtifactStore,
        clock: Clock,
        ids: IdGenerator,
        sink: DynamicRecordSink,
        authorization: DynamicSandboxAuthorizationResolver,
    ) -> None:
        self._work = work
        self._controller = controller
        self._setup = setup
        self._docker = docker
        self._sessions = sessions
        self._artifacts = artifacts
        self._clock = clock
        self._ids = ids
        self._sink = sink
        self._authorization = authorization
        self._records: dict[str, Record] = {}
        self._prepared: PreparedSandbox | None = None
        self._policy: SandboxPolicyDecision | None = None
        self._log: AgentLog | None = None
        self._cleanup: CleanupResult | None = None
        self._binding: DynamicSandboxAuthorization | None = None
        self._agent_action_id: ActionId | None = None
        self._environments: list[SandboxEnvironment] = []
        self._recipes: list[EnvironmentRecipe] = []
        self._commands: list[SandboxCommandRecord] = []
        self._tools: list[DynamicReproductionToolRequest] = []
        self._observations: list[StoredDataRef] = []
        self._resource_groups: list[tuple[StoredDataRef, ...]] = []
        self._selected_candidate_ref: StoredDataRef | None = None
        self._started_at = clock.now()

    def publish(
        self, record: Record, invocation: PersistedLLMInvocation
    ) -> StoredDataRef:
        invocation_refs = (
            cast(StoredDataRef, reference(invocation.request)),
            cast(StoredDataRef, reference(invocation.result)),
            invocation.log_ref,
            *(
                (invocation.result.parsed_output_ref,)
                if invocation.result.parsed_output_ref is not None
                else ()
            ),
        )
        stored = self._publish(
            record,
            RequesterRole.DYNAMIC_REPRODUCTION,
            (*self._work_inputs(), *invocation_refs),
        )
        if isinstance(record, DynamicReproductionToolRequest):
            self._tools.append(record)
        return stored

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
    ) -> DynamicSandboxSession:
        self._require_work(work, request, request_ref)
        binding = self._authorization(work, request, requirements, plan)
        self._binding = binding
        outcome = self._controller.evaluate(
            spec=binding.run_spec,
            action=binding.action,
            action_decision_ref=binding.action_decision_ref,
            request=request,
            plan=plan,
            sandbox_profile=binding.sandbox_profile,
            lifecycle_profile=binding.lifecycle_profile,
            run_policy_state_ref=binding.run_policy_state_ref,
            meta=self._meta("sandbox_policy_decision"),
        )
        self._policy = outcome.decision
        policy_ref = self._publish(
            outcome.decision,
            RequesterRole.SANDBOX_CONTROLLER,
            (
                request_ref,
                requirements_ref,
                plan_ref,
                binding.action_decision_ref,
                binding.run_policy_state_ref,
            ),
        )
        self._start_log(
            request_ref,
            policy_ref=policy_ref,
            agent_started=outcome.decision.decision == "ALLOW",
        )
        if outcome.decision.decision != "ALLOW":
            self._append_event(
                "POLICY_BLOCKED",
                "SANDBOX_CONTROLLER",
                input_refs=(policy_ref,),
                safe_message="Sandbox boundary denied the request",
            )
            return DynamicSandboxSession.blocked(
                policy_ref=policy_ref,
                log_ref=self._log_ref(),
            )
        try:
            prepared = await self._setup.prepare(
                approval=outcome,
                request=request,
                requirements=requirements,
                plan=plan,
                meta=self._meta("sandbox_environment"),
            )
        except Exception as error:
            raise DynamicOperationalError(
                "FAILED", "ENVIRONMENT_SETUP", _safe_error(error)
            ) from error
        self._remember_prepared(prepared)
        return self._session(policy_ref)

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
    ) -> DynamicSandboxSession:
        del requirements, requirements_ref, plan, plan_ref, session
        self._require_work(work, request, request_ref)
        self._ensure_candidate_event(candidate_ref)
        prepared = self._require_prepared()
        if tool.action == "REQUEST_SANDBOX_RECREATE":
            assert tool.recreate_reason is not None
            self._append_event(
                "SANDBOX_RECREATE_REQUESTED",
                "DYNAMIC_REPRODUCTION",
                environment_ref=_exact_ref(prepared.environment),
                environment_recipe_ref=_exact_ref(prepared.recipe),
                input_refs=(tool_ref,),
                safe_message=tool.recreate_reason,
            )
            try:
                prepared = await self._setup.recreate(
                    previous=prepared,
                    reason=tool.recreate_reason,
                    meta=self._meta("sandbox_environment"),
                )
            except Exception as error:
                raise DynamicOperationalError(
                    "FAILED", "ENVIRONMENT_SETUP", _safe_error(error)
                ) from error
            self._remember_prepared(prepared)
            self._append_event(
                "SANDBOX_RECREATED",
                "REPRODUCTION_SETUP_AUTOMATION",
                environment_ref=_exact_ref(prepared.environment),
                environment_recipe_ref=_exact_ref(prepared.recipe),
                output_refs=(_exact_ref(prepared.environment),),
                safe_message=tool.recreate_reason,
            )
            return self._session(self._policy_ref())
        if tool.action == "USE_POC_CANDIDATE":
            if tool.poc_candidate_ref != candidate_ref:
                raise DynamicOperationalError(
                    "FAILED", "AGENT", "PoC candidate selection is not exact"
                )
            self._selected_candidate_ref = candidate_ref
            return self._session(self._policy_ref())
        if tool.action != "RUN_COMMAND" or tool.command is None:
            raise DynamicOperationalError(
                "FAILED", "INTERNAL", "Unsupported dynamic tool action"
            )
        selected_for_poc = self._selected_candidate_ref == candidate_ref
        await self._execute_command(
            request=request,
            candidate_ref=candidate_ref,
            tool_ref=tool_ref,
            command=self._command_for(tool),
            poc=selected_for_poc,
        )
        if selected_for_poc:
            self._selected_candidate_ref = None
        return self._session(self._policy_ref())

    async def cleanup(self, session: DynamicSandboxSession) -> DynamicSandboxSession:
        if not session.allowed or self._cleanup is not None:
            return session
        prepared = self._require_prepared()
        action_id = self._ids.new(ActionId)
        self._append_event(
            "CLEANUP_STARTED",
            "REPRODUCTION_SETUP_AUTOMATION",
            action_id=action_id,
            environment_ref=_exact_ref(prepared.environment),
            environment_recipe_ref=_exact_ref(prepared.recipe),
        )
        try:
            cleanup = await self._setup.cleanup(
                request=cast(DynamicReproductionRequest, self._records["request"]),
                environments=tuple(self._environments),
                resource_refs=tuple(
                    item for env in self._prepared_resources() for item in env
                ),
                meta=self._meta("cleanup_result"),
            )
        except Exception as error:
            cleanup = CleanupResult(
                meta=self._meta("cleanup_result"),
                request_ref=cast(
                    StoredDataRef,
                    reference(self._records["request"]),
                ),
                environment_refs=tuple(
                    _exact_ref(environment) for environment in self._environments
                ),
                resource_refs=tuple(
                    item for refs in self._prepared_resources() for item in refs
                ),
                status="FAILED",
                failure_reason=_safe_error(error),
                finished_at=self._clock.now(),
            )
        self._cleanup = cleanup
        cleanup_ref = self._publish(
            cleanup,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
            (self._log_ref(),),
        )
        self._append_event(
            "CLEANUP_FINISHED",
            "REPRODUCTION_SETUP_AUTOMATION",
            action_id=action_id,
            environment_ref=_exact_ref(prepared.environment),
            environment_recipe_ref=_exact_ref(prepared.recipe),
            output_refs=(cleanup_ref,),
            safe_message=cleanup.status,
        )
        return self._session(self._policy_ref())

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
    ) -> WorkHandlerResult:
        del requirements_ref, plan_ref, candidate_ref, conclusion_ref, session
        self._require_work(work, request, request_ref)
        if self._cleanup is None or self._cleanup.status != "SUCCEEDED":
            return self.finalize_failure(
                work=work,
                request=request,
                request_ref=request_ref,
                session=None,
                failure=DynamicWorkflowFailure(
                    status="FAILED",
                    failure_category="EXECUTION",
                    failure_reason="Sandbox cleanup did not complete",
                ),
            )
        self._finish_log()
        finalized = self._sessions.finalize(
            data=DynamicFinalizationInput(
                request=request,
                requirements=requirements,
                plan=plan,
                policy=self._policy,
                recipe=self._require_prepared().recipe,
                environment=self._require_prepared().environment,
                candidate=candidate,
                conclusion=conclusion,
                cleanup=self._cleanup,
                observation_refs=tuple(self._observations),
                status="SUCCEEDED",
                failure_category="NONE",
                failure_reason=None,
                plan_issues=(),
                started_at=self._started_at,
                finished_at=self._clock.now(),
                command_records=tuple(self._commands),
                tool_requests=tuple(self._tools),
                attempt_environments=tuple(self._environments[:-1]),
                attempt_recipes=tuple(self._recipes[:-1]),
                attempt_resource_refs=tuple(
                    item for refs in self._prepared_resources() for item in refs
                ),
            ),
            log=self._require_log(),
            meta=self._meta("dynamic_reproduction_result"),
        )
        if finalized.poc is not None:
            self._publish(
                finalized.poc,
                RequesterRole.REPRODUCTION_SESSION_MANAGER,
                (self._log_ref(),),
            )
        return self._sink.finish(
            work=work,
            result=finalized.result,
            status=finalized.result.status,
            input_refs=(*self._work_inputs(), self._log_ref()),
        )

    def finalize_failure(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        session: DynamicSandboxSession | None,
        failure: DynamicWorkflowFailure,
    ) -> WorkHandlerResult:
        del session
        self._require_work(work, request, request_ref)
        if self._log is None:
            self._start_log(request_ref, agent_started=False)
        self._append_event(
            "ERROR",
            "REPRODUCTION_SESSION_MANAGER",
            safe_message=failure.failure_reason,
        )
        self._finish_log()
        finalized = self._sessions.finalize(
            data=DynamicFinalizationInput(
                request=request,
                requirements=self._typed_record(
                    "environment_requirements", EnvironmentRequirements
                ),
                plan=self._typed_record("reproduction_plan", ReproductionPlan),
                policy=self._policy,
                recipe=self._prepared.recipe if self._prepared else None,
                environment=self._prepared.environment if self._prepared else None,
                candidate=self._typed_record("poc_candidate", PoCCandidate),
                conclusion=None,
                cleanup=self._cleanup,
                observation_refs=tuple(self._observations),
                status=failure.status,
                failure_category=failure.failure_category,
                failure_reason=failure.failure_reason,
                plan_issues=(),
                started_at=self._started_at,
                finished_at=self._clock.now(),
                command_records=tuple(self._commands),
                tool_requests=tuple(self._tools),
                attempt_environments=tuple(self._environments[:-1]),
                attempt_recipes=tuple(self._recipes[:-1]),
                attempt_resource_refs=tuple(
                    item for refs in self._prepared_resources() for item in refs
                ),
            ),
            log=self._require_log(),
            meta=self._meta("dynamic_reproduction_result"),
        )
        if (
            finalized.poc is not None
            or finalized.result.hypothesis_outcome != "INCONCLUSIVE"
        ):
            raise ValueError("OPERATIONAL_FAILURE_BECAME_VERDICT")
        return self._sink.finish(
            work=work,
            result=finalized.result,
            status=finalized.result.status,
            input_refs=(*self._work_inputs(), self._log_ref()),
        )

    async def _execute_command(
        self,
        *,
        request: DynamicReproductionRequest,
        candidate_ref: StoredDataRef,
        tool_ref: StoredDataRef,
        command: SandboxCommandInput,
        poc: bool,
    ) -> None:
        prepared = self._require_prepared()
        action_id = self._ids.new(ActionId)
        record = SandboxCommandRecord(
            meta=self._meta("sandbox_command_record"),
            request_ref=cast(StoredDataRef, reference(request)),
            action_id=action_id,
            tool_request_ref=tool_ref,
            reproduction_plan_ref=prepared.environment.reproduction_plan_ref,
            environment_recipe_ref=_exact_ref(prepared.recipe),
            environment_ref=_exact_ref(prepared.environment),
            **command.model_dump(),
            command_digest=content_hash(command),
            redaction_status="NOT_REQUIRED",
            created_at=self._clock.now(),
        )
        command_ref = self._publish(
            record,
            RequesterRole.REPRODUCTION_SESSION_MANAGER,
            (tool_ref, candidate_ref),
        )
        self._commands.append(record)
        if poc:
            self._append_event(
                "POC_EXECUTION_STARTED",
                "TOOL_RUNTIME",
                action_id=action_id,
                environment_ref=_exact_ref(prepared.environment),
                environment_recipe_ref=_exact_ref(prepared.recipe),
                poc_candidate_ref=candidate_ref,
            )
        self._append_event(
            "COMMAND_STARTED",
            "TOOL_RUNTIME",
            action_id=action_id,
            environment_ref=_exact_ref(prepared.environment),
            environment_recipe_ref=_exact_ref(prepared.recipe),
            poc_candidate_ref=candidate_ref if poc else None,
            tool_request_ref=tool_ref,
            command_ref=command_ref,
            command_digest=record.command_digest,
            redaction_status="NOT_REQUIRED",
        )
        try:
            outcome = await self._docker.exec(
                prepared.environment.container_instance_id,
                (command.executable, *command.arguments),
                self._execution_timeout(),
            )
        except Exception as error:
            raise DynamicOperationalError(
                "FAILED", "EXECUTION", _safe_error(error)
            ) from error
        output_refs = self._store_observations(outcome)
        self._append_event(
            "COMMAND_FINISHED",
            "TOOL_RUNTIME",
            action_id=action_id,
            environment_ref=_exact_ref(prepared.environment),
            environment_recipe_ref=_exact_ref(prepared.recipe),
            poc_candidate_ref=candidate_ref if poc else None,
            tool_request_ref=tool_ref,
            command_ref=command_ref,
            command_digest=record.command_digest,
            redaction_status="NOT_REQUIRED",
            output_refs=output_refs,
            exit_code=outcome.exit_code,
        )
        if poc:
            self._append_event(
                "POC_EXECUTION_FINISHED",
                "TOOL_RUNTIME",
                action_id=action_id,
                environment_ref=_exact_ref(prepared.environment),
                environment_recipe_ref=_exact_ref(prepared.recipe),
                poc_candidate_ref=candidate_ref,
                output_refs=output_refs,
                exit_code=outcome.exit_code,
            )

    @staticmethod
    def _command_for(tool: DynamicReproductionToolRequest) -> SandboxCommandInput:
        assert tool.command is not None
        if (
            tool.command.working_directory != "/workspace"
            or tool.command.environment_binding_refs
            or tool.command.stdin_ref is not None
            or tool.command.secret_refs
        ):
            raise DynamicOperationalError(
                "BLOCKED",
                "EXTERNAL_CONFIGURATION",
                "The Docker adapter cannot honor the requested command bindings",
            )
        return tool.command

    def _start_log(
        self,
        request_ref: StoredDataRef,
        *,
        policy_ref: StoredDataRef | None = None,
        agent_started: bool = True,
    ) -> None:
        self._records["request"] = cast(Record, self._resolve_request(request_ref))
        self._log = self._sessions.start(
            request_ref=request_ref,
            meta=self._meta("agent_log"),
            policy_decision_ref=policy_ref,
        )
        self._publish_log(self._work_inputs())
        if agent_started:
            self._agent_action_id = self._ids.new(ActionId)
            self._append_event(
                "AGENT_STARTED",
                "REPRODUCTION_SESSION_MANAGER",
                action_id=self._agent_action_id,
                input_refs=(request_ref,),
            )

    def _finish_log(self) -> None:
        log = self._require_log()
        if self._agent_action_id is not None:
            self._append_event(
                "AGENT_FINISHED",
                "REPRODUCTION_SESSION_MANAGER",
                action_id=self._agent_action_id,
            )
        self._append_event(
            "SESSION_FINISHED",
            "REPRODUCTION_SESSION_MANAGER",
            action_id=log.events[0].action_id,
        )

    def _ensure_candidate_event(self, candidate_ref: StoredDataRef) -> None:
        if any(
            event.event_type == "POC_CANDIDATE_CREATED"
            and event.poc_candidate_ref == candidate_ref
            for event in self._require_log().events
        ):
            return
        self._append_event(
            "POC_CANDIDATE_CREATED",
            "DYNAMIC_REPRODUCTION",
            poc_candidate_ref=candidate_ref,
            output_refs=(candidate_ref,),
        )

    def _append_event(
        self,
        event_type: str,
        actor: str,
        *,
        action_id: ActionId | None = None,
        environment_ref: StoredDataRef | None = None,
        environment_recipe_ref: StoredDataRef | None = None,
        poc_candidate_ref: StoredDataRef | None = None,
        tool_request_ref: StoredDataRef | None = None,
        command_ref: StoredDataRef | None = None,
        command_digest: str | None = None,
        redaction_status: str | None = None,
        input_refs: tuple[StoredDataRef, ...] = (),
        output_refs: tuple[StoredDataRef, ...] = (),
        exit_code: int | None = None,
        safe_message: str | None = None,
    ) -> None:
        previous = self._require_log()
        event = AgentLogEvent.model_validate(
            {
                "event_id": str(self._ids.new(RecordId)),
                "sequence": len(previous.events) + 1,
                "action_id": action_id or self._ids.new(ActionId),
                "event_type": event_type,
                "actor": actor,
                "environment_ref": environment_ref,
                "environment_recipe_ref": environment_recipe_ref,
                "poc_candidate_ref": poc_candidate_ref,
                "tool_request_ref": tool_request_ref,
                "command_ref": command_ref,
                "command_digest": command_digest,
                "redaction_status": redaction_status,
                "input_refs": input_refs,
                "output_refs": output_refs,
                "exit_code": exit_code,
                "safe_message": safe_message,
                "occurred_at": self._clock.now(),
            }
        )
        self._log = self._sessions.append(previous=previous, event=event)
        self._publish_log((self._log_ref(previous), *input_refs, *output_refs))

    def _publish_log(self, input_refs: tuple[StoredDataRef, ...]) -> None:
        log = self._require_log()
        self._publish(
            log,
            RequesterRole.REPRODUCTION_SESSION_MANAGER,
            input_refs,
        )

    def _remember_prepared(self, prepared: PreparedSandbox) -> None:
        self._prepared = prepared
        self._recipes.append(prepared.recipe)
        self._environments.append(prepared.environment)
        recipe_ref = self._publish(
            prepared.recipe,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
            self._work_inputs(),
        )
        self._publish(
            prepared.environment,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
            (*self._work_inputs(), recipe_ref),
        )
        self._resource_groups.append(prepared.resource_refs)

    def _publish(
        self,
        record: Record,
        role: RequesterRole,
        input_refs: tuple[StoredDataRef, ...],
    ) -> StoredDataRef:
        stored = self._sink.publish(
            work=self._work,
            role=role,
            record=record,
            input_refs=tuple(dict.fromkeys(input_refs)),
        )
        self._records[record.meta.record_type] = record
        return stored

    def _store_observations(
        self, outcome: DockerCommandOutcome
    ) -> tuple[StoredDataRef, ...]:
        refs = tuple(
            self._artifacts.commit(
                self._artifacts.stage_bytes(data, "application/octet-stream")
            )
            for data in (outcome.stdout, outcome.stderr)
        )
        self._observations.extend(refs)
        return refs

    def _prepared_resources(self) -> tuple[tuple[StoredDataRef, ...], ...]:
        return tuple(self._resource_groups)

    def _session(self, policy_ref: StoredDataRef) -> DynamicSandboxSession:
        prepared = self._require_prepared()
        return DynamicSandboxSession(
            allowed=True,
            policy_ref=policy_ref,
            log_ref=self._log_ref(),
            environment=prepared.environment,
            environment_ref=_exact_ref(prepared.environment),
            log=self._require_log(),
            observation_refs=tuple(self._observations),
            prior_tools=tuple(self._tools),
            prior_tool_refs=tuple(
                cast(StoredDataRef, reference(item)) for item in self._tools
            ),
        )

    def _execution_timeout(self) -> int:
        # The exact bounded value has already been approved in SandboxRunSpec.
        if self._binding is None:
            raise ValueError("SANDBOX_AUTHORIZATION_REQUIRED")
        return self._binding.run_spec.requested_execution_ms

    def _policy_ref(self) -> StoredDataRef:
        if self._policy is None:
            raise ValueError("SANDBOX_POLICY_REQUIRED")
        return cast(StoredDataRef, reference(self._policy))

    def _require_prepared(self) -> PreparedSandbox:
        if self._prepared is None:
            raise ValueError("SANDBOX_ENVIRONMENT_REQUIRED")
        return self._prepared

    def _require_log(self) -> AgentLog:
        if self._log is None:
            raise ValueError("AGENT_LOG_REQUIRED")
        return self._log

    def _log_ref(self, log: AgentLog | None = None) -> StoredDataRef:
        return cast(StoredDataRef, reference(log or self._require_log()))

    def _record(self, kind: str) -> Record | None:
        return self._records.get(kind)

    def _typed_record[T: Record](self, kind: str, model: type[T]) -> T | None:
        record = self._records.get(kind)
        return record if isinstance(record, model) else None

    def _resolve_request(
        self, request_ref: StoredDataRef
    ) -> DynamicReproductionRequest:
        request = self._records.get("request")
        if (
            isinstance(request, DynamicReproductionRequest)
            and reference(request) == request_ref
        ):
            return request
        raise ValueError("DYNAMIC_REQUEST_NOT_BOUND")

    def _meta(self, kind: str) -> RecordMeta:
        if self._work.active_attempt_id is None:
            raise ValueError("DYNAMIC_ATTEMPT_REQUIRED")
        return RecordMeta.model_validate(
            self._work.meta.model_dump()
            | {
                "record_id": self._ids.new(RecordId),
                "logical_record_id": self._ids.new(RecordId),
                "record_type": kind,
                "revision_number": 1,
                "previous_record_id": None,
                "created_at": self._clock.now(),
                "attempt_id": self._work.active_attempt_id,
            }
        )

    def _require_work(
        self,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
    ) -> None:
        if (
            work != self._work
            or reference(request) != request_ref
            or work.input_refs != (request_ref,)
        ):
            raise ValueError("DYNAMIC_REQUEST_NOT_CURRENT")
        self._records["request"] = cast(Record, request)

    def _work_inputs(self) -> tuple[StoredDataRef, ...]:
        if any(not isinstance(item, StoredDataRef) for item in self._work.input_refs):
            raise ValueError("DYNAMIC_REQUEST_NOT_CURRENT")
        return cast(tuple[StoredDataRef, ...], self._work.input_refs)


@dataclass(frozen=True)
class ProductionDynamicExecutor:
    """Create an isolated attempt-local workflow adapter for every invocation."""

    agent: DynamicReproductionAgent | DynamicAgentPort
    workflow_factory: Callable[[WorkExecutionState], ProductionDynamicWorkflow]

    async def __call__(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        authorizations: DynamicStageAuthorizations,
    ) -> WorkHandlerResult:
        service = DynamicReproductionWorkflowService(
            agent=self.agent,
            workflow=self.workflow_factory(work),
        )
        return await service.execute(
            work=work,
            request=request,
            request_ref=request_ref,
            authorizations=authorizations,
        )


def _safe_error(error: Exception) -> str:
    return type(error).__name__


def _exact_ref(record: Record) -> StoredDataRef:
    value = reference(record)
    if not isinstance(value, StoredDataRef):
        raise ValueError("DYNAMIC_RECORD_REFERENCE_REQUIRED")
    return value


__all__ = [
    "DynamicRecordSink",
    "DynamicSandboxAuthorization",
    "DynamicSandboxAuthorizationResolver",
    "ProductionDynamicExecutor",
    "ProductionDynamicWorkflow",
    "RuntimeDynamicRecordSink",
]
