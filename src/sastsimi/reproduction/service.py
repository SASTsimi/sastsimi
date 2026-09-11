"""Deterministic dynamic-reproduction orchestration stages."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from sastsimi.agents.dynamic_reproduction import (
    DynamicAgentInvocation,
    DynamicAgentOutcome,
    DynamicReproductionAgent,
)
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import (
    POC_EXECUTABLE,
    POC_RUNTIME_PATH,
    AgentLog,
    CleanupResult,
    DynamicReproductionConclusion,
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionToolRequest,
    EnvironmentRecipe,
    EnvironmentRequirements,
    PoCBundle,
    PoCCandidate,
    ReproductionPlan,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPolicyDecision,
    SandboxProfile,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.result_registry import RESULT_REGISTRY
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import (
    ApprovedSandboxCommand,
    Record,
    SandboxCleanupRequest,
    SandboxPrepareRequest,
    WorkHandlerResult,
)
from sastsimi.ports.fake_workflow import (
    ProviderInvoker,
    ProviderProber,
    SandboxCleaner,
    SandboxExecutor,
    SandboxPreparer,
)
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_llm_invocation import (
    invoke_fake_provider,
    persist_fake_invocation,
)
from sastsimi.runtime.fake_support import (
    ANALYSIS_ID,
    FakeClock,
    FakeEvidence,
    FakeRecordFactory,
)
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.sandbox.cleanup import owned_container_resource_ref

from .fake_closure import require_poc_execution_events


@dataclass(frozen=True)
class ReproductionDependencies:
    runtime: RuntimeServices
    runner: WorkflowRunner
    clock: FakeClock
    evidence: FakeEvidence
    records: FakeRecordFactory
    provider_invoke: ProviderInvoker
    provider_probe: ProviderProber
    sandbox_prepare: SandboxPreparer
    sandbox_execute: SandboxExecutor
    sandbox_cleanup: SandboxCleaner


class DynamicReproductionService:
    """Own the exact R6 request and R7 reproduction component workflow."""

    def __init__(self, dependencies: ReproductionDependencies) -> None:
        self.runtime = dependencies.runtime
        self.runner = dependencies.runner
        self.clock = dependencies.clock
        self.evidence = dependencies.evidence
        self.provider_invoke = dependencies.provider_invoke
        self.provider_probe = dependencies.provider_probe
        self.sandbox_prepare = dependencies.sandbox_prepare
        self.sandbox_execute = dependencies.sandbox_execute
        self.sandbox_cleanup = dependencies.sandbox_cleanup
        self._record_meta = dependencies.records.record_meta
        self._artifact = dependencies.records.artifact
        self._stored_artifact = dependencies.records.stored_artifact

    def _agent_intermediate(
        self,
        *,
        candidate: Record,
        work: WorkExecutionState,
        scope: StoredDataRef,
        result_kind: str,
        context_refs: tuple[StoredDataRef, ...],
    ) -> tuple[Record, StoredDataRef]:
        assert self.runtime is not None and self.runner is not None
        identity = self.evidence.identity(RequesterRole.DYNAMIC_REPRODUCTION)
        call_ref, provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            work=work,
            scope=scope,
            orchestration_identity=self.evidence.identity(RequesterRole.ORCHESTRATION),
            role="DYNAMIC_REPRODUCTION",
            result_kind=result_kind,
            context_refs=context_refs,
        )
        record, invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=work,
            scope=scope,
            identity=identity,
            action_role=RequesterRole.DYNAMIC_REPRODUCTION,
            action_type="CALL_LLM",
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: candidate,
            provider_invoke=self.provider_invoke,
        )
        persist_fake_invocation(self.runtime, invocation)
        ref = self._publish_intermediate(work, record)
        return record, ref

    def _publish_intermediate(
        self, work: WorkExecutionState, record: Record
    ) -> StoredDataRef:
        """Publish only R6/R7 records with their registry-owned identity."""
        result_kind = record.meta.record_type
        allowed_kinds = {
            "dynamic_reproduction_request",
            "environment_requirements",
            "reproduction_plan",
            "environment_recipe",
            "sandbox_environment",
            "cleanup_result",
            "sandbox_policy_decision",
            "sandbox_command_record",
            "poc_candidate",
            "dynamic_reproduction_tool_request",
            "dynamic_reproduction_conclusion",
            "agent_log",
            "poc_bundle",
            "dynamic_reproduction_result",
        }
        if result_kind not in allowed_kinds:
            raise ValueError("REPRODUCTION_RESULT_KIND_NOT_ALLOWED")
        binding = RESULT_REGISTRY[result_kind]
        if not isinstance(record, binding.model):
            raise TypeError("REPRODUCTION_RESULT_SCHEMA_MISMATCH")
        role = binding.owner
        identity = self.evidence.identity(role)
        candidate = self.runtime.unit_of_work.records.stage_record(record)
        action = self.runner.action(
            work,
            identity,
            role.value,
            "SAVE_RESULT",
            result_kind=result_kind,
            candidate_result_ref=candidate,
        )
        (published,) = self.runtime.intermediate.publish(
            str(work.work_id), self.runner.authorize(work, action), (record,)
        )
        assert isinstance(published, StoredDataRef)
        return published

    def run(
        self,
        *,
        scope: StoredDataRef,
        owner_ref: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        verification_work: WorkExecutionState,
        assignment_ref: StoredDataRef,
        hypothesis_ref: StoredDataRef,
        evidence_ref: StoredDataRef,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        assessment_ref: StoredDataRef,
        policy_ref: StoredDataRef,
        playbook_ref: StoredDataRef,
        application_ref: StoredDataRef,
    ) -> tuple[DynamicReproductionRequest, DynamicReproductionResult, PoCBundle]:
        assert self.runtime is not None and self.runner is not None
        sandbox = SandboxProfile.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._record_meta("sandbox_profile"),
                    network_mode="DEFAULT_DENY",
                    allowed_egress_refs=(),
                    isolation_policy_refs=(),
                    cpu_limit_millicores=100,
                    memory_limit_bytes=64 * 1024 * 1024,
                    disk_limit_bytes=64 * 1024 * 1024,
                    pid_limit=16,
                    max_requested_execution_ms=10_000,
                    created_at=self.clock.now(),
                )
            )
        )
        self.evidence.sandbox_approvals.add(content_hash(sandbox))
        sandbox_ref = self.runtime.configuration.register_sandbox_profile(sandbox)
        request = DynamicReproductionRequest.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        verification_work.meta,
                        "dynamic_reproduction_request",
                        attempt_id=verification_work.active_attempt_id,
                    ),
                    verification_assignment_ref=assignment_ref,
                    verification_generation=verification_work.work_generation,
                    hypothesis_ref=hypothesis_ref,
                    purpose="POC_CONFIRMATION",
                    initial_verdict="TRUE",
                    goal="Reproduce the exact fake path",
                    environment_needs=(),
                    sandbox_profile_ref=sandbox_ref,
                    code_refs=(evidence_ref,),
                    static_evidence_refs=(evidence_ref,),
                    pro_evidence_ref=pro_ref,
                    con_evidence_ref=con_ref,
                    created_at=self.clock.now(),
                )
            )
        )
        request_call_ref, request_provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            work=verification_work,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role="VERIFICATION",
            result_kind="dynamic_reproduction_request",
            task_kind="CREATE_DYNAMIC_REQUEST",
            context_refs=(
                assignment_ref,
                hypothesis_ref,
                assessment_ref,
                pro_ref,
                con_ref,
                evidence_ref,
                policy_ref,
                playbook_ref,
                application_ref,
                sandbox_ref,
            ),
        )
        request_record, request_invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=verification_work,
            scope=scope,
            identity=owner_ref,
            action_role=RequesterRole.VERIFICATION,
            action_type="CALL_LLM",
            call_spec_ref=request_call_ref,
            provider_profile_ref=request_provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: request,
            provider_invoke=self.provider_invoke,
        )
        if not isinstance(request_record, DynamicReproductionRequest):
            raise TypeError("FAKE_DYNAMIC_REQUEST_OUTPUT_MISMATCH")
        persist_fake_invocation(self.runtime, request_invocation)
        request = request_record
        request_ref = self._publish_intermediate(verification_work, request)
        action = self.runner.action(
            verification_work,
            owner_ref,
            "VERIFICATION",
            "REQUEST_DYNAMIC_REPRO",
            dynamic_request_ref=request_ref,
        )
        reservation = self.runner.reserve(
            verification_work, scope, action, self.runner.units(work_count=1)
        )
        decision = self.runner.authorize(verification_work, action, reservation)
        pending = self.runtime.dynamic_registration.register(
            str(verification_work.work_id),
            decision,
            reference(reservation),
        )
        dynamic_work = self.runner.activate(
            pending, scope, owner_ref, role="VERIFICATION"
        )
        attempt_id = dynamic_work.active_attempt_id
        assert attempt_id is not None
        dynamic_identity = self.evidence.identity(RequesterRole.DYNAMIC_REPRODUCTION)
        setup_identity = self.evidence.identity(
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION
        )
        session_identity = self.evidence.identity(
            RequesterRole.REPRODUCTION_SESSION_MANAGER
        )
        runner = self.runner

        def meta(kind: str) -> dict[str, Any]:
            return runner.metadata(dynamic_work.meta, kind, attempt_id=attempt_id)

        requirements = EnvironmentRequirements.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("environment_requirements"),
                    request_ref=request_ref,
                    items=(),
                )
            )
        )
        requirements_record, requirements_ref = self._agent_intermediate(
            candidate=requirements,
            work=dynamic_work,
            scope=scope,
            result_kind="environment_requirements",
            context_refs=(request_ref,),
        )
        assert isinstance(requirements_record, EnvironmentRequirements)
        requirements = requirements_record
        plan = ReproductionPlan.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("reproduction_plan"),
                    request_ref=request_ref,
                    purpose="POC_CONFIRMATION",
                    hypothesis_ref=hypothesis_ref,
                    environment_requirements_ref=requirements_ref,
                    sandbox_profile_ref=sandbox_ref,
                    reproduction_goal="Confirm the fake path",
                    strategy_summary="Use the deterministic local sandbox",
                    requested_evidence=(),
                )
            )
        )
        plan_record, plan_ref = self._agent_intermediate(
            candidate=plan,
            work=dynamic_work,
            scope=scope,
            result_kind="reproduction_plan",
            context_refs=(request_ref, requirements_ref),
        )
        assert isinstance(plan_record, ReproductionPlan)
        plan = plan_record
        recipe = EnvironmentRecipe.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("environment_recipe"),
                    request_ref=request_ref,
                    environment_requirements_ref=requirements_ref,
                    recipe_source_ref=self._artifact("recipe_source", record=True),
                    source_refs=(),
                    base_image_digest="sha256:" + "1" * 64,
                    built_image_digest="sha256:" + "2" * 64,
                    baseline_recipe_ref=None,
                    build_disposition="BUILT",
                    created_at=self.clock.now(),
                )
            )
        )
        recipe_ref = self._publish_intermediate(dynamic_work, recipe)
        environment = SandboxEnvironment.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("sandbox_environment"),
                    request_ref=request_ref,
                    reproduction_plan_ref=plan_ref,
                    environment_recipe_ref=recipe_ref,
                    requirements_ref=requirements_ref,
                    container_instance_id="fake-container",
                    container_action="CREATED",
                    container_reason="INITIAL_CLEAN",
                    previous_environment_ref=None,
                    status="READY",
                    checks=(),
                    limitations=(),
                    created_at=self.clock.now(),
                )
            )
        )
        environment_ref = reference(environment)
        assert isinstance(environment_ref, StoredDataRef)
        lifecycle_ref = self.runtime.budget_registry.current_state(
            str(ANALYSIS_ID)
        ).budget_binding_ref
        run_policy_state_ref = self.runtime.budget_registry.current_state(
            str(ANALYSIS_ID)
        ).run_policy_state_ref
        assert lifecycle_ref is not None
        assert run_policy_state_ref is not None
        binding = self.runtime.unit_of_work.records.get_exact(lifecycle_ref)
        assert isinstance(binding, BudgetProfileBinding)
        resource_ref = binding.dynamic_lifecycle_profile_ref
        sandbox_action = self.runner.action(
            dynamic_work,
            setup_identity,
            "REPRODUCTION_SETUP_AUTOMATION",
            "RUN_SANDBOX",
            input_refs=(
                request_ref,
                requirements_ref,
                plan_ref,
                sandbox_ref,
                resource_ref,
                recipe_ref,
            ),
            dynamic_request_ref=request_ref,
            reproduction_plan_ref=plan_ref,
            sandbox_profile_ref=sandbox_ref,
            resource_profile_ref=resource_ref,
            run_policy_state_ref=run_policy_state_ref,
            image_digest=recipe.built_image_digest,
            network_targets=(),
            resource_limits={
                "cpu_limit_millicores": sandbox.cpu_limit_millicores,
                "memory_limit_bytes": sandbox.memory_limit_bytes,
                "disk_limit_bytes": sandbox.disk_limit_bytes,
                "pid_limit": sandbox.pid_limit,
                "requested_execution_ms": sandbox.max_requested_execution_ms,
            },
        )
        sandbox_units = self.runner.units(elapsed_ms=1, cost_minor_units=1)
        sandbox_reservation = self.runner.reserve(
            dynamic_work, scope, sandbox_action, sandbox_units
        )
        sandbox_decision = self.runner.authorize(
            dynamic_work, sandbox_action, sandbox_reservation
        )
        claimed_sandbox_decision = self.runtime.validator.claim_external(
            str(dynamic_work.work_id),
            sandbox_decision,
            reference(sandbox_reservation),
        )
        assert isinstance(claimed_sandbox_decision, StoredDataRef)
        policy = SandboxPolicyDecision.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("sandbox_policy_decision"),
                    action_decision_ref=claimed_sandbox_decision,
                    request_ref=request_ref,
                    sandbox_profile_ref=sandbox_ref,
                    resource_profile_ref=resource_ref,
                    run_policy_state_ref=run_policy_state_ref,
                    policy_collection_result_ref=None,
                    policy_record_ref=None,
                    execution_scope="LOCAL_ONLY",
                    observed_policy_status="PREPARING",
                    decision="ALLOW",
                    reason_codes=("LOCAL_BOUNDARY_OK",),
                    checked_boundary_refs=(),
                    decided_at=self.clock.now(),
                )
            )
        )
        policy_ref = self._publish_intermediate(dynamic_work, policy)

        async def prepare_environment() -> SandboxEnvironment:
            return await self.sandbox_prepare(
                SandboxPrepareRequest(request, requirements, plan, policy),
                environment,
            )

        returned_environment: SandboxEnvironment = asyncio.run(
            self.runtime.external.invoke(
                str(dynamic_work.work_id),
                sandbox_decision,
                reference(sandbox_reservation),
                prepare_environment,
                idempotency_key=str(sandbox_action.action_id),
            )
        )
        self.runner.account(sandbox_reservation, sandbox_units)
        if returned_environment != environment:
            raise ValueError("FAKE_SANDBOX_ENVIRONMENT_MISMATCH")
        environment_ref = self._publish_intermediate(dynamic_work, returned_environment)
        candidate_content_ref = self._artifact("poc_content", record=True)
        candidate = PoCCandidate.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("poc_candidate"),
                    request_ref=request_ref,
                    reproduction_plan_ref=plan_ref,
                    content_ref=candidate_content_ref,
                    content_digest=candidate_content_ref.content_hash,
                    llm_call_id="fake-poc-call",
                    created_at=self.clock.now(),
                )
            )
        )
        candidate_record, candidate_ref = self._agent_intermediate(
            candidate=candidate,
            work=dynamic_work,
            scope=scope,
            result_kind="poc_candidate",
            context_refs=(request_ref, plan_ref, environment_ref),
        )
        assert isinstance(candidate_record, PoCCandidate)
        candidate = candidate_record
        tool_candidate = DynamicReproductionToolRequest.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("dynamic_reproduction_tool_request"),
                    request_ref=request_ref,
                    reproduction_plan_ref=plan_ref,
                    environment_ref=environment_ref,
                    turn_number=1,
                    action="RUN_COMMAND",
                    command=dict(
                        executable=POC_EXECUTABLE,
                        arguments=(POC_RUNTIME_PATH,),
                        working_directory="/workspace",
                        environment_binding_refs=(),
                        stdin_ref=candidate.content_ref,
                        secret_refs=(),
                    ),
                    poc_candidate_ref=None,
                    recreate_reason=None,
                    rationale="Execute the exact persisted PoC candidate",
                    llm_call_id="pending-tool-request-call",
                )
            )
        )
        tool_record, tool_ref = self._agent_intermediate(
            candidate=tool_candidate,
            work=dynamic_work,
            scope=scope,
            result_kind="dynamic_reproduction_tool_request",
            context_refs=(request_ref, plan_ref, environment_ref, candidate_ref),
        )
        assert isinstance(tool_record, DynamicReproductionToolRequest)
        tool_request = tool_record

        command_action = self.runner.action(
            dynamic_work,
            setup_identity,
            "REPRODUCTION_SETUP_AUTOMATION",
            "RUN_SANDBOX",
            input_refs=(
                request_ref,
                requirements_ref,
                plan_ref,
                sandbox_ref,
                resource_ref,
                environment_ref,
                recipe_ref,
                tool_ref,
                candidate_ref,
            ),
            dynamic_request_ref=request_ref,
            reproduction_plan_ref=plan_ref,
            sandbox_profile_ref=sandbox_ref,
            resource_profile_ref=resource_ref,
            run_policy_state_ref=run_policy_state_ref,
            image_digest=recipe.built_image_digest,
            network_targets=(),
            resource_limits={
                "cpu_limit_millicores": sandbox.cpu_limit_millicores,
                "memory_limit_bytes": sandbox.memory_limit_bytes,
                "disk_limit_bytes": sandbox.disk_limit_bytes,
                "pid_limit": sandbox.pid_limit,
                "requested_execution_ms": sandbox.max_requested_execution_ms,
            },
        )
        command_units = self.runner.units(elapsed_ms=1, cost_minor_units=1)
        command_reservation = self.runner.reserve(
            dynamic_work, scope, command_action, command_units
        )
        command_decision = self.runner.authorize(
            dynamic_work, command_action, command_reservation
        )
        claimed_command_decision = self.runtime.validator.claim_external(
            str(dynamic_work.work_id),
            command_decision,
            reference(command_reservation),
        )
        assert isinstance(claimed_command_decision, StoredDataRef)
        command_policy = SandboxPolicyDecision.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("sandbox_policy_decision"),
                    action_decision_ref=claimed_command_decision,
                    request_ref=request_ref,
                    sandbox_profile_ref=sandbox_ref,
                    resource_profile_ref=resource_ref,
                    run_policy_state_ref=run_policy_state_ref,
                    policy_collection_result_ref=None,
                    policy_record_ref=None,
                    execution_scope="LOCAL_ONLY",
                    observed_policy_status="PREPARING",
                    decision="ALLOW",
                    reason_codes=("LOCAL_BOUNDARY_OK",),
                    checked_boundary_refs=(environment_ref, tool_ref),
                    decided_at=self.clock.now(),
                )
            )
        )
        policy_ref = self._publish_intermediate(dynamic_work, command_policy)
        policy = command_policy
        assert tool_request.command is not None
        command_fields = tool_request.command.model_dump()
        command_candidate = SandboxCommandRecord.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("sandbox_command_record"),
                    request_ref=request_ref,
                    action_id=command_action.action_id,
                    tool_request_ref=tool_ref,
                    reproduction_plan_ref=plan_ref,
                    environment_recipe_ref=recipe_ref,
                    environment_ref=environment_ref,
                    command_digest=content_hash(command_fields),
                    redaction_status="NOT_REQUIRED",
                    created_at=self.clock.now(),
                    **command_fields,
                )
            )
        )

        async def execute_command() -> SandboxCommandRecord:
            return await self.sandbox_execute(
                ApprovedSandboxCommand(tool_request, policy), command_candidate
            )

        returned_command: SandboxCommandRecord = asyncio.run(
            self.runtime.external.invoke(
                str(dynamic_work.work_id),
                command_decision,
                reference(command_reservation),
                execute_command,
                idempotency_key=str(command_action.action_id),
            )
        )
        self.runner.account(command_reservation, command_units)
        if returned_command != command_candidate:
            raise ValueError("FAKE_SANDBOX_COMMAND_MISMATCH")
        command_ref = self._publish_intermediate(dynamic_work, returned_command)
        observation = self._artifact("observation")
        cleanup_resource_refs = (
            owned_container_resource_ref(
                container_id=environment.container_instance_id,
                meta=environment.meta,
            ),
        )
        cleanup_candidate = CleanupResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("cleanup_result"),
                    request_ref=request_ref,
                    environment_refs=(environment_ref,),
                    resource_refs=cleanup_resource_refs,
                    status="SUCCEEDED",
                    failure_reason=None,
                    finished_at=self.clock.now(),
                )
            )
        )

        async def cleanup_environment() -> CleanupResult:
            return await self.sandbox_cleanup(
                SandboxCleanupRequest(
                    request,
                    (environment,),
                    cleanup_resource_refs,
                ),
                cleanup_candidate,
            )

        cleanup_action = self.runner.action(
            dynamic_work,
            setup_identity,
            "REPRODUCTION_SETUP_AUTOMATION",
            "RUN_SANDBOX",
            input_refs=(*sandbox_action.input_refs, environment_ref),
            dynamic_request_ref=request_ref,
            reproduction_plan_ref=plan_ref,
            sandbox_profile_ref=sandbox_ref,
            resource_profile_ref=resource_ref,
            run_policy_state_ref=run_policy_state_ref,
            image_digest=recipe.built_image_digest,
            network_targets=(),
            resource_limits=sandbox_action.resource_limits,
        )
        cleanup_units = self.runner.units(elapsed_ms=1, cost_minor_units=1)
        cleanup_reservation = self.runner.reserve(
            dynamic_work, scope, cleanup_action, cleanup_units
        )
        cleanup_decision = self.runner.authorize(
            dynamic_work, cleanup_action, cleanup_reservation
        )
        cleanup = asyncio.run(
            self.runtime.external.invoke(
                str(dynamic_work.work_id),
                cleanup_decision,
                reference(cleanup_reservation),
                cleanup_environment,
                idempotency_key=str(cleanup_action.action_id),
            )
        )
        self.runner.account(cleanup_reservation, cleanup_units)
        if cleanup != cleanup_candidate:
            raise ValueError("FAKE_SANDBOX_CLEANUP_MISMATCH")
        cleanup_ref = self._publish_intermediate(dynamic_work, cleanup)
        events = []
        for sequence, (event_type, action_id) in enumerate(
            (
                ("SESSION_STARTED", "session"),
                ("AGENT_STARTED", "agent"),
                ("POC_CANDIDATE_CREATED", "candidate"),
                ("COMMAND_STARTED", command_action.action_id),
                ("COMMAND_FINISHED", command_action.action_id),
                ("POC_EXECUTION_STARTED", command_action.action_id),
                ("POC_EXECUTION_FINISHED", command_action.action_id),
                ("CLEANUP_STARTED", cleanup_action.action_id),
                ("CLEANUP_FINISHED", cleanup_action.action_id),
                ("AGENT_FINISHED", "agent"),
                ("SESSION_FINISHED", "session"),
            ),
            1,
        ):
            events.append(
                dict(
                    event_id=f"fake-event-{sequence}",
                    sequence=sequence,
                    action_id=action_id,
                    event_type=event_type,
                    actor="REPRODUCTION_SESSION_MANAGER",
                    environment_ref=environment_ref,
                    environment_recipe_ref=recipe_ref,
                    poc_candidate_ref=candidate_ref
                    if event_type.startswith(("POC_", "COMMAND_"))
                    else None,
                    tool_request_ref=tool_ref
                    if event_type.startswith(("POC_EXECUTION_", "COMMAND_"))
                    else None,
                    command_ref=command_ref
                    if event_type.startswith(("POC_EXECUTION_", "COMMAND_"))
                    else None,
                    command_digest=returned_command.command_digest
                    if event_type.startswith(("POC_EXECUTION_", "COMMAND_"))
                    else None,
                    redaction_status=returned_command.redaction_status
                    if event_type.startswith(("POC_EXECUTION_", "COMMAND_"))
                    else None,
                    input_refs=(policy_ref,)
                    if event_type == "SESSION_STARTED"
                    else (candidate.content_ref,)
                    if event_type.startswith("POC_EXECUTION_")
                    else (),
                    output_refs=(observation,)
                    if event_type == "POC_EXECUTION_FINISHED"
                    else (cleanup_ref,)
                    if event_type == "CLEANUP_FINISHED"
                    else (),
                    exit_code=0 if event_type == "POC_EXECUTION_FINISHED" else None,
                    timed_out=False
                    if event_type in {"COMMAND_FINISHED", "POC_EXECUTION_FINISHED"}
                    else None,
                    safe_message="Deterministic fake event",
                    occurred_at=self.clock.now(),
                )
            )
        log = AgentLog.model_validate_json(
            canonical_bytes(
                dict(meta=meta("agent_log"), request_ref=request_ref, events=events)
            )
        )
        require_poc_execution_events(
            candidate,
            returned_command,
            tuple(
                event
                for event in log.events
                if event.event_type.startswith("POC_EXECUTION_")
            ),
        )
        log_ref = self._publish_intermediate(dynamic_work, log)
        conclusion_candidate = DynamicReproductionConclusion.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("dynamic_reproduction_conclusion"),
                    request_ref=request_ref,
                    reproduction_plan_ref=plan_ref,
                    environment_ref=environment_ref,
                    poc_candidate_ref=candidate_ref,
                    observation_refs=(observation,),
                    proposed_outcome="SUPPORTED",
                    hypothesis_evidence_refs=(observation,),
                    hypothesis_linkage="The executed candidate reached the sink",
                    limitations=(),
                    llm_call_id="fake-conclusion-call",
                )
            )
        )
        call_ref, provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            work=dynamic_work,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role="DYNAMIC_REPRODUCTION",
            result_kind="dynamic_reproduction_conclusion",
            context_refs=(
                request_ref,
                plan_ref,
                environment_ref,
                candidate_ref,
                log_ref,
            ),
        )
        conclusion_record, conclusion_invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=dynamic_work,
            scope=scope,
            identity=dynamic_identity,
            action_role=RequesterRole.DYNAMIC_REPRODUCTION,
            action_type="CALL_LLM",
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: conclusion_candidate,
            provider_invoke=self.provider_invoke,
        )
        assert isinstance(conclusion_record, DynamicReproductionConclusion)
        conclusion = conclusion_record
        persist_fake_invocation(self.runtime, conclusion_invocation)
        conclusion_ref = self._publish_intermediate(dynamic_work, conclusion)
        poc = PoCBundle.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("poc_bundle"),
                    request_ref=request_ref,
                    reproduction_plan_ref=plan_ref,
                    environment_recipe_ref=recipe_ref,
                    environment_ref=environment_ref,
                    agent_log_ref=log_ref,
                    candidate_ref=candidate_ref,
                    candidate_digest=candidate.content_digest,
                    execution_action_id=command_action.action_id,
                    evidence_refs=(observation,),
                    validated_at=self.clock.now(),
                )
            )
        )
        poc_ref = self._publish_intermediate(dynamic_work, poc)
        result = DynamicReproductionResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("dynamic_reproduction_result"),
                    action_decision_ref=claimed_command_decision,
                    request_ref=request_ref,
                    reproduction_plan_ref=plan_ref,
                    purpose="POC_CONFIRMATION",
                    policy_decision_ref=policy_ref,
                    agent_invoked=True,
                    agent_log_ref=log_ref,
                    agent_conclusion_ref=conclusion_ref,
                    environment_recipe_ref=recipe_ref,
                    environment_ref=environment_ref,
                    poc_candidate_ref=candidate_ref,
                    poc_ref=poc_ref,
                    observation_refs=(observation,),
                    status="SUCCEEDED",
                    failure_category="NONE",
                    failure_reason=None,
                    plan_issues=(),
                    hypothesis_outcome="SUPPORTED",
                    hypothesis_evidence_refs=(observation,),
                    hypothesis_disproved=False,
                    disproof_evidence_refs=(),
                    hypothesis_linkage=conclusion.hypothesis_linkage,
                    plan_execution_status="EXECUTABLE",
                    plan_issue_evidence_refs=(),
                    limitations=(),
                    cleanup_required=True,
                    cleanup_status="SUCCEEDED",
                    cleanup_ref=cleanup_ref,
                    started_at=self.clock.now(),
                    finished_at=self.clock.now(),
                    elapsed_ms=1,
                )
            )
        )
        self.runner.complete(
            dynamic_work,
            session_identity,
            "REPRODUCTION_SESSION_MANAGER",
            (result, poc),
        )
        return request, result, poc


@dataclass(frozen=True)
class DynamicStageAuthorizations:
    """Exact T09 call authorizations allocated by the trusted runtime."""

    derive: DynamicAgentInvocation
    plan: DynamicAgentInvocation
    candidate: DynamicAgentInvocation | None
    execute: tuple[DynamicAgentInvocation, ...]
    interpret: DynamicAgentInvocation | None


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
    ) -> None:
        self._agent = agent
        self._workflow = workflow

    async def execute(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        authorizations: DynamicStageAuthorizations,
    ) -> WorkHandlerResult:
        session: DynamicSandboxSession | None = None
        try:
            requirements_outcome = await self._agent.derive_environment(
                work=work,
                authorization=authorizations.derive,
                request=request,
                request_ref=request_ref,
            )
            requirements = _require_stage_record(requirements_outcome, "AGENT")
            requirements_ref = self._workflow.publish(
                requirements, requirements_outcome.invocation
            )

            plan_outcome = await self._agent.plan_reproduction(
                work=work,
                authorization=authorizations.plan,
                request=request,
                request_ref=request_ref,
                requirements=requirements,
                requirements_ref=requirements_ref,
            )
            plan = _require_stage_record(plan_outcome, "PLAN")
            plan_ref = self._workflow.publish(plan, plan_outcome.invocation)

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
            if authorizations.candidate is None:
                raise DynamicOperationalError(
                    "FAILED", "INTERNAL", "PoC candidate authorization is missing"
                )
            assert session.environment is not None
            assert session.environment_ref is not None
            assert session.log is not None
            candidate_outcome = await self._agent.create_poc_candidate(
                work=work,
                authorization=authorizations.candidate,
                request=request,
                request_ref=request_ref,
                plan=plan,
                plan_ref=plan_ref,
                environment=session.environment,
                environment_ref=session.environment_ref,
            )
            candidate = _require_stage_record(candidate_outcome, "AGENT")
            candidate_ref = self._workflow.publish(
                candidate, candidate_outcome.invocation
            )

            finished = False
            for turn_number, authorization in enumerate(
                authorizations.execute, start=1
            ):
                assert session.environment is not None
                assert session.environment_ref is not None
                assert session.log is not None
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
            if authorizations.interpret is None:
                raise DynamicOperationalError(
                    "FAILED",
                    "INTERNAL",
                    "Attempt interpretation authorization is missing",
                )
            assert session.environment is not None
            assert session.environment_ref is not None
            assert session.log is not None
            conclusion_outcome = await self._agent.interpret_attempt(
                work=work,
                authorization=authorizations.interpret,
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
        except Exception:
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
                    failure_reason="Unexpected dynamic workflow failure",
                ),
            )


def _require_stage_record[T](
    outcome: DynamicAgentOutcome[T], category: Literal["AGENT", "PLAN"]
) -> T:
    if outcome.record is None:
        raise DynamicOperationalError(
            "FAILED", category, "LLM stage did not produce a usable result"
        )
    return outcome.record
