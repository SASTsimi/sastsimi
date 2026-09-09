"""Deterministic dynamic-reproduction orchestration stages."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import (
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
from sastsimi.contracts.verification import (
    ConEvidenceResult,
    ProEvidenceResult,
)
from sastsimi.orchestration.fake_base import ANALYSIS_ID
from sastsimi.orchestration.fake_configuration import register_fake_llm_call
from sastsimi.ports.dto import (
    ApprovedSandboxCommand,
    Record,
    SandboxCleanupRequest,
    SandboxPrepareRequest,
)

from .fake_base import FakeStageService
from .fake_provider_runtime import (
    invoke_fake_provider,
    persist_fake_invocation,
)

if TYPE_CHECKING:
    from .fake_base import FakePipelineBase
    from .fake_setup import FakeSetupStages


class FakeDynamicStages(FakeStageService):
    def __init__(self, host: FakePipelineBase, setup: FakeSetupStages) -> None:
        super().__init__(host)
        self._setup = setup

    def _agent_intermediate(
        self,
        *,
        candidate: Record,
        work: Any,
        scope: StoredDataRef,
        identity: StoredDataRef,
        result_kind: str,
        context_refs: tuple[StoredDataRef, ...],
    ) -> tuple[Record, StoredDataRef]:
        assert self.runtime is not None and self.runner is not None
        call_ref, provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            scope=scope,
            orchestration_identity=identity,
            role="DYNAMIC_REPRODUCTION",
            result_kind=result_kind,
            context_refs=context_refs,
        )
        self.evidence.identities[identity] = RequesterRole.DYNAMIC_REPRODUCTION
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
        ref = self._setup._publish_intermediate(
            work,
            identity,
            RequesterRole.DYNAMIC_REPRODUCTION,
            record,
        )
        persist_fake_invocation(self.runtime, invocation, ref)
        return record, ref

    def _evidence_result(
        self,
        *,
        role: str,
        work: Any,
        parent_work: Any,
        debate_inputs: tuple[StoredDataRef, ...],
    ) -> ProEvidenceResult | ConEvidenceResult:
        assert self.runner is not None
        model = ProEvidenceResult if role == "PRO" else ConEvidenceResult
        return model.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        parent_work.meta,
                        f"{role.lower()}_evidence_result",
                        attempt_id=work.active_attempt_id,
                    ),
                    role=role,
                    parent_work_id=parent_work.work_id,
                    evidence_work_id=work.work_id,
                    verification_generation=parent_work.work_generation,
                    llm_call_id=f"fake-{role.lower()}-call",
                    debate_input_hash=content_hash(debate_inputs),
                    evidence=(),
                    summary=f"{role} reviewed the exact fake path",
                    limitations=(),
                )
            )
        )

    def _dynamic_chain(
        self,
        *,
        scope: StoredDataRef,
        owner_ref: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        verification_work: Any,
        assignment_ref: StoredDataRef,
        hypothesis_ref: StoredDataRef,
        evidence_ref: StoredDataRef,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
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
        request_ref = self._setup._publish_intermediate(
            verification_work,
            owner_ref,
            RequesterRole.VERIFICATION,
            request,
        )
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
        dynamic_identity = orchestrator_ref
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
            identity=dynamic_identity,
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
            identity=dynamic_identity,
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
                    base_image_digest="1" * 64,
                    built_image_digest="2" * 64,
                    baseline_recipe_ref=None,
                    build_disposition="BUILT",
                    created_at=self.clock.now(),
                )
            )
        )
        recipe_ref = self._setup._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
            recipe,
        )
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
        self.evidence.identities[dynamic_identity] = (
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION
        )
        sandbox_action = self.runner.action(
            dynamic_work,
            dynamic_identity,
            "REPRODUCTION_SETUP_AUTOMATION",
            "RUN_SANDBOX",
            input_refs=(
                request_ref,
                requirements_ref,
                plan_ref,
                sandbox_ref,
                resource_ref,
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
        policy_ref = self._setup._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.SANDBOX_CONTROLLER,
            policy,
        )
        self.evidence.identities[dynamic_identity] = (
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION
        )

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
        environment_ref = self._setup._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
            returned_environment,
        )
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
            identity=dynamic_identity,
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
                        executable="python",
                        arguments=("poc.py",),
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
            identity=dynamic_identity,
            result_kind="dynamic_reproduction_tool_request",
            context_refs=(request_ref, plan_ref, environment_ref, candidate_ref),
        )
        assert isinstance(tool_record, DynamicReproductionToolRequest)
        tool_request = tool_record

        command_identity = tool_ref
        self.evidence.identities[command_identity] = (
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION
        )
        command_action = self.runner.action(
            dynamic_work,
            command_identity,
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
        policy_ref = self._setup._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.SANDBOX_CONTROLLER,
            command_policy,
        )
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
        command_ref = self._setup._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.REPRODUCTION_SESSION_MANAGER,
            returned_command,
        )
        observation = self._artifact("observation")
        cleanup_candidate = CleanupResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("cleanup_result"),
                    request_ref=request_ref,
                    environment_refs=(environment_ref,),
                    resource_refs=(),
                    status="SUCCEEDED",
                    failure_reason=None,
                    finished_at=self.clock.now(),
                )
            )
        )

        async def cleanup_environment() -> CleanupResult:
            return await self.sandbox_cleanup(
                SandboxCleanupRequest(request, (environment,), ()), cleanup_candidate
            )

        cleanup = asyncio.run(cleanup_environment())
        if cleanup != cleanup_candidate:
            raise ValueError("FAKE_SANDBOX_CLEANUP_MISMATCH")
        cleanup_ref = self._setup._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
            cleanup,
        )
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
                ("CLEANUP_STARTED", "cleanup"),
                ("CLEANUP_FINISHED", "cleanup"),
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
                    if event_type.startswith("POC_")
                    else None,
                    tool_request_ref=tool_ref
                    if event_type.startswith("COMMAND_")
                    else None,
                    command_ref=command_ref
                    if event_type.startswith("COMMAND_")
                    else None,
                    command_digest=returned_command.command_digest
                    if event_type.startswith("COMMAND_")
                    else None,
                    redaction_status=returned_command.redaction_status
                    if event_type.startswith("COMMAND_")
                    else None,
                    input_refs=(policy_ref,) if event_type == "SESSION_STARTED" else (),
                    output_refs=(observation,)
                    if event_type == "POC_EXECUTION_FINISHED"
                    else (cleanup_ref,)
                    if event_type == "CLEANUP_FINISHED"
                    else (),
                    exit_code=0 if event_type == "POC_EXECUTION_FINISHED" else None,
                    safe_message="Deterministic fake event",
                    occurred_at=self.clock.now(),
                )
            )
        log = AgentLog.model_validate_json(
            canonical_bytes(
                dict(meta=meta("agent_log"), request_ref=request_ref, events=events)
            )
        )
        log_ref = self._setup._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.REPRODUCTION_SESSION_MANAGER,
            log,
        )
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
            scope=scope,
            orchestration_identity=dynamic_identity,
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
        self.evidence.identities[dynamic_identity] = RequesterRole.DYNAMIC_REPRODUCTION
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
        conclusion_ref = self._setup._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.DYNAMIC_REPRODUCTION,
            conclusion,
        )
        persist_fake_invocation(self.runtime, conclusion_invocation, conclusion_ref)
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
        poc_ref = self._setup._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.REPRODUCTION_SESSION_MANAGER,
            poc,
        )
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
        self.evidence.identities[dynamic_identity] = (
            RequesterRole.REPRODUCTION_SESSION_MANAGER
        )
        self.evidence.next_outputs = (
            self.runtime.unit_of_work.records.stage_record(result),
            poc_ref,
        )
        try:
            self.runner.complete(
                dynamic_work,
                dynamic_identity,
                "REPRODUCTION_SESSION_MANAGER",
                (result, poc),
            )
        finally:
            self.evidence.next_outputs = None
        return request, result, poc
