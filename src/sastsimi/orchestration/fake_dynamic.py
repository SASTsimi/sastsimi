"""Evidence, dynamic reproduction and Verification generation stages."""

from typing import Any

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
    EnvironmentRecipe,
    EnvironmentRequirements,
    PoCBundle,
    PoCCandidate,
    ReproductionPlan,
    SandboxEnvironment,
    SandboxPolicyDecision,
    SandboxProfile,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import (
    ConEvidenceResult,
    ProEvidenceResult,
)

from .fake_base import ANALYSIS_ID
from .fake_setup import FakeSetupStages


class FakeDynamicStages(FakeSetupStages):
    def _evidence_result(
        self,
        *,
        role: str,
        work: Any,
        parent_work: Any,
        evidence_ref: StoredDataRef,
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
                    debate_input_hash=content_hash((evidence_ref,)),
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
        request_ref = self._publish_intermediate(
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
        requirements_ref = self._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.DYNAMIC_REPRODUCTION,
            requirements,
        )
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
        plan_ref = self._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.DYNAMIC_REPRODUCTION,
            plan,
        )
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
        recipe_ref = self._publish_intermediate(
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
        environment_ref = self._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
            environment,
        )
        lifecycle_ref = self.runtime.budget_registry.current_state(
            str(ANALYSIS_ID)
        ).budget_binding_ref
        assert lifecycle_ref is not None
        binding = self.runtime.unit_of_work.records.get_exact(lifecycle_ref)
        assert isinstance(binding, BudgetProfileBinding)
        resource_ref = binding.dynamic_lifecycle_profile_ref
        policy = SandboxPolicyDecision.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("sandbox_policy_decision"),
                    action_decision_ref=decision,
                    request_ref=request_ref,
                    sandbox_profile_ref=sandbox_ref,
                    resource_profile_ref=resource_ref,
                    run_policy_state_ref=self._artifact(
                        "run_policy_state", record=True
                    ),
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
        policy_ref = self._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.SANDBOX_CONTROLLER,
            policy,
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
        candidate_ref = self._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.DYNAMIC_REPRODUCTION,
            candidate,
        )
        observation = self._artifact("observation")
        events = []
        for sequence, (event_type, action_id) in enumerate(
            (
                ("SESSION_STARTED", "session"),
                ("AGENT_STARTED", "agent"),
                ("POC_CANDIDATE_CREATED", "candidate"),
                ("POC_EXECUTION_STARTED", "execute"),
                ("POC_EXECUTION_FINISHED", "execute"),
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
                    tool_request_ref=None,
                    command_ref=None,
                    command_digest=None,
                    redaction_status=None,
                    input_refs=(policy_ref,) if event_type == "SESSION_STARTED" else (),
                    output_refs=(observation,)
                    if event_type == "POC_EXECUTION_FINISHED"
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
        log_ref = self._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.REPRODUCTION_SESSION_MANAGER,
            log,
        )
        conclusion = DynamicReproductionConclusion.model_validate_json(
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
        conclusion_ref = self._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.DYNAMIC_REPRODUCTION,
            conclusion,
        )
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
                    execution_action_id="execute",
                    evidence_refs=(observation,),
                    validated_at=self.clock.now(),
                )
            )
        )
        poc_ref = self._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.REPRODUCTION_SESSION_MANAGER,
            poc,
        )
        cleanup = CleanupResult.model_validate_json(
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
        cleanup_ref = self._publish_intermediate(
            dynamic_work,
            dynamic_identity,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
            cleanup,
        )
        result = DynamicReproductionResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=meta("dynamic_reproduction_result"),
                    action_decision_ref=decision,
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
