from __future__ import annotations

import asyncio
import json
import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Literal, cast

import pytest

from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionCheck,
    ActionDecision,
    ActionRequest,
    ActionType,
    CheckResult,
    Decision,
    RequesterRole,
    UseStatus,
)
from sastsimi.contracts.budget import (
    DynamicReproductionLifecycleProfile,
    ProfileStatus,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import (
    POC_RUNTIME_PATH,
    DynamicReproductionConclusion,
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionToolRequest,
    EnvironmentRecipe,
    EnvironmentRequirements,
    PoCBundle,
    PoCCandidate,
    ReproductionPlan,
    SandboxCommandInput,
    SandboxEnvironment,
    SandboxPolicyDecision,
    SandboxProfile,
)
from sastsimi.contracts.ids import (
    ActionId,
    AnalysisId,
    CommitId,
    DecisionId,
    ProgramId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.llm import LLMInvocationRequest, LLMInvocationResult
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.dto import Record, StagedArtifact, WorkHandlerResult
from sastsimi.reproduction.production import (
    DynamicRecordSink,
    DynamicSandboxAuthorization,
    ProductionDynamicWorkflow,
)
from sastsimi.reproduction.service import DynamicSandboxSession, DynamicWorkflowFailure
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.sandbox.cleanup import OwnedResourceRegistry
from sastsimi.sandbox.controller import SandboxController, SandboxMount, SandboxRunSpec
from sastsimi.sandbox.docker_adapter import (
    DockerAdapter,
    DockerCommandOutcome,
    DockerContainerState,
)
from sastsimi.sandbox.health_check import SandboxHealthChecker
from sastsimi.sandbox.recipe_store import EnvironmentRecipeStore
from sastsimi.sandbox.session_manager import ReproductionSessionManager
from sastsimi.sandbox.setup_automation import ReproductionSetupAutomation
from tests.integration.runtime_support import TestClock, TestIds
from tests.integration.sandbox.test_container_lifecycle import (
    _dynamic_records,
    _meta,
    _ref,
)

_DOCKER_E2E_ENV = "SASTSIMI_REQUIRE_DOCKER_E2E"


class RecordingDockerAdapter(DockerAdapter):
    """Real argv-only adapter with an attempt-local call audit for E2E assertions."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, str | None]] = []

    async def inspect_image(self, image: str, *, timeout_ms: int) -> str:
        self.calls.append(("inspect_image", image))
        return await super().inspect_image(image, timeout_ms=timeout_ms)

    async def build(
        self,
        dockerfile: bytes,
        labels: Mapping[str, str],
        *,
        timeout_ms: int,
    ) -> str:
        self.calls.append(("build", None))
        return await super().build(dockerfile, labels, timeout_ms=timeout_ms)

    async def create(self, spec: SandboxRunSpec, labels: Mapping[str, str]) -> str:
        self.calls.append(("create", spec.image_digest))
        return await super().create(spec, labels)

    async def start(self, container_id: str) -> None:
        self.calls.append(("start", container_id))
        await super().start(container_id)

    async def inspect(self, container_id: str) -> DockerContainerState:
        self.calls.append(("inspect", container_id))
        return await super().inspect(container_id)

    async def materialize_poc(
        self, container_id: str, content: bytes, content_digest: str
    ) -> str:
        self.calls.append(("materialize_poc", container_id))
        return await super().materialize_poc(container_id, content, content_digest)

    async def execute(
        self,
        container_id: str,
        argv: tuple[str, ...],
        timeout_ms: int,
        *,
        working_directory: str,
    ) -> DockerCommandOutcome:
        self.calls.append(("exec", container_id))
        return await super().execute(
            container_id,
            argv,
            timeout_ms,
            working_directory=working_directory,
        )

    async def remove(self, resource_ids: tuple[str, ...]) -> None:
        self.calls.extend(("remove", resource_id) for resource_id in resource_ids)
        await super().remove(resource_ids)


class MemoryArtifacts:
    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        return StagedArtifact(data, media_type)

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        import hashlib

        digest = hashlib.sha256(staged.data).hexdigest()
        self.data[digest] = staged.data
        return StoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            workspace_id=WorkspaceId("workspace-1"),
            commit_id=CommitId("commit-1"),
            record_id=None,
        )

    def commit_run(
        self, staged: StagedArtifact, analysis_id: AnalysisId
    ) -> RunStoredDataRef:
        import hashlib

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
        from io import BytesIO

        return BytesIO(self.data[ref.content_hash])


@dataclass
class MemorySink:
    published: list[Record]
    finished: list[Record]

    def publish(
        self,
        *,
        work: WorkExecutionState,
        role: RequesterRole,
        record: Record,
        input_refs: tuple[StoredDataRef, ...],
    ) -> StoredDataRef:
        del work, role, input_refs
        self.published.append(record)
        result = reference(record)
        assert isinstance(result, StoredDataRef)
        return result

    def finish(
        self,
        *,
        work: WorkExecutionState,
        result: Record,
        status: str,
        input_refs: tuple[StoredDataRef, ...],
    ) -> WorkHandlerResult:
        del work, status, input_refs
        self.finished.append(result)
        result_ref = reference(result)
        assert isinstance(result_ref, StoredDataRef)
        return WorkHandlerResult((result_ref,))


async def _docker(
    *arguments: str, input_bytes: bytes | None = None
) -> tuple[int, bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        "docker",
        *arguments,
        stdin=(asyncio.subprocess.PIPE if input_bytes is not None else None),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate(input_bytes)
    assert process.returncode is not None
    return process.returncode, stdout, stderr


async def _require_docker() -> None:
    required = os.environ.get(_DOCKER_E2E_ENV) == "1"
    if not required:
        pytest.skip("real Docker E2E is enabled only by the dedicated CI step")
    if shutil.which("docker") is None:
        pytest.fail("Docker CLI is required for the Ubuntu T11 E2E job")
    code, _, error = await _docker("version", "--format", "{{.Server.Version}}")
    if code != 0:
        pytest.fail(f"Docker daemon is required: {error.decode(errors='replace')}")


def _work(request_ref: StoredDataRef) -> WorkExecutionState:
    return WorkExecutionState.model_validate(
        {
            "meta": _meta("work_execution_state", "dynamic-work").model_copy(
                update={"attempt_id": None}
            ),
            "work_id": "dynamic-work",
            "parent_work_ref": _ref("work_execution_state", "verification-work"),
            "work_type": WorkType.DYNAMIC_REPRO,
            "subject_type": SubjectType.HYPOTHESIS,
            "subject_id": "hypothesis-1",
            "work_generation": 1,
            "status": WorkStatus.RUNNING,
            "active_attempt_id": "dynamic-attempt-1",
            "input_refs": (request_ref,),
            "input_hash": content_hash((request_ref,)),
            "dedupe_key": "d" * 64,
            "trigger_primitive_ref": None,
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "waiting_for": (),
            "stop_reason": None,
            "started_at": _meta("unused", "unused").created_at,
            "finished_at": None,
            "elapsed_ms": 0,
            "state_version": 2,
            "last_transition_ref": _ref("state_transition", "started"),
            "last_transition_commit_ref": None,
        }
    )


def _run_spec(workspace: Path) -> SandboxRunSpec:
    return SandboxRunSpec(
        workspace_root=workspace,
        image_digest=None,  # learned from the boundary-approved cold build
        user="65532:65532",
        mounts=(
            SandboxMount(
                source=workspace,
                target=PurePosixPath("/workspace"),
                read_only=True,
            ),
        ),
        network_mode="DEFAULT_DENY",
        network_targets=(),
        secret_refs=(),
        privileged=False,
        pid_mode=None,
        ipc_mode=None,
        capabilities=(),
        cpu_limit_millicores=500,
        memory_limit_bytes=256 * 1024 * 1024,
        disk_limit_bytes=64 * 1024 * 1024,
        pid_limit=64,
        requested_execution_ms=30_000,
    )


class SandboxAuthorizer:
    """Issue and claim exact BUILD/RUN approvals for the public workflow path."""

    def __init__(self, workspace: Path, *, forbidden: bool = False) -> None:
        self.workspace = workspace
        self.forbidden = forbidden
        global_meta = _meta("sandbox_profile", "sandbox-profile").model_copy(
            update={"hypothesis_id": None, "attempt_id": None}
        )
        self.profile = SandboxProfile(
            meta=global_meta,
            network_mode="DEFAULT_DENY",
            allowed_egress_refs=(),
            isolation_policy_refs=(),
            cpu_limit_millicores=1_000,
            memory_limit_bytes=512 * 1024 * 1024,
            disk_limit_bytes=128 * 1024 * 1024,
            pid_limit=128,
            max_requested_execution_ms=30_000,
            created_at=global_meta.created_at,
        )
        lifecycle_meta = global_meta.model_copy(
            update={
                "record_id": "lifecycle-profile",
                "logical_record_id": "lifecycle-profile",
                "record_type": "dynamic_reproduction_lifecycle_profile",
            }
        )
        self.lifecycle = DynamicReproductionLifecycleProfile(
            meta=lifecycle_meta,
            profile_key="dynamic-e2e",
            preflight_budget_ref=_ref("budget_reservation", "preflight-budget"),
            preflight_budget_source="WORK_REMAINING_TIME",
            max_new_attempts=1,
            status=ProfileStatus.ACTIVE,
            created_at=lifecycle_meta.created_at,
        )
        policy_meta = global_meta.model_copy(
            update={
                "record_id": "run-policy",
                "logical_record_id": "run-policy",
                "record_type": "run_policy_state",
            }
        )
        self.policy = RunPolicyState(
            meta=policy_meta,
            program_id=ProgramId(root="local-e2e"),
            status="PREPARING",
            preparation_source=None,
            source_config_ref=_ref("policy_source_config", "policy-source"),
            parser_name="local-e2e",
            parser_version="1.0.0",
            policy_work_ref=_ref("work_execution_state", "policy-work"),
            policy_cache_ref=None,
            collection_result_ref=None,
            policy_record_ref=None,
            freshness_criterion_ref=None,
            freshness_checked_at=None,
            freshness_evidence_refs=(),
            freshness_valid_until=None,
        )
        self.records: dict[str, object] = {}
        self.actions: dict[Literal["BUILD", "RUN"], ActionRequest] = {}
        policy_ref = reference(self.policy)
        assert isinstance(policy_ref, StoredDataRef)
        assert policy_ref.record_id is not None
        self.records[str(policy_ref.record_id)] = self.policy

    def resolve(self, ref: StoredDataRef) -> object:
        assert ref.record_id is not None
        return self.records[str(ref.record_id)]

    def authorize(
        self,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        phase: Literal["BUILD", "RUN"],
        phase_ref: StoredDataRef,
        image_digest: str | None,
        context_refs: tuple[StoredDataRef, ...],
    ) -> DynamicSandboxAuthorization:
        request_ref = cast(StoredDataRef, reference(request))
        requirements_ref = cast(StoredDataRef, reference(requirements))
        plan_ref = cast(StoredDataRef, reference(plan))
        profile_ref = cast(StoredDataRef, reference(self.profile))
        lifecycle_ref = cast(StoredDataRef, reference(self.lifecycle))
        policy_ref = cast(StoredDataRef, reference(self.policy))
        work_ref = cast(StoredDataRef, reference(work))
        spec = replace(_run_spec(self.workspace), image_digest=image_digest)
        if self.forbidden:
            spec = replace(
                spec,
                mounts=(
                    replace(
                        spec.mounts[0],
                        target=PurePosixPath("/var/run/docker.sock"),
                    ),
                ),
            )
        action_meta = _meta(
            "action_request",
            f"sandbox-{phase.lower()}-action",
        )
        action = ActionRequest(
            meta=action_meta,
            action_id=ActionId(root=f"sandbox-{phase.lower()}-action"),
            requested_by=RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
            requester_identity_ref=_ref("identity", "setup-identity"),
            action_type=ActionType.RUN_SANDBOX,
            work_ref=work_ref,
            expected_state_version=work.state_version,
            expected_verification_generation=None,
            generation_restart_reason=None,
            generation_restart_basis_refs=(),
            input_refs=(
                request_ref,
                requirements_ref,
                plan_ref,
                profile_ref,
                lifecycle_ref,
                phase_ref,
                *context_refs,
            ),
            dynamic_request_ref=request_ref,
            reproduction_plan_ref=plan_ref,
            result_kind=None,
            candidate_result_ref=None,
            llm_call_spec_ref=None,
            tool_name=None,
            file_paths=(),
            provider_profile_ref=None,
            session_mode=None,
            sandbox_profile_ref=profile_ref,
            resource_profile_ref=lifecycle_ref,
            run_policy_state_ref=policy_ref,
            image_digest=image_digest,
            network_targets=(),
            resource_limits={
                "cpu_limit_millicores": spec.cpu_limit_millicores,
                "memory_limit_bytes": spec.memory_limit_bytes,
                "disk_limit_bytes": spec.disk_limit_bytes,
                "pid_limit": spec.pid_limit,
                "requested_execution_ms": spec.requested_execution_ms,
            },
            reason=f"Authorize the exact {phase.lower()} phase",
            requested_at=action_meta.created_at,
        )
        action_ref = cast(StoredDataRef, reference(action))
        checks = tuple(sorted(REQUIRED_CHECKS[ActionType.RUN_SANDBOX], key=str))
        decision_meta = _meta(
            "action_decision",
            f"sandbox-{phase.lower()}-decision",
        ).model_copy(
            update={
                "revision_number": 2,
                "previous_record_id": f"sandbox-{phase.lower()}-decision-v1",
            }
        )
        decision = ActionDecision(
            meta=decision_meta,
            decision_id=DecisionId(root=f"sandbox-{phase.lower()}-decision"),
            action_ref=action_ref,
            decision=Decision.ALLOW,
            required_checks=checks,
            check_results=tuple(
                ActionCheck(
                    check_type=check,
                    result=CheckResult.PASS,
                    reason_code="E2E_TRUSTED_RUNTIME",
                    safe_message="The E2E runtime claimed this exact action",
                )
                for check in checks
            ),
            checked_state_version=work.state_version,
            checked_config_refs=(profile_ref, lifecycle_ref),
            valid_until=decision_meta.created_at + timedelta(minutes=1),
            error_ids=(),
            use_status=UseStatus.USED,
            used_at=decision_meta.created_at,
            expired_at=None,
            expire_reason=None,
            outcome_refs=(),
            decided_at=decision_meta.created_at,
        )
        decision_ref = cast(StoredDataRef, reference(decision))
        assert decision_ref.record_id is not None
        self.records[str(decision_ref.record_id)] = decision
        self.actions[phase] = action
        return DynamicSandboxAuthorization(
            action=action,
            action_decision_ref=decision_ref,
            sandbox_profile=self.profile,
            lifecycle_profile=self.lifecycle,
            run_policy_state_ref=policy_ref,
            run_spec=spec,
        )


def _records_for(
    authorizer: SandboxAuthorizer,
) -> tuple[
    DynamicReproductionRequest,
    EnvironmentRequirements,
    ReproductionPlan,
]:
    request, requirements, plan = _dynamic_records()
    profile_ref = cast(StoredDataRef, reference(authorizer.profile))
    request = request.model_copy(update={"sandbox_profile_ref": profile_ref})
    request_ref = cast(StoredDataRef, reference(request))
    requirements = requirements.model_copy(update={"request_ref": request_ref})
    requirements_ref = cast(StoredDataRef, reference(requirements))
    plan = plan.model_copy(
        update={
            "request_ref": request_ref,
            "environment_requirements_ref": requirements_ref,
            "sandbox_profile_ref": profile_ref,
        }
    )
    return request, requirements, plan


def _tool(
    *,
    action: Literal["USE_POC_CANDIDATE", "RUN_COMMAND"],
    turn: int,
    request: DynamicReproductionRequest,
    plan: ReproductionPlan,
    environment: SandboxEnvironment,
    candidate_ref: StoredDataRef,
) -> DynamicReproductionToolRequest:
    command = None
    selected = None
    if action == "USE_POC_CANDIDATE":
        selected = candidate_ref
    elif action == "RUN_COMMAND":
        command = SandboxCommandInput(
            executable="/bin/sh",
            arguments=(POC_RUNTIME_PATH,),
            working_directory="/workspace",
            environment_binding_refs=(),
            stdin_ref=None,
            secret_refs=(),
        )
    return DynamicReproductionToolRequest(
        meta=_meta("dynamic_reproduction_tool_request", f"tool-{turn}"),
        request_ref=cast(StoredDataRef, reference(request)),
        reproduction_plan_ref=cast(StoredDataRef, reference(plan)),
        environment_ref=cast(StoredDataRef, reference(environment)),
        turn_number=turn,
        action=action,
        command=command,
        poc_candidate_ref=selected,
        recreate_reason=None,
        rationale="Run the exact local PoC candidate",
        llm_call_id=f"tool-call-{turn}",
    )


def _invocation(
    artifacts: MemoryArtifacts,
    work: WorkExecutionState,
    *,
    llm_call_id: str,
    task_kind: str,
    output: object,
    sequence: int,
) -> PersistedLLMInvocation:
    output_ref = artifacts.commit(
        artifacts.stage_bytes(canonical_bytes(output), "application/json")
    )
    template_ref = artifacts.commit(
        artifacts.stage_bytes(
            f"dynamic-e2e-template-{sequence}".encode(), "text/markdown"
        )
    )
    request = LLMInvocationRequest.model_validate(
        {
            "meta": _meta("llm_invocation_request", f"invocation-request-{sequence}"),
            "llm_call_id": llm_call_id,
            "action_decision_ref": _ref("action_decision", f"llm-decision-{sequence}"),
            "call_spec_ref": _ref("llm_call_spec", f"call-{sequence}"),
            "agent_role": "DYNAMIC_REPRODUCTION",
            "task_kind": task_kind,
            "purpose": "EVALUATION",
            "provider_profile_ref": _ref("provider_profile", "provider"),
            "model": "docker-e2e-fixture",
            "session_policy": "NEW",
            "parent_session_ref": None,
            "context_refs": work.input_refs,
            "prompt_registry_entry_ref": _ref(
                "prompt_registry_entry", f"prompt-entry-{sequence}"
            ),
            "prompt_key": "dynamic.execute-reproduction.docker-e2e-v1",
            "prompt_template_ref": template_ref,
            "prompt_template_version": "1.0.0",
            "prompt_payload_ref": _ref("prompt_payload", f"payload-{sequence}"),
            "execution_limits_ref": _ref("execution_limits", "limits"),
            "retry_policy_ref": _ref("llm_retry_policy", "retry"),
            "tool_policy_ref": _ref("llm_tool_policy", "dynamic-tools"),
            "redaction_policy_ref": _ref("prompt_redaction_policy", "redaction"),
            "semantic_validator_ref": _ref(
                "semantic_validator_spec", "dynamic-validator"
            ),
            "output_schema_ref": _ref("output_schema_spec", "dynamic-output-schema"),
            "output_schema": "{}",
            "token_budget": 100,
            "timeout_ms": 1_000,
        }
    )
    result = LLMInvocationResult.model_validate(
        {
            "meta": _meta("llm_invocation_result", f"invocation-result-{sequence}"),
            "llm_call_id": llm_call_id,
            "purpose": request.purpose,
            "status": "SUCCEEDED",
            "provider": "FIXTURE",
            "model": request.model,
            "actual_session_mode": "NEW",
            "session_ref": f"dynamic-e2e-session-{sequence}",
            "response_ref": output_ref,
            "parsed_output_ref": output_ref,
            "usage": None,
            "started_at": request.meta.created_at,
            "finished_at": request.meta.created_at,
            "elapsed_ms": 0,
            "safe_error": None,
        }
    )
    return PersistedLLMInvocation(
        request=request,
        result=result,
        log_ref=_ref("llm_invocation_log", f"invocation-log-{sequence}"),
        dispatch_state="RETURNED",
    )


@pytest.mark.asyncio
async def test_supported_fixture_produces_validated_poc(tmp_path: Path) -> None:
    """Fails if real Docker isolation, PoC closure, or exact cleanup regresses."""

    await _require_docker()
    fixture = Path(__file__).parents[1] / "fixtures" / "sandbox" / "sql_injection"
    workspace = tmp_path / "runtime-workspace"
    shutil.copytree(fixture, workspace)
    authorizer = SandboxAuthorizer(workspace)
    request, requirements, plan = _records_for(authorizer)
    request_ref = cast(StoredDataRef, reference(request))
    work = _work(request_ref)
    docker = RecordingDockerAdapter()
    setup = ReproductionSetupAutomation(
        docker=docker,
        recipes=EnvironmentRecipeStore(),
        health=SandboxHealthChecker(),
        resources=OwnedResourceRegistry(),
    )
    controller = SandboxController(
        workspace_root=workspace,
        workspace_id="workspace-1",
        commit_id="commit-1",
        record_resolver=authorizer.resolve,
    )
    artifacts = MemoryArtifacts()
    sink = MemorySink([], [])
    clock = TestClock()
    ids = TestIds()
    workflow = ProductionDynamicWorkflow(
        work=work,
        controller=controller,
        setup=setup,
        docker=docker,
        sessions=ReproductionSessionManager(clock=clock, ids=ids),
        artifacts=artifacts,
        clock=clock,
        ids=ids,
        sink=cast(DynamicRecordSink, sink),
        authorization=authorizer.authorize,
    )
    session: DynamicSandboxSession | None = None
    cleaned = False

    try:
        session = await workflow.open_session(
            work=work,
            request=request,
            request_ref=request_ref,
            requirements=requirements,
            requirements_ref=cast(StoredDataRef, reference(requirements)),
            plan=plan,
            plan_ref=cast(StoredDataRef, reference(plan)),
        )
        assert session.allowed is True
        assert session.environment is not None
        environment = session.environment
        recipe = next(
            item for item in sink.published if isinstance(item, EnvironmentRecipe)
        )
        build_policy = next(
            item for item in sink.published if isinstance(item, SandboxPolicyDecision)
        )
        build_decision = authorizer.records["sandbox-build-decision"]
        assert isinstance(build_decision, ActionDecision)
        assert authorizer.actions["RUN"].input_refs[-2:] == (
            reference(build_policy),
            reference(build_decision),
        )
        container_id = environment.container_instance_id
        inspect_code, inspect_bytes, inspect_error = await _docker(
            "inspect", container_id
        )
        assert inspect_code == 0, inspect_error.decode(errors="replace")
        inspected = json.loads(inspect_bytes)[0]
        host = inspected["HostConfig"]
        ownership_labels = {
            key: value
            for key, value in inspected["Config"]["Labels"].items()
            if key.startswith("sastsimi.")
        }
        assert inspected["Name"] == (
            f"/{DockerAdapter.runtime_container_name(ownership_labels)}"
        )
        assert ownership_labels["sastsimi.owner"] == ("reproduction-setup-automation")
        assert ownership_labels["sastsimi.analysis-id"] == "analysis-1"
        assert ownership_labels["sastsimi.hypothesis-id"] == "hypothesis-1"
        assert ownership_labels["sastsimi.attempt-id"] == "dynamic-attempt-1"
        assert inspected["Config"]["User"] == "65532:65532"
        assert inspected["Image"] == recipe.built_image_digest
        assert host["NetworkMode"] == "none"
        assert host["ReadonlyRootfs"] is True
        assert host["CapDrop"] == ["ALL"]
        assert "no-new-privileges" in host["SecurityOpt"]
        assert host["PidsLimit"] == 64
        assert host["NanoCpus"] == 500_000_000
        assert host["Memory"] == 256 * 1024 * 1024
        tmpfs = host["Tmpfs"]["/tmp"]
        assert "noexec" in tmpfs
        assert "nosuid" in tmpfs
        assert "nodev" in tmpfs
        assert "size=67108864" in tmpfs
        assert inspected["Mounts"][0]["RW"] is False

        candidate_bytes = b"""#!/bin/sh
set -eu
PYTHONDONTWRITEBYTECODE=1 python /workspace/app.py "nobody' OR '1'='1" | grep admin
"""
        content_ref = artifacts.commit(
            artifacts.stage_bytes(candidate_bytes, "text/x-shellscript")
        )
        candidate = PoCCandidate(
            meta=_meta("poc_candidate", "candidate"),
            request_ref=request_ref,
            reproduction_plan_ref=cast(StoredDataRef, reference(plan)),
            content_ref=content_ref,
            content_digest=content_ref.content_hash,
            llm_call_id="candidate-call",
            created_at=request.created_at,
        )
        candidate_ref = workflow.publish(
            candidate,
            _invocation(
                artifacts,
                work,
                llm_call_id=candidate.llm_call_id,
                task_kind="CREATE_POC_CANDIDATE",
                output=candidate,
                sequence=1,
            ),
        )
        actions: tuple[Literal["USE_POC_CANDIDATE", "RUN_COMMAND"], ...] = (
            "USE_POC_CANDIDATE",
            "USE_POC_CANDIDATE",
            "RUN_COMMAND",
        )
        for turn, action in enumerate(actions, start=2):
            tool = _tool(
                action=action,
                turn=turn - 1,
                request=request,
                plan=plan,
                environment=environment,
                candidate_ref=candidate_ref,
            )
            tool_ref = workflow.publish(
                tool,
                _invocation(
                    artifacts,
                    work,
                    llm_call_id=tool.llm_call_id,
                    task_kind="EXECUTE_REPRODUCTION",
                    output=tool,
                    sequence=turn,
                ),
            )
            session = await workflow.apply_tool(
                work=work,
                request=request,
                request_ref=request_ref,
                requirements=requirements,
                requirements_ref=cast(StoredDataRef, reference(requirements)),
                plan=plan,
                plan_ref=cast(StoredDataRef, reference(plan)),
                candidate=candidate,
                candidate_ref=candidate_ref,
                tool=tool,
                tool_ref=tool_ref,
                session=session,
            )
        assert session.observation_refs
        conclusion = DynamicReproductionConclusion(
            meta=_meta("dynamic_reproduction_conclusion", "conclusion"),
            request_ref=request_ref,
            reproduction_plan_ref=cast(StoredDataRef, reference(plan)),
            environment_ref=cast(StoredDataRef, reference(environment)),
            poc_candidate_ref=candidate_ref,
            observation_refs=session.observation_refs,
            proposed_outcome="SUPPORTED",
            hypothesis_evidence_refs=session.observation_refs,
            hypothesis_linkage="The injected input returned the admin role",
            limitations=(),
            llm_call_id="conclusion-call",
        )
        conclusion_ref = workflow.publish(
            conclusion,
            _invocation(
                artifacts,
                work,
                llm_call_id=conclusion.llm_call_id,
                task_kind="INTERPRET_ATTEMPT",
                output=conclusion,
                sequence=4,
            ),
        )
        session = await workflow.cleanup(session)
        cleaned = True
        completed = workflow.finalize(
            work=work,
            request=request,
            request_ref=request_ref,
            requirements=requirements,
            requirements_ref=cast(StoredDataRef, reference(requirements)),
            plan=plan,
            plan_ref=cast(StoredDataRef, reference(plan)),
            candidate=candidate,
            candidate_ref=candidate_ref,
            conclusion=conclusion,
            conclusion_ref=conclusion_ref,
            session=session,
        )

        assert completed.output_refs
        result = cast(DynamicReproductionResult, sink.finished[-1])
        poc = next(item for item in sink.published if isinstance(item, PoCBundle))
        assert result.status == "SUCCEEDED"
        assert result.hypothesis_outcome == "SUPPORTED"
        assert result.poc_ref == reference(poc)
        assert result.meta.attempt_id == environment.meta.attempt_id
        assert result.request_ref == request_ref
        assert result.reproduction_plan_ref == reference(plan)
        assert result.environment_ref == reference(environment)
        assert result.environment_recipe_ref == reference(recipe)
        assert result.observation_refs == session.observation_refs
        assert poc.request_ref == request_ref
        assert poc.environment_ref == reference(environment)
        assert poc.environment_recipe_ref == reference(recipe)
        assert poc.candidate_ref == candidate_ref
        assert poc.candidate_digest == candidate.content_digest
        assert poc.agent_log_ref == result.agent_log_ref
        assert poc.execution_action_id
        assert result.cleanup_status == "SUCCEEDED"
        assert ("remove", container_id) in docker.calls
        assert [call for call in docker.calls if call[0] == "remove"] == [
            ("remove", container_id)
        ]
        removed_code, _, _ = await _docker("inspect", container_id)
        assert removed_code != 0
        assert not any(
            item.meta.record_type == "verification_result" for item in sink.published
        )
    finally:
        if session is not None and session.allowed and not cleaned:
            await workflow.cleanup(session)


@pytest.mark.asyncio
async def test_forbidden_request_is_blocked_before_docker(tmp_path: Path) -> None:
    """Fails if the production boundary allows setup to reach Docker first."""

    fixture = Path(__file__).parents[1] / "fixtures" / "sandbox" / "sql_injection"
    workspace = tmp_path / "runtime-workspace"
    shutil.copytree(fixture, workspace)
    authorizer = SandboxAuthorizer(workspace, forbidden=True)
    request, requirements, plan = _records_for(authorizer)
    request_ref = cast(StoredDataRef, reference(request))
    work = _work(request_ref)
    docker = RecordingDockerAdapter()
    setup = ReproductionSetupAutomation(
        docker=docker,
        recipes=EnvironmentRecipeStore(),
        health=SandboxHealthChecker(),
        resources=OwnedResourceRegistry(),
    )
    controller = SandboxController(
        workspace_root=workspace,
        workspace_id="workspace-1",
        commit_id="commit-1",
        record_resolver=authorizer.resolve,
    )
    artifacts = MemoryArtifacts()
    sink = MemorySink([], [])
    clock = TestClock()
    ids = TestIds()
    workflow = ProductionDynamicWorkflow(
        work=work,
        controller=controller,
        setup=setup,
        docker=docker,
        sessions=ReproductionSessionManager(clock=clock, ids=ids),
        artifacts=artifacts,
        clock=clock,
        ids=ids,
        sink=cast(DynamicRecordSink, sink),
        authorization=authorizer.authorize,
    )

    session = await workflow.open_session(
        work=work,
        request=request,
        request_ref=request_ref,
        requirements=requirements,
        requirements_ref=cast(StoredDataRef, reference(requirements)),
        plan=plan,
        plan_ref=cast(StoredDataRef, reference(plan)),
    )
    workflow.finalize_failure(
        work=work,
        request=request,
        request_ref=request_ref,
        session=session,
        failure=DynamicWorkflowFailure(
            status="BLOCKED",
            failure_category="POLICY_BLOCKED",
            failure_reason="Sandbox boundary denied the request",
        ),
    )

    assert session.allowed is False
    assert docker.calls == []
    result = cast(DynamicReproductionResult, sink.finished[-1])
    assert result.status == "BLOCKED"
    assert result.failure_category == "POLICY_BLOCKED"
    assert result.hypothesis_outcome == "INCONCLUSIVE"
    assert result.agent_invoked is False
    assert result.poc_ref is None
    assert result.cleanup_required is False
    assert result.cleanup_status == "NOT_REQUIRED"
    assert not any(isinstance(item, EnvironmentRecipe) for item in sink.published)
    assert not any(isinstance(item, SandboxEnvironment) for item in sink.published)


@pytest.mark.asyncio
async def test_image_declared_volume_is_rejected_and_reclaimed(tmp_path: Path) -> None:
    """An inherited anonymous volume must never survive the rejected container."""

    await _require_docker()
    image_id: str | None = None
    container_id: str | None = None
    volume_name: str | None = None
    adapter = DockerAdapter()
    try:
        code, output, error = await _docker(
            "build",
            "--quiet",
            "--network",
            "none",
            "-",
            input_bytes=(
                b"FROM python:3.12-slim\nVOLUME /unapproved-volume\nUSER 65532:65532\n"
            ),
        )
        assert code == 0, error.decode(errors="replace")
        image_id = output.decode("ascii").strip().splitlines()[-1]
        spec = replace(_run_spec(tmp_path), image_digest=image_id)
        labels = {
            "sastsimi.owner": "reproduction-setup-automation",
            "sastsimi.analysis-id": "analysis-1",
            "sastsimi.workspace-id": "workspace-1",
            "sastsimi.commit-id": "commit-1",
            "sastsimi.hypothesis-id": "hypothesis-volume",
            "sastsimi.attempt-id": "dynamic-attempt-volume",
            "sastsimi.resource-kind": "container",
            "sastsimi.resource-id": "volume-boundary-e2e",
        }
        container_id = await adapter.create(spec, labels)
        inspect_code, inspect_output, inspect_error = await _docker(
            "inspect", container_id
        )
        assert inspect_code == 0, inspect_error.decode(errors="replace")
        mounts = json.loads(inspect_output)[0]["Mounts"]
        (volume,) = [
            mount for mount in mounts if mount["Destination"] == "/unapproved-volume"
        ]
        volume_name = volume["Name"]

        with pytest.raises(ValueError, match="DOCKER_MOUNT_BOUNDARY_INVALID"):
            await adapter.verify_created_mounts(container_id, spec)
        await adapter.remove((container_id,))

        removed_code, _, _ = await _docker("inspect", container_id)
        volume_code, _, _ = await _docker("volume", "inspect", volume_name)
        assert removed_code != 0
        assert volume_code != 0
        container_id = None
        volume_name = None
    finally:
        if container_id is not None:
            await _docker("rm", "--force", "--volumes", container_id)
        if volume_name is not None:
            await _docker("volume", "rm", volume_name)
        if image_id is not None:
            await _docker("image", "rm", image_id)
