import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, cast

import pytest

from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionCheck,
    ActionDecision,
    ActionRequest,
    ActionType,
    CheckResult,
    Decision,
    UseStatus,
)
from sastsimi.contracts.budget import DynamicReproductionLifecycleProfile
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    EnvironmentRecipe,
    ReproductionPlan,
    SandboxProfile,
)
from sastsimi.contracts.ids import DecisionId
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.sandbox.controller import (
    SandboxController,
    SandboxMount,
    SandboxRunSpec,
)
from sastsimi.sandbox.recipe_store import PreparedRecipeSource

NOW = datetime(2026, 9, 11, tzinfo=UTC)


def _meta(
    kind: str,
    name: str,
    *,
    hypothesis_id: str | None,
    attempt_id: str | None,
    revision_number: int = 1,
    previous_record_id: str | None = None,
) -> dict[str, Any]:
    return {
        "record_id": f"{name}-record-{revision_number}",
        "logical_record_id": f"{name}-logical",
        "record_type": kind,
        "schema_version": "1.0.0",
        "analysis_id": "analysis-1",
        "workspace_id": "workspace-1",
        "commit_id": "commit-1",
        "hypothesis_id": hypothesis_id,
        "attempt_id": attempt_id,
        "revision_number": revision_number,
        "previous_record_id": previous_record_id,
        "created_at": NOW.isoformat(),
    }


def _ref(kind: str, name: str) -> dict[str, Any]:
    return {
        "stored_data_id": f"{name}-stored",
        "data_kind": kind,
        "content_hash": "a" * 64,
        "workspace_id": "workspace-1",
        "commit_id": "commit-1",
        "record_id": f"{name}-record",
    }


def _wire[T](model: type[T], value: dict[str, Any]) -> T:
    return model.model_validate_json(json.dumps(value))  # type: ignore[attr-defined,no-any-return]


@dataclass(frozen=True)
class BoundaryContext:
    controller: SandboxController
    spec: SandboxRunSpec
    arguments: dict[str, object]
    other_workspace: Path
    records: dict[str, Any]


def _context(tmp_path: Path) -> BoundaryContext:
    runtime_root = tmp_path / "runtime-workspace"
    clone_root = runtime_root / "clone"
    other_workspace = tmp_path / "other-workspace"
    clone_root.mkdir(parents=True)
    other_workspace.mkdir()

    profile = _wire(
        SandboxProfile,
        {
            "meta": _meta(
                "sandbox_profile",
                "sandbox-profile",
                hypothesis_id=None,
                attempt_id=None,
            ),
            "network_mode": "DEFAULT_DENY",
            "allowed_egress_refs": [],
            "isolation_policy_refs": [],
            "cpu_limit_millicores": 1_000,
            "memory_limit_bytes": 512 * 1024 * 1024,
            "disk_limit_bytes": 1024 * 1024 * 1024,
            "pid_limit": 128,
            "max_requested_execution_ms": 30_000,
            "created_at": NOW.isoformat(),
        },
    )
    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)

    lifecycle = _wire(
        DynamicReproductionLifecycleProfile,
        {
            "meta": _meta(
                "dynamic_reproduction_lifecycle_profile",
                "lifecycle-profile",
                hypothesis_id=None,
                attempt_id=None,
            ),
            "profile_key": "dynamic-default",
            "preflight_budget_ref": _ref("budget_reservation", "preflight-budget"),
            "preflight_budget_source": "WORK_REMAINING_TIME",
            "max_new_attempts": 2,
            "status": "ACTIVE",
            "created_at": NOW.isoformat(),
        },
    )
    lifecycle_ref = reference(lifecycle)
    assert isinstance(lifecycle_ref, StoredDataRef)

    request = _wire(
        DynamicReproductionRequest,
        {
            "meta": _meta(
                "dynamic_reproduction_request",
                "dynamic-request",
                hypothesis_id="hypothesis-1",
                attempt_id="verification-attempt",
            ),
            "verification_assignment_ref": _ref(
                "verification_assignment", "verification-assignment"
            ),
            "verification_generation": 1,
            "hypothesis_ref": _ref("vulnerability_hypothesis", "hypothesis"),
            "purpose": "POC_CONFIRMATION",
            "initial_verdict": "TRUE",
            "goal": "Confirm the local vulnerability with a PoC.",
            "environment_needs": [],
            "sandbox_profile_ref": profile_ref.model_dump(mode="json"),
            "code_refs": [_ref("code_fragment", "code") | {"record_id": None}],
            "static_evidence_refs": [],
            "pro_evidence_ref": _ref("pro_evidence_result", "pro-evidence"),
            "con_evidence_ref": _ref("con_evidence_result", "con-evidence"),
            "created_at": NOW.isoformat(),
        },
    )
    request_ref = reference(request)
    assert isinstance(request_ref, StoredDataRef)
    requirements_ref = StoredDataRef.model_validate(
        _ref("environment_requirements", "requirements")
    )
    recipe_source_ref = StoredDataRef.model_validate(
        _ref("recipe_source", "recipe-source") | {"record_id": None}
    )

    plan = _wire(
        ReproductionPlan,
        {
            "meta": _meta(
                "reproduction_plan",
                "reproduction-plan",
                hypothesis_id="hypothesis-1",
                attempt_id="dynamic-attempt",
            ),
            "request_ref": request_ref.model_dump(mode="json"),
            "purpose": request.purpose,
            "hypothesis_ref": request.hypothesis_ref.model_dump(mode="json"),
            "environment_requirements_ref": requirements_ref.model_dump(mode="json"),
            "sandbox_profile_ref": profile_ref.model_dump(mode="json"),
            "reproduction_goal": "Exercise the local source-to-sink path.",
            "strategy_summary": "Run a local fixture and observe the sink.",
            "requested_evidence": [],
        },
    )
    plan_ref = reference(plan)
    assert isinstance(plan_ref, StoredDataRef)

    policy_state = _wire(
        RunPolicyState,
        {
            "meta": _meta(
                "run_policy_state",
                "run-policy",
                hypothesis_id=None,
                attempt_id=None,
            ),
            "program_id": "program-1",
            "status": "PREPARING",
            "preparation_source": None,
            "source_config_ref": _ref("policy_source_config", "policy-config"),
            "parser_name": "policy-parser",
            "parser_version": "1.0.0",
            "policy_work_ref": _ref("work_execution_state", "policy-work"),
            "policy_cache_ref": None,
            "collection_result_ref": None,
            "policy_record_ref": None,
            "freshness_criterion_ref": None,
            "freshness_checked_at": None,
            "freshness_evidence_refs": [],
            "freshness_valid_until": None,
        },
    )
    policy_state_ref = reference(policy_state)
    assert isinstance(policy_state_ref, StoredDataRef)

    image_digest = "sha256:" + "1" * 64
    recipe = _wire(
        EnvironmentRecipe,
        {
            "meta": _meta(
                "environment_recipe",
                "environment-recipe",
                hypothesis_id="hypothesis-1",
                attempt_id="dynamic-attempt",
            ),
            "request_ref": request_ref.model_dump(mode="json"),
            "environment_requirements_ref": requirements_ref.model_dump(mode="json"),
            "recipe_source_ref": recipe_source_ref.model_dump(mode="json"),
            "source_refs": [recipe_source_ref.model_dump(mode="json")],
            "base_image_digest": "scratch",
            "built_image_digest": image_digest,
            "baseline_recipe_ref": None,
            "build_disposition": "BUILT",
            "created_at": NOW.isoformat(),
        },
    )
    recipe_ref = reference(recipe)
    assert isinstance(recipe_ref, StoredDataRef)
    limits = {
        "cpu_limit_millicores": 500,
        "memory_limit_bytes": 256 * 1024 * 1024,
        "disk_limit_bytes": 512 * 1024 * 1024,
        "pid_limit": 64,
        "requested_execution_ms": 10_000,
    }
    action = _wire(
        ActionRequest,
        {
            "meta": _meta(
                "action_request",
                "sandbox-action",
                hypothesis_id="hypothesis-1",
                attempt_id="dynamic-attempt",
            ),
            "action_id": "sandbox-action-1",
            "requested_by": "REPRODUCTION_SETUP_AUTOMATION",
            "requester_identity_ref": _ref("identity", "setup-identity"),
            "action_type": "RUN_SANDBOX",
            "work_ref": _ref("work_execution_state", "dynamic-work"),
            "expected_state_version": 1,
            "expected_verification_generation": None,
            "generation_restart_reason": None,
            "generation_restart_basis_refs": [],
            "input_refs": [
                request_ref.model_dump(mode="json"),
                requirements_ref.model_dump(mode="json"),
                plan_ref.model_dump(mode="json"),
                profile_ref.model_dump(mode="json"),
                lifecycle_ref.model_dump(mode="json"),
                recipe_ref.model_dump(mode="json"),
            ],
            "dynamic_request_ref": request_ref.model_dump(mode="json"),
            "reproduction_plan_ref": plan_ref.model_dump(mode="json"),
            "result_kind": None,
            "candidate_result_ref": None,
            "llm_call_spec_ref": None,
            "tool_name": None,
            "file_paths": [],
            "provider_profile_ref": None,
            "session_mode": None,
            "sandbox_profile_ref": profile_ref.model_dump(mode="json"),
            "resource_profile_ref": lifecycle_ref.model_dump(mode="json"),
            "run_policy_state_ref": policy_state_ref.model_dump(mode="json"),
            "image_digest": image_digest,
            "network_targets": [],
            "resource_limits": limits,
            "reason": "Create an isolated local reproduction environment.",
            "requested_at": NOW.isoformat(),
        },
    )
    action_ref = reference(action)
    assert isinstance(action_ref, StoredDataRef)
    check_types = tuple(sorted(REQUIRED_CHECKS[ActionType.RUN_SANDBOX], key=str))
    decision = ActionDecision(
        meta=_wire(
            RecordMeta,
            _meta(
                "action_decision",
                "sandbox-decision",
                hypothesis_id="hypothesis-1",
                attempt_id="dynamic-attempt",
                revision_number=2,
                previous_record_id="sandbox-decision-record-1",
            ),
        ),
        decision_id=DecisionId(root="sandbox-decision-1"),
        action_ref=action_ref,
        decision=Decision.ALLOW,
        required_checks=check_types,
        check_results=tuple(
            ActionCheck(
                check_type=check_type,
                result=CheckResult.PASS,
                reason_code="OK",
                safe_message="Trusted runtime check passed.",
            )
            for check_type in check_types
        ),
        checked_state_version=1,
        checked_config_refs=(profile_ref, lifecycle_ref),
        valid_until=NOW + timedelta(minutes=1),
        error_ids=(),
        use_status=UseStatus.USED,
        used_at=NOW + timedelta(seconds=1),
        expired_at=None,
        expire_reason=None,
        outcome_refs=(),
        decided_at=NOW,
    )
    decision_ref = reference(decision)
    assert isinstance(decision_ref, StoredDataRef)

    records = {
        str(decision_ref.record_id): decision,
        str(policy_state_ref.record_id): policy_state,
    }

    def resolve_record(ref: StoredDataRef) -> object:
        return records[str(ref.record_id)]

    controller = SandboxController(
        workspace_root=runtime_root,
        workspace_id="workspace-1",
        commit_id="commit-1",
        record_resolver=resolve_record,
        isolated_network_targets=(),
    )
    spec = SandboxRunSpec(
        workspace_root=runtime_root,
        image_digest=image_digest,
        user="1000:1000",
        mounts=(
            SandboxMount(
                source=clone_root,
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
        cpu_limit_millicores=limits["cpu_limit_millicores"],
        memory_limit_bytes=limits["memory_limit_bytes"],
        disk_limit_bytes=limits["disk_limit_bytes"],
        pid_limit=limits["pid_limit"],
        requested_execution_ms=limits["requested_execution_ms"],
    )
    output_meta = _wire(
        RecordMeta,
        _meta(
            "sandbox_policy_decision",
            "boundary-decision",
            hypothesis_id="hypothesis-1",
            attempt_id="dynamic-attempt",
        ),
    )
    return BoundaryContext(
        controller=controller,
        spec=spec,
        arguments={
            "spec": spec,
            "recipe": recipe,
            "action": action,
            "action_decision_ref": decision_ref,
            "required_context_refs": (),
            "request": request,
            "plan": plan,
            "sandbox_profile": profile,
            "lifecycle_profile": lifecycle,
            "run_policy_state_ref": policy_state_ref,
            "meta": output_meta,
        },
        other_workspace=other_workspace,
        records=records,
    )


def _replace_action(
    context: BoundaryContext,
    *,
    input_refs: tuple[StoredDataRef, ...],
) -> dict[str, object]:
    current_action = context.arguments["action"]
    current_decision_ref = context.arguments["action_decision_ref"]
    assert isinstance(current_action, ActionRequest)
    assert isinstance(current_decision_ref, StoredDataRef)
    current_decision = context.records[str(current_decision_ref.record_id)]
    assert isinstance(current_decision, ActionDecision)
    action = current_action.model_copy(update={"input_refs": input_refs})
    decision = current_decision.model_copy(update={"action_ref": reference(action)})
    decision_ref = reference(decision)
    assert isinstance(decision_ref, StoredDataRef)
    context.records[str(decision_ref.record_id)] = decision
    return context.arguments | {
        "action": action,
        "action_decision_ref": decision_ref,
    }


def test_build_phase_binds_exact_source_before_docker_access(tmp_path: Path) -> None:
    context = _context(tmp_path)
    run_action = context.arguments["action"]
    run_recipe = context.arguments["recipe"]
    assert isinstance(run_action, ActionRequest)
    assert isinstance(run_recipe, EnvironmentRecipe)
    source_ref = run_recipe.recipe_source_ref
    dockerfile = b"FROM scratch\n"
    source = PreparedRecipeSource(
        workspace_root=context.spec.workspace_root,
        request_ref=run_recipe.request_ref,
        requirements_ref=run_recipe.environment_requirements_ref,
        meta=run_recipe.meta,
        recipe_source_ref=source_ref,
        source_refs=(source_ref,),
        source_digest=source_ref.content_hash,
        dockerfile=dockerfile,
        dockerfile_digest=hashlib.sha256(dockerfile).hexdigest(),
        base_image="scratch",
    )
    action_data = dict(run_action.__dict__)
    action_data.update(
        action_id="sandbox-build-action-1",
        input_refs=tuple(
            source_ref if ref.data_kind == "environment_recipe" else ref
            for ref in run_action.input_refs
        ),
        image_digest=None,
    )
    build_action = ActionRequest.model_validate(action_data)
    prior_decision_ref = context.arguments["action_decision_ref"]
    assert isinstance(prior_decision_ref, StoredDataRef)
    prior_decision = context.records[str(prior_decision_ref.record_id)]
    assert isinstance(prior_decision, ActionDecision)
    build_decision = prior_decision.model_copy(
        update={
            "action_ref": reference(build_action),
            "decision_id": DecisionId(root="sandbox-build-decision-1"),
        }
    )
    build_decision_ref = reference(build_decision)
    assert isinstance(build_decision_ref, StoredDataRef)
    context.records[str(build_decision_ref.record_id)] = build_decision
    arguments = context.arguments | {
        "spec": replace(context.spec, image_digest=None),
        "source": source,
        "action": build_action,
        "action_decision_ref": build_decision_ref,
    }
    arguments.pop("recipe")

    outcome = context.controller.evaluate_build(**arguments)  # type: ignore[arg-type]

    assert outcome.decision.decision == "ALLOW", outcome.decision.reason_codes
    assert outcome.approved_source == source
    assert outcome.approved_spec is not None
    assert outcome.approved_spec.image_digest is None


def _forbidden_spec(context: BoundaryContext, case: str) -> SandboxRunSpec:
    spec = context.spec
    mount = spec.mounts[0]
    assert mount.source is not None
    if case == "HOST_ROOT_MOUNT":
        return replace(spec, mounts=(replace(mount, source=Path(mount.source.anchor)),))
    if case == "DOCKER_SOCKET":
        return replace(
            spec,
            mounts=(replace(mount, target=PurePosixPath("/var/run/docker.sock")),),
        )
    if case == "WINDOWS_DOCKER_PIPE":
        return replace(
            spec,
            mounts=(replace(mount, source=Path(r"\\.\pipe\docker_engine")),),
        )
    if case == "WRITE_MOUNT":
        return replace(spec, mounts=(replace(mount, read_only=False),))
    if case == "OTHER_WORKSPACE":
        return replace(spec, mounts=(replace(mount, source=context.other_workspace),))
    if case == "HOST_PID_NAMESPACE":
        return replace(spec, pid_mode="host")
    if case == "HOST_IPC_NAMESPACE":
        return replace(spec, ipc_mode="host")
    if case == "ROOT_USER":
        return replace(spec, user="0")
    if case == "PRIVILEGED":
        return replace(spec, privileged=True)
    if case == "CAPABILITY_ADD":
        return replace(spec, capabilities=("SYS_ADMIN",))
    if case == "RAW_SECRET":
        return replace(spec, secret_refs=("api_key=not-allowed",))  # type: ignore[arg-type]
    if case == "SECRET_HANDLE":
        return replace(
            spec,
            secret_refs=(
                StoredDataRef.model_validate(_ref("secret_handle", "secret")),
            ),
        )
    if case == "EGRESS":
        return replace(spec, network_targets=("pypi.org:443",))
    if case == "LIVE_ENDPOINT":
        return replace(spec, network_targets=("https://target.example/api",))
    if case == "RESOURCE_LIMIT":
        return replace(spec, memory_limit_bytes=1024 * 1024 * 1024)
    if case == "ACTION_SPEC_DRIFT":
        return replace(spec, image_digest="sha256:" + "2" * 64)
    raise AssertionError(case)


def test_baked_repository_source_uses_no_host_mount(tmp_path: Path) -> None:
    context = _context(tmp_path)
    spec = replace(context.spec, mounts=(), source_baked=True)

    outcome = context.controller.evaluate(**(context.arguments | {"spec": spec}))

    assert outcome.decision.decision == "ALLOW", outcome.decision.reason_codes


def test_baked_repository_source_rejects_even_workspace_mount(tmp_path: Path) -> None:
    context = _context(tmp_path)
    spec = replace(context.spec, source_baked=True)

    outcome = context.controller.evaluate(**(context.arguments | {"spec": spec}))

    assert outcome.decision.decision == "DENY"
    assert "HOST_MOUNT_DENIED" in outcome.decision.reason_codes


@pytest.mark.parametrize(
    ("case", "reason_code"),
    [
        ("HOST_ROOT_MOUNT", "HOST_ROOT_MOUNT_DENIED"),
        ("DOCKER_SOCKET", "DOCKER_SOCKET_DENIED"),
        ("WINDOWS_DOCKER_PIPE", "DOCKER_SOCKET_DENIED"),
        ("WRITE_MOUNT", "WRITE_MOUNT_DENIED"),
        ("OTHER_WORKSPACE", "WORKSPACE_MOUNT_DENIED"),
        ("HOST_PID_NAMESPACE", "HOST_NAMESPACE_DENIED"),
        ("HOST_IPC_NAMESPACE", "HOST_NAMESPACE_DENIED"),
        ("ROOT_USER", "NON_ROOT_USER_REQUIRED"),
        ("PRIVILEGED", "PRIVILEGED_DENIED"),
        ("CAPABILITY_ADD", "CAPABILITY_ADD_DENIED"),
        ("RAW_SECRET", "RAW_SECRET_DENIED"),
        ("SECRET_HANDLE", "SANDBOX_SECRET_DENIED"),
        ("EGRESS", "EGRESS_DENIED"),
        ("LIVE_ENDPOINT", "LIVE_ENDPOINT_DENIED"),
        ("RESOURCE_LIMIT", "RESOURCE_LIMIT_EXCEEDED"),
        ("ACTION_SPEC_DRIFT", "ACTION_SPEC_MISMATCH"),
    ],
)
def test_forbidden_boundary_is_denied_before_adapter(
    tmp_path: Path, case: str, reason_code: str
) -> None:
    context = _context(tmp_path)
    arguments = context.arguments | {"spec": _forbidden_spec(context, case)}

    outcome = context.controller.evaluate(**arguments)  # type: ignore[arg-type]

    assert outcome.decision.decision == "DENY"
    assert outcome.approved_spec is None
    assert outcome.decision.execution_scope == "LOCAL_ONLY"
    assert reason_code in outcome.decision.reason_codes


def test_local_non_root_default_deny_spec_is_approved(tmp_path: Path) -> None:
    context = _context(tmp_path)

    outcome = context.controller.evaluate(**context.arguments)  # type: ignore[arg-type]

    assert outcome.decision.decision == "ALLOW", outcome.decision.reason_codes
    assert outcome.decision.reason_codes == ("LOCAL_BOUNDARY_OK",)
    assert outcome.approved_spec == context.spec
    assert outcome.approved_spec.network_mode == "DEFAULT_DENY"
    assert outcome.approved_spec.user not in {"0", "root"}
    assert outcome.approved_spec.privileged is False


def test_exact_plan_environment_requirements_must_be_in_action_inputs(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    action = context.arguments["action"]
    plan = context.arguments["plan"]
    assert isinstance(action, ActionRequest)
    assert isinstance(plan, ReproductionPlan)
    input_refs = tuple(cast(StoredDataRef, ref) for ref in action.input_refs)
    wrong_requirements_ref = plan.environment_requirements_ref.model_copy(
        update={
            "stored_data_id": "wrong-requirements-stored",
            "content_hash": "b" * 64,
            "record_id": "wrong-requirements-record",
        }
    )
    arguments = _replace_action(
        context,
        input_refs=tuple(
            wrong_requirements_ref if ref == plan.environment_requirements_ref else ref
            for ref in input_refs
        ),
    )

    outcome = context.controller.evaluate(**arguments)  # type: ignore[arg-type]

    assert outcome.decision.decision == "DENY"
    assert "STALE_RESULT" in outcome.decision.reason_codes


@pytest.mark.parametrize("context_ref_count", [0, 2])
def test_required_phase_context_must_appear_exactly_once(
    tmp_path: Path,
    context_ref_count: int,
) -> None:
    context = _context(tmp_path)
    action = context.arguments["action"]
    assert isinstance(action, ActionRequest)
    input_refs = tuple(cast(StoredDataRef, ref) for ref in action.input_refs)
    context_ref = StoredDataRef.model_validate(
        _ref("sandbox_policy_decision", "build-policy")
    )
    arguments = _replace_action(
        context,
        input_refs=(*input_refs, *((context_ref,) * context_ref_count)),
    ) | {"required_context_refs": (context_ref,)}

    outcome = context.controller.evaluate(**arguments)  # type: ignore[arg-type]

    assert outcome.decision.decision == "DENY"
    assert "STALE_RESULT" in outcome.decision.reason_codes


def test_required_phase_context_is_recorded_as_checked_boundary(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    action = context.arguments["action"]
    assert isinstance(action, ActionRequest)
    input_refs = tuple(cast(StoredDataRef, ref) for ref in action.input_refs)
    context_refs = (
        StoredDataRef.model_validate(_ref("sandbox_policy_decision", "build-policy")),
        StoredDataRef.model_validate(_ref("action_decision", "build-decision")),
    )
    arguments = _replace_action(
        context,
        input_refs=(*input_refs, *context_refs),
    ) | {"required_context_refs": context_refs}

    outcome = context.controller.evaluate(**arguments)  # type: ignore[arg-type]

    assert outcome.decision.decision == "ALLOW", outcome.decision.reason_codes
    assert all(ref in outcome.decision.checked_boundary_refs for ref in context_refs)
