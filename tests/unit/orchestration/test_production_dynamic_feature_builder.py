from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from sastsimi.composition.production_dynamic_feature_builder import (
    DockerCapabilityReadiness,
    ProductionDynamicAuthorizationResolver,
    build_current_repository_t11_resolver,
    build_production_dynamic_feature,
)
from sastsimi.composition.production_feature_installer import DynamicProductionFeature
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    BudgetReservation,
    BudgetUnits,
    DynamicReproductionLifecycleProfile,
)
from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    EnvironmentRequirements,
    ReproductionPlan,
    SandboxProfile,
)
from sastsimi.contracts.ids import (
    AnalysisId,
    AttemptId,
    CommitId,
    HypothesisId,
    LogicalRecordId,
    RecordId,
    ReservationId,
    StoredDataId,
    WorkId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef, reference
from sastsimi.contracts.static import RepositoryProfile
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.production_context import ProductionCapabilityUnavailable
from sastsimi.orchestration.production_provisioning import (
    MaterializedProvisioningArtifacts,
    ResolvedProductionProvisioning,
    SandboxProfileProvisioning,
)
from sastsimi.ports.dynamic_sandbox import TrustedDockerTarget
from sastsimi.reproduction.service import DynamicOperationalError

NOW = datetime(2026, 9, 13, tzinfo=UTC)
ANALYSIS = AnalysisId("analysis")
WORKSPACE = WorkspaceId("workspace")
COMMIT = CommitId("c" * 40)
ATTEMPT = AttemptId("attempt")


def _meta(kind: str, record_id: str, *, attempt: bool = False) -> RecordMeta:
    return RecordMeta(
        record_id=RecordId(record_id),
        logical_record_id=LogicalRecordId(record_id),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=NOW,
        analysis_id=ANALYSIS,
        workspace_id=WORKSPACE,
        commit_id=COMMIT,
        hypothesis_id=HypothesisId("hypothesis") if attempt else None,
        attempt_id=ATTEMPT if attempt else None,
    )


def _artifact(kind: str, value: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(value),
        data_kind=kind,
        content_hash="a" * 64,
        workspace_id=WORKSPACE,
        commit_id=COMMIT,
        record_id=RecordId(value),
    )


def _host_artifact(kind: str, value: str) -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId(value),
        data_kind=kind,
        content_hash="b" * 64,
        host_id="host",
        publication_analysis_id=ANALYSIS,
        publication_workspace_id=WORKSPACE,
        publication_commit_id=COMMIT,
        record_id=RecordId(value),
    )


def _sandbox() -> SandboxProfile:
    return SandboxProfile(
        meta=_meta(SandboxProfile.KIND, "sandbox"),
        network_mode="DEFAULT_DENY",
        allowed_egress_refs=(),
        isolation_policy_refs=(_artifact("artifact", "isolation-policy"),),
        cpu_limit_millicores=1000,
        memory_limit_bytes=512 * 1024 * 1024,
        disk_limit_bytes=1024 * 1024 * 1024,
        pid_limit=128,
        max_requested_execution_ms=60_000,
        created_at=NOW,
    )


def _docker(path: Path) -> RuntimeCapabilityProfile:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return RuntimeCapabilityProfile.model_construct(
        meta=_meta(RuntimeCapabilityProfile.KIND, "docker-profile"),
        host_id="host",
        profile_key="docker-production",
        purpose="PRODUCTION",
        status="ACTIVE",
        capability_kind="DOCKER",
        subject_key="docker",
        expected_version="1",
        subject_sha256=digest,
        operating_system="windows",
        architecture="x86_64",
        languages=("ANY",),
        operations=("IMAGE_BUILD", "CONTAINER_RUN", "HEALTH_CHECK", "CLEANUP"),
        capability_evidence_ref=_host_artifact(
            "tool_capability_evidence", "docker-evidence"
        ),
    )


class _DockerTargetResolver:
    def __init__(self, profile: RuntimeCapabilityProfile, executable: Path) -> None:
        profile_ref = reference(profile)
        assert isinstance(profile_ref, HostConfigurationRef)
        self.profile = profile
        self.target = TrustedDockerTarget(
            profile_ref=profile_ref,
            executable=executable.resolve(),
            subject_key=str(profile.subject_key),
            subject_sha256=str(profile.subject_sha256),
            daemon_target="npipe:////./pipe/docker_engine",
            build_backend="LEGACY_LIMITED",
            enforced_build_limits=frozenset({"CPU", "MEMORY", "PID", "DISK"}),
            external_build_disk_limit_bytes=1024 * 1024 * 1024,
        )
        self.calls: list[str] = []

    def resolve_current(self, profile_ref: HostConfigurationRef) -> TrustedDockerTarget:
        self.calls.append("resolve_current")
        if profile_ref != self.target.profile_ref:
            raise ValueError("PRODUCTION_DOCKER_CAPABILITY_STALE")
        return self.target

    def require_current(self, target: TrustedDockerTarget) -> None:
        self.calls.append("require_current")
        if (
            target != self.target
            or not target.executable.is_file()
            or hashlib.sha256(target.executable.read_bytes()).hexdigest()
            != target.subject_sha256
        ):
            raise ValueError("PRODUCTION_DOCKER_CAPABILITY_STALE")


def _provisioning(sandbox: SandboxProfile, policy: bytes) -> SandboxProfileProvisioning:
    sandbox_ref = cast(StoredDataRef, reference(sandbox))
    digest = hashlib.sha256(policy).hexdigest()
    return SandboxProfileProvisioning(
        schema_version=1,
        slot="SANDBOX_PROFILE",
        profile_hash="f" * 64,
        analysis_id=str(ANALYSIS),
        workspace_id=str(WORKSPACE),
        commit_id=str(COMMIT),
        record_refs=(sandbox_ref,),
        evidence_sha256=(digest,),
        container_user="65532:65532",
        max_execute_turns=8,
        resource_journal_relative="sandbox/resource-journal.json",
        authorization_policy_sha256=digest,
        authorization_implementation_key="RUNTIME_DYNAMIC_AUTHORIZATION_V1",
        setup_implementation_key="DOCKER_REPRODUCTION_SETUP_V1",
    )


def _dynamic_records(
    sandbox_ref: StoredDataRef,
) -> tuple[DynamicReproductionRequest, EnvironmentRequirements, ReproductionPlan]:
    request = DynamicReproductionRequest(
        meta=_meta(DynamicReproductionRequest.KIND, "request", attempt=True),
        verification_assignment_ref=_artifact(
            "verification_assignment", "verification-assignment"
        ),
        verification_generation=1,
        hypothesis_ref=_artifact("vulnerability_hypothesis", "hypothesis"),
        purpose="POC_CONFIRMATION",
        initial_verdict="TRUE",
        goal="Confirm the exact hypothesis",
        environment_needs=(),
        sandbox_profile_ref=sandbox_ref,
        code_refs=(),
        static_evidence_refs=(),
        pro_evidence_ref=_artifact("pro_evidence_result", "pro"),
        con_evidence_ref=_artifact("con_evidence_result", "con"),
        created_at=NOW,
    )
    request_ref = cast(StoredDataRef, reference(request))
    requirements = EnvironmentRequirements(
        meta=_meta(EnvironmentRequirements.KIND, "requirements", attempt=True),
        request_ref=request_ref,
        items=(),
    )
    requirements_ref = cast(StoredDataRef, reference(requirements))
    plan = ReproductionPlan(
        meta=_meta(ReproductionPlan.KIND, "plan", attempt=True),
        request_ref=request_ref,
        purpose="POC_CONFIRMATION",
        hypothesis_ref=request.hypothesis_ref,
        environment_requirements_ref=requirements_ref,
        sandbox_profile_ref=sandbox_ref,
        reproduction_goal="Confirm the exact hypothesis",
        strategy_summary="Use the approved isolated Sandbox",
        requested_evidence=(),
    )
    return request, requirements, plan


def test_builder_pins_exact_sandbox_docker_and_t11_settings() -> None:
    data_dir = Path.cwd()
    binary_dir = data_dir / ".r7-approved-bin"
    binary_dir.mkdir(exist_ok=True)
    executable = binary_dir / "docker.exe"
    executable.write_bytes(b"approved docker binary")
    sandbox = _sandbox()
    policy = b"approved compiled boundary policy"
    document = _provisioning(sandbox, policy)
    docker = _docker(executable)
    docker_targets = _DockerTargetResolver(docker, executable)
    resolved = ResolvedProductionProvisioning(
        capabilities={"DOCKER": docker}, artifacts={}
    )
    materialized = MaterializedProvisioningArtifacts(
        documents={"SANDBOX_PROFILE": document},
        records={cast(StoredDataRef, reference(sandbox)): sandbox},
        evidence={document.authorization_policy_sha256: policy},
    )
    record_store = SimpleNamespace(
        get_exact=lambda ref: sandbox if ref == reference(sandbox) else None
    )
    queries = SimpleNamespace(current_records=lambda _analysis, _kind: (sandbox,))
    context = SimpleNamespace(
        data_dir=data_dir,
        scope=SimpleNamespace(
            analysis_id=ANALYSIS, workspace_id=WORKSPACE, commit_id=COMMIT
        ),
        runtime=SimpleNamespace(
            unit_of_work=SimpleNamespace(records=record_store),
            queries=queries,
            budget_registry=SimpleNamespace(current_state=lambda _analysis: None),
            validator=cast(Any, object()),
        ),
        runner=SimpleNamespace(),
        role_identity_refs={RequesterRole.REPRODUCTION_SETUP_AUTOMATION: object()},
    )

    built = build_production_dynamic_feature(
        context=cast(Any, context),
        resolved=resolved,
        materialized=materialized,
        workspace_root_for=lambda _work: data_dir,
        docker_target_resolver=docker_targets,
    )

    assert built.feature.docker_profile_ref == reference(docker)
    assert built.feature.docker_target_resolver is docker_targets
    assert built.feature.max_execute_turns == 8
    assert (
        built.feature.resource_journal_path
        == (data_dir / "sandbox" / str(ANALYSIS) / "resource-journal.json").resolve()
    )
    assert built.readiness_checks == ()
    assert docker_targets.calls == []
    built.docker_readiness()
    assert docker_targets.calls == ["resolve_current", "require_current"]
    executable.unlink()
    binary_dir.rmdir()


def test_builder_rejects_changed_docker_binary_and_unapproved_egress() -> None:
    data_dir = Path.cwd()
    binary_dir = data_dir / ".r7-changed-bin"
    binary_dir.mkdir(exist_ok=True)
    executable = binary_dir / "docker.exe"
    executable.write_bytes(b"approved")
    docker = _docker(executable)
    executable.write_bytes(b"changed")

    docker_targets = _DockerTargetResolver(docker, executable)
    with pytest.raises(ValueError, match="PRODUCTION_DOCKER_CAPABILITY_STALE"):
        DockerCapabilityReadiness(
            cast(HostConfigurationRef, reference(docker)), docker_targets
        )()

    sandbox = _sandbox().model_copy(
        update={"allowed_egress_refs": (_artifact("artifact", "egress"),)}
    )
    policy = b"approved compiled boundary policy"
    document = _provisioning(sandbox, policy)
    materialized = MaterializedProvisioningArtifacts(
        documents={"SANDBOX_PROFILE": document},
        records={cast(StoredDataRef, reference(sandbox)): sandbox},
        evidence={document.authorization_policy_sha256: policy},
    )
    record_store = SimpleNamespace(
        get_exact=lambda ref: sandbox if ref == reference(sandbox) else None
    )
    queries = SimpleNamespace(current_records=lambda _analysis, _kind: (sandbox,))
    context = SimpleNamespace(
        data_dir=data_dir,
        scope=SimpleNamespace(
            analysis_id=ANALYSIS, workspace_id=WORKSPACE, commit_id=COMMIT
        ),
        runtime=SimpleNamespace(
            unit_of_work=SimpleNamespace(records=record_store),
            queries=queries,
            budget_registry=SimpleNamespace(current_state=lambda _analysis: None),
            validator=cast(Any, object()),
        ),
        runner=SimpleNamespace(),
        role_identity_refs={RequesterRole.REPRODUCTION_SETUP_AUTOMATION: object()},
    )

    with pytest.raises(ValueError, match="PRODUCTION_SANDBOX_EGRESS_UNRESOLVED"):
        build_production_dynamic_feature(
            context=cast(Any, context),
            resolved=ResolvedProductionProvisioning(
                capabilities={
                    "DOCKER": docker.model_copy(
                        update={
                            "subject_sha256": hashlib.sha256(
                                executable.read_bytes()
                            ).hexdigest()
                        }
                    )
                },
                artifacts={},
            ),
            materialized=materialized,
            workspace_root_for=lambda _work: data_dir,
            docker_target_resolver=_DockerTargetResolver(
                docker.model_copy(
                    update={
                        "subject_sha256": hashlib.sha256(
                            executable.read_bytes()
                        ).hexdigest()
                    }
                ),
                executable,
            ),
        )
    executable.unlink()
    binary_dir.rmdir()


def test_dynamic_authorization_blocks_when_docker_is_unavailable() -> None:
    def unavailable() -> None:
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_DOCKER_EXECUTABLE_UNAVAILABLE"
        )

    resolver = ProductionDynamicAuthorizationResolver(
        runner=cast(Any, object()),
        records=cast(Any, object()),
        queries=cast(Any, object()),
        current_run=cast(Any, object()),
        setup_identity=cast(Any, object()),
        sandbox_profile=cast(Any, object()),
        container_user="65532:65532",
        workspace_root_for=cast(Any, object()),
        docker_readiness=unavailable,
        authorization=cast(Any, object()),
    )

    with pytest.raises(DynamicOperationalError) as captured:
        resolver(
            cast(Any, object()),
            cast(Any, object()),
            cast(Any, object()),
            cast(Any, object()),
            "BUILD",
            cast(Any, object()),
            None,
            (),
        )

    assert captured.value.failure.status == "BLOCKED"
    assert captured.value.failure.failure_category == "EXTERNAL_CONFIGURATION"
    assert (
        captured.value.failure.hypothesis_outcome == "INCONCLUSIVE"
        and captured.value.failure.poc_ref is None
    )


def test_authorization_resolver_builds_baked_source_default_deny_spec() -> None:
    sandbox = _sandbox()
    sandbox_ref = cast(StoredDataRef, reference(sandbox))
    lifecycle = DynamicReproductionLifecycleProfile.model_construct(
        meta=_meta("dynamic_reproduction_lifecycle_profile", "lifecycle"),
        profile_key="dynamic",
        preflight_budget_ref=_artifact("artifact", "budget"),
        preflight_budget_source="WORK_REMAINING_TIME",
        max_new_attempts=2,
        status="ACTIVE",
        created_at=NOW,
    )
    lifecycle_ref = cast(StoredDataRef, reference(lifecycle))
    binding = BudgetProfileBinding.model_construct(
        dynamic_lifecycle_profile_ref=lifecycle_ref,
    )
    binding_ref = _artifact("budget_profile_binding", "binding")
    policy_ref = _artifact("run_policy_state", "policy")
    request, requirements, plan = _dynamic_records(sandbox_ref)
    request_ref = cast(StoredDataRef, reference(request))
    requirements_ref = cast(StoredDataRef, reference(requirements))
    plan_ref = cast(StoredDataRef, reference(plan))
    phase_ref = _artifact("recipe_source", "recipe-source")
    work = WorkExecutionState.model_construct(
        meta=_meta("work_execution_state", "work", attempt=True),
        work_id=WorkId("work"),
        active_attempt_id=ATTEMPT,
        state_version=2,
        input_refs=(request_ref,),
    )
    action = SimpleNamespace()
    reservation = SimpleNamespace()
    reservation_record = BudgetReservation.model_construct(
        meta=_meta("budget_reservation", "reservation", attempt=True),
        reservation_id=ReservationId("reservation"),
        budget_binding_ref=binding_ref,
        action_ref=_artifact("action_request", "sandbox-action"),
        work_ref=_artifact("work_execution_state", "work"),
        requested_units=BudgetUnits(
            elapsed_ms=sandbox.max_requested_execution_ms,
            work_count=0,
            llm_call_count=0,
            retry_count=0,
            cost_minor_units=0,
            currency="USD",
        ),
        status="RESERVED",
        ledger_entry_ref=None,
        reserved_at=NOW,
        finalized_at=None,
    )

    def capture_action(
        _work: object,
        _identity: object,
        _role: object,
        _kind: object,
        **fields: object,
    ) -> object:
        action.fields = fields
        return SimpleNamespace()

    def capture_reservation(
        _work: object, _scope: object, _action: object, units: object
    ) -> BudgetReservation:
        reservation.units = units
        return reservation_record

    runner = SimpleNamespace(
        units=lambda **values: values,
        action=capture_action,
        reserve=capture_reservation,
        authorize=lambda _work, _action, _reservation: _artifact(
            "action_decision", "decision"
        ),
    )
    records = {
        sandbox_ref: sandbox,
        lifecycle_ref: lifecycle,
        binding_ref: binding,
    }
    resolver = ProductionDynamicAuthorizationResolver(
        runner=cast(Any, runner),
        records=cast(Any, SimpleNamespace(get_exact=records.__getitem__)),
        queries=cast(
            Any,
            SimpleNamespace(
                current_records=lambda _analysis, kind: (
                    (sandbox,) if kind == SandboxProfile.KIND else ()
                )
            ),
        ),
        current_run=lambda _analysis: SimpleNamespace(
            budget_binding_ref=binding_ref, run_policy_state_ref=policy_ref
        ),
        setup_identity=cast(Any, object()),
        sandbox_profile=sandbox,
        container_user="65532:65532",
        workspace_root_for=lambda _work: Path.cwd(),
        docker_readiness=lambda: None,
        authorization=cast(
            Any,
            SimpleNamespace(
                claim_external=lambda _work, _decision, _reservation: _artifact(
                    "action_decision", "claimed-decision"
                )
            ),
        ),
    )

    authorization = resolver(
        work,
        request,
        requirements,
        plan,
        "BUILD",
        phase_ref,
        None,
        (),
    )

    assert authorization.run_spec.source_baked is True
    assert authorization.run_spec.mounts == ()
    assert authorization.run_spec.network_targets == ()
    assert authorization.run_spec.secret_refs == ()
    assert authorization.run_spec.privileged is False
    assert authorization.run_spec.user == "65532:65532"
    assert action.fields["input_refs"] == (
        request_ref,
        requirements_ref,
        plan_ref,
        sandbox_ref,
        lifecycle_ref,
        phase_ref,
    )
    assert reservation.units == {"elapsed_ms": 1, "cost_minor_units": 1}
    assert authorization.action_decision_ref.data_kind == "action_decision"


def test_current_repository_resolver_builds_real_t11_with_exact_feature() -> None:
    root = Path.cwd().resolve()
    profile = RepositoryProfile.model_construct(
        meta=_meta(RepositoryProfile.KIND, "repository-profile"),
    )
    feature = DynamicProductionFeature(
        sandbox_authorization=cast(Any, object()),
        sandbox_profile=cast(Any, object()),
        max_execute_turns=8,
        resource_journal_path=root / "journal.json",
        docker_profile_ref=cast(Any, object()),
        docker_target_resolver=cast(Any, object()),
        docker=cast(Any, object()),
    )
    context = SimpleNamespace(
        runtime=SimpleNamespace(
            unit_of_work=SimpleNamespace(records=cast(Any, object())),
            queries=cast(Any, object()),
        ),
        runner=cast(Any, object()),
        clock=cast(Any, object()),
        ids=cast(Any, object()),
        scope=SimpleNamespace(workspace_id=WORKSPACE, commit_id=COMMIT),
        role_identity_refs=cast(Any, object()),
    )
    expected = cast(Any, object())
    calls = cast(Any, object())

    with patch(
        "sastsimi.composition.production_dynamic_feature_builder.build_t11_services",
        return_value=expected,
    ) as build:
        resolver = build_current_repository_t11_resolver(
            context=cast(Any, context),
            feature=feature,
            workspace_for=cast(Any, object()),
            workspace_locator=cast(Any, object()),
            verification=cast(Any, object()),
            calls=calls,
        )
        assert resolver.build(profile, root) is expected

    build.assert_called_once()
    called = build.call_args.kwargs
    assert called["repository_profile"] is profile
    assert called["workspace_root"] == root
    assert called["sandbox_authorization"] is feature.sandbox_authorization
    assert called["dynamic_calls"] is calls
    assert called["max_execute_turns"] == 8
    assert called["resource_journal_path"] == feature.resource_journal_path
    assert called["docker_profile_ref"] is feature.docker_profile_ref
    assert called["docker_target_resolver"] is feature.docker_target_resolver
