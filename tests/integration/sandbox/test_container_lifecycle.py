from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest

from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    EnvironmentRequirements,
    ReproductionPlan,
    SandboxPolicyDecision,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.sandbox.cleanup import OwnedResourceRegistry
from sastsimi.sandbox.controller import (
    SandboxBoundaryOutcome,
    SandboxMount,
    SandboxRunSpec,
)
from sastsimi.sandbox.docker_adapter import (
    DockerAdapter,
    DockerCommandOutcome,
    DockerContainerState,
    DockerOperationError,
)
from sastsimi.sandbox.health_check import SandboxHealthChecker
from sastsimi.sandbox.recipe_store import EnvironmentRecipeStore
from sastsimi.sandbox.setup_automation import ReproductionSetupAutomation

NOW = datetime(2026, 9, 11, tzinfo=UTC)
IMAGE_DIGEST = "sha256:" + "1" * 64


def _meta(
    kind: str,
    record_id: str,
    *,
    attempt_id: str = "dynamic-attempt-1",
    hypothesis_id: str = "hypothesis-1",
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
            "analysis_id": "analysis-1",
            "workspace_id": "workspace-1",
            "commit_id": "commit-1",
            "hypothesis_id": hypothesis_id,
            "attempt_id": attempt_id,
        }
    )


def _ref(kind: str, name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=name,
        data_kind=kind,
        content_hash="a" * 64,
        workspace_id="workspace-1",
        commit_id="commit-1",
        record_id=name,
    )


def _dynamic_records() -> tuple[
    DynamicReproductionRequest,
    EnvironmentRequirements,
    ReproductionPlan,
]:
    profile_ref = _ref("sandbox_profile", "sandbox-profile")
    request = DynamicReproductionRequest(
        meta=_meta(
            "dynamic_reproduction_request",
            "dynamic-request",
            attempt_id="verification-attempt",
        ),
        verification_assignment_ref=_ref(
            "verification_assignment", "verification-assignment"
        ),
        verification_generation=1,
        hypothesis_ref=_ref("vulnerability_hypothesis", "hypothesis-record"),
        purpose="POC_CONFIRMATION",
        initial_verdict="TRUE",
        goal="Confirm the local fixture",
        environment_needs=(),
        sandbox_profile_ref=profile_ref,
        code_refs=(),
        static_evidence_refs=(),
        pro_evidence_ref=_ref("pro_evidence_result", "pro"),
        con_evidence_ref=_ref("con_evidence_result", "con"),
        created_at=NOW,
    )
    request_ref = reference(request)
    assert isinstance(request_ref, StoredDataRef)

    requirements = EnvironmentRequirements(
        meta=_meta("environment_requirements", "requirements"),
        request_ref=request_ref,
        items=(),
    )
    requirements_ref = reference(requirements)
    assert isinstance(requirements_ref, StoredDataRef)
    plan = ReproductionPlan(
        meta=_meta("reproduction_plan", "plan"),
        request_ref=request_ref,
        purpose=request.purpose,
        hypothesis_ref=request.hypothesis_ref,
        environment_requirements_ref=requirements_ref,
        sandbox_profile_ref=request.sandbox_profile_ref,
        reproduction_goal="Confirm the local fixture",
        strategy_summary="Run the candidate in an isolated container",
        requested_evidence=(),
    )
    return request, requirements, plan


def _approval(
    workspace: Path,
    request: DynamicReproductionRequest,
) -> SandboxBoundaryOutcome:
    policy = SandboxPolicyDecision(
        meta=_meta("sandbox_policy_decision", "policy-decision"),
        request_ref=reference(request),
        action_decision_ref=_ref("action_decision", "action-decision"),
        sandbox_profile_ref=request.sandbox_profile_ref,
        resource_profile_ref=_ref(
            "dynamic_reproduction_lifecycle_profile", "lifecycle-profile"
        ),
        run_policy_state_ref=_ref("run_policy_state", "run-policy"),
        policy_collection_result_ref=None,
        policy_record_ref=None,
        execution_scope="LOCAL_ONLY",
        observed_policy_status="UNVERIFIED",
        decision="ALLOW",
        reason_codes=("LOCAL_BOUNDARY_OK",),
        checked_boundary_refs=(),
        decided_at=NOW,
    )
    return SandboxBoundaryOutcome(
        decision=policy,
        approved_spec=SandboxRunSpec(
            workspace_root=workspace,
            image_digest=IMAGE_DIGEST,
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
            requested_execution_ms=10_000,
        ),
    )


class FakeDockerAdapter:
    def __init__(self) -> None:
        self.created: dict[str, tuple[SandboxRunSpec, Mapping[str, str]]] = {}
        self.removed: list[str] = []
        self.unhealthy: set[str] = set()
        self.inspect_label_overrides: dict[str, Mapping[str, str]] = {}
        self._index = 0

    async def build(self, recipe_source: Path, labels: Mapping[str, str]) -> str:
        assert recipe_source.is_dir()
        assert labels["sastsimi.owner"] == "reproduction-setup-automation"
        return IMAGE_DIGEST

    async def create(self, spec: SandboxRunSpec, labels: Mapping[str, str]) -> str:
        self._index += 1
        container_id = f"owned-container-{self._index}"
        self.created[container_id] = (spec, dict(labels))
        return container_id

    async def start(self, container_id: str) -> None:
        assert container_id in self.created

    async def exec(
        self,
        container_id: str,
        argv: tuple[str, ...],
        timeout_ms: int,
        *,
        working_directory: str,
    ) -> DockerCommandOutcome:
        assert container_id in self.created
        assert working_directory == "/workspace"
        return DockerCommandOutcome(0, b"", b"", False)

    async def inspect(self, container_id: str) -> DockerContainerState:
        spec, labels = self.created[container_id]
        inspected_labels = dict(labels)
        inspected_labels.update(self.inspect_label_overrides.get(container_id, {}))
        return DockerContainerState(
            container_id=container_id,
            image_digest=spec.image_digest,
            user=spec.user,
            network_mode="none",
            privileged=False,
            read_only_rootfs=True,
            running=container_id not in self.unhealthy,
            exit_code=0 if container_id not in self.unhealthy else 137,
            health_status=(
                "healthy" if container_id not in self.unhealthy else "unhealthy"
            ),
            labels=inspected_labels,
        )

    async def remove(self, resource_ids: tuple[str, ...]) -> None:
        for resource_id in resource_ids:
            assert resource_id in self.created
            self.removed.append(resource_id)

    def mark_unhealthy(self, container_id: str) -> None:
        self.unhealthy.add(container_id)


def _setup(adapter: FakeDockerAdapter) -> ReproductionSetupAutomation:
    return ReproductionSetupAutomation(
        docker=adapter,
        recipes=EnvironmentRecipeStore(),
        health=SandboxHealthChecker(),
        resources=OwnedResourceRegistry(),
    )


@pytest.mark.asyncio
async def test_prepare_creates_clean_non_root_default_deny_container(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    request, requirements, plan = _dynamic_records()
    docker = FakeDockerAdapter()

    prepared = await _setup(docker).prepare(
        approval=_approval(tmp_path, request),
        request=request,
        requirements=requirements,
        plan=plan,
        meta=_meta("sandbox_environment", "environment-seed"),
    )
    inspected = await docker.inspect(prepared.environment.container_instance_id)

    assert prepared.environment.container_action == "CREATED"
    assert prepared.environment.container_reason == "INITIAL_CLEAN"
    assert prepared.environment.status == "READY"
    assert inspected.user not in {"0", "root"}
    assert inspected.network_mode == "none"
    assert inspected.privileged is False
    assert inspected.read_only_rootfs is True


@pytest.mark.asyncio
async def test_unhealthy_container_is_recreated_and_only_owned_resources_removed(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    request, requirements, plan = _dynamic_records()
    docker = FakeDockerAdapter()
    setup = _setup(docker)
    first = await setup.prepare(
        approval=_approval(tmp_path, request),
        request=request,
        requirements=requirements,
        plan=plan,
        meta=_meta("sandbox_environment", "environment-seed"),
    )
    docker.mark_unhealthy(first.environment.container_instance_id)

    second = await setup.recreate(
        previous=first,
        reason="STATE_UNCERTAIN",
        meta=_meta(
            "sandbox_environment",
            "environment-retry-seed",
            attempt_id="dynamic-attempt-2",
        ),
    )
    cleanup = await setup.cleanup(
        request=request,
        environments=(first.environment, second.environment),
        resource_refs=(*first.resource_refs, *second.resource_refs),
        meta=_meta("cleanup_result", "cleanup-seed", attempt_id="dynamic-attempt-2"),
    )

    assert second.environment.container_action == "CREATED"
    assert second.environment.container_reason == "STATE_UNCERTAIN"
    assert second.environment.previous_environment_ref == reference(first.environment)
    assert cleanup.status == "SUCCEEDED"
    assert set(docker.removed) == {
        first.environment.container_instance_id,
        second.environment.container_instance_id,
    }
    assert "unrelated-user-container" not in docker.removed


@pytest.mark.asyncio
async def test_same_attempt_recreate_gets_a_distinct_runtime_container_identity(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    request, requirements, plan = _dynamic_records()
    docker = FakeDockerAdapter()
    setup = _setup(docker)
    first = await setup.prepare(
        approval=_approval(tmp_path, request),
        request=request,
        requirements=requirements,
        plan=plan,
        meta=_meta("sandbox_environment", "environment-seed"),
    )

    second = await setup.recreate(
        previous=first,
        reason="STATE_CHANGED",
        meta=_meta("sandbox_environment", "environment-recreated-seed"),
    )

    first_labels = docker.created[first.environment.container_instance_id][1]
    second_labels = docker.created[second.environment.container_instance_id][1]
    assert first_labels["sastsimi.resource-id"] != second_labels["sastsimi.resource-id"]
    assert DockerAdapter.runtime_container_name(
        first_labels
    ) != DockerAdapter.runtime_container_name(second_labels)


@pytest.mark.asyncio
async def test_different_hypothesis_cannot_reuse_writable_container(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    request, requirements, plan = _dynamic_records()
    docker = FakeDockerAdapter()
    setup = _setup(docker)
    first = await setup.prepare(
        approval=_approval(tmp_path, request),
        request=request,
        requirements=requirements,
        plan=plan,
        meta=_meta("sandbox_environment", "environment-seed"),
    )

    with pytest.raises(ValueError, match="SANDBOX_REUSE_SCOPE_MISMATCH"):
        await setup.reuse(
            previous=first,
            meta=_meta(
                "sandbox_environment",
                "foreign-environment-seed",
                attempt_id="dynamic-attempt-2",
                hypothesis_id="hypothesis-2",
            ),
        )

    assert len(docker.created) == 1


@pytest.mark.asyncio
async def test_cleanup_rejects_unknown_resource_without_docker_delete(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    request, requirements, plan = _dynamic_records()
    docker = FakeDockerAdapter()
    setup = _setup(docker)
    prepared = await setup.prepare(
        approval=_approval(tmp_path, request),
        request=request,
        requirements=requirements,
        plan=plan,
        meta=_meta("sandbox_environment", "environment-seed"),
    )
    unknown = _ref("sandbox_resource", "unrelated-user-container")

    cleanup = await setup.cleanup(
        request=request,
        environments=(prepared.environment,),
        resource_refs=(*prepared.resource_refs, unknown),
        meta=_meta("cleanup_result", "cleanup-seed"),
    )

    assert cleanup.status == "FAILED"
    assert docker.removed == []


@pytest.mark.asyncio
async def test_cleanup_allows_extra_labels_but_rejects_required_mismatch(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    request, requirements, plan = _dynamic_records()

    extra_docker = FakeDockerAdapter()
    extra_setup = _setup(extra_docker)
    extra = await extra_setup.prepare(
        approval=_approval(tmp_path, request),
        request=request,
        requirements=requirements,
        plan=plan,
        meta=_meta("sandbox_environment", "extra-label-environment"),
    )
    extra_id = extra.environment.container_instance_id
    extra_docker.inspect_label_overrides[extra_id] = {"image.vendor": "fixture"}

    extra_cleanup = await extra_setup.cleanup(
        request=request,
        environments=(extra.environment,),
        resource_refs=extra.resource_refs,
        meta=_meta("cleanup_result", "extra-label-cleanup"),
    )

    assert extra_cleanup.status == "SUCCEEDED"
    assert extra_docker.removed == [extra_id]

    mismatch_docker = FakeDockerAdapter()
    mismatch_setup = _setup(mismatch_docker)
    mismatch = await mismatch_setup.prepare(
        approval=_approval(tmp_path, request),
        request=request,
        requirements=requirements,
        plan=plan,
        meta=_meta("sandbox_environment", "mismatch-environment"),
    )
    mismatch_id = mismatch.environment.container_instance_id
    mismatch_docker.inspect_label_overrides[mismatch_id] = {
        "sastsimi.attempt-id": "different-attempt"
    }

    mismatch_cleanup = await mismatch_setup.cleanup(
        request=request,
        environments=(mismatch.environment,),
        resource_refs=mismatch.resource_refs,
        meta=_meta("cleanup_result", "mismatch-cleanup"),
    )

    assert mismatch_cleanup.status == "FAILED"
    assert mismatch_cleanup.failure_reason == "CLEANUP_OWNERSHIP_MISMATCH"
    assert mismatch_docker.removed == []


class _Process:
    def __init__(
        self,
        stdout: bytes,
        stderr: bytes = b"",
        returncode: int = 0,
        *,
        forbid_communicate: bool = False,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.forbid_communicate = forbid_communicate
        self.communicate_called = False
        self.killed = False
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stdout.feed_eof()
        self.stderr = asyncio.StreamReader()
        self.stderr.feed_data(stderr)
        self.stderr.feed_eof()

    async def communicate(self) -> tuple[bytes, bytes]:
        self.communicate_called = True
        if self.forbid_communicate:
            raise AssertionError("communicate must not buffer unbounded Docker output")
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    async def wait(self) -> int:
        return self.returncode


@pytest.mark.asyncio
async def test_docker_create_uses_argv_and_hard_isolation_options(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[object, ...]] = []

    async def spawn(*argv: object, **kwargs: object) -> _Process:
        calls.append(argv)
        return _Process(b"owned-container-id\n")

    monkeypatch.setattr(
        "sastsimi.sandbox.docker_adapter.asyncio.create_subprocess_exec", spawn
    )
    request, _, _ = _dynamic_records()
    spec = _approval(tmp_path, request).approved_spec
    assert spec is not None
    adapter = DockerAdapter()

    container_id = await adapter.create(
        spec,
        {
            "sastsimi.owner": "reproduction-setup-automation",
            "sastsimi.analysis-id": "analysis-1",
            "sastsimi.workspace-id": "workspace-1",
            "sastsimi.commit-id": "commit-1",
            "sastsimi.hypothesis-id": "hypothesis-1",
            "sastsimi.attempt-id": "dynamic-attempt-1",
            "sastsimi.resource-kind": "container",
            "sastsimi.resource-id": "container-runtime-1",
        },
    )

    assert container_id == "owned-container-id"
    assert calls
    argv = calls[0]
    assert argv[0] == "docker"
    assert "--network" in argv and "none" in argv
    assert "--read-only" in argv
    assert "no-new-privileges" in argv
    assert "--cap-drop" in argv and "ALL" in argv
    assert "--pids-limit" in argv
    assert all(
        not (isinstance(item, str) and "docker create " in item) for item in argv
    )


@pytest.mark.asyncio
async def test_docker_exec_uses_exact_argv_and_working_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []

    async def spawn(*argv: object, **kwargs: object) -> _Process:
        calls.append(argv)
        return _Process(b"command output")

    monkeypatch.setattr(
        "sastsimi.sandbox.docker_adapter.asyncio.create_subprocess_exec", spawn
    )
    adapter = DockerAdapter()

    outcome = await adapter.exec(
        "owned-container-id",
        ("python", "poc.py"),
        10_000,
        working_directory="/workspace",
    )

    assert outcome.exit_code == 0
    assert calls == [
        (
            "docker",
            "exec",
            "--workdir",
            "/workspace",
            "owned-container-id",
            "python",
            "poc.py",
        )
    ]


def test_runtime_owned_name_does_not_include_repository_path(tmp_path: Path) -> None:
    labels = {
        "sastsimi.owner": "reproduction-setup-automation",
        "sastsimi.analysis-id": "analysis-1",
        "sastsimi.workspace-id": "workspace-1",
        "sastsimi.commit-id": "commit-1",
        "sastsimi.hypothesis-id": "hypothesis-1",
        "sastsimi.attempt-id": "dynamic-attempt-1",
        "sastsimi.resource-kind": "container",
        "sastsimi.resource-id": "container-runtime-1",
    }
    name = DockerAdapter.runtime_container_name(labels)

    assert name.startswith("sastsimi-")
    assert str(tmp_path) not in name
    assert "hypothesis-1" not in name
    assert len(name) <= 63


@pytest.mark.asyncio
async def test_docker_output_limit_stops_process_without_communicate_buffering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _Process(b"x" * (1024 * 1024 + 1), forbid_communicate=True)

    async def spawn(*argv: object, **kwargs: object) -> _Process:
        return process

    monkeypatch.setattr(
        "sastsimi.sandbox.docker_adapter.asyncio.create_subprocess_exec", spawn
    )

    with pytest.raises(DockerOperationError, match="DOCKER_OUTPUT_LIMIT_EXCEEDED"):
        await DockerAdapter().inspect_image("fixture:latest")

    assert process.communicate_called is False
    assert process.killed is True


def test_profile_file_has_bounded_default_deny_values() -> None:
    profile_path = Path(__file__).parents[3] / "docker/profiles/local-default-deny.yaml"
    loaded = __import__("yaml").safe_load(profile_path.read_text())
    profile = json.loads(json.dumps(loaded))

    assert profile == {
        "network_mode": "DEFAULT_DENY",
        "user": "65532:65532",
        "read_only_rootfs": True,
        "privileged": False,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "cpu_limit_millicores": 500,
        "memory_limit_bytes": 268435456,
        "disk_limit_bytes": 67108864,
        "pid_limit": 64,
        "max_requested_execution_ms": 10000,
    }
