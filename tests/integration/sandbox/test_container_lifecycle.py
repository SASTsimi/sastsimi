from __future__ import annotations

import asyncio
import hashlib
import io
import json
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import cast

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.dynamic import (
    POC_RUNTIME_PATH,
    DynamicReproductionRequest,
    EnvironmentRecipe,
    EnvironmentRequirement,
    EnvironmentRequirements,
    ReproductionPlan,
    SandboxPolicyDecision,
)
from sastsimi.contracts.dynamic_resource import owned_container_resource_ref
from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import RepositoryProfile
from sastsimi.ports.dto import StagedArtifact
from sastsimi.sandbox.cleanup import OwnedResourceRegistry
from sastsimi.sandbox.controller import (
    SandboxBoundaryOutcome,
    SandboxBuildBoundaryOutcome,
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
from sastsimi.sandbox.recipe_store import EnvironmentRecipeStore, PreparedRecipeSource
from sastsimi.sandbox.setup_automation import (
    PreparedSandbox,
    ReproductionSetupAutomation,
)

NOW = datetime(2026, 9, 11, tzinfo=UTC)
IMAGE_DIGEST = "sha256:" + "1" * 64


@dataclass
class _MemoryArtifacts:
    values: dict[str, bytes] = field(default_factory=dict)

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        return StagedArtifact(data, media_type)

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        digest = hashlib.sha256(staged.data).hexdigest()
        self.values[digest] = staged.data
        return StoredDataRef(
            stored_data_id=digest,
            data_kind="artifact",
            content_hash=digest,
            workspace_id="workspace-1",
            commit_id="commit-1",
            record_id=None,
        )

    def open_verified(self, ref: StoredDataRef) -> io.BytesIO:
        return io.BytesIO(self.values[ref.content_hash])


def _git_blob(raw: bytes) -> str:
    framed = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    return hashlib.sha1(framed).hexdigest()


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
        stored_data_id=StoredDataId(name),
        data_kind=kind,
        content_hash="a" * 64,
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("commit-1"),
        record_id=RecordId(name),
    )


def _repository_profile(files: Mapping[str, bytes]) -> RepositoryProfile:
    tracked = tuple(
        {
            "git_path": path,
            "git_mode": "100644",
            "blob_id": _git_blob(raw),
            "size_bytes": len(raw),
        }
        for path, raw in sorted(files.items())
    )
    configs = []
    for path in sorted(files):
        name = Path(path).name.lower()
        kind = {
            "dockerfile": "DOCKERFILE",
            "requirements.txt": "REQUIREMENTS",
            "pyproject.toml": "PYPROJECT",
            "package.json": "PACKAGE_JSON",
        }.get(name)
        if kind is not None:
            configs.append({"path": path, "kind": kind})
    languages = []
    if any(path.endswith(".py") for path in files):
        languages.append(
            {
                "name": "PYTHON",
                "evidence_paths": tuple(
                    path for path in sorted(files) if path.endswith(".py")
                ),
            }
        )
    if any(path.endswith((".js", ".mjs", ".cjs")) for path in files):
        languages.append(
            {
                "name": "JAVASCRIPT",
                "evidence_paths": tuple(
                    path
                    for path in sorted(files)
                    if path.endswith((".js", ".mjs", ".cjs"))
                ),
            }
        )
    return RepositoryProfile.model_validate(
        {
            "meta": _meta(
                "repository_profile",
                "repository-profile",
                attempt_id="repository-profile-attempt",
                hypothesis_id=None,
            ),
            "workspace_id": "workspace-1",
            "commit_id": "commit-1",
            "workspace_ref": RunStoredDataRef(
                stored_data_id="code-workspace",
                data_kind="code_workspace",
                content_hash="b" * 64,
                analysis_id="analysis-1",
                record_id="code-workspace",
            ),
            "manifest_hash": content_hash(tuple(tracked)),
            "tracked_files": tracked,
            "languages": tuple(languages),
            "frameworks": (),
            "config_files": tuple(configs),
            "status": "READY",
            "confirmation_reasons": (),
        }
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
    recipe: EnvironmentRecipe | None = None,
) -> SandboxBoundaryOutcome:
    request_ref = reference(request)
    assert isinstance(request_ref, StoredDataRef)
    policy = SandboxPolicyDecision(
        meta=_meta("sandbox_policy_decision", "policy-decision"),
        request_ref=request_ref,
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
        approved_recipe_ref=(
            cast(StoredDataRef, reference(recipe)) if recipe is not None else None
        ),
    )


def _build_approval(
    workspace: Path,
    request: DynamicReproductionRequest,
    source: PreparedRecipeSource,
) -> SandboxBuildBoundaryOutcome:
    run = _approval(workspace, request)
    assert run.approved_spec is not None
    spec = replace(run.approved_spec, image_digest=None)
    if source.repository_profile_ref is not None:
        spec = replace(spec, mounts=(), source_baked=True)
    return SandboxBuildBoundaryOutcome(
        decision=run.decision,
        approved_spec=spec,
        approved_source=source,
    )


async def _prepare(
    setup: ReproductionSetupAutomation,
    workspace: Path,
    request: DynamicReproductionRequest,
    requirements: EnvironmentRequirements,
    plan: ReproductionPlan,
    meta: RecordMeta,
) -> PreparedSandbox:
    source = await setup.preflight(
        workspace_root=workspace,
        request=request,
        requirements=requirements,
        meta=meta,
    )
    recipe = await setup.build(
        approval=_build_approval(workspace, request, source),
        source=source,
        request=request,
        requirements=requirements,
        meta=meta,
    )
    return await setup.create(
        approval=_approval(workspace, request, recipe),
        recipe=recipe,
        request=request,
        requirements=requirements,
        plan=plan,
        meta=meta,
    )


@pytest.mark.asyncio
async def test_cold_build_has_no_docker_access_before_build_approval(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_bytes(b"FROM fixture:local\n")
    request, requirements, _ = _dynamic_records()
    docker = FakeDockerAdapter()
    setup = _setup(docker)

    source = await setup.preflight(
        workspace_root=tmp_path,
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "recipe-source"),
    )

    assert source.base_image == "fixture:local"
    assert docker.inspected_images == []
    assert docker.built == []
    assert docker.created == {}

    allowed = _build_approval(tmp_path, request, source)
    denied = SandboxBuildBoundaryOutcome(
        decision=allowed.decision.model_copy(update={"decision": "DENY"}),
        approved_spec=None,
        approved_source=None,
    )
    with pytest.raises(ValueError, match="SANDBOX_BUILD_APPROVAL_REQUIRED"):
        await setup.build(
            approval=denied,
            source=source,
            request=request,
            requirements=requirements,
            meta=_meta("environment_recipe", "recipe-seed"),
        )

    assert docker.inspected_images == []
    assert docker.built == []


@pytest.mark.asyncio
async def test_forged_run_digest_never_creates_a_container(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_bytes(b"FROM scratch\n")
    request, requirements, plan = _dynamic_records()
    docker = FakeDockerAdapter()
    setup = _setup(docker)
    source = await setup.preflight(
        workspace_root=tmp_path,
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "recipe-source"),
    )
    recipe = await setup.build(
        approval=_build_approval(tmp_path, request, source),
        source=source,
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "recipe-seed"),
    )
    forged = _approval(tmp_path, request, recipe)
    assert forged.approved_spec is not None
    forged = SandboxBoundaryOutcome(
        decision=forged.decision,
        approved_spec=SandboxRunSpec(
            **(forged.approved_spec.__dict__ | {"image_digest": "sha256:" + "2" * 64})
        ),
        approved_recipe_ref=cast(StoredDataRef, reference(recipe)),
    )

    with pytest.raises(ValueError, match="APPROVED_IMAGE_DIGEST_MISMATCH"):
        await setup.create(
            approval=forged,
            recipe=recipe,
            request=request,
            requirements=requirements,
            plan=plan,
            meta=_meta("sandbox_environment", "environment-seed"),
        )

    assert docker.created == {}


class FakeDockerAdapter:
    def __init__(self) -> None:
        self.built: list[tuple[bytes, int]] = []
        self.built_contexts: list[tuple[bytes, str, int]] = []
        self.inspected_images: list[tuple[str, int]] = []
        self.created: dict[str, tuple[SandboxRunSpec, Mapping[str, str]]] = {}
        self.removed: list[str] = []
        self.unhealthy: set[str] = set()
        self.inspect_label_overrides: dict[str, Mapping[str, str]] = {}
        self.started: list[str] = []
        self.hidden_mounts: set[str] = set()
        self._index = 0

    async def build(
        self,
        dockerfile: bytes,
        labels: Mapping[str, str],
        *,
        timeout_ms: int,
    ) -> str:
        self.built.append((dockerfile, timeout_ms))
        assert labels["sastsimi.owner"] == "reproduction-setup-automation"
        return IMAGE_DIGEST

    async def build_context(
        self,
        context_archive: bytes,
        dockerfile_path: str,
        labels: Mapping[str, str],
        *,
        timeout_ms: int,
    ) -> str:
        self.built_contexts.append((context_archive, dockerfile_path, timeout_ms))
        assert labels["sastsimi.owner"] == "reproduction-setup-automation"
        return IMAGE_DIGEST

    async def inspect_image(self, image: str, *, timeout_ms: int) -> str:
        self.inspected_images.append((image, timeout_ms))
        return IMAGE_DIGEST

    async def create(self, spec: SandboxRunSpec, labels: Mapping[str, str]) -> str:
        self._index += 1
        container_id = f"owned-container-{self._index}"
        self.created[container_id] = (spec, dict(labels))
        return container_id

    async def start(self, container_id: str) -> None:
        assert container_id in self.created
        self.started.append(container_id)

    async def verify_created_mounts(
        self, container_id: str, spec: SandboxRunSpec
    ) -> None:
        assert container_id in self.created
        assert self.created[container_id][0] == spec
        if container_id in self.hidden_mounts:
            raise ValueError("DOCKER_MOUNT_BOUNDARY_INVALID")

    async def execute(
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

    async def materialize_poc(
        self,
        container_id: str,
        content: bytes,
        content_digest: str,
    ) -> str:
        assert container_id in self.created
        assert hashlib.sha256(content).hexdigest() == content_digest
        return POC_RUNTIME_PATH

    async def inspect(self, container_id: str) -> DockerContainerState:
        spec, labels = self.created[container_id]
        assert spec.image_digest is not None
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


def _setup(
    adapter: FakeDockerAdapter,
    *,
    artifacts: _MemoryArtifacts | None = None,
) -> ReproductionSetupAutomation:
    return ReproductionSetupAutomation(
        docker=adapter,
        recipes=EnvironmentRecipeStore(artifacts=artifacts),
        health=SandboxHealthChecker(),
        resources=OwnedResourceRegistry(),
    )


@pytest.mark.asyncio
async def test_repository_profile_generates_python_build_context(
    tmp_path: Path,
) -> None:
    files = {
        "app.py": b"print('ready')\n",
        "requirements.txt": b"",
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    profile = _repository_profile(files)
    request, requirements, _ = _dynamic_records()
    docker = FakeDockerAdapter()
    setup = _setup(docker, artifacts=_MemoryArtifacts())

    source = await setup.preflight(
        workspace_root=tmp_path,
        repository_profile=profile,
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "profile-recipe-source"),
    )
    recipe = await setup.build(
        approval=_build_approval(tmp_path, request, source),
        source=source,
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "profile-recipe"),
    )

    assert source.repository_profile_ref == reference(profile)
    assert source.dockerfile_origin == "GENERATED"
    assert recipe.source_refs[0] == reference(profile)
    assert {item.data_kind for item in recipe.source_refs[1:]} == {"artifact"}
    assert docker.built == []
    assert len(docker.built_contexts) == 1
    archive, dockerfile_path, timeout_ms = docker.built_contexts[0]
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        names = tuple(sorted(bundle.getnames()))
        dockerfile = bundle.extractfile(dockerfile_path)
        assert dockerfile is not None
        dockerfile_bytes = dockerfile.read()
    assert names == ("Dockerfile", "app.py", "requirements.txt")
    assert b"FROM python@" in dockerfile_bytes
    assert b"COPY . /workspace" in dockerfile_bytes
    assert b'["python", "-m", "pip", "install"' in dockerfile_bytes
    assert b'"-r", "requirements.txt"' in dockerfile_bytes
    assert timeout_ms == 10_000


@pytest.mark.asyncio
async def test_persisted_recipe_can_rebuild_after_store_restart(tmp_path: Path) -> None:
    files = {
        "app.py": b"print('ready')\n",
        "requirements.txt": b"requests==2.32.5\n",
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    artifacts = _MemoryArtifacts()
    request, requirements, _ = _dynamic_records()
    source = await _setup(
        FakeDockerAdapter(), artifacts=artifacts
    ).preflight(
        workspace_root=tmp_path,
        repository_profile=_repository_profile(files),
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "restart-source"),
    )
    first_docker = FakeDockerAdapter()
    first_store = EnvironmentRecipeStore(artifacts=artifacts)
    recipe = await first_store.build(
        docker=first_docker,
        source=source,
        labels={"sastsimi.owner": "reproduction-setup-automation"},
        build_timeout_ms=10_000,
    )

    restarted_store = EnvironmentRecipeStore(artifacts=artifacts)
    restored = restarted_store.restore_source(recipe, workspace_root=tmp_path)
    restarted_docker = FakeDockerAdapter()
    rebuilt = await restarted_store.build(
        docker=restarted_docker,
        source=restored,
        labels={"sastsimi.owner": "reproduction-setup-automation"},
        build_timeout_ms=10_000,
    )

    assert recipe.source_manifest is not None
    assert rebuilt.recipe_source_ref == recipe.recipe_source_ref
    assert len(restarted_docker.built_contexts) == 1


@pytest.mark.asyncio
async def test_repository_profile_generates_javascript_dependency_install(
    tmp_path: Path,
) -> None:
    files = {
        "package.json": b'{"dependencies": {"express": "1.0.0"}}\n',
        "package-lock.json": b'{"lockfileVersion": 3}\n',
        "server.js": b"console.log('ready')\n",
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    request, requirements, _ = _dynamic_records()

    source = await _setup(
        FakeDockerAdapter(), artifacts=_MemoryArtifacts()
    ).preflight(
        workspace_root=tmp_path,
        repository_profile=_repository_profile(files),
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "node-recipe-source"),
    )

    assert b'["npm", "ci", "--ignore-scripts"]' in source.dockerfile


@pytest.mark.asyncio
async def test_repository_profile_blocks_tracked_secret_before_docker(
    tmp_path: Path,
) -> None:
    files = {
        ".env": b"API_KEY=do-not-send-to-docker\n",
        "app.py": b"print('ready')\n",
        "requirements.txt": b"",
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    profile = _repository_profile(files)
    request, requirements, _ = _dynamic_records()
    docker = FakeDockerAdapter()

    with pytest.raises(ValueError, match="REPOSITORY_SECRET_FILE_DENIED"):
        await _setup(docker, artifacts=_MemoryArtifacts()).preflight(
            workspace_root=tmp_path,
            repository_profile=profile,
            request=request,
            requirements=requirements,
            meta=_meta("environment_recipe", "blocked-recipe-source"),
        )

    assert docker.inspected_images == []
    assert docker.built == []
    assert docker.built_contexts == []


@pytest.mark.asyncio
async def test_repository_profile_blocks_unignored_package_credentials(
    tmp_path: Path,
) -> None:
    files = {
        ".npmrc": b"//registry.npmjs.org/:_authToken=do-not-send\n",
        "package.json": b'{"dependencies": {}}\n',
        "server.js": b"console.log('ready')\n",
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    request, requirements, _ = _dynamic_records()

    with pytest.raises(ValueError, match="REPOSITORY_SECRET_FILE_DENIED"):
        await _setup(
            FakeDockerAdapter(), artifacts=_MemoryArtifacts()
        ).preflight(
            workspace_root=tmp_path,
            repository_profile=_repository_profile(files),
            request=request,
            requirements=requirements,
            meta=_meta("environment_recipe", "credential-recipe-source"),
        )


@pytest.mark.asyncio
async def test_repository_profile_honors_simple_dockerignore_before_archiving(
    tmp_path: Path,
) -> None:
    files = {
        ".dockerignore": b".npmrc\n",
        ".npmrc": b"//registry.npmjs.org/:_authToken=do-not-send\n",
        "package.json": b'{"dependencies": {}}\n',
        "server.js": b"console.log('ready')\n",
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    request, requirements, _ = _dynamic_records()

    source = await _setup(
        FakeDockerAdapter(), artifacts=_MemoryArtifacts()
    ).preflight(
        workspace_root=tmp_path,
        repository_profile=_repository_profile(files),
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "ignored-credential-source"),
    )

    assert source.context_archive is not None
    with tarfile.open(fileobj=io.BytesIO(source.context_archive), mode="r:") as bundle:
        assert ".npmrc" not in bundle.getnames()


@pytest.mark.asyncio
async def test_repository_profile_rejects_unsupported_dockerignore_negation(
    tmp_path: Path,
) -> None:
    files = {
        ".dockerignore": b"*\n!package.json\n",
        "package.json": b'{"dependencies": {}}\n',
        "server.js": b"console.log('ready')\n",
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    request, requirements, _ = _dynamic_records()

    with pytest.raises(ValueError, match="DOCKERIGNORE_UNSUPPORTED"):
        await _setup(
            FakeDockerAdapter(), artifacts=_MemoryArtifacts()
        ).preflight(
            workspace_root=tmp_path,
            repository_profile=_repository_profile(files),
            request=request,
            requirements=requirements,
            meta=_meta("environment_recipe", "unsupported-ignore-source"),
        )


def test_missing_declared_container_health_is_not_a_match() -> None:
    request, requirements, _ = _dynamic_records()
    request_ref = reference(request)
    assert isinstance(request_ref, StoredDataRef)
    requirements = requirements.model_copy(
        update={
            "items": (
                EnvironmentRequirement(
                    requirement_id="health",
                    kind="HEALTH_CHECK",
                    name="Docker health status",
                    required=True,
                    expected="healthy",
                    expected_ref=None,
                    alternatives=(),
                    check_ref=None,
                    secret_ref=None,
                    source_refs=(request_ref,),
                ),
            )
        }
    )
    evidence_ref = _ref("sandbox_resource", "container")
    state = DockerContainerState(
        container_id="owned-container",
        image_digest=IMAGE_DIGEST,
        user="65532:65532",
        network_mode="none",
        privileged=False,
        read_only_rootfs=True,
        running=True,
        exit_code=0,
        health_status=None,
        labels={},
    )

    checks = SandboxHealthChecker().requirement_checks(
        requirements=requirements,
        state=state,
        evidence_ref=evidence_ref,
    )

    assert checks[0].status == "NOT_CHECKED"
    assert checks[0].actual is None


@pytest.mark.asyncio
async def test_repository_profile_keeps_equal_file_refs_distinct(
    tmp_path: Path,
) -> None:
    files = {
        "a.py": b"pass\n",
        "b.py": b"pass\n",
        "requirements.txt": b"",
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    request, requirements, _ = _dynamic_records()

    source = await _setup(FakeDockerAdapter(), artifacts=_MemoryArtifacts()).preflight(
        workspace_root=tmp_path,
        repository_profile=_repository_profile(files),
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "equal-content-source"),
    )

    assert len(source.source_refs) == len(set(source.source_refs))


@pytest.mark.asyncio
async def test_repository_profile_prefers_existing_dockerfile(tmp_path: Path) -> None:
    files = {
        "Dockerfile": b"FROM fixture:local\nWORKDIR /workspace\nCOPY . /workspace\n",
        "package.json": b'{"dependencies": {}}\n',
        "server.js": b"console.log('ready')\n",
    }
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    request, requirements, _ = _dynamic_records()
    docker = FakeDockerAdapter()
    setup = _setup(docker, artifacts=_MemoryArtifacts())

    source = await setup.preflight(
        workspace_root=tmp_path,
        repository_profile=_repository_profile(files),
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "existing-dockerfile-source"),
    )
    await setup.build(
        approval=_build_approval(tmp_path, request, source),
        source=source,
        request=request,
        requirements=requirements,
        meta=_meta("environment_recipe", "existing-dockerfile-recipe"),
    )

    assert source.dockerfile_origin == "REPOSITORY"
    archive, dockerfile_path, _ = docker.built_contexts[0]
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        dockerfile = bundle.extractfile(dockerfile_path)
        assert dockerfile is not None
        content = dockerfile.read()
    assert f"FROM fixture@{IMAGE_DIGEST}\n".encode() in content
    assert b"COPY . /workspace" in content


@pytest.mark.asyncio
async def test_prepare_creates_clean_non_root_default_deny_container(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_bytes(b"FROM scratch\n")
    request, requirements, plan = _dynamic_records()
    docker = FakeDockerAdapter()

    prepared = await _prepare(
        _setup(docker),
        tmp_path,
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
    assert prepared.resource_refs == (
        owned_container_resource_ref(
            container_id=prepared.environment.container_instance_id,
            meta=prepared.environment.meta,
        ),
    )
    assert docker.built == [(b"FROM scratch\n", 10_000)]


@pytest.mark.asyncio
async def test_prepare_bounds_local_base_image_inspection(
    tmp_path: Path,
) -> None:
    base_image = "registry.example:5000/team/fixture:local"
    (tmp_path / "Dockerfile").write_text(f"FROM {base_image}\n", encoding="utf-8")
    request, requirements, plan = _dynamic_records()
    docker = FakeDockerAdapter()

    await _prepare(
        _setup(docker),
        tmp_path,
        request=request,
        requirements=requirements,
        plan=plan,
        meta=_meta("sandbox_environment", "environment-seed"),
    )

    assert docker.inspected_images == [(base_image, 10_000)]
    assert docker.built == [
        (
            f"FROM registry.example:5000/team/fixture@{IMAGE_DIGEST}\n".encode(),
            10_000,
        )
    ]


def test_recipe_pins_named_base_to_repository_manifest_digest() -> None:
    dockerfile = EnvironmentRecipeStore._pin_base_image(
        "FROM registry.example:5000/team/fixture:local\n",
        base_image="registry.example:5000/team/fixture:local",
        base_digest=IMAGE_DIGEST,
    )

    assert dockerfile == (
        f"FROM registry.example:5000/team/fixture@{IMAGE_DIGEST}\n".encode()
    )


@pytest.mark.asyncio
async def test_recipe_lock_wait_is_bounded_by_approved_timeout(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_bytes(b"FROM scratch\n")
    request, requirements, _ = _dynamic_records()
    store = EnvironmentRecipeStore()
    source = store.preflight(
        context=tmp_path,
        request_ref=cast(StoredDataRef, reference(request)),
        requirements=requirements,
        meta=_meta("environment_recipe", "recipe-source"),
    )
    await store._lock.acquire()

    try:
        with pytest.raises(ValueError, match="RECIPE_LOCK_TIMEOUT"):
            await asyncio.wait_for(
                store.build(
                    docker=FakeDockerAdapter(),
                    source=source,
                    labels={
                        "sastsimi.owner": "reproduction-setup-automation",
                        "sastsimi.analysis-id": "analysis-1",
                        "sastsimi.workspace-id": "workspace-1",
                        "sastsimi.commit-id": "commit-1",
                        "sastsimi.hypothesis-id": "hypothesis-1",
                        "sastsimi.attempt-id": "dynamic-attempt-1",
                    },
                    build_timeout_ms=10,
                ),
                timeout=0.25,
            )
    finally:
        store._lock.release()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dockerfile", "error"),
    [
        (b"# syntax=docker/dockerfile:1\nFROM scratch\n", "REMOTE_FRONTEND"),
        (b"FROM scratch\nADD https://example.invalid/payload /tmp/\n", "ADD"),
        (b"FROM scratch\nCOPY payload /tmp/\n", "COPY"),
        (b"FROM scratch AS build\nFROM scratch\n", "SINGLE_BASE_IMAGE"),
        (
            b"FROM scratch\nRUN --mount=from=external/image,target=/mnt true\n",
            "RUN_MOUNT",
        ),
        (
            b"FROM scratch\nRUN --network=host true\n",
            "RUN_NETWORK",
        ),
        (
            b"FROM scratch\nRUN --net\\\nwork=default true\n",
            "RUN_NETWORK",
        ),
        (
            b"# escape=`\nFROM scratch\nRUN --net`\nwork=host true\n",
            "RUN_NETWORK",
        ),
        (b"FROM scratch\nVOLUME /data\n", "VOLUME"),
        (b'FROM scratch\nVOLUME ["/data"]\n', "VOLUME"),
        (b"FROM scratch\nVOL\\\nUME /data\n", "VOLUME"),
    ],
)
async def test_prepare_rejects_dockerfile_daemon_egress_and_context_inputs(
    tmp_path: Path,
    dockerfile: bytes,
    error: str,
) -> None:
    (tmp_path / "Dockerfile").write_bytes(dockerfile)
    request, requirements, _ = _dynamic_records()
    docker = FakeDockerAdapter()

    with pytest.raises(ValueError, match=error):
        await _setup(docker).preflight(
            workspace_root=tmp_path,
            request=request,
            requirements=requirements,
            meta=_meta("environment_recipe", "recipe-source"),
        )

    assert docker.built == []
    assert docker.created == {}


@pytest.mark.asyncio
async def test_hidden_image_volume_is_rejected_before_start_and_removed(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_bytes(b"FROM scratch\n")
    request, requirements, plan = _dynamic_records()
    docker = FakeDockerAdapter()
    docker.hidden_mounts.add("owned-container-1")

    with pytest.raises(ValueError, match="DOCKER_MOUNT_BOUNDARY_INVALID"):
        await _prepare(
            _setup(docker),
            tmp_path,
            request=request,
            requirements=requirements,
            plan=plan,
            meta=_meta("sandbox_environment", "environment-seed"),
        )

    assert docker.started == []
    assert docker.removed == ["owned-container-1"]


def test_dockerfile_rejects_unfinished_line_continuation() -> None:
    with pytest.raises(ValueError, match="DOCKERFILE_CONTINUATION_INVALID"):
        EnvironmentRecipeStore._validated_dockerfile(b"FROM scratch\nRUN true\\")


@pytest.mark.asyncio
async def test_unhealthy_container_is_recreated_and_only_owned_resources_removed(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    request, requirements, plan = _dynamic_records()
    docker = FakeDockerAdapter()
    setup = _setup(docker)
    first = await _prepare(
        setup,
        tmp_path,
        request=request,
        requirements=requirements,
        plan=plan,
        meta=_meta("sandbox_environment", "environment-seed"),
    )
    docker.mark_unhealthy(first.environment.container_instance_id)

    second = await setup.recreate(
        approval=_approval(tmp_path, request, first.recipe),
        previous=first,
        reason="STATE_UNCERTAIN",
        meta=_meta(
            "sandbox_environment",
            "environment-retry-seed",
        ),
    )
    cleanup = await setup.cleanup(
        request=request,
        environments=(first.environment, second.environment),
        resource_refs=(*first.resource_refs, *second.resource_refs),
        meta=_meta("cleanup_result", "cleanup-seed"),
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
    first = await _prepare(
        setup,
        tmp_path,
        request=request,
        requirements=requirements,
        plan=plan,
        meta=_meta("sandbox_environment", "environment-seed"),
    )

    second = await setup.recreate(
        approval=_approval(tmp_path, request, first.recipe),
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
    first = await _prepare(
        setup,
        tmp_path,
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
    prepared = await _prepare(
        setup,
        tmp_path,
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
    extra = await _prepare(
        extra_setup,
        tmp_path,
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
    mismatch = await _prepare(
        mismatch_setup,
        tmp_path,
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
async def test_docker_rejects_image_declared_volume_before_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, ...]] = []

    async def run(
        argv: tuple[str, ...],
        *,
        timeout_ms: int | None = None,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        del timeout_ms, input_bytes
        calls.append(argv)
        return DockerCommandOutcome(
            0,
            json.dumps(
                [
                    {
                        "Type": "volume",
                        "Name": "unexpected-volume",
                        "Source": "/var/lib/docker/volumes/unexpected-volume/_data",
                        "Destination": "/data",
                        "RW": True,
                    }
                ]
            ).encode(),
            b"",
            False,
        )

    request, _, _ = _dynamic_records()
    spec = _approval(tmp_path, request).approved_spec
    assert spec is not None
    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", run)

    with pytest.raises(ValueError, match="DOCKER_MOUNT_BOUNDARY_INVALID"):
        await adapter.verify_created_mounts("owned-container-id", spec)

    assert calls == [("inspect", "--format", "{{json .Mounts}}", "owned-container-id")]


@pytest.mark.asyncio
async def test_docker_cleanup_removes_owned_anonymous_volumes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    async def run(
        argv: tuple[str, ...],
        *,
        timeout_ms: int | None = None,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        del timeout_ms, input_bytes
        calls.append(argv)
        return DockerCommandOutcome(0, b"", b"", False)

    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", run)

    await adapter.remove(("owned-container-id",))

    assert calls == [
        ("rm", "--force", "--volumes", "owned-container-id"),
    ]


@pytest.mark.asyncio
async def test_docker_build_uses_stdin_empty_context_and_approved_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], int | None, bytes | None]] = []

    async def run(
        argv: tuple[str, ...],
        *,
        timeout_ms: int | None = None,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        calls.append((argv, timeout_ms, input_bytes))
        return DockerCommandOutcome(0, (IMAGE_DIGEST + "\n").encode(), b"", False)

    labels = {
        "sastsimi.owner": "reproduction-setup-automation",
        "sastsimi.analysis-id": "analysis-1",
        "sastsimi.workspace-id": "workspace-1",
        "sastsimi.commit-id": "commit-1",
        "sastsimi.hypothesis-id": "hypothesis-1",
        "sastsimi.attempt-id": "dynamic-attempt-1",
    }
    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", run)
    dockerfile = b"FROM scratch\nRUN true\n"

    digest = await adapter.build(dockerfile, labels, timeout_ms=10_000)

    assert digest == IMAGE_DIGEST
    assert len(calls) == 1
    argv, timeout_ms, input_bytes = calls[0]
    assert argv[:6] == (
        "build",
        "--quiet",
        "--pull=false",
        "--network",
        "none",
        "--label",
    )
    assert argv[-1] == "-"
    assert timeout_ms == 10_000
    assert input_bytes == dockerfile


@pytest.mark.asyncio
async def test_docker_context_build_rejects_link_member_before_daemon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        dockerfile = tarfile.TarInfo("Dockerfile")
        dockerfile.size = len(b"FROM scratch\n")
        archive.addfile(dockerfile, io.BytesIO(b"FROM scratch\n"))
        link = tarfile.TarInfo("escape")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../host"
        archive.addfile(link)

    async def unexpected(*_: object, **__: object) -> DockerCommandOutcome:
        raise AssertionError("invalid context must not reach Docker")

    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", unexpected)
    labels = {
        "sastsimi.owner": "reproduction-setup-automation",
        "sastsimi.analysis-id": "analysis-1",
        "sastsimi.workspace-id": "workspace-1",
        "sastsimi.commit-id": "commit-1",
        "sastsimi.hypothesis-id": "hypothesis-1",
        "sastsimi.attempt-id": "dynamic-attempt-1",
    }

    with pytest.raises(ValueError, match="DOCKER_BUILD_CONTEXT_INVALID"):
        await adapter.build_context(
            stream.getvalue(),
            "Dockerfile",
            labels,
            timeout_ms=10_000,
        )


@pytest.mark.asyncio
async def test_docker_context_build_streams_tar_without_host_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = EnvironmentRecipeStore._archive(
        {"Dockerfile": (b"FROM scratch\n", 0o644), "app.py": (b"pass\n", 0o644)}
    )
    calls: list[tuple[tuple[str, ...], int | None, bytes | None]] = []

    async def run(
        argv: tuple[str, ...],
        *,
        timeout_ms: int | None = None,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        calls.append((argv, timeout_ms, input_bytes))
        return DockerCommandOutcome(0, (IMAGE_DIGEST + "\n").encode(), b"", False)

    labels = {
        "sastsimi.owner": "reproduction-setup-automation",
        "sastsimi.analysis-id": "analysis-1",
        "sastsimi.workspace-id": "workspace-1",
        "sastsimi.commit-id": "commit-1",
        "sastsimi.hypothesis-id": "hypothesis-1",
        "sastsimi.attempt-id": "dynamic-attempt-1",
    }
    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", run)

    digest = await adapter.build_context(
        archive,
        "Dockerfile",
        labels,
        timeout_ms=10_000,
    )

    assert digest == IMAGE_DIGEST
    assert len(calls) == 1
    argv, timeout_ms, input_bytes = calls[0]
    assert argv[-3:] == ("--file", "Dockerfile", "-")
    assert timeout_ms == 10_000
    assert input_bytes == archive
    assert all(str(Path.cwd()) not in item for item in argv)


@pytest.mark.asyncio
async def test_docker_image_inspection_uses_approved_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], int | None]] = []

    async def run(
        argv: tuple[str, ...],
        *,
        timeout_ms: int | None = None,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        assert input_bytes is None
        calls.append((argv, timeout_ms))
        return DockerCommandOutcome(
            0,
            json.dumps([f"fixture@{IMAGE_DIGEST}"]).encode(),
            b"",
            False,
        )

    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", run)

    digest = await adapter.inspect_image("fixture:local", timeout_ms=10_000)

    assert digest == IMAGE_DIGEST
    assert calls == [
        (
            (
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                "fixture:local",
            ),
            10_000,
        )
    ]


@pytest.mark.asyncio
async def test_docker_create_rejects_missing_image_digest_before_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request, _, _ = _dynamic_records()
    run = _approval(Path.cwd(), request)
    assert run.approved_spec is not None

    async def unexpected(*_: object, **__: object) -> DockerCommandOutcome:
        raise AssertionError("Docker must not receive a missing image digest")

    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", unexpected)

    with pytest.raises(ValueError, match="IMAGE_DIGEST_REQUIRED"):
        await adapter.create(
            replace(run.approved_spec, image_digest=None),
            {},
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

    outcome = await adapter.execute(
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


@pytest.mark.asyncio
async def test_docker_materializes_verified_poc_only_inside_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], bytes | None]] = []
    content = b"print('candidate')\n"
    content_digest = hashlib.sha256(content).hexdigest()
    staging_path = f"{POC_RUNTIME_PATH}.next"

    async def run(
        argv: tuple[str, ...],
        *,
        timeout_ms: int | None = None,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        del timeout_ms
        calls.append((argv, input_bytes))
        stdout = (
            DockerAdapter._safe_output(f"{content_digest}  {staging_path}\n".encode())
            if argv[-2:] == ("sha256sum", staging_path)
            else b""
        )
        return DockerCommandOutcome(0, stdout, b"", False)

    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", run)

    path = await adapter.materialize_poc(
        "owned-container-id",
        content,
        content_digest,
    )

    assert path == POC_RUNTIME_PATH
    assert calls == [
        (("exec", "owned-container-id", "rm", "-f", staging_path), None),
        (
            (
                "exec",
                "-i",
                "owned-container-id",
                "dd",
                f"of={staging_path}",
                "status=none",
            ),
            content,
        ),
        (("exec", "owned-container-id", "sha256sum", staging_path), None),
        (("exec", "owned-container-id", "chmod", "0444", staging_path), None),
        (
            (
                "exec",
                "owned-container-id",
                "mv",
                "-f",
                staging_path,
                POC_RUNTIME_PATH,
            ),
            None,
        ),
    ]


@pytest.mark.asyncio
async def test_docker_atomically_replaces_poc_with_exact_second_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_path = f"{POC_RUNTIME_PATH}.next"
    staged: bytes | None = None
    materialized: bytes | None = None
    verified_digests: list[str] = []

    async def run(
        argv: tuple[str, ...],
        *,
        timeout_ms: int | None = None,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        nonlocal staged, materialized
        del timeout_ms
        command = argv[3:] if argv[1:2] == ("-i",) else argv[2:]
        if command == ("rm", "-f", staging_path):
            staged = None
        elif command == ("dd", f"of={staging_path}", "status=none"):
            assert input_bytes is not None
            staged = input_bytes
        elif command == ("sha256sum", staging_path):
            assert staged is not None
            digest = hashlib.sha256(staged).hexdigest()
            verified_digests.append(digest)
            return DockerCommandOutcome(
                0,
                DockerAdapter._safe_output(f"{digest}  {staging_path}\n".encode()),
                b"",
                False,
            )
        elif command == ("chmod", "0444", staging_path):
            assert staged is not None
        elif command == ("mv", "-f", staging_path, POC_RUNTIME_PATH):
            assert staged is not None
            materialized = staged
            staged = None
        else:
            raise AssertionError(f"unexpected Docker argv: {argv!r}")
        return DockerCommandOutcome(0, b"", b"", False)

    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", run)
    first = b"print('first')\n"
    second = b"print('second')\n"

    for content in (first, second):
        await adapter.materialize_poc(
            "owned-container-id",
            content,
            hashlib.sha256(content).hexdigest(),
        )

    assert materialized == second
    assert verified_digests == [
        hashlib.sha256(first).hexdigest(),
        hashlib.sha256(second).hexdigest(),
    ]


@pytest.mark.asyncio
async def test_docker_rejects_container_poc_digest_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    staging_path = f"{POC_RUNTIME_PATH}.next"

    async def run(
        argv: tuple[str, ...],
        *,
        timeout_ms: int | None = None,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        del timeout_ms, input_bytes
        calls.append(argv)
        stdout = (
            f"{'0' * 64}  {staging_path}\n".encode()
            if argv[-2:] == ("sha256sum", staging_path)
            else b""
        )
        return DockerCommandOutcome(0, stdout, b"", False)

    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", run)
    content = b"print('candidate')\n"

    with pytest.raises(DockerOperationError, match="DOCKER_POC_DIGEST_MISMATCH"):
        await adapter.materialize_poc(
            "owned-container-id",
            content,
            hashlib.sha256(content).hexdigest(),
        )

    assert all("chmod" not in argv for argv in calls)


@pytest.mark.asyncio
async def test_docker_rejects_unverified_poc_before_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unexpected(*_: object, **__: object) -> DockerCommandOutcome:
        raise AssertionError(
            "Docker must not receive digest-mismatched candidate bytes"
        )

    adapter = DockerAdapter()
    monkeypatch.setattr(adapter, "_run", unexpected)

    with pytest.raises(ValueError, match="POC_CONTENT_DIGEST_MISMATCH"):
        await adapter.materialize_poc(
            "owned-container-id",
            b"changed",
            "a" * 64,
        )


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
        await DockerAdapter().inspect_image("fixture:latest", timeout_ms=10_000)

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
