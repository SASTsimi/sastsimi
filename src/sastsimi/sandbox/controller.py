"""Fail-closed checks for the boundary outside a dynamic Sandbox.

The controller never runs Docker and never interprets vulnerability semantics.
It only turns an already-authorized ``RUN_SANDBOX`` request into an immutable,
locally constrained run specification.
"""

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    Decision,
    RequesterRole,
    UseStatus,
)
from sastsimi.contracts.budget import DynamicReproductionLifecycleProfile
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    EnvironmentRecipe,
    ReproductionPlan,
    SandboxPolicyDecision,
    SandboxProfile,
)
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference, require_record_ref

from .recipe_store import PreparedRecipeSource

_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NUMERIC_USER = re.compile(r"^[1-9][0-9]*(?::[1-9][0-9]*)?$")
_DOCKER_ENDPOINTS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/podman/podman.sock",
    "//./pipe/docker_engine",
)


@dataclass(frozen=True)
class SandboxMount:
    source: Path | None
    target: PurePosixPath
    read_only: bool


@dataclass(frozen=True)
class SandboxRunSpec:
    workspace_root: Path
    image_digest: str | None
    user: str
    mounts: tuple[SandboxMount, ...]
    network_mode: str
    network_targets: tuple[str, ...]
    secret_refs: tuple[StoredDataRef, ...]
    privileged: bool
    pid_mode: str | None
    ipc_mode: str | None
    capabilities: tuple[str, ...]
    cpu_limit_millicores: int
    memory_limit_bytes: int
    disk_limit_bytes: int
    pid_limit: int
    requested_execution_ms: int


@dataclass(frozen=True)
class SandboxBoundaryOutcome:
    decision: SandboxPolicyDecision
    approved_spec: SandboxRunSpec | None
    approved_recipe_ref: StoredDataRef | None = None


@dataclass(frozen=True)
class SandboxBuildBoundaryOutcome:
    decision: SandboxPolicyDecision
    approved_spec: SandboxRunSpec | None
    approved_source: PreparedRecipeSource | None


RecordResolver = Callable[[StoredDataRef], object]


class SandboxController:
    """Validate external isolation before any Docker adapter can be called."""

    def __init__(
        self,
        *,
        workspace_root: Path,
        workspace_id: str,
        commit_id: str,
        record_resolver: RecordResolver,
        isolated_network_targets: Iterable[str] = (),
    ) -> None:
        self._workspace_root = workspace_root.resolve(strict=False)
        self._workspace_id = workspace_id
        self._commit_id = commit_id
        self._resolve = record_resolver
        self._isolated_network_targets = frozenset(isolated_network_targets)

    @property
    def workspace_root(self) -> Path:
        """Return the canonical local workspace boundary used for approval."""

        return self._workspace_root

    def evaluate_build(
        self,
        *,
        spec: SandboxRunSpec,
        source: PreparedRecipeSource,
        action: ActionRequest,
        action_decision_ref: StoredDataRef,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        sandbox_profile: SandboxProfile,
        lifecycle_profile: DynamicReproductionLifecycleProfile,
        run_policy_state_ref: StoredDataRef,
        required_context_refs: tuple[StoredDataRef, ...],
        meta: RecordMeta,
    ) -> SandboxBuildBoundaryOutcome:
        """Approve exact source and host boundary before any Docker daemon access."""

        reasons, action_decision, policy_state = self._initial_checks(
            spec=spec,
            action=action,
            action_decision_ref=action_decision_ref,
            request=request,
            plan=plan,
            sandbox_profile=sandbox_profile,
            lifecycle_profile=lifecycle_profile,
            run_policy_state_ref=run_policy_state_ref,
            meta=meta,
        )
        self._check_action_closure(
            reasons,
            spec=spec,
            action=action,
            action_decision=action_decision,
            action_decision_ref=action_decision_ref,
            request=request,
            plan=plan,
            sandbox_profile=sandbox_profile,
            lifecycle_profile=lifecycle_profile,
            phase_ref=source.recipe_source_ref,
            image_digest=None,
            run_policy_state_ref=run_policy_state_ref,
            required_context_refs=required_context_refs,
        )
        self._check_recipe_source(reasons, spec, request, plan, source)
        self._check_boundary(reasons, spec, action, sandbox_profile)
        if spec.image_digest is not None:
            reasons.append("BUILD_IMAGE_DIGEST_FORBIDDEN")
        allowed = not reasons
        decision = self._decision(
            reasons=reasons,
            action=action,
            action_decision_ref=action_decision_ref,
            request=request,
            plan=plan,
            sandbox_profile=sandbox_profile,
            lifecycle_profile=lifecycle_profile,
            run_policy_state_ref=run_policy_state_ref,
            policy_state=policy_state,
            phase_ref=source.recipe_source_ref,
            required_context_refs=required_context_refs,
            meta=meta,
        )
        return SandboxBuildBoundaryOutcome(
            decision=decision,
            approved_spec=spec if allowed else None,
            approved_source=source if allowed else None,
        )

    def evaluate(
        self,
        *,
        spec: SandboxRunSpec,
        recipe: EnvironmentRecipe,
        action: ActionRequest,
        action_decision_ref: StoredDataRef,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        sandbox_profile: SandboxProfile,
        lifecycle_profile: DynamicReproductionLifecycleProfile,
        run_policy_state_ref: StoredDataRef,
        required_context_refs: tuple[StoredDataRef, ...],
        meta: RecordMeta,
    ) -> SandboxBoundaryOutcome:
        """Return ALLOW only for an exact, local, resource-bounded specification."""

        reasons, action_decision, policy_state = self._initial_checks(
            spec=spec,
            action=action,
            action_decision_ref=action_decision_ref,
            request=request,
            plan=plan,
            sandbox_profile=sandbox_profile,
            lifecycle_profile=lifecycle_profile,
            run_policy_state_ref=run_policy_state_ref,
            meta=meta,
        )
        recipe_ref = self._stored_reference(recipe)
        self._check_action_closure(
            reasons,
            spec=spec,
            action=action,
            action_decision=action_decision,
            action_decision_ref=action_decision_ref,
            request=request,
            plan=plan,
            sandbox_profile=sandbox_profile,
            lifecycle_profile=lifecycle_profile,
            phase_ref=recipe_ref,
            image_digest=recipe.built_image_digest,
            run_policy_state_ref=run_policy_state_ref,
            required_context_refs=required_context_refs,
        )
        self._check_recipe(reasons, recipe, request, plan, meta)
        self._check_boundary(reasons, spec, action, sandbox_profile)
        if not isinstance(spec.image_digest, str) or not _IMAGE_DIGEST.fullmatch(
            spec.image_digest
        ):
            reasons.append("IMAGE_DIGEST_REQUIRED")
        allowed = not reasons
        decision = self._decision(
            reasons=reasons,
            action=action,
            action_decision_ref=action_decision_ref,
            request=request,
            plan=plan,
            sandbox_profile=sandbox_profile,
            lifecycle_profile=lifecycle_profile,
            run_policy_state_ref=run_policy_state_ref,
            policy_state=policy_state,
            phase_ref=recipe_ref,
            required_context_refs=required_context_refs,
            meta=meta,
        )
        return SandboxBoundaryOutcome(
            decision=decision,
            approved_spec=spec if allowed else None,
            approved_recipe_ref=recipe_ref if allowed else None,
        )

    def _initial_checks(
        self,
        *,
        spec: SandboxRunSpec,
        action: ActionRequest,
        action_decision_ref: StoredDataRef,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        sandbox_profile: SandboxProfile,
        lifecycle_profile: DynamicReproductionLifecycleProfile,
        run_policy_state_ref: StoredDataRef,
        meta: RecordMeta,
    ) -> tuple[list[str], ActionDecision | None, RunPolicyState | None]:
        reasons: list[str] = []
        self._check_scope(
            reasons,
            spec=spec,
            action=action,
            request=request,
            plan=plan,
            sandbox_profile=sandbox_profile,
            lifecycle_profile=lifecycle_profile,
            meta=meta,
        )
        action_decision = self._resolve_record(
            action_decision_ref, ActionDecision, "ACTION_DECISION_UNRESOLVED", reasons
        )
        policy_state = self._resolve_record(
            run_policy_state_ref,
            RunPolicyState,
            "POLICY_AUDIT_UNRESOLVED",
            reasons,
        )
        return reasons, action_decision, policy_state

    def _decision(
        self,
        *,
        reasons: list[str],
        action: ActionRequest,
        action_decision_ref: StoredDataRef,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        sandbox_profile: SandboxProfile,
        lifecycle_profile: DynamicReproductionLifecycleProfile,
        run_policy_state_ref: StoredDataRef,
        policy_state: RunPolicyState | None,
        phase_ref: StoredDataRef,
        required_context_refs: tuple[StoredDataRef, ...],
        meta: RecordMeta,
    ) -> SandboxPolicyDecision:
        if policy_state is None:
            policy_state = self._resolve_record(
                run_policy_state_ref,
                RunPolicyState,
                "POLICY_AUDIT_UNRESOLVED",
                reasons,
            )
        reason_codes = tuple(dict.fromkeys(reasons)) or ("LOCAL_BOUNDARY_OK",)
        allowed = not reasons
        checked_refs = self._checked_refs(
            action,
            action_decision_ref,
            request,
            plan,
            sandbox_profile,
            lifecycle_profile,
            phase_ref,
            run_policy_state_ref,
            required_context_refs,
        )
        observed_status = policy_state.status if policy_state is not None else "FAILED"
        collection_ref = (
            policy_state.collection_result_ref if policy_state is not None else None
        )
        policy_ref = (
            policy_state.policy_record_ref if policy_state is not None else None
        )
        return SandboxPolicyDecision(
            meta=meta,
            request_ref=self._stored_reference(request),
            action_decision_ref=action_decision_ref,
            sandbox_profile_ref=self._stored_reference(sandbox_profile),
            resource_profile_ref=self._stored_reference(lifecycle_profile),
            run_policy_state_ref=run_policy_state_ref,
            policy_collection_result_ref=collection_ref,
            policy_record_ref=policy_ref,
            execution_scope="LOCAL_ONLY",
            observed_policy_status=observed_status,
            decision="ALLOW" if allowed else "DENY",
            reason_codes=reason_codes,
            checked_boundary_refs=checked_refs,
            decided_at=meta.created_at,
        )

    def _resolve_record[T](
        self,
        ref: StoredDataRef,
        expected: type[T],
        reason: str,
        reasons: list[str],
    ) -> T | None:
        try:
            require_record_ref(ref)
            record = self._resolve(ref)
            if not isinstance(record, expected) or reference(record) != ref:  # type: ignore[arg-type]
                raise ValueError(reason)
            return record
        except (KeyError, LookupError, TypeError, ValueError):
            reasons.append(reason)
            return None

    def _check_scope(
        self,
        reasons: list[str],
        *,
        spec: SandboxRunSpec,
        action: ActionRequest,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        sandbox_profile: SandboxProfile,
        lifecycle_profile: DynamicReproductionLifecycleProfile,
        meta: RecordMeta,
    ) -> None:
        if spec.workspace_root.resolve(strict=False) != self._workspace_root:
            reasons.append("WORKSPACE_ROOT_MISMATCH")
        if (str(meta.workspace_id), str(meta.commit_id)) != (
            self._workspace_id,
            self._commit_id,
        ):
            reasons.append("WORKSPACE_SCOPE_MISMATCH")
        records = (request, plan, sandbox_profile, lifecycle_profile)
        if any(
            (str(record.meta.workspace_id), str(record.meta.commit_id))
            != (self._workspace_id, self._commit_id)
            for record in records
        ):
            reasons.append("WORKSPACE_SCOPE_MISMATCH")
        if not isinstance(action.meta, RecordMeta):
            reasons.append("WORKSPACE_SCOPE_MISMATCH")
            return
        if (
            (str(action.meta.workspace_id), str(action.meta.commit_id))
            != (self._workspace_id, self._commit_id)
            or action.meta.hypothesis_id != meta.hypothesis_id
            or plan.meta.hypothesis_id != meta.hypothesis_id
            or request.meta.hypothesis_id != meta.hypothesis_id
            or action.meta.attempt_id != meta.attempt_id
            or plan.meta.attempt_id != meta.attempt_id
        ):
            reasons.append("ATTEMPT_SCOPE_MISMATCH")

    def _check_action_closure(
        self,
        reasons: list[str],
        *,
        spec: SandboxRunSpec,
        action: ActionRequest,
        action_decision: ActionDecision | None,
        action_decision_ref: StoredDataRef,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        sandbox_profile: SandboxProfile,
        lifecycle_profile: DynamicReproductionLifecycleProfile,
        phase_ref: StoredDataRef,
        image_digest: str | None,
        run_policy_state_ref: StoredDataRef,
        required_context_refs: tuple[StoredDataRef, ...],
    ) -> None:
        request_ref = self._stored_reference(request)
        plan_ref = self._stored_reference(plan)
        profile_ref = self._stored_reference(sandbox_profile)
        lifecycle_ref = self._stored_reference(lifecycle_profile)
        required_input_refs = (
            request_ref,
            plan.environment_requirements_ref,
            plan_ref,
            profile_ref,
            lifecycle_ref,
            phase_ref,
            *required_context_refs,
        )
        if (
            action.action_type != ActionType.RUN_SANDBOX
            or action.requested_by != RequesterRole.REPRODUCTION_SETUP_AUTOMATION
        ):
            reasons.append("ACTION_AUTHORITY_MISMATCH")
        if (
            action.dynamic_request_ref != request_ref
            or action.reproduction_plan_ref != plan_ref
            or action.sandbox_profile_ref != profile_ref
            or action.resource_profile_ref != lifecycle_ref
            or action.run_policy_state_ref != run_policy_state_ref
            or len(tuple(dict.fromkeys(required_input_refs)))
            != len(required_input_refs)
            or any(action.input_refs.count(ref) != 1 for ref in required_input_refs)
        ):
            reasons.append("STALE_RESULT")
        if (
            plan.request_ref != request_ref
            or plan.purpose != request.purpose
            or plan.hypothesis_ref != request.hypothesis_ref
            or plan.sandbox_profile_ref != profile_ref
            or request.sandbox_profile_ref != profile_ref
        ):
            reasons.append("STALE_RESULT")
        if lifecycle_profile.status != "ACTIVE":
            reasons.append("LIFECYCLE_PROFILE_INACTIVE")
        if action_decision is None:
            return
        action_ref = self._stored_reference(action)
        if (
            action_decision.action_ref != action_ref
            or action_decision.decision != Decision.ALLOW
            or action_decision.use_status != UseStatus.USED
            or action_decision_ref != self._stored_reference(action_decision)
        ):
            reasons.append("ACTION_DECISION_NOT_USED")
        if (
            profile_ref not in action_decision.checked_config_refs
            or lifecycle_ref not in action_decision.checked_config_refs
        ):
            reasons.append("ACTION_CONFIG_NOT_APPROVED")
        if (
            action.image_digest != image_digest
            or spec.image_digest != image_digest
            or tuple(action.network_targets) != tuple(spec.network_targets)
        ):
            reasons.append("ACTION_SPEC_MISMATCH")

    def _check_recipe_source(
        self,
        reasons: list[str],
        spec: SandboxRunSpec,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        source: PreparedRecipeSource,
    ) -> None:
        if source.workspace_root.resolve(strict=False) != spec.workspace_root.resolve(
            strict=False
        ):
            reasons.append("RECIPE_WORKSPACE_MISMATCH")
        if (
            source.request_ref != self._stored_reference(request)
            or source.requirements_ref != plan.environment_requirements_ref
            or source.recipe_source_ref.content_hash != source.source_digest
            or source.recipe_source_ref.workspace_id != request.meta.workspace_id
            or source.recipe_source_ref.commit_id != request.meta.commit_id
            or source.meta.analysis_id != plan.meta.analysis_id
            or source.meta.hypothesis_id != plan.meta.hypothesis_id
            or source.meta.attempt_id != plan.meta.attempt_id
        ):
            reasons.append("RECIPE_SOURCE_BINDING_INVALID")

    def _check_recipe(
        self,
        reasons: list[str],
        recipe: EnvironmentRecipe,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        meta: RecordMeta,
    ) -> None:
        if (
            recipe.request_ref != self._stored_reference(request)
            or recipe.environment_requirements_ref != plan.environment_requirements_ref
            or recipe.built_image_digest == ""
            or recipe.meta.analysis_id != meta.analysis_id
            or recipe.meta.workspace_id != meta.workspace_id
            or recipe.meta.commit_id != meta.commit_id
            or recipe.meta.hypothesis_id != meta.hypothesis_id
            or recipe.meta.attempt_id != meta.attempt_id
        ):
            reasons.append("BUILT_RECIPE_BINDING_INVALID")

    def _check_boundary(
        self,
        reasons: list[str],
        spec: SandboxRunSpec,
        action: ActionRequest,
        profile: SandboxProfile,
    ) -> None:
        self._check_mounts(reasons, spec)
        self._check_isolation(reasons, spec)
        self._check_network(reasons, spec, profile)
        self._check_secrets(reasons, spec)
        self._check_resources(reasons, spec, action, profile)

    def _check_mounts(self, reasons: list[str], spec: SandboxRunSpec) -> None:
        if not spec.mounts:
            reasons.append("WORKSPACE_MOUNT_REQUIRED")
            return
        for mount in spec.mounts:
            source = mount.source
            source_text = self._normalized_path(source) if source is not None else ""
            target_text = self._normalized_path(mount.target)
            source_is_docker_endpoint = self._is_docker_endpoint(source_text)
            if source_is_docker_endpoint or self._is_docker_endpoint(target_text):
                reasons.append("DOCKER_SOCKET_DENIED")
            if source is None:
                reasons.append("MOUNT_SOURCE_REQUIRED")
                continue
            if source_is_docker_endpoint:
                continue
            try:
                resolved = source.resolve(strict=False)
            except OSError:
                reasons.append("MOUNT_SOURCE_INVALID")
                continue
            if self._is_filesystem_root(resolved):
                reasons.append("HOST_ROOT_MOUNT_DENIED")
            if not self._inside(resolved, self._workspace_root):
                reasons.append("WORKSPACE_MOUNT_DENIED")
            if not source.exists() or not source.is_dir():
                reasons.append("MOUNT_SOURCE_INVALID")
            if not mount.read_only:
                reasons.append("WRITE_MOUNT_DENIED")
            if (
                not mount.target.is_absolute()
                or mount.target == PurePosixPath("/")
                or ".." in mount.target.parts
            ):
                reasons.append("MOUNT_TARGET_INVALID")

    @staticmethod
    def _check_isolation(reasons: list[str], spec: SandboxRunSpec) -> None:
        if not _NUMERIC_USER.fullmatch(spec.user):
            reasons.append("NON_ROOT_USER_REQUIRED")
        if spec.privileged:
            reasons.append("PRIVILEGED_DENIED")
        if spec.pid_mode is not None or spec.ipc_mode is not None:
            reasons.append("HOST_NAMESPACE_DENIED")
        if spec.capabilities:
            reasons.append("CAPABILITY_ADD_DENIED")

    def _check_network(
        self,
        reasons: list[str],
        spec: SandboxRunSpec,
        profile: SandboxProfile,
    ) -> None:
        if (
            spec.network_mode != "DEFAULT_DENY"
            or spec.network_mode != profile.network_mode
        ):
            reasons.append("HOST_NAMESPACE_DENIED")
        for target in spec.network_targets:
            if target in self._isolated_network_targets or self._is_loopback(target):
                continue
            if "://" in target:
                reasons.append("LIVE_ENDPOINT_DENIED")
            else:
                reasons.append("EGRESS_DENIED")

    @staticmethod
    def _check_secrets(reasons: list[str], spec: SandboxRunSpec) -> None:
        if any(not isinstance(ref, StoredDataRef) for ref in spec.secret_refs):
            reasons.append("RAW_SECRET_DENIED")
        if any(
            isinstance(ref, StoredDataRef) and ref.data_kind != "secret_handle"
            for ref in spec.secret_refs
        ):
            reasons.append("RAW_SECRET_DENIED")
        if any(isinstance(ref, StoredDataRef) for ref in spec.secret_refs):
            reasons.append("SANDBOX_SECRET_DENIED")

    @staticmethod
    def _check_resources(
        reasons: list[str],
        spec: SandboxRunSpec,
        action: ActionRequest,
        profile: SandboxProfile,
    ) -> None:
        requested = {
            "cpu_limit_millicores": spec.cpu_limit_millicores,
            "memory_limit_bytes": spec.memory_limit_bytes,
            "disk_limit_bytes": spec.disk_limit_bytes,
            "pid_limit": spec.pid_limit,
            "requested_execution_ms": spec.requested_execution_ms,
        }
        ceilings = {
            "cpu_limit_millicores": profile.cpu_limit_millicores,
            "memory_limit_bytes": profile.memory_limit_bytes,
            "disk_limit_bytes": profile.disk_limit_bytes,
            "pid_limit": profile.pid_limit,
            "requested_execution_ms": profile.max_requested_execution_ms,
        }
        if any(value <= 0 for value in requested.values()):
            reasons.append("RESOURCE_LIMIT_INVALID")
        if any(requested[name] > ceilings[name] for name in requested):
            reasons.append("RESOURCE_LIMIT_EXCEEDED")
        if action.resource_limits is None:
            reasons.append("RESOURCE_LIMIT_UNSPECIFIED")
        elif dict(action.resource_limits) != requested:
            reasons.append("ACTION_SPEC_MISMATCH")

    @staticmethod
    def _stored_reference(record: object) -> StoredDataRef:
        ref = reference(record)  # type: ignore[arg-type]
        if not isinstance(ref, StoredDataRef):
            raise ValueError("CODE_SCOPED_REFERENCE_REQUIRED")
        return ref

    @staticmethod
    def _normalized_path(path: Path | PurePosixPath | None) -> str:
        if path is None:
            return ""
        return str(path).replace("\\", "/").lower()

    @staticmethod
    def _is_docker_endpoint(path: str) -> bool:
        collapsed = re.sub(r"/+", "/", path)
        endpoints = tuple(re.sub(r"/+", "/", value) for value in _DOCKER_ENDPOINTS)
        return any(collapsed.endswith(endpoint) for endpoint in endpoints)

    @staticmethod
    def _is_filesystem_root(path: Path) -> bool:
        anchor = path.anchor
        return bool(anchor) and path == Path(anchor).resolve(strict=False)

    @staticmethod
    def _inside(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
        except ValueError:
            return False
        return True

    @staticmethod
    def _is_loopback(target: str) -> bool:
        parsed = urlsplit(target if "://" in target else f"//{target}")
        host = parsed.hostname
        if host is None:
            return False
        if host.lower() == "localhost":
            return True
        try:
            return ip_address(host).is_loopback
        except ValueError:
            return False

    def _checked_refs(
        self,
        action: ActionRequest,
        action_decision_ref: StoredDataRef,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        sandbox_profile: SandboxProfile,
        lifecycle_profile: DynamicReproductionLifecycleProfile,
        phase_ref: StoredDataRef,
        run_policy_state_ref: StoredDataRef,
        required_context_refs: tuple[StoredDataRef, ...],
    ) -> tuple[StoredDataRef, ...]:
        refs = (
            self._stored_reference(action),
            action_decision_ref,
            self._stored_reference(request),
            self._stored_reference(plan),
            self._stored_reference(sandbox_profile),
            self._stored_reference(lifecycle_profile),
            plan.environment_requirements_ref,
            phase_ref,
            run_policy_state_ref,
            *required_context_refs,
        )
        return tuple(dict.fromkeys(refs))
