"""Exact ownership registry and cleanup without Docker-wide discovery."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import (
    CleanupResult,
    DynamicReproductionRequest,
    SandboxEnvironment,
)
from sastsimi.contracts.ids import StoredDataId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference

from .docker_adapter import DockerContainerState
from .recipe_store import fresh_record_meta


@dataclass(frozen=True, slots=True)
class OwnedResource:
    ref: StoredDataRef
    resource_id: str
    labels: Mapping[str, str]


class CleanupDockerPort(Protocol):
    async def inspect(self, container_id: str) -> DockerContainerState: ...
    async def remove(self, resource_ids: tuple[str, ...]) -> None: ...


class OwnedResourceRegistry:
    """Tracks only resources created through this exact setup instance."""

    def __init__(self) -> None:
        self._resources: dict[bytes, OwnedResource] = {}

    def register_container(
        self,
        *,
        container_id: str,
        labels: Mapping[str, str],
        meta: RecordMeta,
    ) -> StoredDataRef:
        payload = {
            "resource_type": "container",
            "resource_id": container_id,
            "labels": dict(sorted(labels.items())),
        }
        digest = content_hash(payload)
        ref = StoredDataRef(
            stored_data_id=StoredDataId(f"sandbox-resource-{digest}"),
            data_kind="sandbox_resource",
            content_hash=digest,
            workspace_id=meta.workspace_id,
            commit_id=meta.commit_id,
            record_id=None,
        )
        key = canonical_bytes(ref)
        if key in self._resources:
            raise ValueError("DUPLICATE_SANDBOX_RESOURCE")
        self._resources[key] = OwnedResource(ref, container_id, dict(labels))
        return ref

    def exact(self, ref: StoredDataRef) -> OwnedResource | None:
        return self._resources.get(canonical_bytes(ref))

    async def cleanup(
        self,
        *,
        docker: CleanupDockerPort,
        request: DynamicReproductionRequest,
        environments: tuple[SandboxEnvironment, ...],
        resource_refs: tuple[StoredDataRef, ...],
        meta: RecordMeta,
    ) -> CleanupResult:
        failure: str | None = None
        request_ref = reference(request)
        if not isinstance(request_ref, StoredDataRef):
            raise ValueError("CODE_SCOPED_REFERENCE_REQUIRED")
        environment_refs: list[StoredDataRef] = []
        owned: list[OwnedResource] = []
        if len(set(canonical_bytes(ref) for ref in resource_refs)) != len(
            resource_refs
        ):
            failure = "DUPLICATE_CLEANUP_RESOURCE"
        for environment in environments:
            environment_ref = reference(environment)
            if not isinstance(environment_ref, StoredDataRef):
                failure = "CLEANUP_ENVIRONMENT_UNRESOLVED"
                continue
            environment_refs.append(environment_ref)
            if (
                environment.request_ref != request_ref
                or environment.meta.hypothesis_id != meta.hypothesis_id
            ):
                failure = "CLEANUP_SCOPE_MISMATCH"
        for ref in resource_refs:
            resource = self.exact(ref)
            if resource is None:
                failure = "CLEANUP_OWNERSHIP_MISMATCH"
            else:
                owned.append(resource)
        environment_ids = {item.container_instance_id for item in environments}
        if {item.resource_id for item in owned} != environment_ids:
            failure = "CLEANUP_RESOURCE_COVERAGE_MISMATCH"

        if failure is None:
            try:
                states = [await docker.inspect(item.resource_id) for item in owned]
                if any(
                    state.container_id != item.resource_id
                    or dict(state.labels) != dict(item.labels)
                    for item, state in zip(owned, states, strict=True)
                ):
                    failure = "CLEANUP_OWNERSHIP_MISMATCH"
                else:
                    await docker.remove(tuple(item.resource_id for item in owned))
            except (OSError, RuntimeError, ValueError):
                failure = "OWNED_RESOURCE_CLEANUP_FAILED"

        return CleanupResult(
            meta=fresh_record_meta(meta, "cleanup_result"),
            request_ref=request_ref,
            environment_refs=tuple(environment_refs),
            resource_refs=resource_refs,
            status="FAILED" if failure else "SUCCEEDED",
            failure_reason=failure,
            finished_at=meta.created_at,
        )
