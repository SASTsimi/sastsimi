"""Exact ownership registry and cleanup without Docker-wide discovery."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast
from uuid import uuid4

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import (
    CleanupResult,
    DynamicReproductionRequest,
    SandboxEnvironment,
)
from sastsimi.contracts.dynamic_resource import (
    owned_container_resource_ref,
    owned_image_resource_ref,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference

from .docker_adapter import DockerContainerState, DockerImageState
from .recipe_store import fresh_record_meta


@dataclass(frozen=True, slots=True)
class OwnedResource:
    ref: StoredDataRef
    resource_id: str
    labels: Mapping[str, str]
    resource_kind: Literal["CONTAINER", "IMAGE"] = "CONTAINER"
    preservation_reason: Literal["REUSABLE_BASELINE"] | None = None
    reconcile_required: bool = False


@dataclass(frozen=True, slots=True)
class ContainerOwnershipIntent:
    container_name: str
    labels: Mapping[str, str]


class CleanupDockerPort(Protocol):
    async def inspect(self, container_id: str) -> DockerContainerState: ...
    async def remove(self, resource_ids: tuple[str, ...]) -> None: ...
    async def inspect_owned_image(self, image_digest: str) -> DockerImageState: ...
    async def remove_images(self, image_digests: tuple[str, ...]) -> None: ...


class OwnedResourceRegistry:
    """Durably tracks exact owned resources and pre-create ownership intents."""

    def __init__(self, *, journal_path: Path | None = None) -> None:
        self._resources: dict[bytes, OwnedResource] = {}
        self._intents: dict[str, ContainerOwnershipIntent] = {}
        self._journal_path = journal_path
        self._load()

    def reserve_container(
        self,
        *,
        container_name: str,
        labels: Mapping[str, str],
    ) -> None:
        if (
            not container_name
            or container_name in self._intents
            or any(
                item.resource_id == container_name for item in self._resources.values()
            )
        ):
            raise ValueError("DUPLICATE_SANDBOX_RESOURCE")
        self._intents[container_name] = ContainerOwnershipIntent(
            container_name,
            dict(labels),
        )
        self._persist()

    def register_reserved_container(
        self,
        *,
        container_name: str,
        container_id: str,
        meta: RecordMeta,
        reconcile_required: bool = False,
    ) -> StoredDataRef:
        intent = self._intents.get(container_name)
        if intent is None:
            raise ValueError("SANDBOX_OWNERSHIP_INTENT_REQUIRED")
        ref = self.register_container(
            container_id=container_id,
            labels=intent.labels,
            meta=meta,
            reconcile_required=reconcile_required,
            persist=False,
        )
        del self._intents[container_name]
        self._persist()
        return ref

    def register_container(
        self,
        *,
        container_id: str,
        labels: Mapping[str, str],
        meta: RecordMeta,
        reconcile_required: bool = False,
        persist: bool = True,
    ) -> StoredDataRef:
        ref = owned_container_resource_ref(
            container_id=container_id,
            meta=meta,
        )
        key = canonical_bytes(ref)
        if key in self._resources:
            raise ValueError("DUPLICATE_SANDBOX_RESOURCE")
        self._resources[key] = OwnedResource(
            ref=ref,
            resource_id=container_id,
            labels=dict(labels),
            resource_kind="CONTAINER",
            reconcile_required=reconcile_required,
        )
        if persist:
            self._persist()
        return ref

    def register_image(
        self,
        *,
        image_digest: str,
        labels: Mapping[str, str],
        meta: RecordMeta,
        preservation_reason: Literal["REUSABLE_BASELINE"] | None,
    ) -> StoredDataRef:
        ref = owned_image_resource_ref(image_digest=image_digest, meta=meta)
        key = canonical_bytes(ref)
        if key in self._resources:
            raise ValueError("DUPLICATE_SANDBOX_RESOURCE")
        self._resources[key] = OwnedResource(
            ref=ref,
            resource_id=image_digest,
            labels=dict(labels),
            resource_kind="IMAGE",
            preservation_reason=preservation_reason,
        )
        self._persist()
        return ref

    def forget(self, ref: StoredDataRef) -> None:
        self._resources.pop(canonical_bytes(ref), None)
        self._persist()

    def pending_resource_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                (
                    *(item.container_name for item in self._intents.values()),
                    *(item.resource_id for item in self._resources.values()),
                )
            )
        )

    def exact(self, ref: StoredDataRef) -> OwnedResource | None:
        return self._resources.get(canonical_bytes(ref))

    def preserved_image_ref(self, image_digest: str) -> StoredDataRef | None:
        matches = tuple(
            item.ref
            for item in self._resources.values()
            if item.resource_kind == "IMAGE"
            and item.resource_id == image_digest
            and item.preservation_reason == "REUSABLE_BASELINE"
        )
        if len(matches) > 1:
            raise ValueError("AMBIGUOUS_BASELINE_IMAGE_OWNERSHIP")
        return matches[0] if matches else None

    async def reconcile_intent(
        self,
        *,
        docker: CleanupDockerPort,
        container_name: str,
    ) -> None:
        intent = self._intents.get(container_name)
        if intent is None:
            raise ValueError("SANDBOX_OWNERSHIP_INTENT_REQUIRED")
        state = await docker.inspect(container_name)
        if any(state.labels.get(key) != value for key, value in intent.labels.items()):
            raise ValueError("CLEANUP_OWNERSHIP_MISMATCH")
        await docker.remove((state.container_id,))
        del self._intents[container_name]
        self._persist()

    async def reconcile_pending(
        self,
        *,
        docker: CleanupDockerPort,
    ) -> tuple[str, ...]:
        """Remove exact journaled leftovers; return entries still needing attention."""

        failures: list[str] = []
        for name in tuple(self._intents):
            try:
                await self.reconcile_intent(docker=docker, container_name=name)
            except (OSError, RuntimeError, ValueError):
                failures.append(name)
        for key, resource in tuple(self._resources.items()):
            if resource.preservation_reason is not None:
                continue
            if not resource.reconcile_required:
                continue
            try:
                if resource.resource_kind == "CONTAINER":
                    state = await docker.inspect(resource.resource_id)
                    if any(
                        state.labels.get(name) != value
                        for name, value in resource.labels.items()
                    ):
                        raise ValueError("CLEANUP_OWNERSHIP_MISMATCH")
                    await docker.remove((state.container_id,))
                else:
                    image_state = await docker.inspect_owned_image(resource.resource_id)
                    if any(
                        image_state.labels.get(name) != value
                        for name, value in resource.labels.items()
                    ):
                        raise ValueError("CLEANUP_OWNERSHIP_MISMATCH")
                    await docker.remove_images((resource.resource_id,))
            except (OSError, RuntimeError, ValueError):
                failures.append(resource.resource_id)
            else:
                del self._resources[key]
                self._persist()
        return tuple(failures)

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
        containers = [item for item in owned if item.resource_kind == "CONTAINER"]
        images = [item for item in owned if item.resource_kind == "IMAGE"]
        environment_ids = {item.container_instance_id for item in environments}
        if {item.resource_id for item in containers} != environment_ids:
            failure = "CLEANUP_RESOURCE_COVERAGE_MISMATCH"

        if failure is None:
            try:
                states = [await docker.inspect(item.resource_id) for item in containers]
                if any(
                    any(
                        state.labels.get(key) != value
                        for key, value in item.labels.items()
                    )
                    for item, state in zip(containers, states, strict=True)
                ):
                    failure = "CLEANUP_OWNERSHIP_MISMATCH"
                else:
                    await docker.remove(tuple(state.container_id for state in states))
                    image_states = [
                        (item, await docker.inspect_owned_image(item.resource_id))
                        for item in images
                    ]
                    if any(
                        any(
                            state.labels.get(key) != value
                            for key, value in item.labels.items()
                        )
                        for item, state in image_states
                    ):
                        raise ValueError("CLEANUP_OWNERSHIP_MISMATCH")
                    removable_images = tuple(
                        item.resource_id
                        for item in images
                        if item.preservation_reason is None
                    )
                    await docker.remove_images(removable_images)
                    for item in (*containers, *images):
                        if item.preservation_reason is not None:
                            continue
                        self._resources.pop(canonical_bytes(item.ref), None)
                    self._persist()
            except (asyncio.CancelledError, OSError, RuntimeError, ValueError):
                failure = "OWNED_RESOURCE_CLEANUP_FAILED"

        if failure is not None and owned:
            for item in owned:
                self._resources[canonical_bytes(item.ref)] = OwnedResource(
                    ref=item.ref,
                    resource_id=item.resource_id,
                    labels=item.labels,
                    resource_kind=item.resource_kind,
                    preservation_reason=item.preservation_reason,
                    reconcile_required=True,
                )
            self._persist()

        return CleanupResult(
            meta=fresh_record_meta(meta, "cleanup_result"),
            request_ref=request_ref,
            environment_refs=tuple(environment_refs),
            resource_refs=resource_refs,
            status="FAILED" if failure else "SUCCEEDED",
            failure_reason=failure,
            finished_at=meta.created_at,
        )

    def _load(self) -> None:
        path = self._journal_path
        if path is None or not path.exists():
            return
        try:
            value = json.loads(path.read_bytes())
            if not isinstance(value, dict):
                raise TypeError
            intents = value.get("intents")
            resources = value.get("resources")
            if not isinstance(intents, list) or not isinstance(resources, list):
                raise TypeError
            for item in intents:
                if not isinstance(item, dict):
                    raise TypeError
                name = item["container_name"]
                labels = item["labels"]
                if (
                    not isinstance(name, str)
                    or not isinstance(labels, dict)
                    or any(
                        not isinstance(key, str) or not isinstance(label, str)
                        for key, label in labels.items()
                    )
                ):
                    raise TypeError
                self._intents[name] = ContainerOwnershipIntent(name, labels)
            for item in resources:
                if not isinstance(item, dict):
                    raise TypeError
                ref = StoredDataRef.model_validate(item["ref"])
                resource_id = item["resource_id"]
                labels = item["labels"]
                resource_kind = item.get("resource_kind", "CONTAINER")
                preservation_reason = item.get("preservation_reason")
                reconcile_required = item.get("reconcile_required", False)
                if (
                    not isinstance(resource_id, str)
                    or not isinstance(labels, dict)
                    or any(
                        not isinstance(key, str) or not isinstance(label, str)
                        for key, label in labels.items()
                    )
                    or resource_kind not in {"CONTAINER", "IMAGE"}
                    or preservation_reason not in {None, "REUSABLE_BASELINE"}
                    or not isinstance(reconcile_required, bool)
                    or (
                        resource_kind == "CONTAINER" and preservation_reason is not None
                    )
                ):
                    raise TypeError
                self._resources[canonical_bytes(ref)] = OwnedResource(
                    ref=ref,
                    resource_id=resource_id,
                    labels=labels,
                    resource_kind=resource_kind,
                    preservation_reason=cast(
                        Literal["REUSABLE_BASELINE"] | None,
                        preservation_reason,
                    ),
                    reconcile_required=preservation_reason is None,
                )
        except (
            KeyError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise ValueError("OWNED_RESOURCE_JOURNAL_INVALID") from error

    def _persist(self) -> None:
        path = self._journal_path
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        value = {
            "intents": [
                {
                    "container_name": item.container_name,
                    "labels": dict(item.labels),
                }
                for item in sorted(
                    self._intents.values(), key=lambda item: item.container_name
                )
            ],
            "resources": [
                {
                    "ref": item.ref.model_dump(mode="json"),
                    "resource_id": item.resource_id,
                    "labels": dict(item.labels),
                    "resource_kind": item.resource_kind,
                    "preservation_reason": item.preservation_reason,
                    "reconcile_required": item.reconcile_required,
                }
                for item in sorted(
                    self._resources.values(), key=lambda item: item.resource_id
                )
            ],
        }
        payload = canonical_bytes(value)
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    raise OSError("OWNED_RESOURCE_JOURNAL_WRITE_FAILED")
                written += count
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
