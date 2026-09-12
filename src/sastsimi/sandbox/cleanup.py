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

from .docker_adapter import (
    DockerAdapter,
    DockerContainerPresence,
    DockerContainerState,
    DockerImageState,
    DockerImageTagPresence,
)
from .recipe_store import fresh_record_meta

_CLEANUP_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class OwnedResource:
    ref: StoredDataRef
    resource_id: str
    labels: Mapping[str, str]
    resource_kind: Literal["CONTAINER", "IMAGE"] = "CONTAINER"
    resource_tag: str | None = None
    lookup_by_name: bool = False
    preservation_reason: Literal["REUSABLE_BASELINE"] | None = None
    reconcile_required: bool = False


@dataclass(frozen=True, slots=True)
class ContainerOwnershipIntent:
    container_name: str
    labels: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class ImageOwnershipIntent:
    image_tag: str
    labels: Mapping[str, str]


class CleanupDockerPort(Protocol):
    async def inspect(self, container_id: str) -> DockerContainerState: ...
    async def inspect_container_presence(
        self, container_id: str, *, by_name: bool = False
    ) -> DockerContainerPresence: ...
    async def remove(self, resource_ids: tuple[str, ...]) -> None: ...
    async def inspect_owned_image(self, image_digest: str) -> DockerImageState: ...
    async def inspect_image_tag(self, image_tag: str) -> DockerImageTagPresence: ...
    async def remove_images(self, image_digests: tuple[str, ...]) -> None: ...
    async def remove_image_tags(self, image_tags: tuple[str, ...]) -> None: ...


class OwnedResourceRegistry:
    """Durably tracks exact owned resources and pre-create ownership intents."""

    def __init__(self, *, journal_path: Path | None = None) -> None:
        self._resources: dict[bytes, OwnedResource] = {}
        self._intents: dict[str, ContainerOwnershipIntent] = {}
        self._image_intents: dict[str, ImageOwnershipIntent] = {}
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
        lookup_by_name: bool = False,
    ) -> StoredDataRef:
        intent = self._intents.get(container_name)
        if intent is None:
            raise ValueError("SANDBOX_OWNERSHIP_INTENT_REQUIRED")
        ref = self.register_container(
            container_id=container_id,
            labels=intent.labels,
            meta=meta,
            reconcile_required=reconcile_required,
            lookup_by_name=lookup_by_name,
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
        lookup_by_name: bool = False,
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
            lookup_by_name=lookup_by_name,
            reconcile_required=reconcile_required,
        )
        if persist:
            self._persist()
        return ref

    def register_image(
        self,
        *,
        image_digest: str,
        image_tag: str,
        labels: Mapping[str, str],
        meta: RecordMeta,
        preservation_reason: Literal["REUSABLE_BASELINE"] | None,
        persist: bool = True,
    ) -> StoredDataRef:
        if DockerAdapter.runtime_image_tag(labels) != image_tag:
            raise ValueError("SANDBOX_IMAGE_TAG_MISMATCH")
        ref = owned_image_resource_ref(image_digest=image_digest, meta=meta)
        key = canonical_bytes(ref)
        if key in self._resources:
            raise ValueError("DUPLICATE_SANDBOX_RESOURCE")
        self._resources[key] = OwnedResource(
            ref=ref,
            resource_id=image_digest,
            labels=dict(labels),
            resource_kind="IMAGE",
            resource_tag=image_tag,
            preservation_reason=preservation_reason,
        )
        if persist:
            self._persist()
        return ref

    def reserve_image(
        self,
        *,
        image_tag: str,
        labels: Mapping[str, str],
    ) -> None:
        if image_tag in self._image_intents or any(
            item.resource_tag == image_tag for item in self._resources.values()
        ):
            raise ValueError("DUPLICATE_SANDBOX_RESOURCE")
        if DockerAdapter.runtime_image_tag(labels) != image_tag:
            raise ValueError("SANDBOX_IMAGE_TAG_MISMATCH")
        self._image_intents[image_tag] = ImageOwnershipIntent(image_tag, dict(labels))
        self._persist()

    def register_reserved_image(
        self,
        *,
        image_tag: str,
        image_digest: str,
        meta: RecordMeta,
        preservation_reason: Literal["REUSABLE_BASELINE"] | None,
    ) -> StoredDataRef:
        intent = self._image_intents.get(image_tag)
        if intent is None:
            raise ValueError("SANDBOX_OWNERSHIP_INTENT_REQUIRED")
        ref = self.register_image(
            image_digest=image_digest,
            image_tag=image_tag,
            labels=intent.labels,
            meta=meta,
            preservation_reason=preservation_reason,
            persist=False,
        )
        del self._image_intents[image_tag]
        self._persist()
        return ref

    def forget_image_intent(self, image_tag: str) -> None:
        if self._image_intents.pop(image_tag, None) is not None:
            self._persist()

    def forget(self, ref: StoredDataRef) -> None:
        self._resources.pop(canonical_bytes(ref), None)
        self._persist()

    def pending_resource_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                (
                    *(item.container_name for item in self._intents.values()),
                    *(item.image_tag for item in self._image_intents.values()),
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
    ) -> Literal["REMOVED", "ABSENT", "UNKNOWN"]:
        intent = self._intents.get(container_name)
        if intent is None:
            raise ValueError("SANDBOX_OWNERSHIP_INTENT_REQUIRED")
        presence = await docker.inspect_container_presence(container_name, by_name=True)
        if presence.status == "ABSENT":
            del self._intents[container_name]
            self._persist()
            return "ABSENT"
        if presence.status != "PRESENT" or presence.state is None:
            return "UNKNOWN"
        state = presence.state
        if any(state.labels.get(key) != value for key, value in intent.labels.items()):
            return "UNKNOWN"
        try:
            await docker.remove((state.container_id,))
        except (OSError, RuntimeError, ValueError):
            return "UNKNOWN"
        del self._intents[container_name]
        self._persist()
        return "REMOVED"

    async def reconcile_image_intent(
        self,
        *,
        docker: CleanupDockerPort,
        image_tag: str,
    ) -> Literal["REMOVED", "ABSENT", "UNKNOWN"]:
        intent = self._image_intents.get(image_tag)
        if intent is None:
            raise ValueError("SANDBOX_OWNERSHIP_INTENT_REQUIRED")
        presence = await docker.inspect_image_tag(image_tag)
        if presence.status == "ABSENT":
            del self._image_intents[image_tag]
            self._persist()
            return "ABSENT"
        if presence.status != "PRESENT" or presence.state is None:
            return "UNKNOWN"
        state = presence.state
        if dict(state.labels) != dict(intent.labels):
            return "UNKNOWN"
        try:
            await docker.remove_image_tags((image_tag,))
        except (OSError, RuntimeError, ValueError):
            return "UNKNOWN"
        del self._image_intents[image_tag]
        self._persist()
        return "REMOVED"

    async def prepare_image_intent(
        self,
        *,
        docker: CleanupDockerPort,
        image_tag: str,
    ) -> Literal["READY", "UNKNOWN"]:
        intent = self._image_intents.get(image_tag)
        if intent is None:
            raise ValueError("SANDBOX_OWNERSHIP_INTENT_REQUIRED")
        presence = await docker.inspect_image_tag(image_tag)
        if presence.status == "ABSENT":
            return "READY"
        if presence.status != "PRESENT" or presence.state is None:
            return "UNKNOWN"
        if dict(presence.state.labels) != dict(intent.labels):
            return "UNKNOWN"
        try:
            await docker.remove_image_tags((image_tag,))
        except (OSError, RuntimeError, ValueError):
            return "UNKNOWN"
        return "READY"

    async def reconcile_pending(
        self,
        *,
        docker: CleanupDockerPort,
    ) -> tuple[str, ...]:
        """Remove exact journaled leftovers; return entries still needing attention."""

        failures: list[str] = []
        for name in tuple(self._intents):
            try:
                status = await self.reconcile_intent(
                    docker=docker, container_name=name
                )
            except (OSError, RuntimeError, ValueError):
                failures.append(name)
            else:
                if status == "UNKNOWN":
                    failures.append(name)
        for image_tag in tuple(self._image_intents):
            try:
                status = await self.reconcile_image_intent(
                    docker=docker, image_tag=image_tag
                )
            except (OSError, RuntimeError, ValueError):
                failures.append(image_tag)
            else:
                if status == "UNKNOWN":
                    failures.append(image_tag)
        for key, resource in tuple(self._resources.items()):
            if resource.preservation_reason is not None:
                continue
            if not resource.reconcile_required:
                continue
            try:
                if resource.resource_kind == "CONTAINER":
                    container_presence = await docker.inspect_container_presence(
                        resource.resource_id,
                        by_name=resource.lookup_by_name,
                    )
                    if container_presence.status == "ABSENT":
                        del self._resources[key]
                        self._persist()
                        continue
                    if (
                        container_presence.status != "PRESENT"
                        or container_presence.state is None
                    ):
                        raise ValueError("CLEANUP_STATE_UNKNOWN")
                    state = container_presence.state
                    if any(
                        state.labels.get(name) != value
                        for name, value in resource.labels.items()
                    ):
                        raise ValueError("CLEANUP_OWNERSHIP_MISMATCH")
                    await docker.remove((state.container_id,))
                else:
                    if resource.resource_tag is None:
                        raise ValueError("CLEANUP_IMAGE_TAG_REQUIRED")
                    image_presence = await docker.inspect_image_tag(
                        resource.resource_tag
                    )
                    if image_presence.status == "ABSENT":
                        del self._resources[key]
                        self._persist()
                        continue
                    if (
                        image_presence.status != "PRESENT"
                        or image_presence.state is None
                    ):
                        raise ValueError("CLEANUP_STATE_UNKNOWN")
                    if (
                        image_presence.state.image_digest != resource.resource_id
                        or dict(image_presence.state.labels) != dict(resource.labels)
                    ):
                        raise ValueError("CLEANUP_OWNERSHIP_MISMATCH")
                    await docker.remove_image_tags((resource.resource_tag,))
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
                async with asyncio.timeout(_CLEANUP_TIMEOUT_SECONDS):
                    container_ids: list[str] = []
                    for item in containers:
                        container_presence = await docker.inspect_container_presence(
                            item.resource_id,
                            by_name=item.lookup_by_name,
                        )
                        if container_presence.status == "ABSENT":
                            continue
                        if (
                            container_presence.status != "PRESENT"
                            or container_presence.state is None
                        ):
                            raise ValueError("CLEANUP_STATE_UNKNOWN")
                        if any(
                            container_presence.state.labels.get(key) != value
                            for key, value in item.labels.items()
                        ):
                            raise ValueError("CLEANUP_OWNERSHIP_MISMATCH")
                        container_ids.append(container_presence.state.container_id)
                    await docker.remove(tuple(container_ids))

                    removable_tags: list[str] = []
                    for item in images:
                        if item.preservation_reason is not None:
                            continue
                        if item.resource_tag is None:
                            raise ValueError("CLEANUP_IMAGE_TAG_REQUIRED")
                        image_presence = await docker.inspect_image_tag(
                            item.resource_tag
                        )
                        if image_presence.status == "ABSENT":
                            continue
                        if (
                            image_presence.status != "PRESENT"
                            or image_presence.state is None
                        ):
                            raise ValueError("CLEANUP_STATE_UNKNOWN")
                        if (
                            image_presence.state.image_digest != item.resource_id
                            or dict(image_presence.state.labels) != dict(item.labels)
                        ):
                            raise ValueError("CLEANUP_OWNERSHIP_MISMATCH")
                        removable_tags.append(item.resource_tag)
                    await docker.remove_image_tags(tuple(removable_tags))
                    for item in (*containers, *images):
                        if item.preservation_reason is not None:
                            continue
                        self._resources.pop(canonical_bytes(item.ref), None)
                    self._persist()
            except (
                TimeoutError,
                asyncio.CancelledError,
                OSError,
                RuntimeError,
                ValueError,
            ) as error:
                failure = (
                    "CLEANUP_OWNERSHIP_MISMATCH"
                    if str(error) == "CLEANUP_OWNERSHIP_MISMATCH"
                    else "OWNED_RESOURCE_CLEANUP_FAILED"
                )

        if failure is not None and owned:
            for item in owned:
                self._resources[canonical_bytes(item.ref)] = OwnedResource(
                    ref=item.ref,
                    resource_id=item.resource_id,
                    labels=item.labels,
                    resource_kind=item.resource_kind,
                    resource_tag=item.resource_tag,
                    lookup_by_name=item.lookup_by_name,
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
            image_intents = value.get("image_intents", [])
            resources = value.get("resources")
            if (
                not isinstance(intents, list)
                or not isinstance(image_intents, list)
                or not isinstance(resources, list)
            ):
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
            for item in image_intents:
                if not isinstance(item, dict):
                    raise TypeError
                image_tag = item["image_tag"]
                labels = item["labels"]
                if (
                    not isinstance(image_tag, str)
                    or not isinstance(labels, dict)
                    or any(
                        not isinstance(key, str) or not isinstance(label, str)
                        for key, label in labels.items()
                    )
                    or DockerAdapter.runtime_image_tag(labels) != image_tag
                ):
                    raise TypeError
                self._image_intents[image_tag] = ImageOwnershipIntent(
                    image_tag, labels
                )
            for item in resources:
                if not isinstance(item, dict):
                    raise TypeError
                ref = StoredDataRef.model_validate(item["ref"])
                resource_id = item["resource_id"]
                labels = item["labels"]
                resource_kind = item.get("resource_kind", "CONTAINER")
                resource_tag = item.get("resource_tag")
                preservation_reason = item.get("preservation_reason")
                reconcile_required = item.get("reconcile_required", False)
                lookup_by_name = item.get("lookup_by_name", False)
                if (
                    not isinstance(resource_id, str)
                    or not isinstance(labels, dict)
                    or any(
                        not isinstance(key, str) or not isinstance(label, str)
                        for key, label in labels.items()
                    )
                    or resource_kind not in {"CONTAINER", "IMAGE"}
                    or (
                        resource_tag is not None and not isinstance(resource_tag, str)
                    )
                    or preservation_reason not in {None, "REUSABLE_BASELINE"}
                    or not isinstance(reconcile_required, bool)
                    or not isinstance(lookup_by_name, bool)
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
                    resource_tag=(
                        resource_tag
                        if resource_kind == "IMAGE"
                        else None
                    ),
                    lookup_by_name=lookup_by_name,
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
            "image_intents": [
                {
                    "image_tag": item.image_tag,
                    "labels": dict(item.labels),
                }
                for item in sorted(
                    self._image_intents.values(), key=lambda item: item.image_tag
                )
            ],
            "resources": [
                {
                    "ref": item.ref.model_dump(mode="json"),
                    "resource_id": item.resource_id,
                    "labels": dict(item.labels),
                    "resource_kind": item.resource_kind,
                    "resource_tag": item.resource_tag,
                    "lookup_by_name": item.lookup_by_name,
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
