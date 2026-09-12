"""Exact ownership registry and cleanup without Docker-wide discovery."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import (
    CleanupResult,
    DynamicReproductionRequest,
    SandboxEnvironment,
)
from sastsimi.contracts.dynamic_resource import owned_container_resource_ref
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference

from .docker_adapter import DockerContainerState
from .recipe_store import fresh_record_meta


@dataclass(frozen=True, slots=True)
class OwnedResource:
    ref: StoredDataRef
    resource_id: str
    labels: Mapping[str, str]
    reconcile_required: bool = False


@dataclass(frozen=True, slots=True)
class ContainerOwnershipIntent:
    container_name: str
    labels: Mapping[str, str]


class CleanupDockerPort(Protocol):
    async def inspect(self, container_id: str) -> DockerContainerState: ...
    async def remove(self, resource_ids: tuple[str, ...]) -> None: ...


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
            ref,
            container_id,
            dict(labels),
            reconcile_required,
        )
        if persist:
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
            if not resource.reconcile_required:
                continue
            try:
                state = await docker.inspect(resource.resource_id)
                if any(
                    state.labels.get(name) != value
                    for name, value in resource.labels.items()
                ):
                    raise ValueError("CLEANUP_OWNERSHIP_MISMATCH")
                await docker.remove((state.container_id,))
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
        environment_ids = {item.container_instance_id for item in environments}
        if {item.resource_id for item in owned} != environment_ids:
            failure = "CLEANUP_RESOURCE_COVERAGE_MISMATCH"

        if failure is None:
            try:
                states = [await docker.inspect(item.resource_id) for item in owned]
                if any(
                    any(
                        state.labels.get(key) != value
                        for key, value in item.labels.items()
                    )
                    for item, state in zip(owned, states, strict=True)
                ):
                    failure = "CLEANUP_OWNERSHIP_MISMATCH"
                else:
                    await docker.remove(tuple(state.container_id for state in states))
                    for item in owned:
                        self._resources.pop(canonical_bytes(item.ref), None)
                    self._persist()
            except (OSError, RuntimeError, ValueError):
                failure = "OWNED_RESOURCE_CLEANUP_FAILED"

        if failure is not None and owned:
            for item in owned:
                self._resources[canonical_bytes(item.ref)] = OwnedResource(
                    item.ref,
                    item.resource_id,
                    item.labels,
                    True,
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
                if (
                    not isinstance(resource_id, str)
                    or not isinstance(labels, dict)
                    or any(
                        not isinstance(key, str) or not isinstance(label, str)
                        for key, label in labels.items()
                    )
                ):
                    raise TypeError
                self._resources[canonical_bytes(ref)] = OwnedResource(
                    ref,
                    resource_id,
                    labels,
                    True,
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
