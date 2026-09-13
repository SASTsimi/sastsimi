"""Fail-closed cancellation adapters for exact production dispatch targets."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Protocol

from sastsimi.contracts.llm import LLMCallSpec
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import CancellationResult
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.scheduler import (
    CancellationObservation,
    CancellationResourceObservation,
    CancellationStatus,
    CancellationTarget,
    SandboxCancellationResource,
)
from sastsimi.runtime.cancellation_service import ExactCancellationRouter
from sastsimi.sandbox.cleanup import CleanupDockerPort, OwnedResourceRegistry


class AttemptCancellationPort(Protocol):
    async def cancel(self, attempt_id: str) -> CancellationResult: ...


class SandboxCancellationDockerPort(CleanupDockerPort, Protocol):
    pass


class ProductionStaticCancellation:
    """Cancel only the attempt fixed by the durable cancellation target."""

    def __init__(self, adapter: AttemptCancellationPort) -> None:
        self._adapter = adapter

    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        if target.target_kind != "STATIC":
            raise ValueError("CANCELLATION_TARGET_KIND_MISMATCH")
        result = await self._adapter.cancel(str(target.attempt.attempt_id))
        return _observation(target, result, "STATIC_CANCELLATION_UNRESOLVED")


class ProductionProviderCancellation:
    """Resolve the exact call spec before addressing one exact Provider adapter."""

    def __init__(
        self,
        *,
        records: RecordStore,
        adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter],
    ) -> None:
        self._records = records
        self._adapters = dict(adapters)

    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        if target.target_kind != "PROVIDER" or target.call_spec_ref is None:
            raise ValueError("CANCELLATION_TARGET_KIND_MISMATCH")
        spec = self._records.get_exact(target.call_spec_ref)
        if not isinstance(spec, LLMCallSpec) or reference(spec) != target.call_spec_ref:
            raise ValueError("CANCELLATION_CALL_SPEC_NOT_EXACT")
        try:
            adapter = self._adapters[(spec.provider_profile_ref, spec.model)]
        except KeyError as error:
            raise ValueError("CANCELLATION_PROVIDER_NOT_EXACT") from error
        result = await adapter.cancel(spec.llm_call_id)
        return _observation(target, result, "PROVIDER_CANCELLATION_UNRESOLVED")


class ProductionSandboxCancellation:
    """Observe only the complete immutable exact-attempt resource snapshot."""

    def __init__(
        self,
        *,
        records: RecordStore,
        docker: SandboxCancellationDockerPort,
        resources: OwnedResourceRegistry,
    ) -> None:
        self._records = records
        self._docker = docker
        self._resources = resources

    async def prepare(self, target: CancellationTarget) -> CancellationTarget:
        if target.target_kind != "SANDBOX":
            raise ValueError("CANCELLATION_TARGET_KIND_MISMATCH")
        meta = target.attempt.meta
        if not isinstance(meta, RecordMeta):
            raise ValueError("CANCELLATION_SANDBOX_SCOPE_MISMATCH")
        snapshot = self._resources.snapshot(meta=meta)
        resources = tuple(
            SandboxCancellationResource(
                resource_kind=item.resource_kind,
                resource_id=item.resource_id,
                resource_ref=item.ref,
                resource_tag=item.resource_tag,
                labels=tuple(sorted(item.labels.items())),
                lookup_by_name=item.lookup_by_name,
                preservation_reason=item.preservation_reason,
            )
            for item in snapshot.resources
        ) + tuple(
            SandboxCancellationResource(
                resource_kind="CONTAINER_INTENT",
                resource_id=item.container_name,
                resource_ref=None,
                resource_tag=None,
                labels=tuple(sorted(item.labels.items())),
                lookup_by_name=True,
                preservation_reason=None,
            )
            for item in snapshot.container_intents
        ) + tuple(
            SandboxCancellationResource(
                resource_kind="IMAGE_INTENT",
                resource_id=item.image_tag,
                resource_ref=None,
                resource_tag=item.image_tag,
                labels=tuple(sorted(item.labels.items())),
                lookup_by_name=False,
                preservation_reason=None,
            )
            for item in snapshot.image_intents
        )
        if not resources:
            raise ValueError("CANCELLATION_SANDBOX_RESOURCE_MISSING")
        return replace(
            target,
            sandbox_resource_refs=tuple(
                item.resource_ref
                for item in resources
                if item.resource_ref is not None
            ),
            sandbox_resources=resources,
            sandbox_inventory_fingerprint=snapshot.fingerprint,
        )

    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        if target.target_kind != "SANDBOX":
            raise ValueError("CANCELLATION_TARGET_KIND_MISMATCH")
        if not target.sandbox_resources or target.sandbox_inventory_fingerprint is None:
            target = await self.prepare(target)
        observations: list[CancellationResourceObservation] = []
        for resource in target.sandbox_resources:
            observations.append(await self._cancel_resource(resource))
        values = tuple(observations)
        status: CancellationStatus
        reason: str | None
        if any(item.status == "UNKNOWN" for item in values):
            status, reason = "UNKNOWN", "SANDBOX_RESOURCE_UNKNOWN"
        elif any(item.status == "STOPPED" for item in values):
            status, reason = "STOPPED", None
        elif any(item.status == "ABSENT" for item in values):
            status, reason = "ABSENT", None
        else:
            status, reason = "PRESERVED", "REUSABLE_BASELINE"
        return CancellationObservation(target, status, reason, values)

    async def _cancel_resource(
        self, resource: SandboxCancellationResource
    ) -> CancellationResourceObservation:
        if resource.preservation_reason == "REUSABLE_BASELINE":
            return CancellationResourceObservation(
                resource, "PRESERVED", "REUSABLE_BASELINE"
            )
        labels = dict(resource.labels)
        try:
            if resource.resource_kind in {"CONTAINER", "CONTAINER_INTENT"}:
                container_presence = await self._docker.inspect_container_presence(
                    resource.resource_id,
                    by_name=resource.lookup_by_name,
                )
                if container_presence.status == "ABSENT":
                    return CancellationResourceObservation(resource, "ABSENT", None)
                if (
                    container_presence.status != "PRESENT"
                    or container_presence.state is None
                ):
                    return _unknown_resource(resource)
                state = container_presence.state
                if dict(state.labels) != labels or (
                    resource.resource_kind == "CONTAINER"
                    and not resource.lookup_by_name
                    and state.container_id != resource.resource_id
                ):
                    return _unknown_resource(resource)
                await self._docker.remove((state.container_id,))
                return CancellationResourceObservation(resource, "STOPPED", None)
            if resource.resource_tag is None:
                return _unknown_resource(resource)
            image_presence = await self._docker.inspect_image_tag(
                resource.resource_tag
            )
            if image_presence.status == "ABSENT":
                return CancellationResourceObservation(resource, "ABSENT", None)
            if image_presence.status != "PRESENT" or image_presence.state is None:
                return _unknown_resource(resource)
            if dict(image_presence.state.labels) != labels or (
                resource.resource_kind == "IMAGE"
                and image_presence.state.image_digest != resource.resource_id
            ):
                return _unknown_resource(resource)
            await self._docker.remove_image_tags((resource.resource_tag,))
            return CancellationResourceObservation(resource, "STOPPED", None)
        except (OSError, RuntimeError, ValueError):
            return _unknown_resource(resource)


def build_production_cancellation_router(
    *,
    records: RecordStore,
    static: AttemptCancellationPort,
    provider_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter],
    docker: SandboxCancellationDockerPort,
    resources: OwnedResourceRegistry,
) -> ExactCancellationRouter:
    """Compose all production cancellation targets without a fallback adapter."""

    return ExactCancellationRouter(
        static=ProductionStaticCancellation(static),
        provider=ProductionProviderCancellation(
            records=records, adapters=provider_adapters
        ),
        sandbox=ProductionSandboxCancellation(
            records=records, docker=docker, resources=resources
        ),
    )


def _observation(
    target: CancellationTarget, result: CancellationResult, unresolved: str
) -> CancellationObservation:
    return CancellationObservation(
        target=target,
        status="STOPPED" if result.cancelled else "UNKNOWN",
        reason_code=None if result.cancelled else unresolved,
    )


def _unknown_resource(
    resource: SandboxCancellationResource,
) -> CancellationResourceObservation:
    return CancellationResourceObservation(
        resource, "UNKNOWN", "SANDBOX_RESOURCE_UNKNOWN"
    )


__all__ = [
    "ProductionProviderCancellation",
    "ProductionSandboxCancellation",
    "ProductionStaticCancellation",
    "SandboxCancellationDockerPort",
    "build_production_cancellation_router",
]
