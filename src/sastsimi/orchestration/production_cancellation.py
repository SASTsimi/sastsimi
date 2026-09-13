"""Fail-closed cancellation adapters for exact production dispatch targets."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from sastsimi.contracts.dynamic import SandboxEnvironment
from sastsimi.contracts.llm import LLMCallSpec
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import CancellationResult
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.scheduler import CancellationObservation, CancellationTarget
from sastsimi.runtime.cancellation_service import ExactCancellationRouter
from sastsimi.sandbox.docker_adapter import DockerContainerState


class AttemptCancellationPort(Protocol):
    async def cancel(self, attempt_id: str) -> CancellationResult: ...


class SandboxCancellationDockerPort(Protocol):
    async def inspect(self, container_id: str) -> DockerContainerState: ...

    async def remove(self, resource_ids: tuple[str, ...]) -> None: ...


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
    """Remove only exact, attempt-owned containers recorded by the runtime."""

    def __init__(
        self, *, records: RecordStore, docker: SandboxCancellationDockerPort
    ) -> None:
        self._records = records
        self._docker = docker

    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        if target.target_kind != "SANDBOX":
            raise ValueError("CANCELLATION_TARGET_KIND_MISMATCH")
        environments: list[SandboxEnvironment] = []
        for ref in target.sandbox_resource_refs:
            record = self._records.get_exact(ref)
            if reference(record) != ref:
                raise ValueError("CANCELLATION_SANDBOX_RESOURCE_NOT_EXACT")
            if isinstance(record, SandboxEnvironment):
                environments.append(record)
        if not environments:
            return CancellationObservation(
                target, "UNRESOLVED", "SANDBOX_CANCELLATION_RESOURCE_MISSING"
            )
        resource_ids = tuple(
            dict.fromkeys(item.container_instance_id for item in environments)
        )
        for environment in environments:
            self._require_owned(target, environment)
        for resource_id in resource_ids:
            state = await self._docker.inspect(resource_id)
            self._require_labels(target, state)
        await self._docker.remove(resource_ids)
        return CancellationObservation(target, "STOPPED", None)

    @staticmethod
    def _require_owned(
        target: CancellationTarget, environment: SandboxEnvironment
    ) -> None:
        meta = environment.meta
        work_meta = target.work.meta
        if not isinstance(meta, RecordMeta) or not isinstance(work_meta, RecordMeta):
            raise ValueError("CANCELLATION_SANDBOX_SCOPE_MISMATCH")
        if (
            meta.analysis_id,
            meta.workspace_id,
            meta.commit_id,
            meta.hypothesis_id,
            meta.attempt_id,
        ) != (
            work_meta.analysis_id,
            work_meta.workspace_id,
            work_meta.commit_id,
            work_meta.hypothesis_id,
            target.attempt.attempt_id,
        ):
            raise ValueError("CANCELLATION_SANDBOX_SCOPE_MISMATCH")

    @staticmethod
    def _require_labels(
        target: CancellationTarget, state: DockerContainerState
    ) -> None:
        meta = target.work.meta
        if not isinstance(meta, RecordMeta):
            raise ValueError("CANCELLATION_SANDBOX_SCOPE_MISMATCH")
        expected = {
            "sastsimi.owner": "reproduction-setup-automation",
            "sastsimi.analysis-id": str(meta.analysis_id),
            "sastsimi.workspace-id": str(meta.workspace_id),
            "sastsimi.commit-id": str(meta.commit_id),
            "sastsimi.hypothesis-id": str(meta.hypothesis_id),
            "sastsimi.attempt-id": str(target.attempt.attempt_id),
            "sastsimi.resource-kind": "container",
        }
        if not state.container_id or any(
            state.labels.get(key) != value for key, value in expected.items()
        ):
            raise ValueError("CANCELLATION_SANDBOX_OWNERSHIP_MISMATCH")


def build_production_cancellation_router(
    *,
    records: RecordStore,
    static: AttemptCancellationPort,
    provider_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter],
    docker: SandboxCancellationDockerPort,
) -> ExactCancellationRouter:
    """Compose all production cancellation targets without a fallback adapter."""

    return ExactCancellationRouter(
        static=ProductionStaticCancellation(static),
        provider=ProductionProviderCancellation(
            records=records, adapters=provider_adapters
        ),
        sandbox=ProductionSandboxCancellation(records=records, docker=docker),
    )


def _observation(
    target: CancellationTarget, result: CancellationResult, unresolved: str
) -> CancellationObservation:
    return CancellationObservation(
        target=target,
        status="STOPPED" if result.cancelled else "UNRESOLVED",
        reason_code=None if result.cancelled else unresolved,
    )


__all__ = [
    "ProductionProviderCancellation",
    "ProductionSandboxCancellation",
    "ProductionStaticCancellation",
    "SandboxCancellationDockerPort",
    "build_production_cancellation_router",
]
