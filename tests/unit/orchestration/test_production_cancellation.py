from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, RunStoredDataRef, StoredDataRef
from sastsimi.contracts.work import (
    AttemptStatus,
    AttemptTrigger,
    WorkAttempt,
    WorkExecutionState,
)
from sastsimi.orchestration.production_cancellation import (
    ProductionProviderCancellation,
    ProductionSandboxCancellation,
)
from sastsimi.ports.docker_state import DockerContainerState
from sastsimi.ports.dto import CancellationResult
from sastsimi.ports.scheduler import CancellationTarget
from sastsimi.sandbox.cleanup import OwnedResourceRegistry
from sastsimi.sandbox.docker_adapter import (
    DockerContainerPresence,
    DockerImageState,
    DockerImageTagPresence,
)
from sastsimi.sandbox.setup_automation import ReproductionSetupAutomation
from tests.e2e.test_dynamic_reproduction import _work as _dynamic_work_fixture
from tests.integration.cli.test_run_control import (
    _attempt as _run_control_attempt,
)
from tests.integration.cli.test_run_control import _run_ref as _run_control_ref
from tests.integration.cli.test_run_control import _work as _run_control_work
from tests.integration.providers.test_llm_call_service import fixture
from tests.integration.sandbox.test_container_lifecycle import _meta as _sandbox_meta
from tests.integration.sandbox.test_container_lifecycle import _ref as _sandbox_ref


def _work(status: str) -> WorkExecutionState:
    return _run_control_work(status)


def _attempt(work: WorkExecutionState) -> WorkAttempt:
    return _run_control_attempt(work)


def _run_ref(kind: str = "action_request") -> RunStoredDataRef:
    return _run_control_ref(kind)


def _meta(kind: str, record_id: str) -> RecordMeta:
    return _sandbox_meta(kind, record_id)


def _ref(kind: str, name: str) -> StoredDataRef:
    return _sandbox_ref(kind, name)


def _dynamic_work(request_ref: StoredDataRef) -> WorkExecutionState:
    return _dynamic_work_fixture(request_ref)


def _target(
    kind: str,
    *,
    call_spec_ref: StoredDataRef | None = None,
    resources: tuple[StoredDataRef, ...] = (),
) -> CancellationTarget:
    work = _work("RUNNING")
    return CancellationTarget(
        target_kind=cast(Any, kind),
        work=work,
        attempt=_attempt(work),
        action_request_ref=cast(RecordRef, _run_ref()),
        action_decision_ref=cast(RecordRef, _run_ref("action_decision")),
        call_spec_ref=call_spec_ref,
        sandbox_resource_refs=resources,
        issued_action_decision_ref=cast(RecordRef, _ref("action_decision", "issued")),
    )


@pytest.mark.asyncio
async def test_provider_cancellation_uses_exact_profile_model_and_call_id() -> None:
    class Calls:
        def __init__(self) -> None:
            self.validated: list[tuple[object, StoredDataRef, StoredDataRef]] = []
            self.cancelled: list[tuple[object, StoredDataRef, StoredDataRef]] = []

        def validate_cancellation(
            self,
            *,
            work: WorkExecutionState,
            decision_ref: StoredDataRef,
            call_spec_ref: StoredDataRef,
        ) -> None:
            self.validated.append((work, decision_ref, call_spec_ref))

        async def cancel(
            self,
            *,
            work: WorkExecutionState,
            decision_ref: StoredDataRef,
            call_spec_ref: StoredDataRef,
        ) -> CancellationResult:
            self.cancelled.append((work, decision_ref, call_spec_ref))
            return CancellationResult(True, None)

    calls = Calls()
    service = ProductionProviderCancellation(calls)
    target = _target("PROVIDER", call_spec_ref=_ref("llm_call_spec", "call-spec"))

    await service.prepare(target)
    observed = await service.cancel(target)

    assert observed.status == "STOPPED"
    assert observed.reason_code is None
    assert calls.validated == [
        (target.work, target.issued_action_decision_ref, target.call_spec_ref)
    ]
    assert calls.cancelled == calls.validated


class _Docker:
    def __init__(self, labels: dict[str, str], *, presence: str = "PRESENT") -> None:
        self.labels = labels
        self.presence = presence
        self.removed: list[tuple[str, ...]] = []
        self.inspected: list[tuple[str, bool]] = []
        self.image_inspected: list[str] = []
        self.image_tags_removed: list[tuple[str, ...]] = []

    async def inspect(self, container_id: str) -> DockerContainerState:
        return DockerContainerState(
            container_id=container_id,
            image_digest="sha256:" + "a" * 64,
            user="65532:65532",
            network_mode="none",
            privileged=False,
            read_only_rootfs=True,
            running=True,
            exit_code=0,
            health_status="healthy",
            labels=self.labels,
        )

    async def remove(self, resource_ids: tuple[str, ...]) -> None:
        self.removed.append(resource_ids)

    async def inspect_container_presence(
        self, container_id: str, *, by_name: bool = False
    ) -> DockerContainerPresence:
        self.inspected.append((container_id, by_name))
        if self.presence == "ABSENT":
            return DockerContainerPresence("ABSENT")
        if self.presence == "UNKNOWN":
            return DockerContainerPresence("UNKNOWN")
        return DockerContainerPresence("PRESENT", await self.inspect(container_id))

    async def inspect_owned_image(self, image_digest: str) -> DockerImageState:
        raise AssertionError(f"unexpected image digest inspection: {image_digest}")

    async def inspect_image_tag(self, image_tag: str) -> DockerImageTagPresence:
        self.image_inspected.append(image_tag)
        if self.presence == "ABSENT":
            return DockerImageTagPresence("ABSENT")
        if self.presence == "UNKNOWN":
            return DockerImageTagPresence("UNKNOWN")
        return DockerImageTagPresence(
            "PRESENT", DockerImageState("sha256:" + "a" * 64, self.labels)
        )

    async def remove_images(self, image_digests: tuple[str, ...]) -> None:
        raise AssertionError(f"unexpected image removal: {image_digests}")

    async def remove_image_tags(self, image_tags: tuple[str, ...]) -> None:
        self.image_tags_removed.append(image_tags)


def _sandbox_target() -> CancellationTarget:
    request_ref = _ref("dynamic_reproduction_request", "dynamic-request")
    work = _dynamic_work(request_ref)
    attempt = WorkAttempt.model_validate(
        {
            "meta": _meta("work_attempt", "dynamic-attempt-record"),
            "work_id": work.work_id,
            "attempt_id": work.active_attempt_id,
            "attempt_number": 1,
            "trigger": AttemptTrigger.INITIAL,
            "input_hash": work.input_hash,
            "status": AttemptStatus.RUNNING,
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "started_at": work.started_at,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )
    return CancellationTarget(
        target_kind="SANDBOX",
        work=work,
        attempt=attempt,
        action_request_ref=cast(RecordRef, _run_ref()),
        action_decision_ref=cast(RecordRef, _run_ref("action_decision")),
        call_spec_ref=None,
        sandbox_resource_refs=(),
    )


@pytest.mark.asyncio
async def test_sandbox_cancellation_rejects_container_from_another_attempt() -> None:
    data = fixture()
    target = _sandbox_target()
    assert isinstance(target.attempt.meta, RecordMeta)
    labels = {
        "sastsimi.owner": "reproduction-setup-automation",
        "sastsimi.analysis-id": "analysis-1",
        "sastsimi.workspace-id": "workspace-1",
        "sastsimi.commit-id": "commit-1",
        "sastsimi.hypothesis-id": "hypothesis-1",
        "sastsimi.attempt-id": "different-attempt",
        "sastsimi.resource-kind": "container",
        "sastsimi.resource-id": "container-runtime-1",
    }
    docker = _Docker(labels)
    resources = OwnedResourceRegistry()
    resources.register_container(
        container_id="a" * 64,
        labels=labels,
        meta=target.attempt.meta,
    )
    service = ProductionSandboxCancellation(
        records=data.records, docker=docker, resources=resources
    )

    with pytest.raises(ValueError, match="SANDBOX_RESOURCE_SCOPE_MISMATCH"):
        await service.cancel(target)

    assert docker.removed == []


@pytest.mark.asyncio
async def test_sandbox_cancellation_observes_exact_absent_container() -> None:
    data = fixture()
    target = _sandbox_target()
    assert isinstance(target.attempt.meta, RecordMeta)
    labels = ReproductionSetupAutomation._container_labels(target.attempt.meta)
    resources = OwnedResourceRegistry()
    resources.register_container(
        container_id="container-runtime-1",
        labels=labels,
        meta=target.attempt.meta,
    )
    docker = _Docker(dict(labels), presence="ABSENT")
    service = ProductionSandboxCancellation(
        records=data.records, docker=docker, resources=resources
    )

    prepared = await service.prepare(target)
    observed = await service.cancel(prepared)

    assert observed.status == "ABSENT"
    assert tuple(item.status for item in observed.resource_observations) == ("ABSENT",)
    assert docker.inspected == [("container-runtime-1", False)]
    assert docker.removed == []


@pytest.mark.asyncio
async def test_sandbox_prepare_reloads_resource_journal(
    tmp_path: Path,
) -> None:
    data = fixture()
    target = _sandbox_target()
    assert isinstance(target.attempt.meta, RecordMeta)
    journal = tmp_path / "owned-resources.json"
    stale = OwnedResourceRegistry(journal_path=journal)
    labels = ReproductionSetupAutomation._container_labels(target.attempt.meta)
    writer = OwnedResourceRegistry(journal_path=journal)
    writer.register_container(
        container_id="container-written-after-composition",
        labels=labels,
        meta=target.attempt.meta,
    )
    service = ProductionSandboxCancellation(
        records=data.records,
        docker=_Docker(dict(labels), presence="ABSENT"),
        resources=stale,
    )

    prepared = await service.prepare(target)

    assert tuple(item.resource_id for item in prepared.sandbox_resources) == (
        "container-written-after-composition",
    )


@pytest.mark.asyncio
async def test_sandbox_current_inventory_rejects_growth_after_prepare(
    tmp_path: Path,
) -> None:
    data = fixture()
    target = _sandbox_target()
    assert isinstance(target.attempt.meta, RecordMeta)
    journal = tmp_path / "owned-resources.json"
    labels = ReproductionSetupAutomation._container_labels(target.attempt.meta)
    writer = OwnedResourceRegistry(journal_path=journal)
    writer.register_container(
        container_id="initial-container",
        labels=labels,
        meta=target.attempt.meta,
    )
    service = ProductionSandboxCancellation(
        records=data.records,
        docker=_Docker(dict(labels), presence="ABSENT"),
        resources=OwnedResourceRegistry(journal_path=journal),
    )
    prepared = await service.prepare(target)

    OwnedResourceRegistry(journal_path=journal).register_container(
        container_id="late-container",
        labels=labels,
        meta=target.attempt.meta,
    )

    with pytest.raises(ValueError, match="CANCELLATION_SANDBOX_INVENTORY_CHANGED"):
        service.validate_inventory("analysis-1", (prepared,))

    retried = await service.prepare(target)
    service.validate_inventory("analysis-1", (retried,))
    assert {item.resource_id for item in retried.sandbox_resources} == {
        "initial-container",
        "late-container",
    }


def test_sandbox_current_inventory_rejects_targetless_leftover(tmp_path: Path) -> None:
    data = fixture()
    target = _sandbox_target()
    assert isinstance(target.attempt.meta, RecordMeta)
    journal = tmp_path / "owned-resources.json"
    labels = ReproductionSetupAutomation._container_labels(target.attempt.meta)
    OwnedResourceRegistry(journal_path=journal).reserve_container(
        container_name="leftover-container",
        labels=labels,
    )
    service = ProductionSandboxCancellation(
        records=data.records,
        docker=_Docker(dict(labels), presence="ABSENT"),
        resources=OwnedResourceRegistry(journal_path=journal),
    )

    with pytest.raises(ValueError, match="CANCELLATION_SANDBOX_INVENTORY_INCOMPLETE"):
        service.validate_inventory("analysis-1", ())


@pytest.mark.asyncio
async def test_sandbox_label_mismatch_is_unknown_and_never_removed() -> None:
    data = fixture()
    target = _sandbox_target()
    assert isinstance(target.attempt.meta, RecordMeta)
    labels = ReproductionSetupAutomation._container_labels(target.attempt.meta)
    resources = OwnedResourceRegistry()
    resources.register_container(
        container_id="container-runtime-1",
        labels=labels,
        meta=target.attempt.meta,
    )
    docker = _Docker(dict(labels) | {"sastsimi.resource-id": "foreign"})
    service = ProductionSandboxCancellation(
        records=data.records, docker=docker, resources=resources
    )

    observed = await service.cancel(await service.prepare(target))

    assert observed.status == "UNKNOWN"
    assert observed.reason_code == "SANDBOX_RESOURCE_UNKNOWN"
    assert docker.removed == []


@pytest.mark.asyncio
async def test_sandbox_snapshot_includes_intents_and_preserves_reusable_image() -> None:
    data = fixture()
    target = _sandbox_target()
    assert isinstance(target.attempt.meta, RecordMeta)
    resources = OwnedResourceRegistry()
    container_labels = ReproductionSetupAutomation._container_labels(
        target.attempt.meta
    )
    image_labels = ReproductionSetupAutomation._image_labels(target.attempt.meta)
    preserved_labels = ReproductionSetupAutomation._image_labels(target.attempt.meta)
    from sastsimi.sandbox.docker_adapter import DockerAdapter

    container_name = DockerAdapter.runtime_container_name(container_labels)
    image_tag = DockerAdapter.runtime_image_tag(image_labels)
    preserved_tag = DockerAdapter.runtime_image_tag(preserved_labels)
    resources.reserve_container(container_name=container_name, labels=container_labels)
    resources.reserve_image(image_tag=image_tag, labels=image_labels)
    resources.register_image(
        image_digest="sha256:" + "a" * 64,
        image_tag=preserved_tag,
        labels=preserved_labels,
        meta=target.attempt.meta,
        preservation_reason="REUSABLE_BASELINE",
    )
    docker = _Docker(dict(container_labels), presence="ABSENT")
    service = ProductionSandboxCancellation(
        records=data.records, docker=docker, resources=resources
    )

    observed = await service.cancel(await service.prepare(target))

    assert {item.resource.resource_kind for item in observed.resource_observations} == {
        "IMAGE",
        "CONTAINER_INTENT",
        "IMAGE_INTENT",
    }
    assert {item.status for item in observed.resource_observations} == {
        "ABSENT",
        "PRESERVED",
    }
    assert observed.status == "ABSENT"
    assert docker.inspected == [(container_name, True)]
    assert docker.image_inspected == [image_tag]
    assert docker.removed == []
    assert docker.image_tags_removed == []
