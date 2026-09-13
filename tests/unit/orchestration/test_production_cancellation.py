from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from typing import Any, cast

import pytest

from sastsimi.contracts.dynamic import SandboxEnvironment
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
from sastsimi.ports.dto import CancellationResult
from sastsimi.ports.scheduler import CancellationTarget
from sastsimi.sandbox.docker_adapter import DockerContainerState
from tests.integration.providers.test_llm_call_service import fixture


def _work(status: str) -> WorkExecutionState:
    helper = cast(
        Callable[[str], WorkExecutionState],
        import_module("tests.integration.cli.test_run_control")._work,
    )
    return helper(status)


def _attempt(work: WorkExecutionState) -> WorkAttempt:
    helper = cast(
        Callable[[WorkExecutionState], WorkAttempt],
        import_module("tests.integration.cli.test_run_control")._attempt,
    )
    return helper(work)


def _run_ref(kind: str = "action_request") -> RunStoredDataRef:
    helper = cast(
        Callable[[str], RunStoredDataRef],
        import_module("tests.integration.cli.test_run_control")._run_ref,
    )
    return helper(kind)


def _meta(kind: str, record_id: str) -> RecordMeta:
    helper = cast(
        Callable[[str, str], RecordMeta],
        import_module("tests.integration.sandbox.test_container_lifecycle")._meta,
    )
    return helper(kind, record_id)


def _ref(kind: str, name: str) -> StoredDataRef:
    helper = cast(
        Callable[[str, str], StoredDataRef],
        import_module("tests.integration.sandbox.test_container_lifecycle")._ref,
    )
    return helper(kind, name)


def _dynamic_work(request_ref: StoredDataRef) -> WorkExecutionState:
    helper = cast(
        Callable[[StoredDataRef], WorkExecutionState],
        import_module("tests.e2e.test_dynamic_reproduction")._work,
    )
    return helper(request_ref)


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
    )


@pytest.mark.asyncio
async def test_provider_cancellation_uses_exact_profile_model_and_call_id() -> None:
    data = fixture()

    class Provider:
        def __init__(self) -> None:
            self.cancelled_ids: list[str] = []

        async def probe(self, _candidate: object) -> object:
            raise AssertionError("not used")

        async def invoke(self, _request: object) -> object:
            raise AssertionError("not used")

        async def cancel(self, invocation_id: str) -> CancellationResult:
            self.cancelled_ids.append(invocation_id)
            return CancellationResult(True, None)

    adapter = Provider()
    service = ProductionProviderCancellation(
        records=data.records,
        adapters={(data.provider_ref, "gpt-test"): cast(Any, adapter)},
    )

    observed = await service.cancel(
        _target("PROVIDER", call_spec_ref=data.spec_ref)
    )

    assert observed.status == "STOPPED"
    assert observed.reason_code is None
    assert adapter.cancelled_ids == ["call-1"]


class _Docker:
    def __init__(self, labels: dict[str, str]) -> None:
        self.labels = labels
        self.removed: list[tuple[str, ...]] = []

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


@pytest.mark.asyncio
async def test_sandbox_cancellation_rejects_container_from_another_attempt() -> None:
    data = fixture()
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
    environment = SandboxEnvironment(
        meta=_meta("sandbox_environment", "sandbox-environment-r1"),
        request_ref=request_ref,
        reproduction_plan_ref=_ref("reproduction_plan", "plan"),
        environment_recipe_ref=_ref("environment_recipe", "recipe"),
        requirements_ref=_ref("environment_requirements", "requirements"),
        container_instance_id="a" * 64,
        container_action="CREATED",
        container_reason="INITIAL_CLEAN",
        previous_environment_ref=None,
        status="READY",
        checks=(),
        limitations=(),
        created_at=_meta("unused", "unused").created_at,
    )
    environment_ref = data.records.publish(environment)
    labels = {
        "sastsimi.owner": "reproduction-setup-automation",
        "sastsimi.analysis-id": "analysis-1",
        "sastsimi.workspace-id": "workspace-1",
        "sastsimi.commit-id": "commit-1",
        "sastsimi.hypothesis-id": "hypothesis-1",
        "sastsimi.attempt-id": "different-attempt",
        "sastsimi.resource-kind": "container",
    }
    docker = _Docker(labels)
    service = ProductionSandboxCancellation(records=data.records, docker=docker)
    target = CancellationTarget(
        target_kind="SANDBOX",
        work=work,
        attempt=attempt,
        action_request_ref=cast(RecordRef, _run_ref()),
        action_decision_ref=cast(RecordRef, _run_ref("action_decision")),
        call_spec_ref=None,
        sandbox_resource_refs=(environment_ref,),
    )

    with pytest.raises(ValueError, match="CANCELLATION_SANDBOX_OWNERSHIP_MISMATCH"):
        await service.cancel(target)

    assert docker.removed == []
