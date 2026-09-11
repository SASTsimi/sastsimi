from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.contracts.dynamic import (
    DynamicReproductionToolRequest,
)
from sastsimi.contracts.ids import StoredDataId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.reproduction.production import DynamicSandboxAuthorization
from sastsimi.reproduction.service import DynamicOperationalError
from sastsimi.sandbox.cleanup import owned_container_resource_ref
from sastsimi.sandbox.controller import (
    SandboxBoundaryOutcome,
    SandboxController,
    SandboxRunSpec,
)
from sastsimi.sandbox.setup_automation import (
    PreparedSandbox,
    ReproductionSetupAutomation,
    SandboxSetupCleanupError,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import wire
from tests.integration.sandbox.test_container_lifecycle import (
    FakeDockerAdapter,
    _dynamic_records,
    _meta,
    _prepare,
    _setup,
)
from tests.integration.sandbox.test_production_poc_binding import (
    _CleanupSetup,
    _prepared_workflow,
    _RecreateController,
    _Sink,
)


class _StartFailureDocker(FakeDockerAdapter):
    def __init__(self, *, cleanup_fails: bool) -> None:
        super().__init__()
        self.cleanup_fails = cleanup_fails
        self.remove_attempts: list[str] = []

    async def start(self, container_id: str) -> None:
        assert container_id in self.created
        raise RuntimeError("START_FAILED")

    async def remove(self, resource_ids: tuple[str, ...]) -> None:
        self.remove_attempts.extend(resource_ids)
        if self.cleanup_fails:
            raise RuntimeError("sensitive cleanup diagnostic")
        await super().remove(resource_ids)


@pytest.mark.asyncio
async def test_failed_start_is_compensated_before_setup_error_escapes(
    tmp_path: Path,
) -> None:
    """Fails if a failed start can escape before its container is removed."""

    (tmp_path / "Dockerfile").write_bytes(b"FROM scratch\n")
    request, requirements, plan = _dynamic_records()
    docker = _StartFailureDocker(cleanup_fails=False)

    with pytest.raises(RuntimeError, match="START_FAILED"):
        await _prepare(
            _setup(docker),
            tmp_path,
            request=request,
            requirements=requirements,
            plan=plan,
            meta=_meta("sandbox_environment", "environment-seed"),
        )

    assert docker.remove_attempts == ["owned-container-1"]
    assert docker.removed == ["owned-container-1"]


@pytest.mark.asyncio
async def test_failed_compensation_exposes_exact_owned_resource_for_final_cleanup(
    tmp_path: Path,
) -> None:
    """Fails if cleanup failure loses the only exact handle to a live container."""

    (tmp_path / "Dockerfile").write_bytes(b"FROM scratch\n")
    request, requirements, plan = _dynamic_records()
    docker = _StartFailureDocker(cleanup_fails=True)
    setup = _setup(docker)

    with pytest.raises(Exception) as raised:
        await _prepare(
            setup,
            tmp_path,
            request=request,
            requirements=requirements,
            plan=plan,
            meta=_meta("sandbox_environment", "environment-seed"),
        )

    assert type(raised.value).__name__ == "SandboxSetupCleanupError"
    assert str(raised.value) == "OWNED_RESOURCE_CLEANUP_FAILED"
    prepared = cast(SandboxSetupCleanupError, raised.value).prepared
    assert prepared.environment.container_instance_id == "owned-container-1"
    assert prepared.environment.status == "READY"
    assert prepared.environment.limitations == ("Sandbox setup did not complete",)
    assert prepared.resource_refs == (
        owned_container_resource_ref(
            container_id="owned-container-1",
            meta=prepared.environment.meta,
        ),
    )

    cleanup = await setup.cleanup(
        request=request,
        environments=(prepared.environment,),
        resource_refs=prepared.resource_refs,
        meta=_meta("cleanup_result", "cleanup-seed"),
    )
    assert cleanup.status == "FAILED"
    assert cleanup.failure_reason == "OWNED_RESOURCE_CLEANUP_FAILED"
    assert cleanup.resource_refs == prepared.resource_refs
    assert docker.remove_attempts == ["owned-container-1", "owned-container-1"]


@pytest.mark.asyncio
async def test_recreate_cleanup_failure_is_recorded_as_required_failed_cleanup() -> (
    None
):
    """Fails if Production can finalize a leaked recreate container as NOT_REQUIRED."""

    workflow, _, chain, request_ref = _prepared_workflow()
    previous = cast(PreparedSandbox, workflow._prepared)
    workflow._environments.append(previous.environment)
    workflow._recipes.append(previous.recipe)
    workflow._resource_groups.append(previous.resource_refs)
    previous_environment_ref = cast(StoredDataRef, reference(previous.environment))
    failed_environment = previous.environment.model_copy(
        update={
            "container_instance_id": "owned-container-leaked",
            "container_reason": "STATE_UNCERTAIN",
            "previous_environment_ref": previous_environment_ref,
            "status": "READY",
            "limitations": ("Sandbox setup did not complete",),
        }
    )
    failed_environment = failed_environment.model_copy(
        update={
            "meta": RecordMeta.model_validate(
                failed_environment.meta.model_dump()
                | {
                    "record_id": "failed-environment",
                    "logical_record_id": "failed-environment",
                }
            )
        }
    )
    resource_ref = StoredDataRef(
        stored_data_id=StoredDataId("owned-container-leaked-resource"),
        data_kind="sandbox_resource",
        content_hash="e" * 64,
        workspace_id=chain["request"].meta.workspace_id,
        commit_id=chain["request"].meta.commit_id,
        record_id=None,
    )
    partial = PreparedSandbox(previous.recipe, failed_environment, (resource_ref,))

    class _FailedRecreateSetup(_CleanupSetup):
        async def recreate(self, **_: object) -> PreparedSandbox:
            raise SandboxSetupCleanupError(partial)

    cleanup = chain["cleanup"].model_copy(
        update={
            "status": "FAILED",
            "failure_reason": "OWNED_RESOURCE_CLEANUP_FAILED",
        }
    )
    setup = _FailedRecreateSetup(cleanup)
    workflow._setup = cast(ReproductionSetupAutomation, setup)

    recreate_policy = chain["policy"].model_copy(
        update={"reason_codes": ("RECREATE_APPROVED",)}
    )
    workflow._controller = cast(
        SandboxController,
        _RecreateController(
            SandboxBoundaryOutcome(
                decision=recreate_policy,
                approved_spec=cast(SandboxRunSpec, SimpleNamespace()),
                approved_recipe_ref=cast(StoredDataRef, reference(previous.recipe)),
            )
        ),
    )

    def authorize_recreate(
        work: WorkExecutionState,
        request: object,
        requirements: object,
        plan: object,
        phase: object,
        phase_ref: StoredDataRef,
        image_digest: str | None,
        context_refs: tuple[StoredDataRef, ...],
    ) -> DynamicSandboxAuthorization:
        del (
            work,
            request,
            requirements,
            plan,
            phase,
            phase_ref,
            image_digest,
            context_refs,
        )
        return cast(
            DynamicSandboxAuthorization,
            SimpleNamespace(
                action=object(),
                action_decision_ref=cast(StoredDataRef, reference(chain["policy"])),
                sandbox_profile=object(),
                lifecycle_profile=object(),
                run_policy_state_ref=request_ref,
                run_spec=SimpleNamespace(requested_execution_ms=1_000),
            ),
        )

    workflow._authorization = authorize_recreate
    tool = wire(
        DynamicReproductionToolRequest,
        make("DynamicReproductionToolRequest")
        | {
            "request_ref": request_ref.model_dump(mode="json"),
            "reproduction_plan_ref": reference(chain["plan"]).model_dump(mode="json"),
            "environment_ref": previous_environment_ref.model_dump(mode="json"),
            "action": "REQUEST_SANDBOX_RECREATE",
            "command": None,
            "poc_candidate_ref": None,
            "recreate_reason": "STATE_UNCERTAIN",
        },
    )

    with pytest.raises(DynamicOperationalError) as raised:
        await workflow.apply_tool(
            work=workflow._work,
            request=chain["request"],
            request_ref=request_ref,
            requirements=chain["requirements"],
            requirements_ref=cast(StoredDataRef, reference(chain["requirements"])),
            plan=chain["plan"],
            plan_ref=cast(StoredDataRef, reference(chain["plan"])),
            candidate=chain["candidate"],
            candidate_ref=cast(StoredDataRef, reference(chain["candidate"])),
            tool=tool,
            tool_ref=cast(StoredDataRef, reference(tool)),
            session=workflow._session(workflow._policy_ref()),
        )

    assert raised.value.failure.failure_reason == "OWNED_RESOURCE_CLEANUP_FAILED"
    assert workflow._prepared == partial
    assert workflow._cleanup is not None
    assert workflow._cleanup.status == "FAILED"
    assert setup.calls[-1][1:] == (
        (previous.environment, failed_environment),
        (resource_ref,),
    )
    assert [
        event.event_type
        for event in workflow._require_log().events
        if event.environment_ref == reference(failed_environment)
    ] == ["CLEANUP_STARTED", "CLEANUP_FINISHED"]

    workflow.finalize_failure(
        work=workflow._work,
        request=chain["request"],
        request_ref=request_ref,
        session=None,
        failure=raised.value.failure,
    )
    result = cast(_Sink, workflow._sink).finished[-1]
    assert result.cleanup_required is True  # type: ignore[attr-defined]
    assert result.cleanup_status == "FAILED"  # type: ignore[attr-defined]
    assert result.environment_ref == reference(failed_environment)  # type: ignore[attr-defined]
