from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import TypedDict, cast

import pytest

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.dynamic import (
    POC_RUNTIME_PATH,
    CleanupResult,
    DynamicReproductionRequest,
    DynamicReproductionToolRequest,
    EnvironmentRecipe,
    EnvironmentRequirements,
    PoCCandidate,
    ReproductionPlan,
    SandboxEnvironment,
    SandboxPolicyDecision,
)
from sastsimi.contracts.ids import StoredDataId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record, WorkHandlerResult
from sastsimi.reproduction.production import (
    DynamicRecordSink,
    DynamicSandboxAuthorization,
    ProductionDynamicWorkflow,
)
from sastsimi.reproduction.service import DynamicOperationalError
from sastsimi.sandbox.controller import SandboxController
from sastsimi.sandbox.docker_adapter import DockerCommandOutcome
from sastsimi.sandbox.session_manager import ReproductionSessionManager
from sastsimi.sandbox.setup_automation import (
    DockerLifecyclePort,
    PreparedSandbox,
    ReproductionSetupAutomation,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import wire
from tests.contract.domain.success_fixture import dynamic_success
from tests.integration.runtime_support import TestClock, TestIds
from tests.integration.sandbox.test_dynamic_reproduction_workflow import (
    MemoryArtifacts,
    dynamic_work,
)


class _Chain(TypedDict):
    request: DynamicReproductionRequest
    requirements: EnvironmentRequirements
    plan: ReproductionPlan
    recipe: EnvironmentRecipe
    environment: SandboxEnvironment
    policy: SandboxPolicyDecision
    candidate: PoCCandidate
    cleanup: CleanupResult


@dataclass
class _Docker:
    materialized: list[tuple[str, bytes, str]] = field(default_factory=list)
    executed: list[tuple[str, tuple[str, ...], int, str]] = field(default_factory=list)
    time_out: bool = False

    async def materialize_poc(
        self, container_id: str, content: bytes, content_digest: str
    ) -> str:
        self.materialized.append((container_id, content, content_digest))
        return "/tmp/sastsimi-poc-candidate"

    async def exec(
        self,
        container_id: str,
        argv: tuple[str, ...],
        timeout_ms: int,
        *,
        working_directory: str,
    ) -> DockerCommandOutcome:
        self.executed.append((container_id, argv, timeout_ms, working_directory))
        return DockerCommandOutcome(
            -9 if self.time_out else 0,
            b"observed",
            b"timed out" if self.time_out else b"",
            self.time_out,
        )


@dataclass
class _Sink:
    published: list[Record] = field(default_factory=list)
    finished: list[Record] = field(default_factory=list)
    fail_on: str | None = None
    failure_observer: Callable[[], None] | None = None

    def publish(
        self,
        *,
        work: object,
        role: RequesterRole,
        record: Record,
        input_refs: tuple[StoredDataRef, ...],
    ) -> StoredDataRef:
        del work, role, input_refs
        if record.meta.record_type == self.fail_on:
            if self.failure_observer is not None:
                self.failure_observer()
            raise RuntimeError("publication unavailable")
        self.published.append(record)
        record_ref = reference(record)
        assert isinstance(record_ref, StoredDataRef)
        return record_ref

    def finish(
        self,
        *,
        work: object,
        result: Record,
        status: str,
        input_refs: tuple[StoredDataRef, ...],
    ) -> WorkHandlerResult:
        del work, status, input_refs
        self.finished.append(result)
        result_ref = reference(result)
        assert isinstance(result_ref, StoredDataRef)
        return WorkHandlerResult((result_ref,))


@dataclass
class _CleanupSetup:
    result: CleanupResult
    calls: list[
        tuple[
            DynamicReproductionRequest,
            tuple[SandboxEnvironment, ...],
            tuple[StoredDataRef, ...],
        ]
    ] = field(default_factory=list)

    async def cleanup(
        self,
        *,
        request: DynamicReproductionRequest,
        environments: tuple[SandboxEnvironment, ...],
        resource_refs: tuple[StoredDataRef, ...],
        meta: RecordMeta,
    ) -> CleanupResult:
        del meta
        self.calls.append((request, environments, resource_refs))
        request_ref = reference(request)
        assert isinstance(request_ref, StoredDataRef)
        environment_refs: list[StoredDataRef] = []
        for environment in environments:
            environment_ref = reference(environment)
            assert isinstance(environment_ref, StoredDataRef)
            environment_refs.append(environment_ref)
        return self.result.model_copy(
            update={
                "request_ref": request_ref,
                "environment_refs": tuple(environment_refs),
                "resource_refs": resource_refs,
            }
        )


def _selection_tool(chain: _Chain) -> DynamicReproductionToolRequest:
    return wire(
        DynamicReproductionToolRequest,
        make("DynamicReproductionToolRequest")
        | {
            "request_ref": reference(chain["request"]).model_dump(mode="json"),
            "reproduction_plan_ref": reference(chain["plan"]).model_dump(mode="json"),
            "environment_ref": reference(chain["environment"]).model_dump(mode="json"),
            "action": "USE_POC_CANDIDATE",
            "command": None,
            "poc_candidate_ref": reference(chain["candidate"]).model_dump(mode="json"),
        },
    )


def _command_tool(
    chain: _Chain,
    arguments: tuple[str, ...],
    *,
    executable: str = "/bin/sh",
) -> DynamicReproductionToolRequest:
    command = make("SandboxCommandInput") | {
        "executable": executable,
        "arguments": list(arguments),
        "working_directory": "/workspace",
    }
    return wire(
        DynamicReproductionToolRequest,
        make("DynamicReproductionToolRequest")
        | {
            "request_ref": reference(chain["request"]).model_dump(mode="json"),
            "reproduction_plan_ref": reference(chain["plan"]).model_dump(mode="json"),
            "environment_ref": reference(chain["environment"]).model_dump(mode="json"),
            "action": "RUN_COMMAND",
            "command": command,
            "poc_candidate_ref": None,
        },
    )


def _unused_authorization(
    work: WorkExecutionState,
    request: DynamicReproductionRequest,
    requirements: EnvironmentRequirements,
    plan: ReproductionPlan,
) -> DynamicSandboxAuthorization:
    del work, request, requirements, plan
    raise AssertionError("prepared workflow must not resolve authorization")


def _prepared_workflow() -> tuple[
    ProductionDynamicWorkflow,
    _Docker,
    _Chain,
    StoredDataRef,
]:
    raw_chain = dynamic_success()
    request = cast(DynamicReproductionRequest, raw_chain["request"])
    request_ref = cast(StoredDataRef, reference(request))
    requirements = cast(EnvironmentRequirements, raw_chain["requirements"]).model_copy(
        update={"request_ref": request_ref}
    )
    requirements_ref = cast(StoredDataRef, reference(requirements))
    plan = cast(ReproductionPlan, raw_chain["plan"]).model_copy(
        update={
            "request_ref": request_ref,
            "environment_requirements_ref": requirements_ref,
        }
    )
    plan_ref = cast(StoredDataRef, reference(plan))
    recipe = cast(EnvironmentRecipe, raw_chain["recipe"]).model_copy(
        update={
            "request_ref": request_ref,
            "environment_requirements_ref": requirements_ref,
        }
    )
    recipe_ref = cast(StoredDataRef, reference(recipe))
    environment = cast(SandboxEnvironment, raw_chain["environment"]).model_copy(
        update={
            "request_ref": request_ref,
            "reproduction_plan_ref": plan_ref,
            "environment_recipe_ref": recipe_ref,
            "requirements_ref": requirements_ref,
        }
    )
    policy = cast(SandboxPolicyDecision, raw_chain["policy"]).model_copy(
        update={"request_ref": request_ref}
    )
    artifacts = MemoryArtifacts()
    content = b"print('candidate')\n"
    content_ref = artifacts.commit(artifacts.stage_bytes(content, "text/plain"))
    candidate = cast(PoCCandidate, raw_chain["candidate"]).model_copy(
        update={
            "request_ref": request_ref,
            "reproduction_plan_ref": plan_ref,
            "content_ref": content_ref,
            "content_digest": content_ref.content_hash,
        }
    )
    chain = _Chain(
        request=request,
        requirements=requirements,
        plan=plan,
        recipe=recipe,
        environment=environment,
        policy=policy,
        candidate=candidate,
        cleanup=cast(CleanupResult, raw_chain["cleanup"]),
    )
    work = dynamic_work(request_ref).model_copy(update={"active_attempt_id": "at1"})
    docker = _Docker()
    sink = _Sink()
    ids = TestIds()
    sessions = ReproductionSessionManager(clock=TestClock(), ids=ids)
    workflow = ProductionDynamicWorkflow(
        work=work,
        controller=cast(SandboxController, object()),
        setup=cast(ReproductionSetupAutomation, object()),
        docker=cast(DockerLifecyclePort, docker),
        sessions=sessions,
        artifacts=artifacts,
        clock=TestClock(),
        ids=ids,
        sink=cast(DynamicRecordSink, sink),
        authorization=_unused_authorization,
    )
    workflow._records["request"] = cast(Record, chain["request"])
    workflow._records["environment_requirements"] = cast(Record, chain["requirements"])
    workflow._records["reproduction_plan"] = cast(Record, chain["plan"])
    workflow._policy = policy
    workflow._prepared = PreparedSandbox(
        chain["recipe"],
        chain["environment"],
        (),
    )
    workflow._start_log(
        request_ref,
        policy_ref=cast(StoredDataRef, reference(chain["policy"])),
    )
    return workflow, docker, chain, request_ref


@pytest.mark.asyncio
async def test_selecting_candidate_materializes_exact_verified_bytes() -> None:
    workflow, docker, chain, request_ref = _prepared_workflow()
    tool = _selection_tool(chain)
    tool_ref = cast(StoredDataRef, reference(tool))
    candidate = chain["candidate"]

    await workflow.apply_tool(
        work=workflow._work,
        request=chain["request"],
        request_ref=request_ref,
        requirements=chain["requirements"],
        requirements_ref=cast(StoredDataRef, reference(chain["requirements"])),
        plan=chain["plan"],
        plan_ref=cast(StoredDataRef, reference(chain["plan"])),
        candidate=candidate,
        candidate_ref=cast(StoredDataRef, reference(candidate)),
        tool=tool,
        tool_ref=tool_ref,
        session=workflow._session(workflow._policy_ref()),
    )

    expected = b"print('candidate')\n"
    assert docker.materialized == [
        (
            chain["environment"].container_instance_id,
            expected,
            hashlib.sha256(expected).hexdigest(),
        )
    ]


@pytest.mark.asyncio
async def test_selected_candidate_rejects_unrelated_command() -> None:
    workflow, docker, chain, request_ref = _prepared_workflow()
    selection = _selection_tool(chain)
    candidate = chain["candidate"]
    common = {
        "work": workflow._work,
        "request": chain["request"],
        "request_ref": request_ref,
        "requirements": chain["requirements"],
        "requirements_ref": cast(StoredDataRef, reference(chain["requirements"])),
        "plan": chain["plan"],
        "plan_ref": cast(StoredDataRef, reference(chain["plan"])),
        "candidate": candidate,
        "candidate_ref": cast(StoredDataRef, reference(candidate)),
    }
    await workflow.apply_tool(
        **common,  # type: ignore[arg-type]
        tool=selection,
        tool_ref=cast(StoredDataRef, reference(selection)),
        session=workflow._session(workflow._policy_ref()),
    )
    unrelated = _command_tool(chain, ("unrelated.py",))

    with pytest.raises(DynamicOperationalError, match="runtime-owned candidate path"):
        await workflow.apply_tool(
            **common,  # type: ignore[arg-type]
            tool=unrelated,
            tool_ref=cast(StoredDataRef, reference(unrelated)),
            session=workflow._session(workflow._policy_ref()),
        )

    assert docker.executed == []


@pytest.mark.asyncio
async def test_exact_candidate_command_records_materialized_content_binding() -> None:
    workflow, docker, chain, request_ref = _prepared_workflow()
    selection = _selection_tool(chain)
    candidate = chain["candidate"]
    common = {
        "work": workflow._work,
        "request": chain["request"],
        "request_ref": request_ref,
        "requirements": chain["requirements"],
        "requirements_ref": cast(StoredDataRef, reference(chain["requirements"])),
        "plan": chain["plan"],
        "plan_ref": cast(StoredDataRef, reference(chain["plan"])),
        "candidate": candidate,
        "candidate_ref": cast(StoredDataRef, reference(candidate)),
    }
    await workflow.apply_tool(
        **common,  # type: ignore[arg-type]
        tool=selection,
        tool_ref=cast(StoredDataRef, reference(selection)),
        session=workflow._session(workflow._policy_ref()),
    )
    command = _command_tool(chain, (POC_RUNTIME_PATH,))
    workflow._binding = cast(
        DynamicSandboxAuthorization,
        SimpleNamespace(run_spec=SimpleNamespace(requested_execution_ms=1_000)),
    )

    await workflow.apply_tool(
        **common,  # type: ignore[arg-type]
        tool=command,
        tool_ref=cast(StoredDataRef, reference(command)),
        session=workflow._session(workflow._policy_ref()),
    )

    assert docker.executed == [
        ("container_instance_id", ("/bin/sh", POC_RUNTIME_PATH), 1_000, "/workspace")
    ]
    poc_events = [
        event
        for event in workflow._require_log().events
        if event.event_type.startswith("POC_EXECUTION_")
    ]
    command_finished = next(
        event
        for event in workflow._require_log().events
        if event.event_type == "COMMAND_FINISHED"
    )
    assert len(poc_events) == 2
    assert [event.timed_out for event in poc_events] == [None, False]
    for event in poc_events:
        assert event.input_refs == (candidate.content_ref,)
        assert (
            event.command_ref,
            event.tool_request_ref,
            event.command_digest,
            event.redaction_status,
            event.environment_ref,
            event.environment_recipe_ref,
        ) == (
            command_finished.command_ref,
            command_finished.tool_request_ref,
            command_finished.command_digest,
            command_finished.redaction_status,
            command_finished.environment_ref,
            command_finished.environment_recipe_ref,
        )


@pytest.mark.asyncio
async def test_timed_out_poc_command_records_output_then_fails_execution() -> None:
    workflow, docker, chain, request_ref = _prepared_workflow()
    docker.time_out = True
    selection = _selection_tool(chain)
    command = _command_tool(chain, (POC_RUNTIME_PATH,))
    candidate = chain["candidate"]
    common = {
        "work": workflow._work,
        "request": chain["request"],
        "request_ref": request_ref,
        "requirements": chain["requirements"],
        "requirements_ref": cast(StoredDataRef, reference(chain["requirements"])),
        "plan": chain["plan"],
        "plan_ref": cast(StoredDataRef, reference(chain["plan"])),
        "candidate": candidate,
        "candidate_ref": cast(StoredDataRef, reference(candidate)),
    }
    await workflow.apply_tool(
        **common,  # type: ignore[arg-type]
        tool=selection,
        tool_ref=cast(StoredDataRef, reference(selection)),
        session=workflow._session(workflow._policy_ref()),
    )
    workflow._binding = cast(
        DynamicSandboxAuthorization,
        SimpleNamespace(run_spec=SimpleNamespace(requested_execution_ms=1_000)),
    )

    with pytest.raises(DynamicOperationalError) as raised:
        await workflow.apply_tool(
            **common,  # type: ignore[arg-type]
            tool=command,
            tool_ref=cast(StoredDataRef, reference(command)),
            session=workflow._session(workflow._policy_ref()),
        )

    assert raised.value.failure.status == "FAILED"
    assert raised.value.failure.failure_category == "EXECUTION"
    assert len(workflow._observations) == 2
    finished = [
        event
        for event in workflow._require_log().events
        if event.event_type in {"COMMAND_FINISHED", "POC_EXECUTION_FINISHED"}
    ]
    assert [event.exit_code for event in finished] == [-9, -9]
    assert [event.timed_out for event in finished] == [True, True]


@pytest.mark.asyncio
async def test_publication_failure_cleans_registered_owned_resource() -> None:
    workflow, _, chain, _ = _prepared_workflow()
    resource_ref = StoredDataRef(
        stored_data_id=StoredDataId("owned-container-resource"),
        data_kind="sandbox_resource",
        content_hash="e" * 64,
        workspace_id=chain["request"].meta.workspace_id,
        commit_id=chain["request"].meta.commit_id,
        record_id=None,
    )
    prepared = PreparedSandbox(
        chain["recipe"],
        chain["environment"],
        (resource_ref,),
    )
    cleanup = chain["cleanup"]
    setup = _CleanupSetup(cleanup)
    workflow._setup = cast(ReproductionSetupAutomation, setup)
    sink = cast(_Sink, workflow._sink)
    sink.fail_on = "sandbox_environment"
    resources_at_publish: list[tuple[tuple[StoredDataRef, ...], ...]] = []
    sink.failure_observer = lambda: resources_at_publish.append(
        workflow._prepared_resources()
    )
    workflow._prepared = None

    with pytest.raises(DynamicOperationalError, match="publication failed") as raised:
        await workflow._remember_prepared(prepared)

    assert resources_at_publish == [((resource_ref,),)]
    assert setup.calls == [
        (
            chain["request"],
            (chain["environment"],),
            (resource_ref,),
        )
    ]
    assert workflow._cleanup is not None
    assert workflow._cleanup.status == "SUCCEEDED"
    completed = workflow.finalize_failure(
        work=workflow._work,
        request=chain["request"],
        request_ref=cast(StoredDataRef, reference(chain["request"])),
        session=None,
        failure=raised.value.failure,
    )
    assert completed.output_refs
    assert sink.finished[-1].status == "FAILED"  # type: ignore[attr-defined]
    assert sink.finished[-1].hypothesis_outcome == "INCONCLUSIVE"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_publication_cleanup_failure_is_reported() -> None:
    workflow, _, chain, _ = _prepared_workflow()
    resource_ref = StoredDataRef(
        stored_data_id=StoredDataId("owned-container-resource"),
        data_kind="sandbox_resource",
        content_hash="e" * 64,
        workspace_id=chain["request"].meta.workspace_id,
        commit_id=chain["request"].meta.commit_id,
        record_id=None,
    )
    prepared = PreparedSandbox(
        chain["recipe"],
        chain["environment"],
        (resource_ref,),
    )
    cleanup = chain["cleanup"].model_copy(
        update={
            "status": "FAILED",
            "failure_reason": "OWNED_RESOURCE_CLEANUP_FAILED",
        }
    )
    setup = _CleanupSetup(cleanup)
    workflow._setup = cast(ReproductionSetupAutomation, setup)
    sink = cast(_Sink, workflow._sink)
    sink.fail_on = "sandbox_environment"
    workflow._prepared = None

    with pytest.raises(DynamicOperationalError) as raised:
        await workflow._remember_prepared(prepared)

    assert raised.value.failure.status == "FAILED"
    assert raised.value.failure.failure_category == "ENVIRONMENT_SETUP"
    assert raised.value.failure.failure_reason == "OWNED_RESOURCE_CLEANUP_FAILED"
