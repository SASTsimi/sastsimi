from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.dynamic import (
    POC_RUNTIME_PATH,
    DynamicReproductionToolRequest,
    PoCCandidate,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import Record
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


@dataclass
class _Docker:
    materialized: list[tuple[str, bytes, str]] = field(default_factory=list)
    executed: list[tuple[str, tuple[str, ...], int, str]] = field(
        default_factory=list
    )

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
        return DockerCommandOutcome(0, b"observed", b"", False)


@dataclass
class _Sink:
    published: list[Record] = field(default_factory=list)

    def publish(
        self,
        *,
        work: object,
        role: RequesterRole,
        record: Record,
        input_refs: tuple[StoredDataRef, ...],
    ) -> StoredDataRef:
        del work, role, input_refs
        self.published.append(record)
        return cast(StoredDataRef, reference(record))


def _selection_tool(chain: dict[str, object]) -> DynamicReproductionToolRequest:
    return wire(
        DynamicReproductionToolRequest,
        make("DynamicReproductionToolRequest")
        | {
            "request_ref": reference(chain["request"]).model_dump(mode="json"),
            "reproduction_plan_ref": reference(chain["plan"]).model_dump(
                mode="json"
            ),
            "environment_ref": reference(chain["environment"]).model_dump(
                mode="json"
            ),
            "action": "USE_POC_CANDIDATE",
            "command": None,
            "poc_candidate_ref": reference(chain["candidate"]).model_dump(
                mode="json"
            ),
        },
    )


def _command_tool(
    chain: dict[str, object],
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
            "reproduction_plan_ref": reference(chain["plan"]).model_dump(
                mode="json"
            ),
            "environment_ref": reference(chain["environment"]).model_dump(
                mode="json"
            ),
            "action": "RUN_COMMAND",
            "command": command,
            "poc_candidate_ref": None,
        },
    )


def _prepared_workflow() -> tuple[
    ProductionDynamicWorkflow,
    _Docker,
    dict[str, object],
    StoredDataRef,
]:
    chain = dynamic_success()
    artifacts = MemoryArtifacts()
    content = b"print('candidate')\n"
    content_ref = artifacts.commit(artifacts.stage_bytes(content, "text/plain"))
    candidate = PoCCandidate.model_validate(
        chain["candidate"].model_dump()
        | {"content_ref": content_ref, "content_digest": content_ref.content_hash}
    )
    chain["candidate"] = candidate
    request_ref = cast(StoredDataRef, reference(chain["request"]))
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
        authorization=cast(object, lambda *_: None),
    )
    workflow._records["request"] = cast(Record, chain["request"])
    workflow._policy = chain["policy"]
    workflow._prepared = PreparedSandbox(
        chain["recipe"], chain["environment"], ()  # type: ignore[arg-type]
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
    candidate = cast(PoCCandidate, chain["candidate"])

    await workflow.apply_tool(
        work=workflow._work,
        request=chain["request"],  # type: ignore[arg-type]
        request_ref=request_ref,
        requirements=chain["requirements"],  # type: ignore[arg-type]
        requirements_ref=cast(StoredDataRef, reference(chain["requirements"])),
        plan=chain["plan"],  # type: ignore[arg-type]
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
            chain["environment"].container_instance_id,  # type: ignore[attr-defined]
            expected,
            hashlib.sha256(expected).hexdigest(),
        )
    ]


@pytest.mark.asyncio
async def test_selected_candidate_rejects_unrelated_command() -> None:
    workflow, docker, chain, request_ref = _prepared_workflow()
    selection = _selection_tool(chain)
    candidate = cast(PoCCandidate, chain["candidate"])
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
    candidate = cast(PoCCandidate, chain["candidate"])
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
