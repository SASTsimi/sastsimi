"""Exact-current composition boundary for the T11 reproduction slice."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from sastsimi.agents.dynamic_reproduction import DynamicReproductionAgent
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.dynamic import DynamicReproductionRequest
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import WorkHandlerResult
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.sandbox.controller import SandboxController
from sastsimi.sandbox.session_manager import ReproductionSessionManager
from sastsimi.sandbox.setup_automation import (
    DockerLifecyclePort,
    ReproductionSetupAutomation,
)

from .production import (
    DynamicSandboxAuthorizationResolver,
    ProductionDynamicExecutor,
    ProductionDynamicWorkflow,
    RuntimeDynamicRecordSink,
)
from .service import DynamicAgentPort, DynamicStageAuthorizations


class DynamicExecutor(Protocol):
    async def __call__(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        authorizations: DynamicStageAuthorizations,
    ) -> WorkHandlerResult: ...


type CurrentProcessResolver = Callable[
    [DynamicReproductionRequest], HypothesisProcessState
]


@dataclass(frozen=True)
class T11Services:
    """Run one R7 work only against its exact current R6 request."""

    execute_dynamic: DynamicExecutor
    current_process: CurrentProcessResolver

    async def execute(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        authorizations: DynamicStageAuthorizations,
    ) -> WorkHandlerResult:
        process = self.current_process(request)
        _require_current_request(work, request, request_ref, process)
        result = await self.execute_dynamic(
            work=work,
            request=request,
            request_ref=request_ref,
            authorizations=authorizations,
        )
        if len(result.output_refs) != 1 or any(
            output.data_kind != "dynamic_reproduction_result"
            for output in result.output_refs
        ):
            raise ValueError("R7_OUTPUT_AUTHORITY_DENIED")
        return result


def _require_current_request(
    work: WorkExecutionState,
    request: DynamicReproductionRequest,
    request_ref: StoredDataRef,
    process: HypothesisProcessState,
) -> None:
    if not isinstance(work.meta, RecordMeta) or not isinstance(
        process.meta, RecordMeta
    ):
        raise ValueError("DYNAMIC_REQUEST_NOT_CURRENT")
    if (
        reference(request) != request_ref
        or work.work_type != "DYNAMIC_REPRO"
        or work.status != "RUNNING"
        or work.active_attempt_id is None
        or work.input_refs != (request_ref,)
        or request.verification_generation != work.work_generation
        or process.status != "VERIFYING"
        or process.verification_generation != request.verification_generation
        or process.verification_assignment_ref != request.verification_assignment_ref
        or request.meta.analysis_id != work.meta.analysis_id
        or request.meta.workspace_id != work.meta.workspace_id
        or request.meta.commit_id != work.meta.commit_id
        or request.meta.hypothesis_id != work.meta.hypothesis_id
        or process.meta.analysis_id != work.meta.analysis_id
        or process.meta.workspace_id != work.meta.workspace_id
        or process.meta.commit_id != work.meta.commit_id
        or process.meta.hypothesis_id != work.meta.hypothesis_id
    ):
        raise ValueError("DYNAMIC_REQUEST_NOT_CURRENT")


def current_process_from(
    records: Callable[[str, str], tuple[object, ...]],
) -> CurrentProcessResolver:
    """Build an exact current-process resolver over the runtime query port."""

    def resolve(request: DynamicReproductionRequest) -> HypothesisProcessState:
        candidates = tuple(
            item
            for item in records(
                str(request.meta.analysis_id), "hypothesis_process_state"
            )
            if isinstance(item, HypothesisProcessState)
            and item.meta.hypothesis_id == request.meta.hypothesis_id
        )
        if len(candidates) != 1:
            raise ValueError("DYNAMIC_REQUEST_NOT_CURRENT")
        return candidates[0]

    return resolve


def dynamic_executor(
    execute: Callable[..., Awaitable[WorkHandlerResult]],
) -> DynamicExecutor:
    """Narrow an injected workflow method to the public T11 executor port."""

    async def invoke(
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        authorizations: DynamicStageAuthorizations,
    ) -> WorkHandlerResult:
        return await execute(
            work=work,
            request=request,
            request_ref=request_ref,
            authorizations=authorizations,
        )

    return invoke


def compose_t11_services(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    agent: DynamicReproductionAgent | DynamicAgentPort,
    controller: SandboxController,
    setup: ReproductionSetupAutomation,
    docker: DockerLifecyclePort,
    sessions: ReproductionSessionManager,
    artifacts: ArtifactStore,
    clock: Clock,
    ids: IdGenerator,
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef],
    sandbox_authorization: DynamicSandboxAuthorizationResolver,
) -> T11Services:
    """Compose the real R7 slice without selecting a Provider or R6 verdict."""

    sink = RuntimeDynamicRecordSink(runner, role_identity_refs)

    def workflow_factory(work: WorkExecutionState) -> ProductionDynamicWorkflow:
        return ProductionDynamicWorkflow(
            work=work,
            controller=controller,
            setup=setup,
            docker=docker,
            sessions=sessions,
            artifacts=artifacts,
            clock=clock,
            ids=ids,
            sink=sink,
            authorization=sandbox_authorization,
        )

    production = ProductionDynamicExecutor(agent, workflow_factory)
    return T11Services(
        execute_dynamic=production,
        current_process=current_process_from(runtime.queries.current_records),
    )


__all__ = [
    "CurrentProcessResolver",
    "DynamicExecutor",
    "T11Services",
    "compose_t11_services",
    "current_process_from",
    "dynamic_executor",
]
