from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Protocol, runtime_checkable

from sastsimi.contracts.actions import ActionDecision, Decision
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.refs import (
    StoredDataRef,
    reference,
    require_record_ref,
    validate_exact_ref,
)
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.contracts.work import WorkExecutionState

from .dto import (
    CancellationResult,
    MonotonicActionDeadline,
    PublishedStaticToolMaterial,
    StaticCapabilityObservation,
    StaticToolObservation,
    StaticToolRequest,
    ToolCapabilityResult,
    ToolRunResult,
)


@runtime_checkable
class StaticToolAdapter(Protocol):
    async def probe(self, profile_ref: StoredDataRef) -> ToolCapabilityResult: ...
    async def run(self, request: StaticToolRequest) -> ToolRunResult: ...
    async def cancel(self, attempt_id: str) -> CancellationResult: ...


class StaticProcessAdapter(Protocol):
    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation: ...

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation: ...

    async def cancel(self, attempt_id: str) -> CancellationResult: ...


class StaticExternalExecutionPort(Protocol):
    async def invoke(
        self,
        request: StaticToolRequest,
        profile: StaticToolProfile,
        operation: Callable[
            [MonotonicActionDeadline], Awaitable[StaticToolObservation]
        ],
    ) -> ToolRunResult: ...


class StaticToolProfileResolverPort(Protocol):
    def resolve(self, profile_ref: StoredDataRef) -> StaticToolProfile: ...


class StaticAttemptPublisherPort(Protocol):
    def publish(
        self, request: StaticToolRequest, observation: StaticToolObservation
    ) -> PublishedStaticToolMaterial: ...


def validate_static_tool_profile_binding(
    request: StaticToolRequest,
    work: WorkExecutionState,
    decision: ActionDecision,
    resolved_profile: StaticToolProfile,
) -> None:
    """Close one authorized tool call over one exact resolved profile revision."""

    profile_ref = request.tool_profile_ref
    try:
        require_record_ref(profile_ref, "static_tool_profile")
        validate_exact_ref(
            profile_ref,
            resolved_profile.meta,
            content_hash(resolved_profile),
            analysis_id=work.meta.analysis_id,
        )
    except ValueError as error:
        raise ValueError("STATIC_TOOL_PROFILE_BINDING_MISMATCH") from error
    action = request.action
    if (
        resolved_profile.status != "APPROVED"
        or resolved_profile.purpose not in {"FIXTURE", "EVALUATION"}
        or work.work_type != "STATIC_TOOL"
        or action.action_type != "RUN_TOOL"
        or action.tool_name != resolved_profile.tool_name
        or action.work_ref != reference(work)
        or action.input_refs.count(profile_ref) != 1
        or work.input_refs.count(profile_ref) != 1
        or decision.action_ref != reference(action)
        or decision.decision != Decision.ALLOW
        or decision.checked_config_refs.count(profile_ref) != 1
    ):
        raise ValueError("STATIC_TOOL_PROFILE_BINDING_MISMATCH")
