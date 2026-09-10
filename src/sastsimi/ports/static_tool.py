from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Protocol, runtime_checkable

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import StaticToolProfile

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
