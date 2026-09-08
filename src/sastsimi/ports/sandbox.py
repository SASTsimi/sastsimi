from typing import Protocol, runtime_checkable

from .dto import (
    ApprovedSandboxCommand,
    CleanupResult,
    SandboxCleanupRequest,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPrepareRequest,
)


@runtime_checkable
class SandboxPort(Protocol):
    async def prepare(self, request: SandboxPrepareRequest) -> SandboxEnvironment: ...
    async def execute(
        self, request: ApprovedSandboxCommand
    ) -> SandboxCommandRecord: ...
    async def cleanup(self, request: SandboxCleanupRequest) -> CleanupResult: ...
