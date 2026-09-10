"""Deterministic sandbox adapter with exact configured responses."""

from collections.abc import Mapping
from types import MappingProxyType

from sastsimi.contracts.refs import RecordRef, reference
from sastsimi.ports.dto import (
    ApprovedSandboxCommand,
    CleanupResult,
    SandboxCleanupRequest,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPrepareRequest,
)


class FakeSandboxAdapter:
    def __init__(
        self,
        *,
        environments: Mapping[RecordRef, SandboxEnvironment],
        commands: Mapping[RecordRef, SandboxCommandRecord],
        cleanups: Mapping[RecordRef, CleanupResult],
    ) -> None:
        self.environments = MappingProxyType(dict(environments))
        self.commands = MappingProxyType(dict(commands))
        self.cleanups = MappingProxyType(dict(cleanups))

    async def prepare(self, request: SandboxPrepareRequest) -> SandboxEnvironment:
        try:
            return self.environments[reference(request.request)]
        except KeyError as error:
            raise ValueError("FAKE_SANDBOX_PREPARE_NOT_CONFIGURED") from error

    async def execute(self, request: ApprovedSandboxCommand) -> SandboxCommandRecord:
        try:
            return self.commands[reference(request.tool_request)]
        except KeyError as error:
            raise ValueError("FAKE_SANDBOX_COMMAND_NOT_CONFIGURED") from error

    async def cleanup(self, request: SandboxCleanupRequest) -> CleanupResult:
        try:
            return self.cleanups[reference(request.request)]
        except KeyError as error:
            raise ValueError("FAKE_SANDBOX_CLEANUP_NOT_CONFIGURED") from error
