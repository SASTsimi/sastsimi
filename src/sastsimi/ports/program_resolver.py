"""Trusted catalog lookup without inventing a persisted catalog contract."""

from typing import Protocol

from sastsimi.contracts.ids import ProgramId


class ProgramResolverPort(Protocol):
    def resolve(self, program_id: ProgramId) -> tuple[ProgramId, ...]: ...
