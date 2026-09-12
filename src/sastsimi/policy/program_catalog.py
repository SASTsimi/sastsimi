"""Policy-local lookup for one versioned official program source."""

from __future__ import annotations

from sastsimi.contracts.ids import ProgramId
from sastsimi.ports.policy_catalog import ProgramCatalogEntry


class ProgramCatalog:
    """Exact policy entry lookup without changing analysis-start ProgramResolver."""

    def __init__(self, entries: tuple[ProgramCatalogEntry, ...]) -> None:
        self._entries = tuple(entries)

    def resolve_policy_entry(self, program_id: ProgramId) -> ProgramCatalogEntry:
        matches = tuple(
            entry for entry in self._entries if entry.program_id == program_id
        )
        if len(matches) != 1:
            raise ValueError("POLICY_PROGRAM_UNKNOWN_OR_AMBIGUOUS")
        return matches[0]


__all__ = ["ProgramCatalog", "ProgramCatalogEntry"]
