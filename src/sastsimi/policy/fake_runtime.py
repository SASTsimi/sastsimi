"""Deterministic policy source adapter used through the external-call service."""

from dataclasses import dataclass

from sastsimi.contracts.refs import StoredDataRef


@dataclass(frozen=True)
class FakePolicySource:
    source_ref: StoredDataRef

    async def fetch(self) -> StoredDataRef:
        return self.source_ref
