from typing import Protocol, runtime_checkable

from .dto import OfficialPolicyFetchRequest, OfficialPolicySource


@runtime_checkable
class PolicySourcePort(Protocol):
    async def fetch_official(
        self, request: OfficialPolicyFetchRequest
    ) -> OfficialPolicySource: ...
