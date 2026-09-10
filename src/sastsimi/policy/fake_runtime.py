"""Deterministic policy source adapter used through the external-call service."""

from dataclasses import dataclass

from sastsimi.ports.dto import OfficialPolicyFetchRequest, OfficialPolicySource


@dataclass(frozen=True)
class FakePolicySource:
    source: OfficialPolicySource

    async def fetch_official(
        self, request: OfficialPolicyFetchRequest
    ) -> OfficialPolicySource:
        if (
            request.action.action_type != "FETCH_POLICY"
            or self.source.source_check.source_ref not in request.action.input_refs
            or request.source_config_ref not in request.action.input_refs
        ):
            raise ValueError("FAKE_POLICY_FETCH_REQUEST_MISMATCH")
        return self.source
