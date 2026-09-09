"""Exact fake reproduction adapter closure at the public port seam."""

from sastsimi.contracts.dynamic import SandboxEnvironment
from sastsimi.contracts.refs import reference
from sastsimi.ports.dto import SandboxPrepareRequest


def require_prepared_environment(
    request: SandboxPrepareRequest,
    configured: SandboxEnvironment,
    returned: SandboxEnvironment,
) -> SandboxEnvironment:
    """Accept only the exact configured environment for the exact request."""
    if returned != configured or returned.request_ref != reference(request.request):
        raise ValueError("FAKE_SANDBOX_ENVIRONMENT_MISMATCH")
    return returned
