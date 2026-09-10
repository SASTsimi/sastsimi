"""Exact fake reproduction adapter closure at the public port seam."""

from sastsimi.contracts.dynamic import (
    CleanupResult,
    SandboxCommandRecord,
    SandboxEnvironment,
)
from sastsimi.contracts.refs import reference
from sastsimi.ports.dto import (
    ApprovedSandboxCommand,
    SandboxCleanupRequest,
    SandboxPrepareRequest,
)


def require_prepared_environment(
    request: SandboxPrepareRequest,
    configured: SandboxEnvironment,
    returned: SandboxEnvironment,
) -> SandboxEnvironment:
    """Accept only the exact configured environment for the exact request."""
    if returned != configured or returned.request_ref != reference(request.request):
        raise ValueError("FAKE_SANDBOX_ENVIRONMENT_MISMATCH")
    return returned


def require_executed_command(
    request: ApprovedSandboxCommand,
    configured: SandboxCommandRecord,
    returned: SandboxCommandRecord,
) -> SandboxCommandRecord:
    if returned != configured or returned.tool_request_ref != reference(
        request.tool_request
    ):
        raise ValueError("FAKE_SANDBOX_COMMAND_MISMATCH")
    return returned


def require_cleanup_result(
    request: SandboxCleanupRequest,
    configured: CleanupResult,
    returned: CleanupResult,
) -> CleanupResult:
    if returned != configured or returned.request_ref != reference(request.request):
        raise ValueError("FAKE_SANDBOX_CLEANUP_MISMATCH")
    return returned
