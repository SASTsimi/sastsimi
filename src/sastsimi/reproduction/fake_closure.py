"""Exact fake reproduction adapter closure at the public port seam."""

from sastsimi.contracts._domain import exact
from sastsimi.contracts.dynamic import (
    AgentLogEvent,
    CleanupResult,
    PoCCandidate,
    SandboxCommandRecord,
    SandboxEnvironment,
    is_poc_execution_command,
)
from sastsimi.contracts.refs import reference
from sastsimi.ports.dto import (
    ApprovedSandboxCommand,
    SandboxCleanupRequest,
    SandboxPrepareRequest,
)
from sastsimi.sandbox.cleanup import owned_container_resource_ref


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
    expected_resource_refs = tuple(
        owned_container_resource_ref(
            container_id=environment.container_instance_id,
            meta=environment.meta,
        )
        for environment in request.environments
    )
    if (
        request.resource_refs != expected_resource_refs
        or configured.resource_refs != expected_resource_refs
        or returned.resource_refs != expected_resource_refs
    ):
        raise ValueError("FAKE_SANDBOX_CLEANUP_RESOURCE_MISMATCH")
    return returned


def require_poc_execution_events(
    candidate: PoCCandidate,
    command: SandboxCommandRecord,
    events: tuple[AgentLogEvent, ...],
) -> tuple[AgentLogEvent, ...]:
    """Reject fake PoC logs that do not prove the exact executed candidate."""
    try:
        if not is_poc_execution_command(command) or tuple(
            event.event_type for event in events
        ) != ("POC_EXECUTION_STARTED", "POC_EXECUTION_FINISHED"):
            raise ValueError("FAKE_POC_EXECUTION_PROVENANCE_MISMATCH")
        for event in events:
            if event.poc_candidate_ref is None or event.command_ref is None:
                raise ValueError("FAKE_POC_EXECUTION_PROVENANCE_MISMATCH")
            exact(event.poc_candidate_ref, candidate, command.meta)
            exact(event.command_ref, command, command.meta)
            if (
                event.action_id != command.action_id
                or event.tool_request_ref != command.tool_request_ref
                or event.command_digest != command.command_digest
                or event.redaction_status != command.redaction_status
                or event.environment_ref != command.environment_ref
                or event.environment_recipe_ref != command.environment_recipe_ref
                or event.input_refs != (candidate.content_ref,)
            ):
                raise ValueError("FAKE_POC_EXECUTION_PROVENANCE_MISMATCH")
    except ValueError as error:
        raise ValueError("FAKE_POC_EXECUTION_PROVENANCE_MISMATCH") from error
    return events
