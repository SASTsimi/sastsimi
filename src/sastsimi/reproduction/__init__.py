"""Dynamic reproduction composition boundary over sandbox/provider ports."""

from .composition import T11Services, compose_t11_services
from .fake_closure import (
    require_cleanup_result,
    require_executed_command,
    require_prepared_environment,
)
from .production import (
    DynamicSandboxAuthorization,
    ProductionDynamicExecutor,
    ProductionDynamicWorkflow,
    RuntimeDynamicRecordSink,
)
from .service import (
    DynamicOperationalError,
    DynamicReproductionWorkflowService,
    DynamicSandboxSession,
    DynamicStageAuthorizations,
    DynamicWorkflowFailure,
)

__all__ = [
    "require_cleanup_result",
    "require_executed_command",
    "require_prepared_environment",
    "DynamicOperationalError",
    "DynamicReproductionWorkflowService",
    "DynamicSandboxAuthorization",
    "DynamicSandboxSession",
    "DynamicStageAuthorizations",
    "DynamicWorkflowFailure",
    "ProductionDynamicExecutor",
    "ProductionDynamicWorkflow",
    "RuntimeDynamicRecordSink",
    "T11Services",
    "compose_t11_services",
]
