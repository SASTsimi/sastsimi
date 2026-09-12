"""Worker entry point for a claimed policy-preparation attempt."""

from sastsimi.ports.dto import WorkContext, WorkHandlerResult

from .preparation_service import PolicyPreparationService


class PolicyWorkHandler:
    def __init__(self, service: PolicyPreparationService) -> None:
        self._service = service

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        result = await self._service.prepare(context)
        return WorkHandlerResult(result.completed_work.output_refs)


__all__ = ["PolicyWorkHandler"]
