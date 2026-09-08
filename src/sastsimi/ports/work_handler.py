from typing import Protocol, runtime_checkable

from .dto import WorkContext, WorkHandlerResult


@runtime_checkable
class WorkHandler(Protocol):
    async def execute(self, context: WorkContext) -> WorkHandlerResult: ...
