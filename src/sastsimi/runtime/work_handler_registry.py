"""Concrete work-handler registration without worker scheduling policy."""

from __future__ import annotations

from collections.abc import Mapping

from sastsimi.contracts.work import WorkType
from sastsimi.ports.work_handler import WorkHandler


class WorkHandlerRegistry:
    """Install and resolve one exact handler for each work type.

    Registration is an application-composition concern. Polling, concurrency,
    cancellation, and retry policy remain outside this registry and belong to
    the T14 production worker.
    """

    def __init__(self) -> None:
        self._handlers: dict[WorkType, WorkHandler] = {}

    def register_many(self, handlers: Mapping[WorkType, WorkHandler]) -> None:
        duplicates = tuple(kind for kind in handlers if kind in self._handlers)
        if duplicates:
            raise ValueError("WORK_HANDLER_ALREADY_REGISTERED")
        self._handlers.update(handlers)

    def require(self, work_type: WorkType) -> WorkHandler:
        try:
            return self._handlers[work_type]
        except KeyError as error:
            raise LookupError("WORK_HANDLER_NOT_REGISTERED") from error

    @property
    def registered_work_types(self) -> tuple[WorkType, ...]:
        return tuple(self._handlers)
