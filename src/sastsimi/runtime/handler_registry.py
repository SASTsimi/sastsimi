"""Exact production work-handler registry."""

from __future__ import annotations

from collections.abc import Mapping

from sastsimi.contracts.work import WorkType
from sastsimi.ports.work_handler import WorkHandler


class HandlerRegistry:
    """Resolve one explicitly injected handler for every required work type."""

    def __init__(self, handlers: Mapping[WorkType, WorkHandler] | None = None) -> None:
        self._handlers: dict[WorkType, WorkHandler] = {}
        if handlers is not None:
            self.register_many(handlers)

    def register_many(self, handlers: Mapping[WorkType, WorkHandler]) -> None:
        if any(not isinstance(key, WorkType) for key in handlers):
            raise TypeError("WORK_HANDLER_TYPE_INVALID")
        invalid = tuple(
            key
            for key, handler in handlers.items()
            if not isinstance(handler, WorkHandler)
        )
        if invalid:
            raise TypeError("WORK_HANDLER_INVALID")
        duplicates = tuple(key for key in handlers if key in self._handlers)
        if duplicates:
            raise ValueError("WORK_HANDLER_ALREADY_REGISTERED")
        self._handlers.update(handlers)

    def validate_complete(self, required: tuple[WorkType, ...]) -> None:
        if len(required) != len(set(required)):
            raise ValueError("WORK_HANDLER_REQUIREMENT_DUPLICATED")
        required_set = set(required)
        registered_set = set(self._handlers)
        if required_set != registered_set:
            raise ValueError("WORK_HANDLER_REGISTRY_INCOMPLETE")

    def resolve(self, work_type: WorkType) -> WorkHandler:
        try:
            return self._handlers[work_type]
        except KeyError as error:
            raise LookupError("WORK_HANDLER_NOT_REGISTERED") from error

    @property
    def registered_work_types(self) -> tuple[WorkType, ...]:
        return tuple(kind for kind in WorkType if kind in self._handlers)


__all__ = ["HandlerRegistry"]
