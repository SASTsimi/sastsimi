"""Validated production handler mapping for every canonical work type."""

from __future__ import annotations

from collections.abc import Iterable
from types import MappingProxyType

from sastsimi.contracts.work import WorkType
from sastsimi.ports.work_handler import WorkHandler


class ProductionHandlerRegistry:
    """Resolve exactly one injected T08-T13 handler for each work type."""

    def __init__(self, entries: Iterable[tuple[WorkType, WorkHandler]]) -> None:
        handlers: dict[WorkType, WorkHandler] = {}
        for work_type, handler in entries:
            if work_type in handlers:
                raise ValueError("WORK_HANDLER_MAPPING_DUPLICATED")
            handlers[work_type] = handler
        self._handlers = MappingProxyType(handlers)

    def validate_complete(self, required: tuple[WorkType, ...]) -> None:
        if len(required) != len(set(required)):
            raise ValueError("WORK_HANDLER_REQUIREMENTS_DUPLICATED")
        expected = set(required)
        if set(self._handlers) != expected:
            raise ValueError("WORK_HANDLER_MAPPING_INCOMPLETE")

    def resolve(self, work_type: WorkType) -> WorkHandler:
        try:
            return self._handlers[work_type]
        except KeyError as error:
            raise LookupError("WORK_HANDLER_NOT_REGISTERED") from error


__all__ = ["ProductionHandlerRegistry"]
