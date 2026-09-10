"""Read-only runtime snapshots for workflow projections and local CLI queries."""

from typing import Protocol

from .dto import Record


class RuntimeQueryPort(Protocol):
    def current_records(self, analysis_id: str, kind: str) -> tuple[Record, ...]: ...
    def published_records(self, analysis_id: str) -> tuple[Record, ...]: ...
