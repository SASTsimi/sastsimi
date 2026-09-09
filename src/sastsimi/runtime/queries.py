"""Read-only snapshots; exact input resolution remains a distinct API."""

from sastsimi.ports.dto import Record
from sastsimi.ports.runtime_query import RuntimeQueryPort


class RuntimeQueries:
    def __init__(self, store: RuntimeQueryPort) -> None:
        self.store = store

    def current_records(self, analysis_id: str, kind: str) -> tuple[Record, ...]:
        return self.store.current_records(analysis_id, kind)

    def published_records(self, analysis_id: str) -> tuple[Record, ...]:
        return self.store.published_records(analysis_id)
