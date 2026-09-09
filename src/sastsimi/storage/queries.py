"""Coherent published/current snapshots; candidates never appear in either view."""

from sqlalchemy import select

from sastsimi.ports.dto import Record

from . import models
from .codec import REF_ADAPTER
from .repositories import SQLiteRecordStore


class RuntimeQueries:
    def __init__(self, records: SQLiteRecordStore) -> None:
        self.records = records

    def read(self, analysis_id: str, kind: str | None) -> tuple[Record, ...]:
        query = select(models.records.c.ref).join(
            models.record_revisions,
            models.record_revisions.c.record_id == models.records.c.record_id,
        )
        if kind is not None:
            query = query.join(
                models.current_records,
                models.current_records.c.record_id == models.records.c.record_id,
            ).where(models.records.c.kind == kind)
        query = query.order_by(models.records.c.record_id)
        with self.records.database.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN")
            result = []
            for wire in connection.execute(query).scalars():
                record = self.records.resolve(
                    connection, REF_ADAPTER.validate_json(wire)
                )
                if str(getattr(record.meta, "analysis_id", "")) == analysis_id:
                    result.append(record)
            return tuple(result)

    def current_records(self, analysis_id: str, kind: str) -> tuple[Record, ...]:
        return self.read(analysis_id, kind)

    def published_records(self, analysis_id: str) -> tuple[Record, ...]:
        return self.read(analysis_id, None)
