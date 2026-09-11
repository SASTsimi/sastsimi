"""Immutable candidates and published revision repository."""

from collections.abc import Callable

from sqlalchemy import Connection, insert, select

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.records import validate_revision
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.work import TransitionCommit
from sastsimi.ports.dto import Record, TransitionCommitRequest
from sastsimi.ports.trusted_evidence import TrustedEvidencePort, UnprovenEvidence

from . import models
from .codec import REF_ADAPTER, decode, encode, reference
from .database import Database


class SQLiteRecordStore:
    def __init__(
        self,
        database: Database,
        evidence: TrustedEvidencePort | None = None,
        finding_service_identity_ref: StoredDataRef | None = None,
    ) -> None:
        self.database = database
        self.evidence = evidence or UnprovenEvidence()
        self.finding_service_identity_ref = finding_service_identity_ref
        self.transition_writer: (
            Callable[[TransitionCommitRequest], TransitionCommit] | None
        ) = None

    def commit_transition(self, request: TransitionCommitRequest) -> TransitionCommit:
        if self.transition_writer is None:
            raise ValueError("Transition writer must be composed before committing")
        return self.transition_writer(request)

    def stage_record(self, record: Record) -> RecordRef:
        with self.database.write() as connection:
            return self.stage(connection, record)

    def stage(self, connection: Connection, record: Record) -> RecordRef:
        payload = encode(record)
        ref = reference(record)
        old = (
            connection.execute(
                select(models.records).where(
                    models.records.c.record_id == str(record.meta.record_id)
                )
            )
            .mappings()
            .first()
        )
        if old:
            if old["payload"] != payload:
                raise ValueError("RECORD_REVISION_MISMATCH: immutable record ID")
            return REF_ADAPTER.validate_json(old["ref"])
        connection.execute(
            insert(models.records).values(
                record_id=str(record.meta.record_id),
                logical_record_id=str(record.meta.logical_record_id),
                revision_number=record.meta.revision_number,
                kind=record.meta.record_type,
                content_hash=ref.content_hash,
                payload=payload,
                ref=canonical_bytes(ref).decode(),
            )
        )
        return ref

    def resolve(
        self, connection: Connection, ref: RecordRef, *, candidate: bool = False
    ) -> Record:
        query = select(models.records).where(
            models.records.c.record_id == str(ref.record_id)
        )
        if not candidate:
            query = query.join(models.record_revisions)
        row = connection.execute(query).mappings().first()
        if row is None:
            raise LookupError("Exact record is not published")
        if REF_ADAPTER.validate_json(row["ref"]) != ref:
            raise ValueError("RECORD_REVISION_MISMATCH: exact reference")
        record = decode(row["kind"], row["payload"])
        if content_hash(record) != ref.content_hash:
            raise ValueError("HASH_MISMATCH")
        return record

    def get_exact(self, ref: RecordRef) -> Record:
        if self.database.recovery_failed:
            raise ValueError("RECOVERY_FAILED")
        with self.database.engine.connect() as connection:
            return self.resolve(connection, ref)

    def is_revision_descendant(
        self,
        earlier_ref: RecordRef,
        later_ref: RecordRef,
        *,
        connection: Connection | None = None,
    ) -> bool:
        """Return whether the later ref descends from the earlier published ref."""

        if connection is None:
            with self.database.engine.connect() as own_connection:
                return self.is_revision_descendant(
                    earlier_ref, later_ref, connection=own_connection
                )
        earlier = self.resolve(connection, earlier_ref)
        current = self.resolve(connection, later_ref)
        if (
            type(earlier.meta) is not type(current.meta)
            or earlier.meta.logical_record_id != current.meta.logical_record_id
            or earlier.meta.record_type != current.meta.record_type
            or current.meta.revision_number < earlier.meta.revision_number
        ):
            return False
        visited: set[str] = set()
        while current.meta.record_id != earlier.meta.record_id:
            current_id = str(current.meta.record_id)
            if current_id in visited or current.meta.previous_record_id is None:
                return False
            visited.add(current_id)
            row = (
                connection.execute(
                    select(models.records)
                    .join(models.record_revisions)
                    .where(
                        models.records.c.record_id
                        == str(current.meta.previous_record_id)
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                return False
            previous = decode(row["kind"], row["payload"])
            validate_revision(previous.meta, current.meta)
            current = previous
        return reference(current) == earlier_ref

    def publish(self, connection: Connection, ref: RecordRef) -> None:
        record = self.resolve(connection, ref, candidate=True)
        meta = record.meta
        if connection.execute(
            select(models.record_revisions.c.record_id).where(
                models.record_revisions.c.record_id == str(meta.record_id)
            )
        ).first():
            return
        if meta.previous_record_id is not None:
            previous = (
                connection.execute(
                    select(models.records)
                    .join(models.record_revisions)
                    .where(models.records.c.record_id == str(meta.previous_record_id))
                )
                .mappings()
                .first()
            )
            if previous is None:
                raise ValueError("Missing published predecessor")
            validate_revision(decode(previous["kind"], previous["payload"]).meta, meta)
        connection.execute(
            insert(models.record_revisions).values(
                record_id=str(meta.record_id),
                logical_record_id=str(meta.logical_record_id),
                revision_number=meta.revision_number,
            )
        )
