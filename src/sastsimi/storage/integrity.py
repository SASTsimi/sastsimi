"""Full persisted-record, artifact and current-work closure verification."""

import hashlib
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from pydantic import BaseModel
from sqlalchemy import select

from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef
from sastsimi.contracts.work import TransitionCommit, WorkAttempt, WorkExecutionState

from . import models
from .artifact_store import LocalArtifactStore, sync_directory
from .codec import REF_ADAPTER, reference
from .repositories import SQLiteRecordStore


@dataclass(frozen=True)
class IntegrityReport:
    checked_artifacts: int
    quarantined_artifacts: int


def artifact_hashes(value: object) -> Iterator[str]:
    if isinstance(value, (StoredDataRef, RunStoredDataRef)):
        if value.record_id is None:
            yield value.content_hash
    elif isinstance(value, BaseModel):
        for name in type(value).model_fields:
            yield from artifact_hashes(getattr(value, name))
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from artifact_hashes(item)
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from artifact_hashes(item)


def verify(
    records: SQLiteRecordStore,
    artifacts: LocalArtifactStore,
    *,
    quarantine: bool = True,
) -> IntegrityReport:
    with records.database.engine.connect() as connection:
        connection.exec_driver_sql("BEGIN")
        digests = set(
            connection.execute(select(models.artifacts.c.content_hash)).scalars()
        )
        for digest in digests:
            if (
                hashlib.sha256(artifacts.path_for(digest).read_bytes()).hexdigest()
                != digest
            ):
                raise ValueError("HASH_MISMATCH")
        for wire in connection.execute(
            select(models.records.c.ref).join(models.record_revisions)
        ).scalars():
            record = records.resolve(connection, REF_ADAPTER.validate_json(wire))
            for digest in artifact_hashes(record):
                if digest not in digests:
                    if (
                        hashlib.sha256(
                            artifacts.path_for(digest).read_bytes()
                        ).hexdigest()
                        != digest
                    ):
                        raise ValueError("HASH_MISMATCH: nested artifact reference")
                    digests.add(digest)
        for row in connection.execute(select(models.work_states)).mappings():
            work = WorkExecutionState.model_validate_json(row["payload"])
            pointer = (
                connection.execute(
                    select(models.current_records).where(
                        models.current_records.c.logical_record_id
                        == str(work.meta.logical_record_id)
                    )
                )
                .mappings()
                .one()
            )
            if (
                row["state_version"],
                pointer["state_version"],
                pointer["record_id"],
            ) != (work.state_version, work.state_version, str(work.meta.record_id)):
                raise ValueError("CURRENT_POINTER_MISMATCH")
            records.resolve(connection, reference(work))
            if work.last_transition_commit_ref is not None and work.status.value in {
                "SUCCEEDED",
                "PARTIAL",
                "FAILED",
                "CANCELLED",
                "BLOCKED",
            }:
                commit = records.resolve(connection, work.last_transition_commit_ref)
                if (
                    not isinstance(commit, TransitionCommit)
                    or commit.state != "COMMITTED"
                    or commit.output_refs != work.output_refs
                    or commit.target_state_version != work.state_version
                ):
                    raise ValueError("COMMITTED_OUTPUT_MISMATCH")
                if commit.attempt_id is not None:
                    payload = connection.execute(
                        select(models.work_attempts.c.payload).where(
                            models.work_attempts.c.attempt_id == str(commit.attempt_id)
                        )
                    ).scalar_one()
                    attempt = WorkAttempt.model_validate_json(payload)
                    if (
                        attempt.output_refs != work.output_refs
                        or attempt.status == "RUNNING"
                    ):
                        raise ValueError("ATTEMPT_OUTPUT_MISMATCH")
                for ref in work.output_refs:
                    records.resolve(connection, ref)
    quarantined = 0
    if not quarantine:
        return IntegrityReport(len(digests), 0)
    for path in (artifacts.root / "sha256").iterdir():
        if path.is_file() and path.name not in digests:
            actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            # Orphans are never exposed; preserve even corrupt bytes for investigation.
            quarantine_name = (
                path.name
                if actual_digest == path.name
                else path.name + "-" + actual_digest
            )
            destination = artifacts.root / "quarantine" / quarantine_name
            if destination.exists():
                if destination.read_bytes() != path.read_bytes():
                    raise ValueError("Conflicting quarantined artifact")
                path.unlink()
            else:
                os.replace(path, destination)
            quarantined += 1
    sync_directory(artifacts.root / "quarantine")
    return IntegrityReport(len(digests), quarantined)
