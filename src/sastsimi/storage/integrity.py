"""Full persisted-record, artifact and current-work closure verification."""

import hashlib
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from pydantic import BaseModel
from sqlalchemy import select

from sastsimi.contracts.analysis import AnalysisRunState
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
        for pointer in connection.execute(select(models.current_records)).mappings():
            wire = connection.execute(
                select(models.records.c.ref).where(
                    models.records.c.record_id == pointer["record_id"]
                )
            ).scalar_one()
            current = records.resolve(connection, REF_ADAPTER.validate_json(wire))
            expected_version = (
                current.state_version
                if isinstance(current, WorkExecutionState)
                else current.meta.revision_number
            )
            if (
                str(current.meta.logical_record_id) != pointer["logical_record_id"]
                or pointer["state_version"] != expected_version
            ):
                raise ValueError("CURRENT_POINTER_MISMATCH")
        journal_outputs: dict[str, tuple[int, str]] = {}
        for payload in connection.execute(
            select(models.transition_commits.c.payload).where(
                models.transition_commits.c.state == "COMMITTED"
            )
        ).scalars():
            journal = TransitionCommit.model_validate_json(payload)
            for ref in journal.output_refs:
                output = records.resolve(connection, ref)
                logical_id = str(output.meta.logical_record_id)
                entry = (output.meta.revision_number, str(output.meta.record_id))
                if (
                    logical_id not in journal_outputs
                    or journal_outputs[logical_id][0] < entry[0]
                ):
                    journal_outputs[logical_id] = entry
                output_pointer = (
                    connection.execute(
                        select(models.current_records).where(
                            models.current_records.c.logical_record_id
                            == str(output.meta.logical_record_id)
                        )
                    )
                    .mappings()
                    .first()
                )
                if (
                    output_pointer is None
                    or output_pointer["state_version"] < output.meta.revision_number
                ):
                    raise ValueError("CURRENT_POINTER_MISMATCH: committed output")
        for logical_id, expected in journal_outputs.items():
            actual = connection.execute(
                select(
                    models.current_records.c.state_version,
                    models.current_records.c.record_id,
                ).where(models.current_records.c.logical_record_id == logical_id)
            ).one()
            if tuple(actual) != expected:
                raise ValueError(
                    "CURRENT_POINTER_MISMATCH: unjournaled domain revision"
                )
        for row in connection.execute(select(models.analysis_runs)).mappings():
            state = AnalysisRunState.model_validate_json(row["payload"])
            exact_state = records.resolve(connection, reference(state))
            run_pointer = connection.execute(
                select(
                    models.current_records.c.record_id,
                    models.current_records.c.state_version,
                ).where(
                    models.current_records.c.logical_record_id
                    == str(state.meta.logical_record_id)
                )
            ).first()
            if (
                state != exact_state
                or str(state.meta.analysis_id) != row["analysis_id"]
                or run_pointer is None
                or tuple(run_pointer)
                != (str(state.meta.record_id), state.meta.revision_number)
            ):
                raise ValueError("CURRENT_POINTER_MISMATCH: analysis projection")
            for _, record_id in journal_outputs.values():
                wire = connection.execute(
                    select(models.records.c.ref).where(
                        models.records.c.record_id == record_id
                    )
                ).scalar_one()
                ref = REF_ADAPTER.validate_json(wire)
                if (
                    ref.data_kind == "code_workspace"
                    and getattr(ref, "analysis_id", None) == state.meta.analysis_id
                ):
                    if state.workspace_ref != ref:
                        raise ValueError(
                            "CURRENT_POINTER_MISMATCH: analysis workspace companion"
                        )
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
            if work.status.value == "RUNNING":
                active_payload = connection.execute(
                    select(models.work_attempts.c.payload).where(
                        models.work_attempts.c.attempt_id == str(work.active_attempt_id)
                    )
                ).scalar()
                if active_payload is None:
                    raise ValueError("ATTEMPT_NOT_ACTIVE")
                active = WorkAttempt.model_validate_json(active_payload)
                if active.status.value != "RUNNING" or active.work_id != work.work_id:
                    raise ValueError("ATTEMPT_NOT_ACTIVE")
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
    for path in (artifacts.root / "sha256").glob("*/*"):
        claimed_digest = path.parent.name + path.name
        if path.is_file() and claimed_digest not in digests:
            actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            # Orphans are never exposed; preserve even corrupt bytes for investigation.
            quarantine_name = (
                claimed_digest
                if actual_digest == claimed_digest
                else claimed_digest + "-" + actual_digest
            )
            destination = artifacts.paths.quarantine / quarantine_name
            if destination.exists():
                if destination.read_bytes() != path.read_bytes():
                    raise ValueError("Conflicting quarantined artifact")
                path.unlink()
            else:
                os.replace(path, destination)
            quarantined += 1
    sync_directory(artifacts.paths.quarantine)
    return IntegrityReport(len(digests), quarantined)
