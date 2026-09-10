"""Atomically claim owner SAVE_RESULT and publish without ending the attempt."""

from collections.abc import Callable

from sqlalchemy import insert, select

from sastsimi.contracts.actions import ActionType
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import WorkAttempt
from sastsimi.ports.dto import Record

from . import models
from .codec import encode
from .intermediate_policy import validate_intermediate_owner
from .output_closures import read_outputs
from .transition_service import TransitionService


class IntermediatePublicationService:
    def __init__(
        self,
        transitions: TransitionService,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.transitions = transitions
        self.checkpoint = checkpoint or (lambda stage: None)

    def publish(
        self,
        work_id: str,
        decision_ref: RecordRef,
        outputs: tuple[Record, ...],
    ) -> tuple[RecordRef, ...]:
        works = self.transitions.works
        records = works.records
        if not outputs:
            raise ValueError("OUTPUT_BINDING_MISMATCH")
        refs = tuple(records.stage_record(record) for record in outputs)
        artifacts = self.transitions.artifacts
        digests = tuple(
            artifacts.promote(
                artifacts.stage_bytes(
                    encode(record).encode(),
                    "application/json",
                )
            )
            for record in outputs
        )
        self.checkpoint("artifacts_promoted")
        with records.database.write() as connection:
            work = works.get(work_id, connection)
            if work.status != "RUNNING" or work.active_attempt_id is None:
                raise ValueError("ATTEMPT_NOT_ACTIVE")
            attempt_row = (
                connection.execute(
                    select(models.work_attempts).where(
                        models.work_attempts.c.attempt_id
                        == str(work.active_attempt_id),
                    )
                )
                .mappings()
                .one_or_none()
            )
            if attempt_row is None or (
                attempt_row["status"] != "RUNNING" or attempt_row["work_id"] != work_id
            ):
                raise ValueError("ATTEMPT_NOT_ACTIVE")
            attempt = WorkAttempt.model_validate_json(attempt_row["payload"])
            if attempt.status != "RUNNING" or attempt.work_id != work.work_id:
                raise ValueError("ATTEMPT_NOT_ACTIVE")
            _, action = works.validator.check(
                connection,
                decision_ref,
                ActionType.SAVE_RESULT,
                work,
            )
            if len(set(refs)) != len(refs) or set(refs) != set(
                read_outputs(connection, action, decision_ref)
            ):
                raise ValueError("OUTPUT_BINDING_MISMATCH")
            for record in outputs:
                if not isinstance(record, ContractModel):
                    raise ValueError("OUTPUT_SCHEMA_MISMATCH")
                validate_intermediate_owner(record, action, work)
                if any(
                    getattr(record.meta, name, None) != getattr(work.meta, name, None)
                    for name in (
                        "analysis_id",
                        "workspace_id",
                        "commit_id",
                        "hypothesis_id",
                    )
                ):
                    raise ValueError("OUTPUT_SCOPE_MISMATCH")
                if getattr(record.meta, "attempt_id", None) != work.active_attempt_id:
                    raise ValueError("ATTEMPT_NOT_ACTIVE")
                current_id = connection.execute(
                    select(models.current_records.c.record_id).where(
                        models.current_records.c.logical_record_id
                        == str(record.meta.logical_record_id),
                    )
                ).scalar()
                previous = record.meta.previous_record_id
                if current_id != (str(previous) if previous is not None else None):
                    raise ValueError("STALE_RESULT: intermediate predecessor changed")
            claimed = works.validator.claim(
                connection,
                decision_ref,
                ActionType.SAVE_RESULT,
                work,
            )
            for ref in refs:
                records.publish(connection, ref)
                self.transitions.publish_pointer(connection, ref)
            for digest in digests:
                if not connection.execute(
                    select(models.artifacts.c.content_hash).where(
                        models.artifacts.c.content_hash == digest,
                    )
                ).first():
                    connection.execute(
                        insert(models.artifacts).values(
                            content_hash=digest,
                            path="sha256/" + digest[:2] + "/" + digest[2:],
                        )
                    )
            works.validator.record_outcome(connection, claimed, refs)
            self.checkpoint("before_commit")
        self.checkpoint("committed")
        return refs
