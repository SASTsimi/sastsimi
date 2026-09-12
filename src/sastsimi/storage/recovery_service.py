"""SQLite adapter: Startup verification and conservative local lease recovery."""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from sastsimi.contracts.actions import (
    ActionRequest,
    ActionType,
    Decision,
    RequesterRole,
)
from sastsimi.contracts.ids import (
    ActionId,
    LogicalRecordId,
    RecordId,
    TransitionCommitId,
    TransitionId,
)
from sastsimi.contracts.refs import BudgetScopeRef
from sastsimi.contracts.work import (
    CommitState,
    CommitTargetStatus,
    StateTransition,
    TransitionCommit,
    TransitionTargetStatus,
    WorkExecutionState,
)
from sastsimi.ports.dto import TransitionCommitRequest
from sastsimi.ports.runtime_store import RecoveryReport
from sastsimi.storage import models
from sastsimi.storage.codec import reference
from sastsimi.storage.integrity import verify

from .lease_recovery import uncertain
from .run_control import cancel_latched
from .transition_service import TransitionService


class RecoveryService:
    def __init__(
        self,
        transitions: TransitionService,
        recovery_identity_ref: BudgetScopeRef | None = None,
    ) -> None:
        self.transitions, self.recovery_identity_ref = (
            transitions,
            recovery_identity_ref,
        )

    def recover(self) -> RecoveryReport:
        service = self.transitions.works
        database = service.records.database
        try:
            database.check_ready()
            verify(service.records, self.transitions.artifacts, quarantine=False)
            database.recovery_failed = False
            # Replay before orphan handling so renamed PREPARED files stay available.
            self.transitions.recover_prepared()
            integrity = verify(service.records, self.transitions.artifacts)
            blocked = self.expired_leases()
            verify(service.records, self.transitions.artifacts)
            database.recovery_failed = False
            return RecoveryReport(
                integrity.checked_artifacts, integrity.quarantined_artifacts, blocked
            )
        except (ValueError, OSError, LookupError, SQLAlchemyError) as error:
            database.recovery_failed = True
            raise ValueError("RECOVERY_FAILED: " + str(error)) from error

    def expired_leases(self) -> int:
        service = self.transitions.works
        with service.records.database.engine.connect() as connection:
            expired = [
                WorkExecutionState.model_validate_json(row["payload"])
                for row in connection.execute(
                    select(models.work_states).where(
                        models.work_states.c.status == "RUNNING"
                    )
                ).mappings()
                if uncertain(
                    connection, WorkExecutionState.model_validate_json(row["payload"])
                )
                or (
                    row["lease_expires_at"] is not None
                    and datetime.fromisoformat(row["lease_expires_at"])
                    <= service.clock.now()
                )
            ]
        blocked = 0
        for work in expired:
            if self._cancel_latched(work):
                # The cancellation owner must close only exact persisted targets.
                # A recovery transition to BLOCKED would race that path and is
                # rejected by the same durable latch in TransitionService.
                continue
            try:
                self.block_uncertain(work)
            except ValueError as error:
                # Cancellation may win after the read above.  Its durable latch
                # still prevents scheduling; do not turn that valid race into a
                # global recovery failure.
                if str(error) == "RUN_CANCELLED" and self._cancel_latched(work):
                    continue
                raise
            blocked += 1
        return blocked

    def _cancel_latched(self, work: WorkExecutionState) -> bool:
        database = self.transitions.works.records.database
        with database.engine.connect() as connection:
            return cancel_latched(connection, str(work.meta.analysis_id))

    def block_uncertain(self, work: WorkExecutionState) -> None:
        service = self.transitions.works
        identity = self.recovery_identity_ref
        if identity is None:
            raise ValueError("Recovery identity is required to close an expired lease")
        now = service.clock.now()
        with service.records.database.engine.connect() as connection:
            cause = (
                "RECOVERY_FAILED" if uncertain(connection, work) else "LEASE_EXPIRED"
            )

        def meta(kind: str) -> dict[str, object]:
            data = work.meta.model_dump()
            data.update(
                record_id=service.ids.new(RecordId),
                logical_record_id=service.ids.new(LogicalRecordId),
                record_type=kind,
                revision_number=1,
                previous_record_id=None,
                created_at=now,
            )
            if "attempt_id" in data:
                data["attempt_id"] = work.active_attempt_id
            return data

        action = ActionRequest.model_validate(
            dict(
                meta=meta("action_request"),
                action_id=service.ids.new(ActionId),
                requested_by=RequesterRole.RECOVERY,
                requester_identity_ref=identity,
                action_type=ActionType.CHANGE_WORK_STATE,
                work_ref=reference(work),
                expected_state_version=work.state_version,
                expected_verification_generation=None,
                generation_restart_reason=None,
                generation_restart_basis_refs=(),
                input_refs=(),
                dynamic_request_ref=None,
                reproduction_plan_ref=None,
                result_kind=None,
                candidate_result_ref=None,
                llm_call_spec_ref=None,
                tool_name=None,
                file_paths=(),
                provider_profile_ref=None,
                session_mode=None,
                sandbox_profile_ref=None,
                resource_profile_ref=None,
                run_policy_state_ref=None,
                image_digest=None,
                network_targets=(),
                resource_limits=None,
                reason=cause,
                requested_at=now,
            )
        )
        decision = service.validator.authorize(action, work)
        if decision.decision != Decision.ALLOW:
            raise ValueError("Recovery identity authorization denied")
        transition = StateTransition.model_validate(
            dict(
                meta=meta("state_transition"),
                transition_id=service.ids.new(TransitionId),
                work_id=work.work_id,
                action_decision_ref=reference(decision),
                from_status=work.status,
                to_status=TransitionTargetStatus.BLOCKED,
                expected_state_version=work.state_version,
                new_state_version=work.state_version + 1,
                attempt_id=work.active_attempt_id,
                cause=cause,
                output_refs=(),
                gap_ids=(),
                error_ids=(),
                dedupe_key=work.dedupe_key,
                created_at=now,
            )
        )
        commit = TransitionCommit.model_validate(
            dict(
                meta=meta("transition_commit"),
                transition_commit_id=service.ids.new(TransitionCommitId),
                work_id=work.work_id,
                transition_ref=reference(transition),
                expected_state_version=work.state_version,
                target_state_version=work.state_version + 1,
                attempt_id=work.active_attempt_id,
                target_status=CommitTargetStatus.BLOCKED,
                output_refs=(),
                gap_ids=(),
                error_ids=(),
                state=CommitState.PREPARED,
                prepared_at=now,
                committed_at=None,
                abort_reason=None,
            )
        )
        self.transitions.commit(TransitionCommitRequest(transition, commit, ()))
