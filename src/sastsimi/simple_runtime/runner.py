from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from typing import Literal, Protocol
from uuid import uuid4

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import ActivityKind

from .artifacts import SimpleArtifactRepository
from .models import (
    HYPOTHESIS_STAGES,
    STAGE_ORDER,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
    terminal_gate_outcome,
    terminal_initial_outcome,
    terminal_poc_outcome,
)
from .recovery import (
    MAX_RECOVERY_ATTEMPTS,
    RecoveryAction,
    RecoveryCoordinator,
)
from .store import SimpleCheckpointStore


class SimpleStageHandler(Protocol):
    async def __call__(
        self,
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult: ...


class StageBlocked(Exception):
    def __init__(self, failure: StageFailure) -> None:
        super().__init__(failure.safe_message)
        self.failure = failure


class StageFailed(Exception):
    def __init__(self, failure: StageFailure) -> None:
        super().__init__(failure.safe_message)
        self.failure = failure


class RunOutcome(ContractModel):
    current_stage: SimpleStage
    status: StageStatus
    error_code: str | None = None
    hypothesis_id: str | None = None
    attempt_id: str | None = None


class SimpleRuntimeRunner:
    def __init__(
        self,
        store: SimpleCheckpointStore,
        handlers: Mapping[SimpleStage, SimpleStageHandler],
        *,
        recovery: RecoveryCoordinator | None = None,
        policy_snapshot_ref: StoredDataRef | None = None,
        codex_invalid_output_resume: bool = False,
        cleanup_artifacts: SimpleArtifactRepository | None = None,
        offline_base_ready: Callable[[], Awaitable[bool]] | None = None,
    ) -> None:
        self.store = store
        self.handlers = handlers
        self.recovery = recovery
        self.policy_snapshot_ref = policy_snapshot_ref
        self.codex_invalid_output_resume = codex_invalid_output_resume
        self.cleanup_artifacts = cleanup_artifacts
        self.offline_base_ready = offline_base_ready

    async def resume_analysis(self, identity: CheckpointIdentity) -> RunOutcome:
        return await self.resume_hypothesis(identity)

    async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
        if self.recovery is None:
            self._reset_incomplete_poc_attempt(identity)
        while True:
            restart_requested = False
            for stage in HYPOTHESIS_STAGES:
                final = self.store.get(
                    identity,
                    SimpleStage.VERIFICATION_FINAL_DONE,
                )
                if (
                    final is not None
                    and final.status is StageStatus.SUCCEEDED
                    and final.verdict == "HOLD"
                    and stage
                    in {
                        SimpleStage.CWE_DONE,
                        SimpleStage.TECH_GATE_DONE,
                        SimpleStage.SCOPE_GATE_DONE,
                        SimpleStage.FINDING_DONE,
                        SimpleStage.REPORT_DONE,
                    }
                ):
                    continue
                existing = self.store.get(identity, stage)
                if existing is not None and self._has_prior_poc_recovery_decision(
                    existing
                ):
                    promoted = self._promote_stopped_inconclusive_poc(existing)
                    if promoted is not None:
                        return promoted
                    return RunOutcome(
                        current_stage=stage,
                        status=existing.status,
                        error_code=existing.error_code,
                        attempt_id=existing.attempt_id,
                    )
                if (
                    stage is SimpleStage.POC_EXECUTION_DONE
                    and existing is not None
                    and existing.status in {StageStatus.BLOCKED, StageStatus.FAILED}
                    and not existing.retryable
                    and not (
                        self.codex_invalid_output_resume
                        and existing.error_code == "INVALID_OUTPUT"
                        and existing.attempt_number < MAX_RECOVERY_ATTEMPTS
                    )
                ):
                    # A version bump cannot authorize replaying a terminal PoC.
                    return RunOutcome(
                        current_stage=stage,
                        status=existing.status,
                        error_code=existing.error_code,
                        attempt_id=existing.attempt_id,
                    )
                if (
                    existing is not None
                    and existing.stage_version != STAGE_VERSION[stage]
                ):
                    if (
                        stage is SimpleStage.VERIFICATION_INITIAL_DONE
                        and existing.status is StageStatus.BLOCKED
                        and existing.error_code == "POC_OFFLINE_BASE_IMAGE_UNAVAILABLE"
                    ):
                        # The guarded retry below also handles legacy stage versions.
                        pass
                    elif (
                        stage is SimpleStage.VERIFICATION_INITIAL_DONE
                        and existing.status is StageStatus.BLOCKED
                        and existing.error_code == "POC_OFFLINE_REQUIREMENT_UNSUPPORTED"
                    ):
                        if existing.attempt_number >= MAX_RECOVERY_ATTEMPTS:
                            return RunOutcome(
                                current_stage=stage,
                                status=existing.status,
                                error_code=existing.error_code,
                                attempt_id=existing.attempt_id,
                            )
                        existing = existing.model_copy(
                            update={
                                "stage_version": STAGE_VERSION[stage],
                                "status": StageStatus.PENDING,
                                "output_refs": (),
                                "attempt_id": None,
                                "error_code": None,
                                "retryable": False,
                            }
                        )
                        self.store.replace_from(existing)
                    elif (
                        stage is SimpleStage.POC_EXECUTION_DONE
                        and existing.status in {StageStatus.BLOCKED, StageStatus.FAILED}
                        and existing.error_code == "INVALID_OUTPUT"
                        and self.codex_invalid_output_resume
                        and existing.attempt_number < MAX_RECOVERY_ATTEMPTS
                    ):
                        # Keep the exhausted-attempt boundary across a stage
                        # version upgrade; the old failure is not a new first
                        # attempt. replace_from also clears downstream work.
                        existing = existing.model_copy(
                            update={
                                "stage_version": STAGE_VERSION[stage],
                                "status": StageStatus.PENDING,
                                "output_refs": (),
                                "attempt_id": None,
                                "error_code": None,
                                "retryable": False,
                            }
                        )
                        self.store.replace_from(existing)
                    else:
                        self.store.invalidate_from(
                            identity, stage, new_inputs=existing.input_refs
                        )
                        existing = None
                if existing is not None and (
                    self.recovery is not None
                    or existing.status in {StageStatus.BLOCKED, StageStatus.FAILED}
                    and (
                        not existing.retryable
                        or self.codex_invalid_output_resume
                        and existing.error_code == "INVALID_OUTPUT"
                    )
                ):
                    recovery_outcome = await self._recover_existing(existing)
                    if recovery_outcome is False:
                        pass
                    elif recovery_outcome is None:
                        restart_requested = True
                        break
                    else:
                        return recovery_outcome
                input_refs = self.store.input_refs_for(identity, stage)
                if (
                    stage is SimpleStage.SCOPE_GATE_DONE
                    and existing is None
                    and self.policy_snapshot_ref is not None
                ):
                    input_refs = tuple(
                        dict.fromkeys((*input_refs, self.policy_snapshot_ref))
                    )
                if self.store.reusable(identity, stage, input_refs):
                    reusable = self.store.require(identity, stage)
                    if terminal_initial_outcome(reusable) is not None:
                        return self._verified_initial_terminal(reusable)
                    if (
                        terminal_poc_outcome(reusable) is not None
                        or reusable.poc_stop_decision_ref is not None
                    ):
                        return self._verified_poc_terminal(reusable)
                    if (
                        stage is SimpleStage.VERIFICATION_FINAL_DONE
                        and reusable.verdict == "FALSE"
                    ):
                        return RunOutcome(
                            current_stage=stage,
                            status=StageStatus.SUCCEEDED,
                        )
                    gate_action = self._gate_action(reusable)
                    if gate_action == "restart":
                        restart_requested = True
                        break
                    if isinstance(gate_action, RunOutcome):
                        return gate_action
                    continue
                existing = self.store.get(identity, stage)
                prior = self.store.prior(identity, stage)
                preceding = next(reversed(prior.values()), None)
                inherit_from = (
                    existing
                    if existing is not None
                    and existing.recipe_ref is not None
                    and existing.image_digest is not None
                    else preceding
                )
                attempt_id = (
                    preceding.attempt_id
                    if stage is SimpleStage.POC_EXECUTION_DONE
                    and preceding is not None
                    and preceding.stage is SimpleStage.POC_CANDIDATE_DONE
                    and preceding.attempt_id is not None
                    and existing is None
                    else uuid4().hex
                )
                retry_seed = (
                    existing
                    if existing is not None and existing.status is StageStatus.PENDING
                    else None
                )
                if retry_seed is None:
                    self.store.invalidate_from(identity, stage, new_inputs=input_refs)
                checkpoint = self.store.mark_running(
                    identity,
                    stage,
                    input_refs,
                    attempt_id=attempt_id,
                    inherit_from=inherit_from,
                )
                handler = self.handlers.get(stage)
                if handler is None:
                    failure = StageFailure(
                        code="STAGE_HANDLER_MISSING",
                        retryable=False,
                        safe_message=f"No handler registered for {stage.value}",
                    )
                    self.store.mark_failure(
                        checkpoint,
                        failure,
                        StageStatus.FAILED,
                    )
                    return RunOutcome(
                        current_stage=stage,
                        status=StageStatus.FAILED,
                        error_code=failure.code,
                        attempt_id=checkpoint.attempt_id,
                    )
                try:
                    result = await handler(checkpoint, prior)
                except asyncio.CancelledError:
                    self.store.mark_failure(
                        checkpoint,
                        StageFailure(
                            code="STAGE_CANCELLED",
                            retryable=True,
                            safe_message="Stage was cancelled before completion",
                        ),
                        StageStatus.BLOCKED,
                    )
                    raise
                except StageBlocked as error:
                    outcome = await self._recover_or_stop(
                        checkpoint,
                        error.failure,
                        StageStatus.BLOCKED,
                    )
                except StageFailed as error:
                    outcome = await self._recover_or_stop(
                        checkpoint,
                        error.failure,
                        StageStatus.FAILED,
                    )
                except Exception as error:
                    code = getattr(error, "code", "STAGE_UNEXPECTED_ERROR")
                    if not isinstance(code, str) or not code:
                        code = "STAGE_UNEXPECTED_ERROR"
                    outcome = await self._recover_or_stop(
                        checkpoint,
                        StageFailure(
                            code=code[:160],
                            retryable=True,
                            safe_message=(
                                "Stage execution ended unexpectedly; retry is allowed"
                            ),
                        ),
                        StageStatus.BLOCKED,
                    )
                else:
                    completed = self.store.complete(checkpoint, result)
                    if terminal_initial_outcome(completed) is not None:
                        return self._verified_initial_terminal(completed)
                    if (
                        terminal_poc_outcome(completed) is not None
                        or completed.poc_stop_decision_ref is not None
                    ):
                        return self._verified_poc_terminal(completed)
                    if (
                        stage is SimpleStage.VERIFICATION_FINAL_DONE
                        and completed.verdict == "FALSE"
                    ):
                        return RunOutcome(
                            current_stage=stage,
                            status=StageStatus.SUCCEEDED,
                        )
                    if (
                        stage is SimpleStage.CHAINING_DONE
                        and final is not None
                        and final.verdict == "HOLD"
                    ):
                        return RunOutcome(
                            current_stage=stage,
                            status=StageStatus.SUCCEEDED,
                        )
                    gate_action = self._gate_action(completed)
                    if gate_action == "restart":
                        restart_requested = True
                        break
                    if isinstance(gate_action, RunOutcome):
                        return gate_action
                    continue
                if outcome is None:
                    restart_requested = True
                    break
                return outcome
            if restart_requested:
                continue
            return RunOutcome(
                current_stage=SimpleStage.REPORT_DONE,
                status=StageStatus.SUCCEEDED,
            )

    def _gate_action(
        self, checkpoint: StageCheckpoint
    ) -> RunOutcome | Literal["restart"] | None:
        terminal = terminal_gate_outcome(checkpoint)
        if terminal is not None:
            return RunOutcome(
                current_stage=SimpleStage.TECH_GATE_DONE,
                status=StageStatus.SUCCEEDED,
            )
        if (
            checkpoint.stage is SimpleStage.TECH_GATE_DONE
            and checkpoint.status is StageStatus.SUCCEEDED
            and checkpoint.stage_version == STAGE_VERSION[SimpleStage.TECH_GATE_DONE]
            and checkpoint.gate_decision == "REVISE"
        ):
            self.store.prepare_gate_revision(checkpoint)
            return "restart"
        return None

    def _verified_initial_terminal(self, checkpoint: StageCheckpoint) -> RunOutcome:
        artifacts = self.cleanup_artifacts
        if artifacts is not None:
            try:
                artifacts.verified_terminal_initial_outcome(checkpoint)
            except (OSError, ValueError, sqlite3.Error):
                failed = self.store.mark_failure(
                    checkpoint,
                    StageFailure(
                        code="INITIAL_VERIFICATION_EVIDENCE_INVALID",
                        retryable=False,
                        safe_message=(
                            "Initial verification evidence is unavailable or invalid"
                        ),
                        evidence_refs=checkpoint.output_refs,
                    ),
                    StageStatus.BLOCKED,
                )
                return RunOutcome(
                    current_stage=checkpoint.stage,
                    status=StageStatus.BLOCKED,
                    error_code=failed.error_code,
                    attempt_id=failed.attempt_id,
                )
        return RunOutcome(
            current_stage=checkpoint.stage,
            status=StageStatus.SUCCEEDED,
        )

    def _verified_poc_terminal(self, checkpoint: StageCheckpoint) -> RunOutcome:
        error_code = (
            "POC_STOP_EVIDENCE_INVALID"
            if checkpoint.poc_stop_decision_ref is not None
            else "POC_TERMINAL_EVIDENCE_INVALID"
        )
        try:
            if self.cleanup_artifacts is None:
                raise ValueError(error_code)
            self.cleanup_artifacts.verified_terminal_poc_outcome(checkpoint)
        except (OSError, ValueError, sqlite3.Error):
            failed = self.store.mark_failure(
                checkpoint,
                StageFailure(
                    code=error_code,
                    retryable=False,
                    safe_message="Terminal PoC evidence is unavailable or invalid",
                    evidence_refs=checkpoint.output_refs,
                ),
                StageStatus.BLOCKED,
            )
            return RunOutcome(
                current_stage=checkpoint.stage,
                status=StageStatus.BLOCKED,
                error_code=failed.error_code,
                attempt_id=failed.attempt_id,
            )
        return RunOutcome(
            current_stage=checkpoint.stage,
            status=StageStatus.SUCCEEDED,
        )

    async def _recover_existing(
        self,
        checkpoint: StageCheckpoint,
    ) -> RunOutcome | None | Literal[False]:
        if checkpoint.status is StageStatus.PENDING:
            return False
        if checkpoint.status is StageStatus.SUCCEEDED:
            return False
        promoted = self._promote_stopped_inconclusive_poc(checkpoint)
        if promoted is not None:
            return promoted
        if self._has_prior_poc_recovery_decision(checkpoint):
            return RunOutcome(
                current_stage=checkpoint.stage,
                status=checkpoint.status,
                error_code=checkpoint.error_code,
                attempt_id=checkpoint.attempt_id,
            )
        if checkpoint.status in {
            StageStatus.RUNNING,
            StageStatus.BLOCKED,
            StageStatus.FAILED,
        } and self._confirmed_codex_cleanup_allows_replay(checkpoint):
            self.store.replace_from(
                checkpoint.model_copy(
                    update={
                        "status": StageStatus.PENDING,
                        "output_refs": (),
                        "attempt_id": None,
                        "error_code": None,
                        "retryable": False,
                    }
                )
            )
            return False
        if checkpoint.status is StageStatus.RUNNING:
            return await self._recover_or_stop(
                checkpoint,
                StageFailure(
                    code="STAGE_INTERRUPTED",
                    retryable=True,
                    safe_message="Stage execution was interrupted before completion",
                ),
                StageStatus.BLOCKED,
            )
        if (
            checkpoint.stage is SimpleStage.VERIFICATION_INITIAL_DONE
            and checkpoint.status is StageStatus.BLOCKED
            and checkpoint.error_code == "POC_OFFLINE_BASE_IMAGE_UNAVAILABLE"
        ):
            if (
                checkpoint.attempt_number >= MAX_RECOVERY_ATTEMPTS
                or self.offline_base_ready is None
            ):
                return RunOutcome(
                    current_stage=checkpoint.stage,
                    status=checkpoint.status,
                    error_code=checkpoint.error_code,
                    attempt_id=checkpoint.attempt_id,
                )
            try:
                if self.store.unresolved_codex_call(checkpoint.identity.analysis_id):
                    ready = False
                else:
                    ready = await self.offline_base_ready()
            except (sqlite3.Error, OSError, RuntimeError, ValueError):
                ready = False
            if not ready:
                return RunOutcome(
                    current_stage=checkpoint.stage,
                    status=checkpoint.status,
                    error_code=checkpoint.error_code,
                    attempt_id=checkpoint.attempt_id,
                )
            self.store.replace_from(
                checkpoint.model_copy(
                    update={
                        "stage_version": STAGE_VERSION[checkpoint.stage],
                        "status": StageStatus.PENDING,
                        "output_refs": (),
                        "attempt_id": None,
                        "error_code": None,
                        "retryable": False,
                    }
                )
            )
            return False
        if (
            checkpoint.stage is SimpleStage.VERIFICATION_INITIAL_DONE
            and checkpoint.status is StageStatus.BLOCKED
            and checkpoint.error_code == "POC_OFFLINE_REQUIREMENT_UNSUPPORTED"
        ):
            if checkpoint.attempt_number >= MAX_RECOVERY_ATTEMPTS:
                return RunOutcome(
                    current_stage=checkpoint.stage,
                    status=checkpoint.status,
                    error_code=checkpoint.error_code,
                    attempt_id=checkpoint.attempt_id,
                )
            # Earlier prompts mixed attack preconditions with installable
            # requirements. Re-evaluate only this failed stage under the
            # separated schema, preserving the retry count and prior agents.
            self.store.replace_from(
                checkpoint.model_copy(
                    update={
                        "status": StageStatus.PENDING,
                        "output_refs": (),
                        "attempt_id": None,
                        "error_code": None,
                        "retryable": False,
                    }
                )
            )
            return False
        if (
            checkpoint.status in {StageStatus.BLOCKED, StageStatus.FAILED}
            and checkpoint.error_code == "INVALID_OUTPUT"
            and self.codex_invalid_output_resume
        ):
            if checkpoint.attempt_number >= MAX_RECOVERY_ATTEMPTS:
                if checkpoint.retryable:
                    self.store.save_checkpoint(
                        checkpoint.model_copy(update={"retryable": False})
                    )
                return RunOutcome(
                    current_stage=checkpoint.stage,
                    status=checkpoint.status,
                    error_code=checkpoint.error_code,
                    attempt_id=checkpoint.attempt_id,
                )
            self.store.replace_from(
                checkpoint.model_copy(
                    update={
                        "status": StageStatus.PENDING,
                        "output_refs": (),
                        "attempt_id": None,
                        "error_code": None,
                        "retryable": False,
                    }
                )
            )
            return False
        if not checkpoint.retryable:
            return RunOutcome(
                current_stage=checkpoint.stage,
                status=checkpoint.status,
                error_code=checkpoint.error_code,
                attempt_id=checkpoint.attempt_id,
            )
        return await self._recover_or_stop(
            checkpoint,
            StageFailure(
                code=checkpoint.error_code or "STAGE_RECOVERY_REQUIRED",
                retryable=True,
                safe_message="Resume the recorded retryable stage failure",
                evidence_refs=checkpoint.output_refs,
            ),
            checkpoint.status,
            already_failed=True,
        )

    def _confirmed_codex_cleanup_allows_replay(
        self, checkpoint: StageCheckpoint
    ) -> bool:
        artifacts = self.cleanup_artifacts
        if (
            checkpoint.identity.hypothesis_id is None
            or artifacts is None
            or artifacts.identity != checkpoint.identity
        ):
            return False
        try:
            if self.store.unresolved_codex_call(checkpoint.identity.analysis_id):
                return False
            if checkpoint.status is StageStatus.RUNNING:
                return self.store.has_codex_cleanup_confirmation(checkpoint, artifacts)
            if checkpoint.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED":
                return self.store.has_codex_cleanup_confirmation(checkpoint, artifacts)
            if checkpoint.error_code == "CODEX_CALL_IN_FLIGHT_UNRESOLVED":
                return self.store.confirmed_codex_call_covering(
                    checkpoint.identity.analysis_id, checkpoint.updated_at
                )
            return False
        except (OSError, ValueError, LookupError, sqlite3.Error):
            return False

    async def _recover_or_stop(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
        original_status: StageStatus,
        *,
        already_failed: bool = False,
    ) -> RunOutcome | None:
        failed = (
            checkpoint
            if already_failed
            else self.store.mark_failure(checkpoint, failure, original_status)
        )
        if self.recovery is None or not failure.retryable:
            return RunOutcome(
                current_stage=checkpoint.stage,
                status=original_status,
                error_code=failure.code,
                attempt_id=failed.attempt_id,
            )
        if failed.attempt_number >= MAX_RECOVERY_ATTEMPTS:
            exhausted = self.store.mark_recovery_exhausted(failed)
            return RunOutcome(
                current_stage=checkpoint.stage,
                status=StageStatus.BLOCKED,
                error_code=exhausted.error_code,
                attempt_id=exhausted.attempt_id,
            )
        resolution = await self.recovery.decide(failed, failure)
        if resolution.decision.action is RecoveryAction.STOP:
            self.store.record_recovery_stop(failed, resolution)
            promoted = self._promote_stopped_inconclusive_poc(failed)
            if promoted is not None:
                return promoted
            return RunOutcome(
                current_stage=checkpoint.stage,
                status=original_status,
                error_code=failure.code,
                attempt_id=failed.attempt_id,
            )
        restart_stage = self._recovery_restart_stage(
            checkpoint.stage,
            resolution.decision.action,
        )
        if restart_stage is None:
            self.store.record_recovery_decision(failed, resolution)
            return RunOutcome(
                current_stage=checkpoint.stage,
                status=original_status,
                error_code=failure.code,
                attempt_id=failed.attempt_id,
            )
        self.store.prepare_recovery(failed, resolution, restart_stage)
        return None

    def _promote_stopped_inconclusive_poc(
        self, checkpoint: StageCheckpoint
    ) -> RunOutcome | None:
        if (
            checkpoint.stage is not SimpleStage.POC_EXECUTION_DONE
            or checkpoint.status is not StageStatus.BLOCKED
            or checkpoint.error_code != "POC_INCONCLUSIVE"
            or self.cleanup_artifacts is None
        ):
            return None
        try:
            self.store.promote_inconclusive_execution(
                checkpoint, artifacts=self.cleanup_artifacts
            )
        except ValueError:
            return None
        return RunOutcome(
            current_stage=checkpoint.stage,
            status=StageStatus.SUCCEEDED,
        )

    def _has_prior_poc_recovery_decision(self, checkpoint: StageCheckpoint) -> bool:
        if (
            checkpoint.stage is not SimpleStage.POC_EXECUTION_DONE
            or checkpoint.status is not StageStatus.BLOCKED
            or checkpoint.error_code != "POC_INCONCLUSIVE"
            or checkpoint.attempt_id is None
        ):
            return False
        try:
            return any(
                event.kind is ActivityKind.DECISION_RECORDED
                and event.error_code == checkpoint.error_code
                for event in self.store.stage_activity(
                    checkpoint.identity, checkpoint.stage, checkpoint.attempt_id
                )
            )
        except (ValueError, sqlite3.Error):
            # Unknown append-only history must never authorize PoC replay.
            return True

    @staticmethod
    def _recovery_restart_stage(
        failed_stage: SimpleStage,
        action: RecoveryAction,
    ) -> SimpleStage | None:
        if action is RecoveryAction.REBUILD_ENVIRONMENT:
            if STAGE_ORDER.index(failed_stage) < STAGE_ORDER.index(
                SimpleStage.VERIFICATION_INITIAL_DONE
            ):
                return None
            return SimpleStage.VERIFICATION_INITIAL_DONE
        if failed_stage is SimpleStage.POC_EXECUTION_DONE:
            return SimpleStage.POC_CANDIDATE_DONE
        return failed_stage

    def _reset_incomplete_poc_attempt(self, identity: CheckpointIdentity) -> None:
        candidate = self.store.get(identity, SimpleStage.POC_CANDIDATE_DONE)
        execution = self.store.get(identity, SimpleStage.POC_EXECUTION_DONE)
        if candidate is None:
            return
        if candidate.status is not StageStatus.SUCCEEDED:
            return
        if (
            execution is not None
            and execution.status is StageStatus.SUCCEEDED
            and execution.stage_version != STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]
        ):
            # A completed legacy PoC needs a new stage run, not a new candidate.
            return
        if execution is not None and (
            execution.error_code == "INVALID_OUTPUT"
            or self._has_prior_poc_recovery_decision(execution)
            or execution.status is StageStatus.PENDING
            or execution.status in {StageStatus.BLOCKED, StageStatus.FAILED}
            and not execution.retryable
        ):
            return
        execution_inputs = self.store.input_refs_for(
            identity,
            SimpleStage.POC_EXECUTION_DONE,
        )
        reusable_execution = execution is not None and self.store.reusable(
            identity, SimpleStage.POC_EXECUTION_DONE, execution_inputs
        )
        orphaned_execution_activity = (
            execution is None
            and candidate.attempt_id is not None
            and self.store.has_stage_activity(
                identity,
                SimpleStage.POC_EXECUTION_DONE,
                candidate.attempt_id,
            )
        )
        if reusable_execution or (
            execution is None and not orphaned_execution_activity
        ):
            return

        activity_refs = tuple(
            ref
            for event in (
                self.store.stage_activity(
                    identity,
                    SimpleStage.POC_EXECUTION_DONE,
                    candidate.attempt_id,
                )
                if candidate.attempt_id is not None
                else ()
            )
            for ref in event.output_refs
        )
        repair_inputs = tuple(
            dict.fromkeys(
                candidate.input_refs
                + candidate.output_refs
                + (execution.output_refs if execution is not None else ())
                + activity_refs
            )
        )

        # A retry is a new attempt. The candidate and its execution must share
        # that attempt, so restart the pair instead of reusing an old attempt ID.
        self.store.replace_from(
            StageCheckpoint(
                identity=identity,
                stage=SimpleStage.POC_CANDIDATE_DONE,
                stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
                status=StageStatus.PENDING,
                input_refs=repair_inputs,
                input_hash=input_reference_hash(repair_inputs),
                gate_revision_count=candidate.gate_revision_count,
                recipe_ref=candidate.recipe_ref,
                image_digest=candidate.image_digest,
                container_id=candidate.container_id,
            )
        )
