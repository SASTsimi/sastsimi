from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol
from uuid import uuid4

from sastsimi.contracts.base import ContractModel

from .models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from .store import SimpleCheckpointStore
from .usage import labelled


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


# Failures that hinge on what the model happened to write: another attempt
# on the same inputs can pass, so each gets a bounded number of resumes before
# it is final.  Every other FAILED is final on the inputs that produced it.
REPAIRABLE_CODES = frozenset(
    {
        "INVALID_OUTPUT",
        "REPORT_SENSITIVE_CONTENT",
        "TRUE_WITHOUT_VALIDATED_POC",
    }
)
MAX_REPAIR_ATTEMPTS = 3

# Every other BLOCKED code is retryable with no bound, so a hypothesis that
# keeps hitting a wall the model never gets past - the model repairing a
# script into the very rule it just broke, an environment gap no repair
# touches - retried forever without the run ever settling.  Comparing only
# the immediately preceding code lets a hypothesis alternate between two
# walls (A, B, A, B, ...) forever without either ever counting as a repeat,
# so what is tracked instead is every code this stage has already hit for
# this hypothesis: landing back on one of those, in any order, means nothing
# was actually resolved between attempts.  Only a code this stage has never
# produced before resets the count - real progress, not a different flavor
# of the same wall.
MAX_STALL_REPEATS = 3


class RunOutcome(ContractModel):
    current_stage: SimpleStage
    status: StageStatus
    error_code: str | None = None


class SimpleRuntimeRunner:
    def __init__(
        self,
        store: SimpleCheckpointStore,
        handlers: Mapping[SimpleStage, SimpleStageHandler],
    ) -> None:
        self.store = store
        self.handlers = handlers

    async def resume_analysis(self, identity: CheckpointIdentity) -> RunOutcome:
        return await self.resume_hypothesis(identity)

    async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
        # Carried in a local rather than a re-saved placeholder row: resetting
        # POC_CANDIDATE_DONE invalidates every stage from it onward, which
        # deletes POC_EXECUTION_DONE's own record - and a placeholder written
        # there survives only until this same call reaches the candidate
        # stage's own reset, whose invalidation range covers it too.
        carried_execution_stall = self._reset_incomplete_poc_attempt(identity)
        self._reset_technical_revision(identity)
        for stage in HYPOTHESIS_STAGES:
            final = self.store.get(identity, SimpleStage.VERIFICATION_FINAL_DONE)
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
            input_refs = self.store.input_refs_for(identity, stage)
            if self.store.reusable(identity, stage, input_refs):
                reusable = self.store.require(identity, stage)
                if (
                    stage is SimpleStage.VERIFICATION_FINAL_DONE
                    and reusable.verdict == "FALSE"
                ):
                    return RunOutcome(
                        current_stage=stage,
                        status=StageStatus.SUCCEEDED,
                    )
                continue
            existing = self.store.get(identity, stage)
            repairing = existing is not None and existing.error_code in REPAIRABLE_CODES
            if (
                existing is not None
                and existing.status is StageStatus.FAILED
                and existing.stage_version == STAGE_VERSION[stage]
                and not (repairing and existing.repair_attempts < MAX_REPAIR_ATTEMPTS)
            ):
                return RunOutcome(
                    current_stage=stage,
                    status=StageStatus.FAILED,
                    error_code=existing.error_code,
                )
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
                else uuid4().hex
            )
            retry_seed = (
                existing
                if existing is not None and existing.status is StageStatus.PENDING
                else None
            )
            # A retryable block records why it stopped; the next attempt starts
            # from that instead of relearning it.
            retry_evidence_refs = (
                existing.output_refs
                if existing is not None
                and existing.status is StageStatus.BLOCKED
                and existing.retryable
                else ()
            )
            self.store.invalidate_from(identity, stage, new_inputs=input_refs)
            if retry_seed is not None:
                self.store.save_checkpoint(retry_seed)
            checkpoint = self.store.mark_running(
                identity,
                stage,
                input_refs,
                attempt_id=attempt_id,
                inherit_from=inherit_from,
                retry_evidence_refs=retry_evidence_refs,
                repair_attempts=(
                    existing.repair_attempts + 1
                    if existing is not None and repairing
                    else 1
                ),
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
                )
            try:
                with labelled(stage.value, identity.hypothesis_id):
                    result = await handler(checkpoint, prior)
            except (StageBlocked, StageFailed) as error:
                failure = error.failure
                status = (
                    StageStatus.BLOCKED
                    if isinstance(error, StageBlocked)
                    else StageStatus.FAILED
                )
                if failure.code in REPAIRABLE_CODES:
                    exhausted = checkpoint.repair_attempts >= MAX_REPAIR_ATTEMPTS
                    status = StageStatus.FAILED if exhausted else StageStatus.BLOCKED
                    failure = failure.model_copy(update={"retryable": not exhausted})
                elif status is StageStatus.BLOCKED:
                    # existing is None here for POC_EXECUTION_DONE on every
                    # retry of an incomplete pair: the reset that restarts it
                    # together with POC_CANDIDATE_DONE deletes its record, so
                    # what it was blocked on last only survives in the value
                    # carried from `_reset_incomplete_poc_attempt`.
                    fallback = (
                        carried_execution_stall
                        if existing is None and stage is SimpleStage.POC_EXECUTION_DONE
                        else None
                    )
                    seen_codes = (
                        existing.stall_codes
                        if existing is not None
                        else fallback[1]
                        if fallback is not None
                        else ()
                    )
                    prior_streak = (
                        existing.stall_streak
                        if existing is not None
                        else fallback[0]
                        if fallback is not None
                        else 0
                    )
                    novel = failure.code not in seen_codes
                    streak = 1 if novel else prior_streak + 1
                    checkpoint = checkpoint.model_copy(
                        update={
                            "stall_streak": streak,
                            "stall_codes": (
                                seen_codes if not novel else (*seen_codes, failure.code)
                            ),
                        }
                    )
                    if streak >= MAX_STALL_REPEATS:
                        status = StageStatus.FAILED
                        failure = failure.model_copy(update={"retryable": False})
                self.store.mark_failure(checkpoint, failure, status)
                return RunOutcome(
                    current_stage=stage,
                    status=status,
                    error_code=failure.code,
                )
            except Exception as error:
                code = getattr(error, "code", "STAGE_UNEXPECTED_ERROR")
                if not isinstance(code, str) or not code:
                    code = "STAGE_UNEXPECTED_ERROR"
                failure = StageFailure(
                    code=code[:160],
                    retryable=True,
                    safe_message="Stage execution ended unexpectedly; retry is allowed",
                )
                self.store.mark_failure(
                    checkpoint,
                    failure,
                    StageStatus.BLOCKED,
                )
                return RunOutcome(
                    current_stage=stage,
                    status=StageStatus.BLOCKED,
                    error_code=failure.code,
                )
            completed = self.store.complete(checkpoint, result)
            if stage is SimpleStage.VERIFICATION_FINAL_DONE and completed.verdict == (
                "FALSE"
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
        return RunOutcome(
            current_stage=SimpleStage.REPORT_DONE,
            status=StageStatus.SUCCEEDED,
        )

    def _reset_incomplete_poc_attempt(
        self, identity: CheckpointIdentity
    ) -> tuple[int, tuple[str, ...]]:
        """Restart an incomplete PoC pair, returning the execution stall it had.

        Its own record cannot carry that value forward: restarting the pair
        invalidates POC_EXECUTION_DONE along with the candidate it shares an
        attempt with, and that invalidation is not undone before the resumed
        run's own stage loop reaches either of them again.
        """

        no_carry = (0, ())
        candidate = self.store.get(identity, SimpleStage.POC_CANDIDATE_DONE)
        execution = self.store.get(identity, SimpleStage.POC_EXECUTION_DONE)
        if candidate is None:
            return no_carry
        if candidate.status is not StageStatus.SUCCEEDED:
            return no_carry
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
        # A stall-exhausted execution is FAILED with retryable=False - a
        # verdict this pairing must leave standing, not restart the pair
        # over.  Without this, the reset ran again on the very next resume,
        # since nothing else here checks for a final, non-retryable outcome.
        exhausted = (
            execution is not None
            and execution.status is StageStatus.FAILED
            and not execution.retryable
        )
        if (
            reusable_execution
            or exhausted
            or (execution is None and not orphaned_execution_activity)
        ):
            return no_carry

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
        self.store.invalidate_from(
            identity,
            SimpleStage.POC_CANDIDATE_DONE,
            new_inputs=candidate.input_refs,
            force=True,
        )
        self.store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=SimpleStage.POC_CANDIDATE_DONE,
                stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
                status=StageStatus.PENDING,
                input_refs=repair_inputs,
                input_hash=input_reference_hash(repair_inputs),
                recipe_ref=candidate.recipe_ref,
                image_digest=candidate.image_digest,
                container_id=candidate.container_id,
            )
        )
        return (
            (execution.stall_streak, execution.stall_codes)
            if execution is not None
            else no_carry
        )

    def _reset_technical_revision(self, identity: CheckpointIdentity) -> None:
        gate = self.store.get(identity, SimpleStage.TECH_GATE_DONE)
        verification = self.store.get(
            identity,
            SimpleStage.VERIFICATION_FINAL_DONE,
        )
        if (
            gate is None
            or gate.status is not StageStatus.BLOCKED
            or gate.error_code != "TECH_GATE_REVISE"
            or not gate.retryable
            or verification is None
            or verification.status is not StageStatus.SUCCEEDED
            or verification.attempt_number >= 2
        ):
            return

        repair_inputs = tuple(
            dict.fromkeys(
                verification.input_refs + verification.output_refs + gate.output_refs
            )
        )
        self.store.invalidate_from(
            identity,
            SimpleStage.VERIFICATION_FINAL_DONE,
            new_inputs=repair_inputs,
            force=True,
        )
        self.store.save_checkpoint(
            verification.model_copy(
                update={
                    "status": StageStatus.PENDING,
                    "input_refs": repair_inputs,
                    "input_hash": input_reference_hash(repair_inputs),
                    "output_refs": (),
                    "attempt_id": None,
                    "error_code": None,
                    "retryable": False,
                    "validated_poc_ref": None,
                    "verdict": None,
                }
            )
        )
