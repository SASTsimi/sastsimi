from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol
from uuid import uuid4

from sastsimi.contracts.base import ContractModel

from .models import (
    HYPOTHESIS_STAGES,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
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
        for stage in HYPOTHESIS_STAGES:
            input_refs = self.store.input_refs_for(identity, stage)
            if self.store.reusable(identity, stage, input_refs):
                reusable = self.store.require(identity, stage)
                if (
                    stage is SimpleStage.VERIFICATION_FINAL_DONE
                    and reusable.verdict in {"FALSE", "HOLD"}
                ):
                    return RunOutcome(
                        current_stage=stage,
                        status=StageStatus.SUCCEEDED,
                    )
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
                else uuid4().hex
            )
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
                )
            try:
                result = await handler(checkpoint, prior)
            except StageBlocked as error:
                self.store.mark_failure(
                    checkpoint,
                    error.failure,
                    StageStatus.BLOCKED,
                )
                return RunOutcome(
                    current_stage=stage,
                    status=StageStatus.BLOCKED,
                    error_code=error.failure.code,
                )
            except StageFailed as error:
                self.store.mark_failure(
                    checkpoint,
                    error.failure,
                    StageStatus.FAILED,
                )
                return RunOutcome(
                    current_stage=stage,
                    status=StageStatus.FAILED,
                    error_code=error.failure.code,
                )
            completed = self.store.complete(checkpoint, result)
            if (
                stage is SimpleStage.VERIFICATION_FINAL_DONE
                and completed.verdict in {"FALSE", "HOLD"}
            ):
                return RunOutcome(
                    current_stage=stage,
                    status=StageStatus.SUCCEEDED,
                )
        return RunOutcome(
            current_stage=SimpleStage.REPORT_DONE,
            status=StageStatus.SUCCEEDED,
        )
