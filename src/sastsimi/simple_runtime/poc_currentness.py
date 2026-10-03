"""Read-side currentness checks for previously completed PoC executions."""

from __future__ import annotations

from collections.abc import Iterable

from .models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)

_PRE_POC_STAGES = frozenset(
    HYPOTHESIS_STAGES[: HYPOTHESIS_STAGES.index(SimpleStage.POC_EXECUTION_DONE)]
)


def stale_successful_poc(checkpoint: StageCheckpoint | None) -> bool:
    """A successful pre-gate version-2 PoC needs revalidation."""

    return bool(
        checkpoint is not None
        and checkpoint.stage is SimpleStage.POC_EXECUTION_DONE
        and checkpoint.status is StageStatus.SUCCEEDED
        and checkpoint.stage_version == "2"
        and checkpoint.stage_version != STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]
    )


def stale_poc_hypothesis_ids(checkpoints: Iterable[StageCheckpoint]) -> frozenset[str]:
    return frozenset(
        checkpoint.identity.hypothesis_id
        for checkpoint in checkpoints
        if stale_successful_poc(checkpoint)
        and checkpoint.identity.hypothesis_id is not None
    )


def completed_before_poc_count(checkpoints: Iterable[StageCheckpoint]) -> int:
    """Count only stages whose outcome predates PoC execution."""

    return sum(
        checkpoint.stage in _PRE_POC_STAGES
        and checkpoint.status is StageStatus.SUCCEEDED
        for checkpoint in checkpoints
    )
