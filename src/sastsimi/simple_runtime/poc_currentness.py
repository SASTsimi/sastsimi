"""Read-side currentness checks for previously completed PoC executions."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from sastsimi.contracts.poc_provenance import (
    PocProvenanceStatus,
    assess_poc_provenance,
)
from sastsimi.contracts.refs import StoredDataRef

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
_MAX_POC_SOURCE_BYTES = 1024 * 1024


def poc_source_current(
    candidate: StageCheckpoint | None,
    *,
    read_content: Callable[[StoredDataRef, int], bytes],
) -> bool:
    """Historical success is not proof when its saved PoC fails today's guard."""

    if (
        candidate is None
        or candidate.stage is not SimpleStage.POC_CANDIDATE_DONE
        or candidate.status is not StageStatus.SUCCEEDED
        or candidate.stage_version != STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE]
        or candidate.identity.hypothesis_id is None
        or len(candidate.output_refs) < 2
    ):
        return False
    try:
        source = read_content(candidate.output_refs[1], _MAX_POC_SOURCE_BYTES)
        return (
            assess_poc_provenance(source).status
            is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
        )
    except (OSError, ValueError, TypeError, UnicodeError):
        return False


def poc_source_revalidation_required(
    checkpoints: Iterable[StageCheckpoint],
    *,
    read_content: Callable[[StoredDataRef, int], bytes],
) -> bool:
    """Only PoC-backed historical claims need this read-side revalidation."""

    values = tuple(checkpoints)
    if not any(
        item.stage is SimpleStage.POC_EXECUTION_DONE
        or item.validated_poc_ref is not None
        for item in values
    ):
        return False  # A legacy report with only a candidate makes no PoC claim.
    candidate = next(
        (item for item in values if item.stage is SimpleStage.POC_CANDIDATE_DONE),
        None,
    )
    return not poc_source_current(candidate, read_content=read_content)


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
