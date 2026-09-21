"""Shared CLI/dashboard progress calculation."""

from __future__ import annotations

from collections import defaultdict
from typing import Literal, Protocol

from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)

from .models import ProgressSnapshot

_ANALYSIS_STAGES = (SimpleStage.STATIC_DONE, SimpleStage.HYPOTHESIS_DONE)


class CheckpointQuery(Protocol):
    def list_checkpoints(self, analysis_id: str) -> tuple[StageCheckpoint, ...]: ...


class ProgressProjector:
    def __init__(self, store: CheckpointQuery) -> None:
        self._store = store

    def snapshot(self, analysis_id: str) -> ProgressSnapshot:
        checkpoints = self._store.list_checkpoints(analysis_id)
        if not checkpoints:
            raise LookupError("ANALYSIS_PROGRESS_NOT_FOUND")
        by_hypothesis: dict[str, list[StageCheckpoint]] = defaultdict(list)
        analysis_level: list[StageCheckpoint] = []
        for checkpoint in checkpoints:
            hypothesis_id = checkpoint.identity.hypothesis_id
            if hypothesis_id is None:
                analysis_level.append(checkpoint)
            else:
                by_hypothesis[hypothesis_id].append(checkpoint)

        completed = sum(item.status is StageStatus.SUCCEEDED for item in analysis_level)
        known = len(_ANALYSIS_STAGES) if analysis_level else 0
        skipped = 0
        terminal_hypotheses = 0
        for values in by_hypothesis.values():
            known += len(HYPOTHESIS_STAGES)
            completed += sum(item.status is StageStatus.SUCCEEDED for item in values)
            final = next(
                (
                    item
                    for item in values
                    if item.stage is SimpleStage.VERIFICATION_FINAL_DONE
                    and item.status is StageStatus.SUCCEEDED
                ),
                None,
            )
            report = next(
                (
                    item
                    for item in values
                    if item.stage is SimpleStage.REPORT_DONE
                    and item.status is StageStatus.SUCCEEDED
                ),
                None,
            )
            if final is not None and final.verdict in {"FALSE", "HOLD"}:
                final_index = HYPOTHESIS_STAGES.index(
                    SimpleStage.VERIFICATION_FINAL_DONE
                )
                present_after = sum(
                    item.stage in HYPOTHESIS_STAGES[final_index + 1 :]
                    and item.status is StageStatus.SUCCEEDED
                    for item in values
                )
                skipped += len(HYPOTHESIS_STAGES[final_index + 1 :]) - present_after
                terminal_hypotheses += 1
            elif report is not None:
                terminal_hypotheses += 1

        status, current = self._status(
            checkpoints,
            terminal_hypotheses,
            len(by_hypothesis),
        )
        credited = completed + skipped
        percent = (
            100
            if status == "COMPLETE"
            else min(99, int(credited * 100 / max(known, 1)))
        )
        return ProgressSnapshot(
            analysis_id=analysis_id,
            status=status,
            completed_units=completed,
            skipped_units=skipped,
            known_units=known,
            percent=percent,
            current_stage=current.stage.value,
            current_hypothesis_id=current.identity.hypothesis_id,
            error_code=current.error_code,
            denominator_change_reason=(
                "NEW_HYPOTHESIS_REGISTERED" if len(by_hypothesis) > 1 else None
            ),
        )

    @staticmethod
    def _status(
        checkpoints: tuple[StageCheckpoint, ...],
        terminal_hypotheses: int,
        hypothesis_count: int,
    ) -> tuple[Literal["RUNNING", "BLOCKED", "FAILED", "COMPLETE"], StageCheckpoint]:
        current = max(checkpoints, key=lambda item: item.updated_at)
        for status in (StageStatus.BLOCKED, StageStatus.FAILED, StageStatus.RUNNING):
            matches = [item for item in checkpoints if item.status is status]
            if matches:
                result_status: Literal["BLOCKED", "FAILED", "RUNNING"] = (
                    "BLOCKED"
                    if status is StageStatus.BLOCKED
                    else "FAILED"
                    if status is StageStatus.FAILED
                    else "RUNNING"
                )
                return result_status, max(matches, key=lambda item: item.updated_at)
        if hypothesis_count > 0 and terminal_hypotheses == hypothesis_count:
            return "COMPLETE", current
        return "RUNNING", current


__all__ = ["ProgressProjector"]
