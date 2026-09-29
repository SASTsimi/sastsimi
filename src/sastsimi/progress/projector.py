"""Shared CLI/dashboard progress calculation."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Literal, Protocol

from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    CandidateTerminal,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    terminal_gate_outcome,
    terminal_poc_outcome,
)

from .models import ProgressSnapshot

_ANALYSIS_STAGES = (SimpleStage.STATIC_DONE, SimpleStage.HYPOTHESIS_DONE)
_CANDIDATE_DECISIONS = ("PENDING", "INCLUDE", "EXCLUDE", "UNDECIDED", "ERROR")
_DEEP_STATUSES = ("PENDING", "RUNNING", "COMPLETE", "NO_HYPOTHESIS", "ERROR")
_BUDGET_CODES = frozenset(
    {
        "LLM_TOKEN_BUDGET_EXHAUSTED",
        "LLM_COST_BUDGET_EXHAUSTED",
        "LLM_ELAPSED_BUDGET_EXHAUSTED",
        "LLM_TOKEN_USAGE_UNAVAILABLE",
        "LLM_COST_USAGE_UNAVAILABLE",
    }
)


def _normalized_counts(
    counts: Mapping[str, int] | None, statuses: tuple[str, ...]
) -> dict[str, int]:
    if counts is None:
        return {status: 0 for status in statuses}
    if any(
        status not in statuses or type(value) is not int or value < 0
        for status, value in counts.items()
    ):
        raise ValueError("ANALYSIS_PROGRESS_CANDIDATE_COUNTS_INVALID")
    return {status: counts.get(status, 0) for status in statuses}


class CheckpointQuery(Protocol):
    def list_checkpoints(self, analysis_id: str) -> tuple[StageCheckpoint, ...]: ...


class ProgressProjector:
    def __init__(self, store: CheckpointQuery) -> None:
        self._store = store

    def snapshot(
        self,
        analysis_id: str,
        *,
        static_disposition: Literal["FULL", "PARTIAL"] = "FULL",
        candidate_pipeline_version: int = 0,
        candidate_counts: Mapping[str, int] | None = None,
        candidate_deep_counts: Mapping[str, int] | None = None,
        registered_hypothesis_count: int | None = None,
        candidate_terminal: CandidateTerminal | None = None,
        candidate_bundle_hash: str | None = None,
        candidate_scope_fingerprint: str | None = None,
    ) -> ProgressSnapshot:
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
        inconclusive_hypotheses = 0
        rejected_hypotheses = 0
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
            chain = next(
                (
                    item
                    for item in values
                    if item.stage is SimpleStage.CHAINING_DONE
                    and item.status is StageStatus.SUCCEEDED
                ),
                None,
            )
            execution = next(
                (
                    item
                    for item in values
                    if item.stage is SimpleStage.POC_EXECUTION_DONE
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
            gate = next(
                (item for item in values if item.stage is SimpleStage.TECH_GATE_DONE),
                None,
            )
            gate_outcome = terminal_gate_outcome(gate)
            if terminal_poc_outcome(execution) is not None:
                execution_index = HYPOTHESIS_STAGES.index(
                    SimpleStage.POC_EXECUTION_DONE
                )
                present_after = sum(
                    item.stage in HYPOTHESIS_STAGES[execution_index + 1 :]
                    and item.status is StageStatus.SUCCEEDED
                    for item in values
                )
                skipped += len(HYPOTHESIS_STAGES[execution_index + 1 :]) - present_after
                terminal_hypotheses += 1
                inconclusive_hypotheses += 1
            elif final is not None and (
                final.verdict == "FALSE"
                or final.verdict == "HOLD"
                and chain is not None
            ):
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
            elif gate_outcome is not None:
                gate_index = HYPOTHESIS_STAGES.index(SimpleStage.TECH_GATE_DONE)
                present_after = sum(
                    item.stage in HYPOTHESIS_STAGES[gate_index + 1 :]
                    and item.status is StageStatus.SUCCEEDED
                    for item in values
                )
                skipped += len(HYPOTHESIS_STAGES[gate_index + 1 :]) - present_after
                terminal_hypotheses += 1
                if gate_outcome == "REJECT":
                    rejected_hypotheses += 1
                else:
                    inconclusive_hypotheses += 1
            elif report is not None:
                terminal_hypotheses += 1

        registered_hypotheses = max(
            len(by_hypothesis), registered_hypothesis_count or 0
        )
        known += (registered_hypotheses - len(by_hypothesis)) * len(HYPOTHESIS_STAGES)
        candidate_mode = candidate_pipeline_version >= 1
        decisions = (
            _normalized_counts(candidate_counts, _CANDIDATE_DECISIONS)
            if candidate_mode and candidate_counts is not None
            else {}
        )
        deep = (
            _normalized_counts(candidate_deep_counts, _DEEP_STATUSES)
            if candidate_mode and candidate_counts is not None
            else {}
        )
        candidate_total = sum(decisions.values())
        deep_eligible = decisions.get("INCLUDE", 0) + decisions.get("UNDECIDED", 0)
        deep_completed = deep.get("COMPLETE", 0) + deep.get("NO_HYPOTHESIS", 0)
        terminal_valid = bool(
            candidate_mode
            and candidate_counts is not None
            and candidate_terminal is not None
            and candidate_bundle_hash is not None
            and candidate_scope_fingerprint is not None
            and candidate_terminal.status
            == ("PARTIAL" if static_disposition == "PARTIAL" else "COMPLETE")
            and candidate_terminal.bundle_hash == candidate_bundle_hash
            and candidate_terminal.scope_fingerprint == candidate_scope_fingerprint
            and _normalized_counts(
                candidate_terminal.decision_counts, _CANDIDATE_DECISIONS
            )
            == decisions
            and _normalized_counts(candidate_terminal.deep_counts, _DEEP_STATUSES)
            == deep
            and candidate_terminal.hypothesis_count == registered_hypotheses
        )
        if candidate_mode and candidate_counts is not None:
            known += candidate_total + deep_eligible
            completed += (
                decisions["INCLUDE"]
                + decisions["EXCLUDE"]
                + decisions["UNDECIDED"]
                + min(deep_completed, deep_eligible)
            )
        finding_count = sum(
            item.stage is SimpleStage.FINDING_DONE
            and item.status is StageStatus.SUCCEEDED
            and item.verdict == "TRUE"
            and bool(item.output_refs)
            for item in checkpoints
        )
        status, current = self._status(
            checkpoints,
            terminal_hypotheses,
            registered_hypotheses,
            static_disposition=static_disposition,
            candidate_pipeline_version=candidate_pipeline_version,
            candidate_counts=decisions if candidate_counts is not None else None,
            candidate_deep_counts=deep,
            candidate_terminal_valid=terminal_valid,
        )
        credited = completed + skipped
        percent = (
            100
            if status == "COMPLETE"
            else min(99, int(credited * 100 / max(known, 1)))
        )
        error_code = current.error_code
        if status == "BLOCKED" and error_code is None:
            if decisions.get("ERROR", 0):
                error_code = "CANDIDATE_DISCOVERY_ERROR"
            elif deep.get("ERROR", 0):
                error_code = "CANDIDATE_DEEP_ERROR"
        return ProgressSnapshot(
            analysis_id=analysis_id,
            status=status,
            completed_units=completed,
            skipped_units=skipped,
            known_units=known,
            percent=percent,
            current_stage=current.stage.value,
            current_hypothesis_id=current.identity.hypothesis_id,
            error_code=error_code,
            attempt_number=max(1, current.attempt_number),
            inconclusive_hypothesis_count=inconclusive_hypotheses,
            rejected_hypothesis_count=rejected_hypotheses,
            candidate_total_count=(
                candidate_total
                if candidate_mode and candidate_counts is not None
                else None
            ),
            candidate_decision_counts=decisions,
            deep_analysis_running_count=deep.get("RUNNING", 0),
            deep_analysis_completed_count=deep_completed,
            deep_analysis_pending_count=deep.get("PENDING", 0),
            hypothesis_count=registered_hypotheses,
            finding_count=finding_count,
            resume_action=(
                "CHECK_USAGE_TELEMETRY"
                if status == "PAUSED"
                and error_code
                in {
                    "LLM_TOKEN_USAGE_UNAVAILABLE",
                    "LLM_COST_USAGE_UNAVAILABLE",
                }
                else "INCREASE_BUDGET_AND_RESUME"
                if status == "PAUSED"
                else None
            ),
            denominator_change_reason=(
                "NEW_HYPOTHESIS_REGISTERED" if registered_hypotheses > 1 else None
            ),
        )

    @staticmethod
    def _status(
        checkpoints: tuple[StageCheckpoint, ...],
        terminal_hypotheses: int,
        hypothesis_count: int,
        *,
        static_disposition: Literal["FULL", "PARTIAL"] = "FULL",
        candidate_pipeline_version: int = 0,
        candidate_counts: Mapping[str, int] | None = None,
        candidate_deep_counts: Mapping[str, int] | None = None,
        candidate_terminal_valid: bool = False,
    ) -> tuple[
        Literal["RUNNING", "PAUSED", "BLOCKED", "FAILED", "COMPLETE", "PARTIAL"],
        StageCheckpoint,
    ]:
        current = max(checkpoints, key=lambda item: item.updated_at)
        if candidate_pipeline_version >= 1:
            running = [
                item for item in checkpoints if item.status is StageStatus.RUNNING
            ]
            if running:
                return "RUNNING", max(running, key=lambda item: item.updated_at)
            failed = [
                item
                for item in checkpoints
                if item.status is StageStatus.FAILED
                and item.error_code not in _BUDGET_CODES
            ]
            if failed:
                return "FAILED", max(failed, key=lambda item: item.updated_at)
            blocked = [
                item
                for item in checkpoints
                if item.status is StageStatus.BLOCKED
                and item.error_code not in _BUDGET_CODES
            ]
            if blocked:
                return "BLOCKED", max(blocked, key=lambda item: item.updated_at)
            if (candidate_counts or {}).get("ERROR", 0) or (
                candidate_deep_counts or {}
            ).get("ERROR", 0):
                return "BLOCKED", current
            paused = [
                item
                for item in checkpoints
                if item.status in {StageStatus.BLOCKED, StageStatus.FAILED}
                and item.error_code in _BUDGET_CODES
            ]
            if paused:
                return "PAUSED", max(paused, key=lambda item: item.updated_at)
        # An active stage is the current analysis, even when an earlier
        # hypothesis has already stopped. Once idle, failed outranks blocked.
        for status in (StageStatus.RUNNING, StageStatus.FAILED, StageStatus.BLOCKED):
            matches = [item for item in checkpoints if item.status is status]
            if matches:
                if status is StageStatus.BLOCKED:
                    operational = [
                        item for item in matches if item.error_code not in _BUDGET_CODES
                    ]
                    if (
                        operational
                        or (candidate_counts or {}).get("ERROR", 0)
                        or (candidate_deep_counts or {}).get("ERROR", 0)
                    ):
                        return "BLOCKED", max(
                            operational or matches, key=lambda item: item.updated_at
                        )
                    return "PAUSED", max(matches, key=lambda item: item.updated_at)
                if status is StageStatus.FAILED:
                    return "FAILED", max(matches, key=lambda item: item.updated_at)
                return "RUNNING", max(matches, key=lambda item: item.updated_at)
        if candidate_pipeline_version >= 1:
            if candidate_counts is None:
                return "RUNNING", current
            deep = candidate_deep_counts or {}
            if candidate_counts.get("ERROR", 0) or deep.get("ERROR", 0):
                return "BLOCKED", current
            deep_eligible = candidate_counts.get("INCLUDE", 0) + candidate_counts.get(
                "UNDECIDED", 0
            )
            deep_terminal = deep.get("COMPLETE", 0) + deep.get("NO_HYPOTHESIS", 0)
            if (
                candidate_counts.get("PENDING", 0)
                or deep.get("PENDING", 0)
                or deep.get("RUNNING", 0)
                or deep_terminal < deep_eligible
                or terminal_hypotheses != hypothesis_count
                or not candidate_terminal_valid
                or not all(
                    any(
                        item.stage is stage and item.status is StageStatus.SUCCEEDED
                        for item in checkpoints
                    )
                    for stage in _ANALYSIS_STAGES
                )
            ):
                return "RUNNING", current
            return (
                "PARTIAL" if static_disposition == "PARTIAL" else "COMPLETE"
            ), current
        if hypothesis_count > 0 and terminal_hypotheses == hypothesis_count:
            return (
                "PARTIAL" if static_disposition == "PARTIAL" else "COMPLETE"
            ), current
        return "RUNNING", current


__all__ = ["ProgressProjector"]
