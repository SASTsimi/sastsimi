from __future__ import annotations

from typing import Literal

from pydantic import Field

from sastsimi.contracts.base import ContractModel
from sastsimi.simple_runtime.recovery import MAX_RECOVERY_ATTEMPTS


class ProgressSnapshot(ContractModel):
    analysis_id: str
    status: Literal["RUNNING", "PAUSED", "BLOCKED", "FAILED", "COMPLETE", "PARTIAL"]
    completed_units: int
    skipped_units: int = 0
    known_units: int
    percent: int
    percentage_kind: Literal["known_checkpoint_fraction"] | None = None
    phase_counts: dict[str, dict[str, int]] = Field(default_factory=dict)
    current_stage: str | None = None
    current_hypothesis_id: str | None = None
    error_code: str | None = None
    denominator_change_reason: str | None = None
    attempt_number: int = 1
    attempt_limit: int = MAX_RECOVERY_ATTEMPTS
    inconclusive_hypothesis_count: int = 0
    rejected_hypothesis_count: int = 0
    candidate_total_count: int | None = None
    candidate_decision_counts: dict[str, int] = Field(default_factory=dict)
    deep_analysis_running_count: int = 0
    deep_analysis_completed_count: int = 0
    deep_analysis_pending_count: int = 0
    hypothesis_count: int = 0
    finding_count: int = 0
    resume_action: str | None = None


__all__ = ["ProgressSnapshot"]
