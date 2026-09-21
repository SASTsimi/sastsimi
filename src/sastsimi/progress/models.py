from __future__ import annotations

from typing import Literal

from sastsimi.contracts.base import ContractModel


class ProgressSnapshot(ContractModel):
    analysis_id: str
    status: Literal["RUNNING", "BLOCKED", "FAILED", "COMPLETE"]
    completed_units: int
    skipped_units: int = 0
    known_units: int
    percent: int
    current_stage: str | None = None
    current_hypothesis_id: str | None = None
    error_code: str | None = None
    denominator_change_reason: str | None = None


__all__ = ["ProgressSnapshot"]
