"""Strict, post-run human review links for a frozen recall oracle."""

from __future__ import annotations

from dataclasses import replace
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sastsimi.simple_runtime.recall_audit import Oracle


class CaseReview(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    case_id: str = Field(min_length=1)
    candidate_ids: tuple[str, ...] = ()
    hypothesis_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    rationale: str = Field(min_length=1)


class FindingReview(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    finding_id: str = Field(pattern=r"^F-[0-9]{3,}$")
    status: Literal["MATCHED", "FALSE_POSITIVE", "UNMATCHED_REVIEWED"]
    case_id: str | None = None
    evidence: str = Field(min_length=1)

    @model_validator(mode="after")
    def require_case_only_for_match(self) -> FindingReview:
        if (self.status == "MATCHED") != (self.case_id is not None):
            raise ValueError("matched Finding requires exactly one case")
        return self


class ReviewLedger(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[2]
    analysis_id: str = Field(min_length=1)
    oracle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inventory_reviewed: bool
    cases: tuple[CaseReview, ...]
    findings: tuple[FindingReview, ...]

    @model_validator(mode="after")
    def unique_links(self) -> ReviewLedger:
        def unique(values: list[str]) -> bool:
            return len(values) == len(set(values))

        if not unique([case.case_id for case in self.cases]):
            raise ValueError("duplicate case review")
        if not unique([finding.finding_id for finding in self.findings]):
            raise ValueError("duplicate Finding review")
        linked = [finding for case in self.cases for finding in case.finding_ids]
        if not unique(linked):
            raise ValueError("Finding linked to multiple cases")
        if set(linked) != {
            finding.finding_id
            for finding in self.findings
            if finding.status == "MATCHED"
        }:
            raise ValueError("case Finding requires matching adjudication")
        for case in self.cases:
            if not all(
                unique(list(values))
                for values in (
                    case.candidate_ids,
                    case.hypothesis_ids,
                    case.finding_ids,
                )
            ):
                raise ValueError("duplicate case link")
        for finding in self.findings:
            if finding.status == "MATCHED" and finding.finding_id not in linked:
                raise ValueError("matched Finding lacks case link")
            if finding.status != "MATCHED" and finding.finding_id in linked:
                raise ValueError("nonmatching Finding has case link")
            if finding.status == "MATCHED" and any(
                case.case_id != finding.case_id
                for case in self.cases
                if finding.finding_id in case.finding_ids
            ):
                raise ValueError("Finding case link mismatch")
        return self


def load_review(payload: bytes) -> ReviewLedger:
    """Parse bounded JSON; no database or analysis write occurs here."""

    if len(payload) > 1024 * 1024:
        raise ValueError("RECALL_REVIEW_TOO_LARGE")
    return ReviewLedger.model_validate_json(payload)


def reviewed_oracle(
    oracle: Oracle, review: ReviewLedger, *, complete_inventory: bool
) -> Oracle:
    """Create an in-memory legacy-audit view; never modify the frozen oracle."""

    if oracle.version != 2:
        raise ValueError("RECALL_REVIEW_VERSION_MISMATCH")
    case_ids = {case.case_id for case in oracle.cases}
    if any(case.case_id not in case_ids for case in review.cases):
        raise ValueError("RECALL_REVIEW_CASE_MISMATCH")
    by_id = {case.case_id: case for case in review.cases}
    return replace(
        oracle,
        cases=tuple(
            replace(
                case,
                vetted_candidate_ids=by_id[case.case_id].candidate_ids,
                vetted_hypothesis_ids=by_id[case.case_id].hypothesis_ids,
                finding_inventory_reviewed=(
                    complete_inventory
                    and review.inventory_reviewed
                    and case.case_id in by_id
                ),
            )
            if case.case_id in by_id
            else case
            for case in oracle.cases
        ),
    )
