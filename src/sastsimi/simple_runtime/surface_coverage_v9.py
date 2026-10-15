"""Add independently tracked child-HOLD obligations to v10 surface coverage.

This evaluator does not certify a revalidation result. Its caller must pass
only dispositions whose artifact, checkpoint and runtime lineage has been
independently replayed. Missing, malformed or contradictory input is never
silently treated as an absence of findings.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Literal

from .models import SimpleStage
from .surface_child_evidence_v11 import ChildHoldTargetV11
from .surface_coverage_v8 import SurfaceCoverageV8, SurfaceProofV8
from .surface_enrichment_v9 import _digest

ChildStatusV11 = Literal["PENDING", "RESOLVED", "STILL_HOLD", "ERROR"]
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RESOLVED_REASONS = frozenset({"VERIFIED_POC_INCONCLUSIVE"})


@dataclass(frozen=True, slots=True)
class ChildDispositionV11:
    checkpoint_hash: str
    status: ChildStatusV11
    reason_code: str
    evidence_hash: str | None


@dataclass(frozen=True, slots=True)
class ChildObligationV11:
    hypothesis_id: str
    stage: SimpleStage
    checkpoint_hash: str
    surface_ids: tuple[str, ...]
    status: ChildStatusV11
    reason_code: str
    evidence_hash: str | None

    def to_json(self) -> dict[str, object]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "stage": self.stage.value,
            "checkpoint_hash": self.checkpoint_hash,
            "surface_ids": list(self.surface_ids),
            "status": self.status,
            "reason_code": self.reason_code,
            "evidence_hash": self.evidence_hash,
        }


@dataclass(frozen=True, slots=True)
class SurfaceCoverageV9:
    parent_v8_hash: str
    scope_fingerprint: str
    index_hash: str
    surfaces: tuple[SurfaceProofV8, ...]
    child_obligations: tuple[ChildObligationV11, ...]
    effective_python_gaps: tuple[dict[str, object], ...]
    missing_v9_parts: tuple[dict[str, str], ...]
    remaining_route_gap_events: tuple[dict[str, object], ...]
    pending_candidate_count: int
    pending_child_count: int

    @property
    def resolved_child_revalidation_count(self) -> int:
        return sum(row.status == "RESOLVED" for row in self.child_obligations)

    @property
    def pending_child_revalidation_count(self) -> int:
        return sum(row.status == "PENDING" for row in self.child_obligations)

    @property
    def still_hold_child_revalidation_count(self) -> int:
        return sum(row.status == "STILL_HOLD" for row in self.child_obligations)

    @property
    def error_child_revalidation_count(self) -> int:
        return sum(row.status == "ERROR" for row in self.child_obligations)

    @property
    def complete(self) -> bool:
        return (
            bool(self.surfaces)
            and not self.effective_python_gaps
            and not self.missing_v9_parts
            and not self.remaining_route_gap_events
            and self.pending_candidate_count == 0
            and self.pending_child_count == 0
            and self.pending_child_revalidation_count == 0
            and self.still_hold_child_revalidation_count == 0
            and self.error_child_revalidation_count == 0
            and all(row.coverage_status == "COVERED" for row in self.surfaces)
        )

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_attack_surface_coverage_v9",
            "parent_v8_hash": self.parent_v8_hash,
            "scope_fingerprint": self.scope_fingerprint,
            "index_hash": self.index_hash,
            "surfaces": [row.to_json() for row in self.surfaces],
            "child_obligations": [row.to_json() for row in self.child_obligations],
            "effective_python_gaps": list(self.effective_python_gaps),
            "missing_v9_parts": list(self.missing_v9_parts),
            "remaining_route_gap_events": list(self.remaining_route_gap_events),
            "pending_candidate_count": self.pending_candidate_count,
            "pending_child_count": self.pending_child_count,
            "complete": self.complete,
        }


def _obligation(
    target: ChildHoldTargetV11,
    disposition: ChildDispositionV11 | None,
) -> ChildObligationV11:
    if disposition is None:
        status: ChildStatusV11 = "PENDING"
        reason = "REVALIDATION_NOT_RUN"
        evidence_hash: str | None = None
    elif (
        disposition.checkpoint_hash != target.checkpoint_hash
        or disposition.status not in {"PENDING", "RESOLVED", "STILL_HOLD", "ERROR"}
        or disposition.status == "RESOLVED"
        and (
            disposition.reason_code not in _RESOLVED_REASONS
            or target.stage is not SimpleStage.POC_EXECUTION_DONE
            or disposition.evidence_hash is None
            or _SHA256.fullmatch(disposition.evidence_hash) is None
        )
        or disposition.status != "RESOLVED"
        and (not disposition.reason_code or disposition.evidence_hash is not None)
    ):
        status = "ERROR"
        reason = "REVALIDATION_RESULT_INVALID"
        evidence_hash = None
    else:
        status = disposition.status
        reason = disposition.reason_code
        evidence_hash = disposition.evidence_hash
    return ChildObligationV11(
        hypothesis_id=target.hypothesis_id,
        stage=target.stage,
        checkpoint_hash=target.checkpoint_hash,
        surface_ids=target.surface_ids,
        status=status,
        reason_code=reason,
        evidence_hash=evidence_hash,
    )


def evaluate_surface_coverage_v9(
    parent: SurfaceCoverageV8,
    targets: tuple[ChildHoldTargetV11, ...],
    dispositions: Mapping[tuple[str, SimpleStage], ChildDispositionV11],
    *,
    current_pending_child_count: int | None = None,
) -> SurfaceCoverageV9:
    """Project verified child results without rewriting v10 evidence."""

    if current_pending_child_count is not None and (
        type(current_pending_child_count) is not int or current_pending_child_count < 0
    ):
        raise ValueError("SURFACE_COVERAGE_V9_PENDING_CHILD_INVALID")
    keys = [(item.hypothesis_id, item.stage) for item in targets]
    if len(keys) != len(set(keys)) or not set(dispositions) <= set(keys):
        raise ValueError("SURFACE_COVERAGE_V9_CHILD_SET_INVALID")
    surface_ids = {row.surface_id for row in parent.surfaces}
    if any(
        not target.surface_ids
        or len(target.surface_ids) != len(set(target.surface_ids))
        or not set(target.surface_ids) <= surface_ids
        for target in targets
    ):
        raise ValueError("SURFACE_COVERAGE_V9_CHILD_SURFACE_INVALID")
    obligations = tuple(
        _obligation(target, dispositions.get((target.hypothesis_id, target.stage)))
        for target in targets
    )
    rows: list[SurfaceProofV8] = []
    for prior in parent.surfaces:
        linked = tuple(
            obligation
            for obligation in obligations
            if prior.surface_id in obligation.surface_ids
        )
        reasons = set(prior.unresolved_reason_codes)
        if linked:
            if any(item.status != "RESOLVED" for item in linked):
                reasons.add("CHILD_HOLD")
            else:
                reasons.discard("CHILD_HOLD")
        status = (
            "INSUFFICIENT"
            if reasons
            else "COVERED"
            if linked and prior.coverage_status in {"COVERED", "INSUFFICIENT"}
            else prior.coverage_status
        )
        rows.append(
            replace(
                prior,
                coverage_status=status,
                unresolved_reason_codes=tuple(sorted(reasons)),
            )
        )
    return SurfaceCoverageV9(
        parent_v8_hash=_digest(parent.to_json()),
        scope_fingerprint=parent.scope_fingerprint,
        index_hash=parent.index_hash,
        surfaces=tuple(rows),
        child_obligations=obligations,
        effective_python_gaps=parent.effective_python_gaps,
        missing_v9_parts=parent.missing_v9_parts,
        remaining_route_gap_events=parent.remaining_route_gap_events,
        pending_candidate_count=parent.pending_candidate_count,
        pending_child_count=(
            parent.pending_child_count
            if current_pending_child_count is None
            else current_pending_child_count
        ),
    )
