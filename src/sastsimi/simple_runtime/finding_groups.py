"""Immutable presentation groups for independently verified Findings.

No Finding, PoC, scope verdict, or artifact is rewritten by this projection.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Literal

from sastsimi.contracts.refs import StoredDataRef

from .candidates import CandidateOrigin
from .finding_flow import FlowAnchor

_GROUP_VERSION = "verified-python-flow-v1"


@dataclass(frozen=True, slots=True)
class VerifiedFindingMember:
    analysis_id: str
    workspace_id: str
    commit_id: str
    display_id: str
    finding_ref: StoredDataRef
    hypothesis_id: str
    validated_poc_ref: StoredDataRef
    proposal_ref: StoredDataRef
    cwe_ref: StoredDataRef
    candidate_ids: tuple[str, ...]
    candidate_origins: tuple[CandidateOrigin, ...]
    scope_status: str
    anchor: FlowAnchor | None
    undetermined_reason: str | None = None
    surface_id: str | None = None


@dataclass(frozen=True, slots=True)
class FindingGroup:
    group_id: str
    representative_id: str
    member_ids: tuple[str, ...]
    members: tuple[VerifiedFindingMember, ...]
    status: Literal["PROVEN_SAME_FLOW", "GROUPING_UNDETERMINED"]
    scope_status: str


@dataclass(frozen=True, slots=True)
class FindingGroupProjection:
    groups: tuple[FindingGroup, ...]
    raw_count: int
    visible_group_count: int
    undetermined_count: int


def _display_order(display_id: str) -> tuple[int, str]:
    prefix, separator, number = display_id.partition("-")
    if prefix == "F" and separator and number.isdecimal():
        return int(number), display_id
    return 2**63, display_id


def _digest(value: dict[str, object]) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _group_key(member: VerifiedFindingMember) -> str:
    common: dict[str, object] = {
        "version": _GROUP_VERSION,
        "analysis_id": member.analysis_id,
        "workspace_id": member.workspace_id,
        "commit_id": member.commit_id,
    }
    if member.anchor is not None:
        return _digest({**common, "flow": asdict(member.anchor)})
    return _digest(
        {
            **common,
            "singleton_display_id": member.display_id,
            "hypothesis_id": member.hypothesis_id,
            "finding_hash": member.finding_ref.content_hash,
        }
    )


def group_verified_findings(
    members: Sequence[VerifiedFindingMember],
) -> FindingGroupProjection:
    """Only byte-equivalent proven flow anchors converge; unknowns never do."""

    by_display: set[tuple[str, str]] = set()
    buckets: dict[str, list[VerifiedFindingMember]] = {}
    for member in members:
        identity = member.analysis_id, member.display_id
        if identity in by_display:
            raise ValueError("FINDING_GROUP_DUPLICATE_DISPLAY_ID")
        by_display.add(identity)
        buckets.setdefault(_group_key(member), []).append(member)
    groups: list[FindingGroup] = []
    for group_id, entries in buckets.items():
        ordered = tuple(
            sorted(entries, key=lambda entry: _display_order(entry.display_id))
        )
        scope_values = {entry.scope_status for entry in ordered}
        groups.append(
            FindingGroup(
                group_id=group_id,
                representative_id=ordered[0].display_id,
                member_ids=tuple(entry.display_id for entry in ordered),
                members=ordered,
                status=(
                    "PROVEN_SAME_FLOW"
                    if ordered[0].anchor is not None
                    else "GROUPING_UNDETERMINED"
                ),
                scope_status=scope_values.pop() if len(scope_values) == 1 else "MIXED",
            )
        )
    groups.sort(key=lambda group: _display_order(group.representative_id))
    return FindingGroupProjection(
        groups=tuple(groups),
        raw_count=len(members),
        visible_group_count=len(groups),
        undetermined_count=sum(
            group.status == "GROUPING_UNDETERMINED" for group in groups
        ),
    )


def finding_group_rows(
    projection: FindingGroupProjection,
) -> tuple[dict[str, object], ...]:
    """Public, JSON-safe provenance without code, prompts, or local paths."""

    return tuple(
        {
            "group_id": group.group_id,
            "representative_id": group.representative_id,
            "member_ids": group.member_ids,
            "status": group.status,
            "scope_status": group.scope_status,
            "members": tuple(
                {
                    "display_id": member.display_id,
                    "hypothesis_id": member.hypothesis_id,
                    "finding_hash": member.finding_ref.content_hash,
                    "validated_poc_hash": member.validated_poc_ref.content_hash,
                    "candidate_ids": member.candidate_ids,
                    "candidate_origins": tuple(
                        {
                            "engine": origin.engine,
                            "rule_id": origin.rule_id,
                            "artifact_hash": origin.artifact_ref.content_hash,
                            "result_index": origin.result_index,
                        }
                        for origin in member.candidate_origins
                    ),
                    "surface_id": member.surface_id,
                    "scope_status": member.scope_status,
                    "undetermined_reason": member.undetermined_reason,
                }
                for member in group.members
            ),
        }
        for group in projection.groups
    )
