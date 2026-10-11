"""Fail-closed semantic gate between v5 surface review and HOLD replay."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .models import CheckpointIdentity, StageCheckpoint, StageStatus
from .surface_hold_replay_v5 import HoldReplayDecision

if TYPE_CHECKING:
    from .store import SurfaceExplorationProgressRecord
    from .surface_evidence_validation_v5 import V5ValidatedResponse


@dataclass(frozen=True, slots=True)
class V5HoldReplaySignal:
    """Navigation review evidence, kept distinct from replay-proof evidence."""

    decision: HoldReplayDecision
    review_plan_ref: StoredDataRef | None
    review_context_ref: StoredDataRef | None
    review_result_ref: StoredDataRef | None


def evaluate_v5_hold_replay_signal(
    identity: CheckpointIdentity,
    child: StageCheckpoint,
    record: SurfaceExplorationProgressRecord,
    saved_result: Mapping[str, object],
    validated: V5ValidatedResponse,
    *,
    plan_ref: StoredDataRef,
    context_ref: StoredDataRef,
) -> V5HoldReplaySignal:
    """Never turn a v5 graph-path review into a child replay by inference.

    The caller first revalidates the saved context/graph/result using the v5
    coverage reader and passes its ``V5ValidatedResponse`` here. The current
    result schema has no bound contradiction or test-material reference, so
    even a complete source path and persuasive Agent prose are review-only.
    A future producer needs a separately verified, schema-bound proof before
    calling ``classify_hold_replay`` for a non-KEEP_HOLD decision.
    """

    checkpoint_sha256 = hashlib.sha256(canonical_bytes(child)).hexdigest()
    reason = "V5_RESULT_UNVERIFIED"
    review_plan_ref: StoredDataRef | None = None
    review_context_ref: StoredDataRef | None = None
    review_ref: StoredDataRef | None = None
    try:
        result_hash = hashlib.sha256(canonical_bytes(saved_result)).hexdigest()
        ref = record.result_ref
        scoped_refs = (plan_ref, context_ref, ref)
        if (
            child.identity == identity
            and identity.hypothesis_id is not None
            and child.status is StageStatus.SUCCEEDED
            and child.verdict == "HOLD"
            and record.proposal_version == 5
            and all(
                item.data_kind == "artifact"
                and item.record_id is None
                and str(item.stored_data_id) == item.content_hash
                and item.workspace_id.root == identity.workspace_id
                and item.commit_id.root == identity.commit_id
                for item in scoped_refs
            )
            and context_ref.content_hash == record.context_hash
            and ref.content_hash == result_hash
            and saved_result.get("kind") == "simple_surface_hypothesis_result_v5"
            and saved_result.get("analysis_id") == identity.analysis_id
            and saved_result.get("surface_id") == record.surface_id
            and saved_result.get("context_id") == record.context_id
            and saved_result.get("context_hash") == record.context_hash
            and saved_result.get("static_bundle_hash") == record.static_bundle_hash
            and saved_result.get("status") == record.status == validated.status
            and saved_result.get("reason") == validated.reason
            and saved_result.get("validation_status") == "VALID"
            and saved_result.get("verified_roles") == list(validated.verified_roles)
            and saved_result.get("reviewed_parts") == sorted(validated.reviewed_parts)
            and saved_result.get("evidence_locations")
            == list(validated.evidence_locations)
            and saved_result.get("verified_path_id") == validated.verified_path_id
            and saved_result.get("seed_ids") == list(record.hypothesis_ids)
            and isinstance(saved_result.get("response"), dict)
        ):
            reason = "V5_NAVIGATION_ONLY_NO_REPLAY_PROOF"
            review_plan_ref = plan_ref
            review_context_ref = context_ref
            review_ref = ref
    except (TypeError, ValueError):
        pass
    return V5HoldReplaySignal(
        decision=HoldReplayDecision(
            action="KEEP_HOLD",
            restart_stage=None,
            evidence_refs=(),
            reason=reason,
            checkpoint_sha256=checkpoint_sha256,
        ),
        review_plan_ref=review_plan_ref,
        review_context_ref=review_context_ref,
        review_result_ref=review_ref,
    )
