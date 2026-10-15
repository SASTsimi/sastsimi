"""An inherited COVERED row must not hide a linked terminal HOLD."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import cast

import pytest

from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import (
    SimpleCheckpointStore,
    SurfaceExplorationProgressRecord,
)
from sastsimi.simple_runtime.surface_child_evidence_v11 import (
    ChildHoldTargetV11,
    collect_child_hold_targets_v11,
    recount_incomplete_hypotheses_v11,
)


def test_recount_incomplete_hypotheses_paginates_exact_ids() -> None:
    class _PagingStore:
        def list_incomplete_hypotheses(
            self, _identity: CheckpointIdentity, *, after_id: str | None, limit: int
        ) -> tuple[str, ...]:
            ids = tuple(f"h{n:03}" for n in range(105))
            remaining = tuple(
                item for item in ids if after_id is None or item > after_id
            )
            return remaining[:limit]

    identity = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id=None,
    )
    assert (
        recount_incomplete_hypotheses_v11(
            identity, cast(SimpleCheckpointStore, _PagingStore())
        )
        == 105
    )


@dataclass(frozen=True)
class _Progress:
    surface_id: str
    hypothesis_ids: tuple[str, ...]


class _Store:
    def __init__(self, checkpoints: dict[tuple[str, SimpleStage], StageCheckpoint]):
        self.checkpoints = checkpoints

    def get(
        self, identity: CheckpointIdentity, stage: SimpleStage
    ) -> StageCheckpoint | None:
        return self.checkpoints.get((identity.hypothesis_id or "", stage))

    def list_candidate_hypothesis_ids(
        self, *_args: object, **_kwargs: object
    ) -> tuple[str, ...]:
        return ()

    def list_checkpoints(self, _analysis_id: str) -> tuple[StageCheckpoint, ...]:
        return tuple(self.checkpoints.values())


def _collect(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    progress: Mapping[tuple[str, str], _Progress],
    store: _Store,
) -> tuple[tuple[ChildHoldTargetV11, ...], str]:
    """Exercise the real collector with intentionally narrow test doubles."""

    return collect_child_hold_targets_v11(
        identity,
        index,
        cast(Mapping[tuple[str, str], SurfaceExplorationProgressRecord], progress),
        cast(SimpleCheckpointStore, store),
    )


def _checkpoint(hypothesis: str, stage: SimpleStage) -> StageCheckpoint:
    return StageCheckpoint(
        identity=CheckpointIdentity(
            analysis_id="analysis",
            workspace_id="workspace",
            commit_id="commit",
            hypothesis_id=hypothesis,
        ),
        stage=stage,
        stage_version=STAGE_VERSION[stage],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(),
        attempt_id="attempt",
        attempt_number=1,
        verdict="HOLD",
    )


def _index() -> SurfaceIndex:
    return SurfaceIndex(
        scope_fingerprint="scope",
        static_bundle_hash="static",
        ast_manifest_hash="ast",
        workspace_id="workspace",
        commit_id="commit",
        candidate_inventory_hash="inventory",
        candidate_count=0,
        surfaces=(
            AttackSurface(
                surface_id="s1",
                type="REQUEST_ENTRY",
                path="app.py",
                symbol="route",
                line=1,
                linked_candidate_ids=(),
                evidence_refs=(),
                detector="ast",
                coverage_status="COVERED",
            ),
            AttackSurface(
                surface_id="s2",
                type="SQL_EXECUTION",
                path="app.py",
                symbol="query",
                line=7,
                linked_candidate_ids=(),
                evidence_refs=(),
                detector="ast",
                coverage_status="COVERED",
            ),
        ),
        static_gaps=(),
    )


def test_collects_every_linked_hold_even_from_covered_surfaces() -> None:
    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id=None,
    )
    first = _checkpoint("h1", SimpleStage.VERIFICATION_INITIAL_DONE)
    final = _checkpoint("h2", SimpleStage.VERIFICATION_FINAL_DONE)
    store = _Store(
        {
            ("h1", first.stage): first,
            ("h2", final.stage): final,
        }
    )
    progress = {
        ("s1", "context"): _Progress("s1", ("h1", "h2")),
        ("s2", "context"): _Progress("s2", ("h1",)),
    }

    targets, snapshot_hash = _collect(root, _index(), progress, store)

    assert [
        (item.hypothesis_id, item.stage.value, item.surface_ids) for item in targets
    ] == [
        ("h1", "VERIFICATION_INITIAL_DONE", ("s1", "s2")),
        ("h2", "VERIFICATION_FINAL_DONE", ("s1",)),
    ]
    assert len(snapshot_hash) == 64
    assert snapshot_hash != hashlib.sha256(b"").hexdigest()


def test_new_linked_child_changes_frozen_snapshot() -> None:
    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id=None,
    )
    first = _checkpoint("h1", SimpleStage.VERIFICATION_INITIAL_DONE)
    second = _checkpoint("h2", SimpleStage.POC_EXECUTION_DONE)
    store = _Store(
        {
            ("h1", first.stage): first,
            ("h2", second.stage): second,
        }
    )
    old = {("s1", "context"): _Progress("s1", ("h1",))}
    new = {("s1", "context"): _Progress("s1", ("h1", "h2"))}

    old_targets, old_hash = _collect(root, _index(), old, store)
    new_targets, new_hash = _collect(root, _index(), new, store)

    assert len(old_targets) == 1
    assert len(new_targets) == 2
    assert new_hash != old_hash


def test_non_hold_checkpoint_mutation_changes_snapshot() -> None:
    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id=None,
    )
    hold = _checkpoint("h1", SimpleStage.VERIFICATION_INITIAL_DONE)
    non_hold = _checkpoint("h1", SimpleStage.POC_EXECUTION_DONE).model_copy(
        update={"verdict": "FALSE"}
    )
    old_store = _Store(
        {
            ("h1", hold.stage): hold,
            ("h1", non_hold.stage): non_hold,
        }
    )
    changed_store = _Store(
        {
            ("h1", hold.stage): hold,
            ("h1", non_hold.stage): non_hold.model_copy(update={"attempt_number": 2}),
        }
    )
    progress = {("s1", "context"): _Progress("s1", ("h1",))}

    old_targets, old_hash = _collect(root, _index(), progress, old_store)
    changed_targets, changed_hash = _collect(root, _index(), progress, changed_store)

    assert changed_targets == old_targets
    assert changed_hash != old_hash


def test_new_linked_non_hold_child_changes_snapshot_without_changing_targets() -> None:
    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id=None,
    )
    hold = _checkpoint("h1", SimpleStage.VERIFICATION_INITIAL_DONE)
    non_hold = _checkpoint("h2", SimpleStage.VERIFICATION_FINAL_DONE).model_copy(
        update={"verdict": "FALSE"}
    )
    store = _Store(
        {
            ("h1", hold.stage): hold,
            ("h2", non_hold.stage): non_hold,
        }
    )
    old = {("s1", "context"): _Progress("s1", ("h1",))}
    new = {("s1", "context"): _Progress("s1", ("h1", "h2"))}

    old_targets, old_hash = _collect(root, _index(), old, store)
    new_targets, new_hash = _collect(root, _index(), new, store)

    assert new_targets == old_targets
    assert new_hash != old_hash


@pytest.mark.parametrize(
    "checkpoint",
    [
        _checkpoint("h1", SimpleStage.VERIFICATION_INITIAL_DONE).model_copy(
            update={
                "identity": CheckpointIdentity(
                    analysis_id="other",
                    workspace_id="workspace",
                    commit_id="commit",
                    hypothesis_id="h1",
                )
            }
        ),
        _checkpoint("h1", SimpleStage.VERIFICATION_FINAL_DONE),
    ],
)
def test_mismatched_checkpoint_identity_or_stage_fails_closed(
    checkpoint: StageCheckpoint,
) -> None:
    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id=None,
    )
    store = _Store({("h1", SimpleStage.VERIFICATION_INITIAL_DONE): checkpoint})
    progress = {("s1", "context"): _Progress("s1", ("h1",))}

    with pytest.raises(ValueError, match="CHILD_EVIDENCE_V11_CHECKPOINT_INVALID"):
        _collect(root, _index(), progress, store)


def test_duplicate_linked_child_id_fails_closed() -> None:
    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id=None,
    )
    progress = {("s1", "context"): _Progress("s1", ("h1", "h1"))}

    with pytest.raises(ValueError, match="CHILD_EVIDENCE_V11_DUPLICATE_ID"):
        _collect(root, _index(), progress, _Store({}))


def test_candidate_page_duplicate_child_id_fails_closed() -> None:
    class DuplicateStore(_Store):
        def list_candidate_hypothesis_ids(
            self, *_args: object, **_kwargs: object
        ) -> tuple[str, ...]:
            return ("h1", "h1")

    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id=None,
    )
    index = _index()
    first = replace(index.surfaces[0], linked_candidate_ids=("c1",))
    index = replace(index, surfaces=(first, *index.surfaces[1:]))

    with pytest.raises(ValueError, match="CHILD_EVIDENCE_V11_DUPLICATE_ID"):
        _collect(root, index, {}, DuplicateStore({}))


def test_checkpoint_hidden_by_store_get_still_fails_closed() -> None:
    class HidingStore(_Store):
        def get(
            self, identity: CheckpointIdentity, stage: SimpleStage
        ) -> StageCheckpoint | None:
            checkpoint = super().get(identity, stage)
            if checkpoint is not None and checkpoint.identity != identity:
                return None
            return checkpoint

    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id=None,
    )
    malformed = _checkpoint("h1", SimpleStage.VERIFICATION_INITIAL_DONE).model_copy(
        update={
            "identity": CheckpointIdentity(
                analysis_id="other",
                workspace_id="workspace",
                commit_id="commit",
                hypothesis_id="h1",
            )
        }
    )
    store = HidingStore({("h1", malformed.stage): malformed})
    progress = {("s1", "context"): _Progress("s1", ("h1",))}

    with pytest.raises(ValueError, match="CHILD_EVIDENCE_V11_CHECKPOINT_INVALID"):
        _collect(root, _index(), progress, store)


def test_duplicate_stage_checkpoint_in_store_listing_fails_closed() -> None:
    class DuplicateCheckpointStore(_Store):
        def list_checkpoints(self, _analysis_id: str) -> tuple[StageCheckpoint, ...]:
            checkpoint = next(iter(self.checkpoints.values()))
            return checkpoint, checkpoint

    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id=None,
    )
    hold = _checkpoint("h1", SimpleStage.VERIFICATION_INITIAL_DONE)
    store = DuplicateCheckpointStore({("h1", hold.stage): hold})
    progress = {("s1", "context"): _Progress("s1", ("h1",))}

    with pytest.raises(ValueError, match="CHILD_EVIDENCE_V11_DUPLICATE_ID"):
        _collect(root, _index(), progress, store)
