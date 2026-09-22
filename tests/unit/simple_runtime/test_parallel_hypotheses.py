"""Hypotheses may be worked on at once, but only as far as the operator allows."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageStatus,
)
from sastsimi.simple_runtime.runner import RunOutcome

_COMMIT = "a" * 40


def _ref(name: str) -> StoredDataRef:
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return StoredDataRef(
        stored_data_id=digest,
        data_kind="artifact",
        content_hash=digest,
        workspace_id="workspace-1",
        commit_id=_COMMIT,
        record_id=None,
    )


class _Runner:
    """Records how many hypotheses are in flight at the same moment."""

    def __init__(self, tracker: dict[str, int]) -> None:
        self._tracker = tracker

    async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
        self._tracker["live"] += 1
        self._tracker["peak"] = max(self._tracker["peak"], self._tracker["live"])
        # Yield twice so a concurrent sibling has a chance to start.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self._tracker["live"] -= 1
        return RunOutcome(
            status=StageStatus.BLOCKED,
            current_stage=SimpleStage.PRO_CON_DONE,
            error_code="POC_EXECUTION_FAILED",
        )


def _application(tmp_path: Path, tracker: dict[str, int], parallel: int) -> Any:
    application = SimpleAnalysisApplication.__new__(SimpleAnalysisApplication)
    application._store = cast(Any, object())
    application._runner_factory = cast(
        Any, lambda _store, _identity, _static: _Runner(tracker)
    )
    application._max_parallel = parallel
    application._register_chain_children = cast(  # type: ignore[method-assign]
        Any, lambda run, _child, _static: run
    )
    return application


def _run(count: int) -> SimpleAnalysisRun:
    return SimpleAnalysisRun(
        analysis_id="analysis-1",
        display_analysis_id="A-001",
        workspace_id="workspace-1",
        commit_id=_COMMIT,
        repository="https://example.invalid/repo.git",
        workspace_path=Path("/tmp/workspace"),
        repository_profile_ref=_ref("profile"),
        static_bundle_ref=_ref("bundle"),
        hypothesis_ids=tuple(f"hypothesis-{index}" for index in range(count)),
    )


def _static() -> StaticBootstrapResult:
    return StaticBootstrapResult(
        repository_profile_ref=_ref("profile"),
        static_bundle_ref=_ref("bundle"),
        workspace_path=Path("/tmp/workspace"),
    )


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id=_COMMIT,
        hypothesis_id=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("parallel", "expected_peak"), [(1, 1), (3, 3)])
async def test_the_setting_decides_how_many_run_at_once(
    tmp_path: Path, parallel: int, expected_peak: int
) -> None:
    tracker = {"live": 0, "peak": 0}
    application = _application(tmp_path, tracker, parallel)

    outcome = await application._run_hypotheses(_run(6), _identity(), _static())

    assert tracker["peak"] == expected_peak
    assert outcome.status == "BLOCKED"


@pytest.mark.asyncio
async def test_every_hypothesis_is_still_visited(tmp_path: Path) -> None:
    seen: list[str] = []
    tracker = {"live": 0, "peak": 0}
    application = _application(tmp_path, tracker, 4)
    inner = application._runner_factory

    def factory(store: Any, identity: CheckpointIdentity, static: Any) -> Any:
        seen.append(identity.hypothesis_id or "")
        return inner(store, identity, static)

    application._runner_factory = factory

    await application._run_hypotheses(_run(7), _identity(), _static())

    assert sorted(seen) == sorted(f"hypothesis-{index}" for index in range(7))


class _UnevenRunner:
    """One hypothesis is slow; the rest are quick, as real stages are."""

    def __init__(self, tracker: dict[str, int], slow: str) -> None:
        self._tracker = tracker
        self._slow = slow

    async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
        self._tracker["live"] += 1
        self._tracker["peak"] = max(self._tracker["peak"], self._tracker["live"])
        if self._tracker["live"] == 2:
            # Every time the second slot fills, the scheduler kept both busy.
            self._tracker["pairs"] = self._tracker.get("pairs", 0) + 1
        turns = 40 if identity.hypothesis_id == self._slow else 1
        for _ in range(turns):
            await asyncio.sleep(0)
        self._tracker["live"] -= 1
        self._tracker["done"] = self._tracker.get("done", 0) + 1
        return RunOutcome(
            status=StageStatus.BLOCKED,
            current_stage=SimpleStage.PRO_CON_DONE,
            error_code="POC_EXECUTION_FAILED",
        )


@pytest.mark.asyncio
async def test_a_free_slot_is_filled_before_the_slow_one_finishes(
    tmp_path: Path,
) -> None:
    """A long hypothesis must not hold its partner's slot empty behind it."""

    tracker = {"live": 0, "peak": 0}
    application = _application(tmp_path, tracker, 2)
    application._runner_factory = cast(
        Any,
        lambda _store, _identity, _static: _UnevenRunner(tracker, "hypothesis-0"),
    )

    await application._run_hypotheses(_run(6), _identity(), _static())

    # Six hypotheses, one of them slow.  Fixed batches pair them [0,1] [2,3]
    # [4,5] and idle the free slot until the slow one ends, so the second slot
    # fills three times.  Refilling as soon as a slot frees pairs the slow one
    # with each of the five quick ones in turn.
    assert tracker["done"] == 6
    assert tracker["peak"] == 2
    assert tracker["pairs"] == 5
