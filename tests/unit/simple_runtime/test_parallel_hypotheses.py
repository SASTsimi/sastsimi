from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path

import pytest

from sastsimi.simple_runtime.application import (
    HypothesisSeed,
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
)
from sastsimi.simple_runtime.runner import RunOutcome, SimpleRuntimeRunner
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.simple_runtime.test_simple_analysis_application import _ref, _Static


class _ThreeHypotheses:
    async def propose(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> tuple[HypothesisSeed, ...]:
        del identity, static
        return tuple(
            HypothesisSeed(
                hypothesis_id=f"hypothesis-{index}",
                proposal_ref=_ref(f"proposal-{index}"),
            )
            for index in range(1, 4)
        )


@pytest.mark.asyncio
async def test_parallel_hypotheses_never_exceed_configured_run_limit(
    tmp_path: Path,
) -> None:
    active = 0
    peak = 0

    class Runner:
        async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
            nonlocal active, peak
            del identity
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.03)
            finally:
                active -= 1
            return RunOutcome(
                current_stage=SimpleStage.REPORT_DONE, status=StageStatus.SUCCEEDED
            )

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_ThreeHypotheses(),
        runner_factory=lambda *_: Runner(),  # type: ignore[arg-type]
        id_factory=iter(("analysis-parallel", "workspace-1")).__next__,
        max_parallel_hypotheses=2,
    )
    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert outcome.status == "COMPLETE"
    assert peak == 2
    assert len(store.require_analysis_run("analysis-parallel").hypothesis_ids) == 3


@pytest.mark.asyncio
async def test_cancelled_hypothesis_is_retryable_not_left_running(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-cancel",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    entered = asyncio.Event()

    async def blocking(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        del checkpoint, prior
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    runner = SimpleRuntimeRunner(store, {SimpleStage.PRO_CON_DONE: blocking})
    task = asyncio.create_task(runner.resume_hypothesis(identity))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    checkpoint = store.require(identity, SimpleStage.PRO_CON_DONE)
    assert checkpoint.status is StageStatus.BLOCKED
    assert checkpoint.retryable is True
    assert checkpoint.error_code == "STAGE_CANCELLED"


@pytest.mark.asyncio
async def test_resume_skips_completed_sibling_after_batch_cancellation(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    entered = asyncio.Event()
    release = asyncio.Event()
    calls: dict[str, int] = {}

    def runner_factory(
        current_store: SimpleCheckpointStore,
        child: CheckpointIdentity,
        _static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        async def handle(
            checkpoint: StageCheckpoint,
            prior: Mapping[SimpleStage, StageCheckpoint],
        ) -> StageResult:
            del prior
            name = child.hypothesis_id or ""
            if checkpoint.stage is SimpleStage.PRO_CON_DONE:
                calls[name] = calls.get(name, 0) + 1
                if name == "hypothesis-2" and not release.is_set():
                    entered.set()
                    await release.wait()
            return StageResult(
                output_refs=(_ref(f"{name}-{checkpoint.stage.value}"),),
                verdict="FALSE"
                if checkpoint.stage is SimpleStage.VERIFICATION_FINAL_DONE
                else None,
            )

        return SimpleRuntimeRunner(
            current_store, {stage: handle for stage in HYPOTHESIS_STAGES}
        )

    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_ThreeHypotheses(),
        runner_factory=runner_factory,
        id_factory=iter(("analysis-resume", "workspace-1")).__next__,
        max_parallel_hypotheses=2,
    )
    task = asyncio.create_task(
        application.analyze(
            SimpleAnalysisRequest(
                data_dir=tmp_path,
                repository="https://example.invalid/repo.git",
                commit="a" * 40,
            )
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=2)
    first = CheckpointIdentity(
        analysis_id="analysis-resume",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    for _ in range(100):
        completed = store.get(first, SimpleStage.VERIFICATION_FINAL_DONE)
        if completed is not None and completed.status is StageStatus.SUCCEEDED:
            break
        await asyncio.sleep(0.01)
    else:
        pytest.fail("first sibling did not complete")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()

    resumed = await application.resume("analysis-resume")
    assert resumed.status == "COMPLETE"
    assert calls == {
        "hypothesis-1": 1,
        "hypothesis-2": 2,
        "hypothesis-3": 1,
    }
