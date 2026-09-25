"""Application service for new and resumed repository analyses."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal, Protocol
from uuid import uuid4

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore

from .artifacts import SimpleArtifactRepository
from .models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from .runner import RunOutcome, SimpleRuntimeRunner
from .store import SimpleCheckpointStore
from .usage import labelled


class SimpleAnalysisRequest(ContractModel):
    data_dir: Path
    repository: str
    commit: str


class StaticBootstrapResult(ContractModel):
    repository_profile_ref: StoredDataRef
    static_bundle_ref: StoredDataRef
    workspace_path: Path


class HypothesisSeed(ContractModel):
    hypothesis_id: str
    proposal_ref: StoredDataRef


class SimpleAnalysisOutcome(ContractModel):
    identity: CheckpointIdentity
    display_analysis_id: str
    status: Literal["RUNNING", "BLOCKED", "FAILED", "COMPLETE"]
    current_stage: SimpleStage
    error_code: str | None = None


class StaticBootstrap(Protocol):
    async def run(
        self,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
    ) -> StaticBootstrapResult: ...


class HypothesisBootstrap(Protocol):
    async def propose(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> tuple[HypothesisSeed, ...]: ...


type RunnerFactory = Callable[
    [SimpleCheckpointStore, CheckpointIdentity, StaticBootstrapResult],
    SimpleRuntimeRunner,
]


class SimpleAnalysisApplication:
    def __init__(
        self,
        *,
        data_dir: Path,
        store: SimpleCheckpointStore,
        static_bootstrap: StaticBootstrap,
        hypothesis_bootstrap: HypothesisBootstrap,
        runner_factory: RunnerFactory,
        id_factory: Callable[[], str] | None = None,
        max_parallel_hypotheses: int = 1,
    ) -> None:
        self._data_dir = data_dir
        self._store = store
        self._static = static_bootstrap
        self._hypotheses = hypothesis_bootstrap
        self._runner_factory = runner_factory
        self._ids = id_factory or (lambda: uuid4().hex)
        self._max_parallel = max(1, max_parallel_hypotheses)
        self._display = AnalysisDisplayIdStore(store.database_path)

    async def analyze(
        self,
        request: SimpleAnalysisRequest,
        *,
        on_analysis_started: Callable[[str], None] | None = None,
    ) -> SimpleAnalysisOutcome:
        analysis_id = self._ids()
        workspace_id = self._ids()
        display_id = self._display.get_or_allocate(analysis_id)
        identity = CheckpointIdentity(
            analysis_id=analysis_id,
            workspace_id=workspace_id,
            commit_id=request.commit.lower(),
            hypothesis_id=None,
        )
        run = SimpleAnalysisRun(
            analysis_id=analysis_id,
            display_analysis_id=display_id,
            workspace_id=workspace_id,
            commit_id=request.commit.lower(),
            repository=request.repository,
        )
        self._store.save_analysis_run(run)
        if on_analysis_started is not None:
            on_analysis_started(analysis_id)
        return await self._run_static(run, identity)

    async def _run_static(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
    ) -> SimpleAnalysisOutcome:
        checkpoint = self._store.mark_running(
            identity,
            SimpleStage.STATIC_DONE,
            (),
            attempt_id=uuid4().hex,
        )
        try:
            static = await self._static.run(
                SimpleAnalysisRequest(
                    data_dir=self._data_dir,
                    repository=run.repository,
                    commit=run.commit_id,
                ),
                identity,
            )
        except Exception as error:
            failed = self._store.mark_failure(
                checkpoint,
                StageFailure(
                    code=self._safe_error_code(error, "STATIC_BOOTSTRAP_BLOCKED"),
                    retryable=True,
                    safe_message="Repository or static analysis did not complete",
                ),
                StageStatus.BLOCKED,
            )
            return SimpleAnalysisOutcome(
                identity=identity,
                display_analysis_id=run.display_analysis_id,
                status="BLOCKED",
                current_stage=failed.stage,
                error_code=failed.error_code,
            )
        self._store.complete(
            checkpoint,
            self._stage_result(
                static.repository_profile_ref,
                static.static_bundle_ref,
            ),
        )
        updated_run = run.model_copy(
            update={
                "workspace_path": static.workspace_path,
                "repository_profile_ref": static.repository_profile_ref,
                "static_bundle_ref": static.static_bundle_ref,
            }
        )
        self._store.save_analysis_run(updated_run)
        return await self._propose_and_run(updated_run, identity, static)

    async def resume(self, analysis_id_or_display: str) -> SimpleAnalysisOutcome:
        exact = self._display.resolve(analysis_id_or_display)
        run = self._store.require_analysis_run(exact)
        identity = CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        if (
            run.workspace_path is None
            or run.repository_profile_ref is None
            or run.static_bundle_ref is None
        ):
            return await self._run_static(run, identity)
        static = StaticBootstrapResult(
            repository_profile_ref=run.repository_profile_ref,
            static_bundle_ref=run.static_bundle_ref,
            workspace_path=run.workspace_path,
        )
        if not run.hypothesis_ids:
            return await self._propose_and_run(run, identity, static)
        return await self._run_hypotheses(run, identity, static)

    async def _propose_and_run(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisOutcome:
        checkpoint = self._store.mark_running(
            identity,
            SimpleStage.HYPOTHESIS_DONE,
            (static.static_bundle_ref,),
            attempt_id=uuid4().hex,
        )
        try:
            with labelled("HYPOTHESIS"):
                seeds = await self._hypotheses.propose(identity, static)
            if not seeds:
                raise ValueError("HYPOTHESIS_OUTPUT_EMPTY")
        except Exception as error:
            failed = self._store.mark_failure(
                checkpoint,
                StageFailure(
                    code=self._safe_error_code(
                        error,
                        "HYPOTHESIS_BOOTSTRAP_BLOCKED",
                    ),
                    retryable=True,
                    safe_message="Hypothesis generation did not complete",
                ),
                StageStatus.BLOCKED,
            )
            return SimpleAnalysisOutcome(
                identity=identity,
                display_analysis_id=run.display_analysis_id,
                status="BLOCKED",
                current_stage=failed.stage,
                error_code=failed.error_code,
            )
        self._store.complete(
            checkpoint,
            self._stage_result(*(seed.proposal_ref for seed in seeds)),
        )
        for seed in seeds:
            child = identity.model_copy(update={"hypothesis_id": seed.hypothesis_id})
            inputs = (seed.proposal_ref, static.static_bundle_ref)
            self._store.save_checkpoint(
                StageCheckpoint(
                    identity=child,
                    stage=SimpleStage.PRO_CON_DONE,
                    status=StageStatus.PENDING,
                    input_refs=inputs,
                    input_hash=input_reference_hash(inputs),
                )
            )
        run = run.model_copy(
            update={"hypothesis_ids": tuple(seed.hypothesis_id for seed in seeds)}
        )
        self._store.save_analysis_run(run)
        return await self._run_hypotheses(run, identity, static)

    async def _run_hypotheses(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisOutcome:
        latest_stage = SimpleStage.HYPOTHESIS_DONE
        incomplete: RunOutcome | None = None
        # A semaphore rather than fixed batches: stage times differ by an order
        # of magnitude - minutes for evidence, tens of minutes for one
        # reproduction - so waiting for a whole batch leaves the other worker
        # idle.  Here a finished hypothesis frees its slot at once.
        slots = asyncio.Semaphore(self._max_parallel)

        async def work(
            hypothesis_id: str,
        ) -> tuple[CheckpointIdentity, RunOutcome]:
            child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
            async with slots:
                outcome = await self._runner_factory(
                    self._store, child, static
                ).resume_hypothesis(child)
            return child, outcome

        started: set[str] = set()
        running: set[asyncio.Task[tuple[CheckpointIdentity, RunOutcome]]] = set()
        while True:
            # Chaining appends hypotheses while the run is under way, so the
            # list is re-read after every completion rather than sliced once.
            for hypothesis_id in run.hypothesis_ids:
                if hypothesis_id not in started:
                    started.add(hypothesis_id)
                    running.add(asyncio.create_task(work(hypothesis_id)))
            if not running:
                break
            finished, running = await asyncio.wait(
                running, return_when=asyncio.FIRST_COMPLETED
            )
            for task in finished:
                child, outcome = task.result()
                latest_stage = outcome.current_stage
                if outcome.status in {StageStatus.BLOCKED, StageStatus.FAILED}:
                    if (
                        incomplete is None
                        or outcome.status is StageStatus.FAILED
                        and incomplete.status is StageStatus.BLOCKED
                    ):
                        incomplete = outcome
                    continue
                # Only this loop rewrites the run record, and it does so between
                # awaits, so the appended children are visible to the next pass.
                run = self._register_chain_children(run, child, static)
        if incomplete is not None:
            outcome_status: Literal["BLOCKED", "FAILED"] = (
                "BLOCKED" if incomplete.status is StageStatus.BLOCKED else "FAILED"
            )
            return SimpleAnalysisOutcome(
                identity=identity,
                display_analysis_id=run.display_analysis_id,
                status=outcome_status,
                current_stage=incomplete.current_stage,
                error_code=incomplete.error_code,
            )
        return SimpleAnalysisOutcome(
            identity=identity,
            display_analysis_id=run.display_analysis_id,
            status="COMPLETE",
            current_stage=latest_stage,
        )

    def _register_chain_children(
        self,
        run: SimpleAnalysisRun,
        parent: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisRun:
        checkpoint = self._store.get(parent, SimpleStage.CHAINING_DONE)
        if checkpoint is None or len(checkpoint.output_refs) != 1:
            return run
        artifacts = SimpleArtifactRepository(self._data_dir, parent)
        try:
            value = json.loads(artifacts.read(checkpoint.output_refs[0]))
            children = value.get("children", [])
        except (OSError, ValueError, json.JSONDecodeError):
            return run
        if not isinstance(children, list):
            return run
        hypothesis_ids = list(run.hypothesis_ids)
        parents = dict(run.parent_hypothesis_ids)
        depths = dict(run.chain_depths)
        changed = False
        for child_value in children:
            if not isinstance(child_value, dict) or len(hypothesis_ids) >= 32:
                continue
            parent_ids = tuple(
                str(item) for item in child_value.get("parent_hypothesis_ids", [])
            )
            depth = 1 + max((depths.get(item, 0) for item in parent_ids), default=0)
            if not parent_ids or depth > 4:
                continue
            hypothesis_id = (
                "hypothesis-chain-"
                + hashlib.sha256(canonical_bytes(child_value)).hexdigest()[:32]
            )
            if hypothesis_id in hypothesis_ids:
                continue
            proposal_ref = artifacts.put_json(
                {
                    "kind": "simple_hypothesis_proposal",
                    "origin": "CHAINING",
                    "analysis_id": parent.analysis_id,
                    "hypothesis_id": hypothesis_id,
                    "static_bundle_ref": static.static_bundle_ref.model_dump(
                        mode="json"
                    ),
                    "parent_chaining_result_ref": checkpoint.output_refs[0].model_dump(
                        mode="json"
                    ),
                    "proposal": child_value,
                }
            )
            child_identity = parent.model_copy(update={"hypothesis_id": hypothesis_id})
            inputs = (proposal_ref, static.static_bundle_ref)
            self._store.save_checkpoint(
                StageCheckpoint(
                    identity=child_identity,
                    stage=SimpleStage.PRO_CON_DONE,
                    status=StageStatus.PENDING,
                    input_refs=inputs,
                    input_hash=input_reference_hash(inputs),
                )
            )
            hypothesis_ids.append(hypothesis_id)
            parents[hypothesis_id] = parent_ids
            depths[hypothesis_id] = depth
            changed = True
        if not changed:
            return run
        updated = run.model_copy(
            update={
                "hypothesis_ids": tuple(hypothesis_ids),
                "parent_hypothesis_ids": parents,
                "chain_depths": depths,
            }
        )
        self._store.save_analysis_run(updated)
        return updated

    @staticmethod
    def _stage_result(*refs: StoredDataRef) -> StageResult:
        return StageResult(output_refs=tuple(refs))

    @staticmethod
    def _safe_error_code(error: Exception, fallback: str) -> str:
        message = str(error)
        if message and all(
            character.isupper() or character.isdigit() or character in "_:"
            for character in message
        ):
            return message[:160]
        return fallback


__all__ = [
    "HypothesisSeed",
    "SimpleAnalysisApplication",
    "SimpleAnalysisOutcome",
    "SimpleAnalysisRequest",
    "SimpleAnalysisRun",
    "StaticBootstrapResult",
]
