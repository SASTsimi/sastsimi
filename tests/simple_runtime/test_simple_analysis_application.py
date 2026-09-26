from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    HypothesisSeed,
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
    SimpleAnalysisRun,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
)
from sastsimi.simple_runtime.runner import RunOutcome, SimpleRuntimeRunner, StageBlocked
from sastsimi.simple_runtime.store import SimpleCheckpointStore


class _RecoveryFactory:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.calls: list[tuple[StageCheckpoint, StageFailure]] = []

    def __call__(self, _identity: CheckpointIdentity) -> _RecoveryFactory:
        return self

    async def decide(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
    ) -> RecoveryResolution:
        self.calls.append((checkpoint, failure))
        decision = RecoveryDecision(
            category=RecoveryCategory.TRANSIENT_TOOL,
            action=RecoveryAction.RETRY_STAGE,
            diagnosis="temporary test failure",
            guidance="retry the owning stage",
            environment_patch="",
        )
        ref = SimpleArtifactRepository(self.data_dir, checkpoint.identity).put_json(
            {
                "kind": "simple_recovery_decision",
                "decision": decision.model_dump(mode="json"),
            }
        )
        return RecoveryResolution(decision=decision, decision_ref=ref)


def _ref(name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"stored-{name}"),
        data_kind=name,
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("a" * 40),
        record_id=None,
    )


class _Static:
    async def run(
        self,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
    ) -> StaticBootstrapResult:
        assert request.repository == "https://example.invalid/repo.git"
        return StaticBootstrapResult(
            repository_profile_ref=_ref("repository-profile"),
            static_bundle_ref=_ref("static-bundle"),
            workspace_path=request.data_dir / "workspaces" / identity.workspace_id,
        )


class _Hypotheses:
    async def propose(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> tuple[HypothesisSeed, ...]:
        del identity
        assert static.static_bundle_ref == _ref("static-bundle")
        return (
            HypothesisSeed(
                hypothesis_id="hypothesis-1",
                proposal_ref=_ref("hypothesis"),
            ),
        )


def _runner(
    store: SimpleCheckpointStore,
    identity: CheckpointIdentity,
    _static: StaticBootstrapResult,
) -> SimpleRuntimeRunner:
    del identity, _static
    handlers: dict[SimpleStage, Any] = {}
    for stage in tuple(SimpleStage)[2:]:

        async def handle(
            _checkpoint: StageCheckpoint,
            _prior: Mapping[SimpleStage, StageCheckpoint],
            *,
            current: SimpleStage = stage,
        ) -> StageResult:
            return StageResult(
                output_refs=(_ref(current.value.lower()),),
                verdict="FALSE"
                if current is SimpleStage.VERIFICATION_FINAL_DONE
                else None,
            )

        handlers[stage] = handle
    return SimpleRuntimeRunner(store, handlers)


@pytest.mark.asyncio
async def test_concurrent_resume_does_not_repeat_gate_replay_or_raise_stale(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    display = AnalysisDisplayIdStore(store.database_path).get_or_allocate(
        "analysis-concurrent"
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-concurrent",
            display_analysis_id=display,
            workspace_id="workspace-1",
            commit_id="a" * 40,
            repository="https://example.invalid/repo.git",
            workspace_path=tmp_path / "workspaces" / "workspace-1",
            repository_profile_ref=_ref("repository-profile"),
            static_bundle_ref=_ref("static-bundle"),
            hypothesis_ids=("hypothesis-1",),
        )
    )
    entered = asyncio.Event()
    release = asyncio.Event()
    duplicate_calls = 0

    class FirstRunner:
        async def resume_hypothesis(self, _identity: CheckpointIdentity) -> RunOutcome:
            entered.set()
            await release.wait()
            return RunOutcome(
                current_stage=SimpleStage.POC_CANDIDATE_DONE,
                status=StageStatus.BLOCKED,
                error_code="TEST_PAUSED",
            )

    class SecondRunner:
        async def resume_hypothesis(self, _identity: CheckpointIdentity) -> RunOutcome:
            nonlocal duplicate_calls
            duplicate_calls += 1
            raise ValueError("GATE_REVISION_STALE")

    first = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=lambda *_args: FirstRunner(),  # type: ignore[arg-type]
    )
    second = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=SimpleCheckpointStore(store.database_path),
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=lambda *_args: SecondRunner(),  # type: ignore[arg-type]
    )

    active = asyncio.create_task(first.resume(display))
    await asyncio.wait_for(entered.wait(), timeout=2)
    try:
        overlapping = await asyncio.wait_for(second.resume(display), timeout=2)
        assert overlapping.status == "RUNNING"
        assert overlapping.error_code == "ANALYSIS_ALREADY_RUNNING"
        assert duplicate_calls == 0
    finally:
        release.set()
        await active


@pytest.mark.asyncio
async def test_new_analysis_persists_bootstrap_then_runs_hypotheses(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )

    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert outcome.status == "COMPLETE"
    assert outcome.display_analysis_id == "A-001"
    analysis_identity = outcome.identity.model_copy(update={"hypothesis_id": None})
    assert store.require(analysis_identity, SimpleStage.STATIC_DONE).status == (
        StageStatus.SUCCEEDED
    )
    hypothesis_checkpoint = store.require(
        analysis_identity,
        SimpleStage.HYPOTHESIS_DONE,
    )
    assert hypothesis_checkpoint.output_refs == (_ref("hypothesis"),)
    hypothesis_identity = outcome.identity.model_copy(
        update={"hypothesis_id": "hypothesis-1"}
    )
    assert (
        store.require(hypothesis_identity, SimpleStage.VERIFICATION_FINAL_DONE).verdict
        == "FALSE"
    )


@pytest.mark.asyncio
async def test_repository_policy_ref_survives_analysis_resume(tmp_path: Path) -> None:
    class StaticWithPolicy:
        calls = 0

        async def run(
            self,
            request: SimpleAnalysisRequest,
            identity: CheckpointIdentity,
        ) -> StaticBootstrapResult:
            self.calls += 1
            return StaticBootstrapResult(
                repository_profile_ref=_ref("repository-profile"),
                static_bundle_ref=_ref("static-bundle"),
                workspace_path=request.data_dir / "workspaces" / identity.workspace_id,
                security_policy_ref=_ref("security-policy"),
            )

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    static = StaticWithPolicy()
    seen_refs: list[StoredDataRef | None] = []

    def runner_factory(
        current_store: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        bootstrap: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        seen_refs.append(bootstrap.security_policy_ref)
        return _runner(current_store, identity, bootstrap)

    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=runner_factory,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )

    await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )
    assert store.require_analysis_run("analysis-1").security_policy_ref == _ref(
        "security-policy"
    )

    await application.resume("analysis-1")

    assert static.calls == 1
    assert seen_refs == [_ref("security-policy"), _ref("security-policy")]


@pytest.mark.asyncio
async def test_policy_snapshot_is_shared_by_gate_checkpoints_and_reused_on_resume(
    tmp_path: Path,
) -> None:
    class StaticWithSnapshot:
        calls = 0

        async def run(
            self, request: SimpleAnalysisRequest, identity: CheckpointIdentity
        ) -> StaticBootstrapResult:
            self.calls += 1
            return StaticBootstrapResult(
                repository_profile_ref=_ref("repository-profile"),
                static_bundle_ref=_ref("static-bundle"),
                workspace_path=request.data_dir / "workspaces" / identity.workspace_id,
                policy_snapshot_ref=_ref("policy-snapshot"),
            )

    class TwoHypotheses:
        async def propose(
            self, _identity: CheckpointIdentity, _static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            return (
                HypothesisSeed(hypothesis_id="hypothesis-1", proposal_ref=_ref("h1")),
                HypothesisSeed(hypothesis_id="hypothesis-2", proposal_ref=_ref("h2")),
            )

    def with_scope_gate(
        current_store: SimpleCheckpointStore,
        _identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        handlers: dict[SimpleStage, Any] = {}
        for stage in tuple(SimpleStage)[2:]:

            async def handle(
                _checkpoint: StageCheckpoint,
                _prior: Mapping[SimpleStage, StageCheckpoint],
                *,
                current: SimpleStage = stage,
            ) -> StageResult:
                return StageResult(
                    output_refs=(_ref(current.value.lower()),),
                    verdict="TRUE"
                    if current is SimpleStage.VERIFICATION_FINAL_DONE
                    else None,
                    gate_decision="ACCEPT"
                    if current is SimpleStage.TECH_GATE_DONE
                    else None,
                )

            handlers[stage] = handle
        return SimpleRuntimeRunner(
            current_store, handlers, policy_snapshot_ref=static.policy_snapshot_ref
        )

    static = StaticWithSnapshot()
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=TwoHypotheses(),
        runner_factory=with_scope_gate,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )

    first = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://github.com/acme/app",
            commit="a" * 40,
        )
    )
    run = store.require_analysis_run("analysis-1")
    assert run.policy_snapshot_ref == _ref("policy-snapshot")
    assert (
        _ref("policy-snapshot")
        in store.require(first.identity, SimpleStage.STATIC_DONE).output_refs
    )
    before: list[tuple[StoredDataRef, ...]] = []
    for hypothesis_id in run.hypothesis_ids:
        child = first.identity.model_copy(update={"hypothesis_id": hypothesis_id})
        gate = store.require(child, SimpleStage.SCOPE_GATE_DONE)
        assert gate.input_refs.count(_ref("policy-snapshot")) == 1
        before.append(gate.input_refs)

    await application.resume(first.display_analysis_id)

    assert static.calls == 1
    for hypothesis_id, inputs in zip(run.hypothesis_ids, before, strict=True):
        child = first.identity.model_copy(update={"hypothesis_id": hypothesis_id})
        assert store.require(child, SimpleStage.SCOPE_GATE_DONE).input_refs == inputs


def test_legacy_run_without_policy_snapshot_field_remains_loadable() -> None:
    original = SimpleAnalysisRun(
        analysis_id="legacy",
        display_analysis_id="A-001",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        repository="https://github.com/acme/app",
    )
    data = original.model_dump(mode="json", exclude={"policy_snapshot_ref"})

    loaded = SimpleAnalysisRun.model_validate_json(json.dumps(data))

    assert loaded.policy_snapshot_ref is None


class _BlockedStatic:
    calls = 0

    async def run(
        self,
        _request: SimpleAnalysisRequest,
        _identity: CheckpointIdentity,
    ) -> StaticBootstrapResult:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("OPENGREP_EXECUTION_FAILED")
        return StaticBootstrapResult(
            repository_profile_ref=_ref("repository-profile"),
            static_bundle_ref=_ref("static-bundle"),
            workspace_path=_request.data_dir / "workspaces" / _identity.workspace_id,
        )


@pytest.mark.asyncio
async def test_bootstrap_failure_recovers_automatically_and_never_false(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    recovery = _RecoveryFactory(tmp_path)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=(static := _BlockedStatic()),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
        recovery_factory=recovery,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )

    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert outcome.status == "COMPLETE"
    assert static.calls == 2
    repaired = store.require(outcome.identity, SimpleStage.STATIC_DONE)
    assert repaired.status is StageStatus.SUCCEEDED
    assert repaired.attempt_number == 2
    assert len(recovery.calls) == 1


@pytest.mark.asyncio
async def test_static_bootstrap_exhausts_after_three_automatic_attempts(
    tmp_path: Path,
) -> None:
    class AlwaysBlockedStatic:
        calls = 0

        async def run(
            self,
            _request: SimpleAnalysisRequest,
            _identity: CheckpointIdentity,
        ) -> StaticBootstrapResult:
            self.calls += 1
            raise RuntimeError("DOCKER_BUILD_FAILED")

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    static = AlwaysBlockedStatic()
    recovery = _RecoveryFactory(tmp_path)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
        recovery_factory=recovery,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )

    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    exhausted = store.require(outcome.identity, SimpleStage.STATIC_DONE)
    assert outcome.status == "BLOCKED"
    assert outcome.error_code == "RECOVERY_EXHAUSTED"
    assert static.calls == 3
    assert len(recovery.calls) == 2
    assert exhausted.attempt_number == 3
    assert exhausted.retryable is False
    assert exhausted.verdict is None


@pytest.mark.asyncio
async def test_hypothesis_generation_recovers_without_manual_resume(
    tmp_path: Path,
) -> None:
    class FlakyHypotheses(_Hypotheses):
        calls = 0

        async def propose(
            self,
            identity: CheckpointIdentity,
            static: StaticBootstrapResult,
        ) -> tuple[HypothesisSeed, ...]:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("HYPOTHESIS_PROVIDER_FAILED")
            return await super().propose(identity, static)

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    hypotheses = FlakyHypotheses()
    recovery = _RecoveryFactory(tmp_path)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=hypotheses,
        runner_factory=_runner,
        recovery_factory=recovery,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )

    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    hypothesis = store.require(outcome.identity, SimpleStage.HYPOTHESIS_DONE)
    assert outcome.status == "COMPLETE"
    assert hypotheses.calls == 2
    assert hypothesis.attempt_number == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("retryable", "expected_status"),
    [(False, StageStatus.FAILED), (True, StageStatus.BLOCKED)],
)
async def test_hypothesis_provider_failure_preserves_retryability(
    tmp_path: Path, retryable: bool, expected_status: StageStatus
) -> None:
    class FailedHypotheses:
        async def propose(
            self, identity: CheckpointIdentity, static: StaticBootstrapResult
        ) -> StageFailure:
            del identity, static
            return StageFailure(
                code="CURSOR_INVALID_OUTPUT",
                retryable=retryable,
                safe_message="Invalid structured output",
            )

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=FailedHypotheses(),
        runner_factory=_runner,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )
    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )
    checkpoint = store.require(outcome.identity, SimpleStage.HYPOTHESIS_DONE)
    assert checkpoint.status is expected_status
    assert checkpoint.retryable is retryable
    assert checkpoint.error_code == "CURSOR_INVALID_OUTPUT"
    assert outcome.status == ("BLOCKED" if retryable else "FAILED")


@pytest.mark.asyncio
async def test_resume_reuses_static_and_hypothesis_results(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    static = _Static()
    hypotheses = _Hypotheses()
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=hypotheses,
        runner_factory=_runner,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )
    first = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    resumed = await application.resume(first.display_analysis_id)

    assert resumed.status == "COMPLETE"
    assert len(store.list_checkpoints("analysis-1")) >= 4


@pytest.mark.asyncio
async def test_resume_does_not_rerun_completed_agents(tmp_path: Path) -> None:
    calls: list[SimpleStage] = []
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")

    def counting_runner(
        runtime_store: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        del identity, static
        handlers: dict[SimpleStage, Any] = {}
        for stage in tuple(SimpleStage)[2:]:

            async def handle(
                _checkpoint: StageCheckpoint,
                _prior: Mapping[SimpleStage, StageCheckpoint],
                *,
                current: SimpleStage = stage,
            ) -> StageResult:
                calls.append(current)
                return StageResult(
                    output_refs=(_ref(current.value.lower()),),
                    verdict="FALSE"
                    if current is SimpleStage.VERIFICATION_FINAL_DONE
                    else None,
                )

            handlers[stage] = handle
        return SimpleRuntimeRunner(runtime_store, handlers)

    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=counting_runner,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )
    first = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )
    before = tuple(calls)
    assert before
    resumed = await application.resume(first.display_analysis_id)
    assert resumed.status == "COMPLETE"
    assert tuple(calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure_code", "recorded_llm_ms", "expected_status"),
    [
        ("LLM_ELAPSED_BUDGET_EXHAUSTED", 500, "COMPLETE"),
        ("LLM_ELAPSED_BUDGET_EXHAUSTED", 1000, "FAILED"),
        ("LLM_TOKEN_BUDGET_EXHAUSTED", 500, "FAILED"),
    ],
)
async def test_resume_reopens_only_elapsed_failure_with_remaining_budget(
    tmp_path: Path,
    failure_code: str,
    recorded_llm_ms: int,
    expected_status: str,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    recovery = _RecoveryFactory(tmp_path)

    def recovering_runner(
        current_store: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        baseline = _runner(current_store, identity, static)
        return SimpleRuntimeRunner(current_store, baseline.handlers, recovery=recovery)

    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=recovering_runner,
        recovery_factory=recovery,
        max_elapsed_seconds=1,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )
    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )
    child = outcome.identity.model_copy(update={"hypothesis_id": "hypothesis-1"})
    completed = store.require(child, SimpleStage.PRO_CON_DONE)
    store.save_checkpoint(
        completed.model_copy(
            update={
                "status": StageStatus.FAILED,
                "error_code": failure_code,
                "retryable": False,
                "output_refs": (),
            }
        )
    )
    artifacts = SimpleArtifactRepository(tmp_path, outcome.identity)
    store.record_llm_attempt(
        attempt_id="recorded",
        analysis_id=outcome.identity.analysis_id,
        agent="pro_con",
        model="test",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=recorded_llm_ms,
        input_tokens=None,
        output_tokens=None,
        cost_cents=None,
        artifact_ref=artifacts.put_json({"kind": "attempt"}),
    )

    resumed = await application.resume(outcome.display_analysis_id)

    assert resumed.status == expected_status
    assert recovery.calls == []
    assert store.require(child, SimpleStage.PRO_CON_DONE).status is (
        StageStatus.SUCCEEDED if expected_status == "COMPLETE" else StageStatus.FAILED
    )
    assert store.require(child, SimpleStage.VERIFICATION_FINAL_DONE).attempt_number == 1


@pytest.mark.asyncio
async def test_blocked_hypothesis_does_not_stop_independent_sibling(
    tmp_path: Path,
) -> None:
    recovery = _RecoveryFactory(tmp_path)
    blocked_calls: list[SimpleStage] = []

    class TwoHypotheses:
        async def propose(
            self,
            _identity: CheckpointIdentity,
            _static: StaticBootstrapResult,
        ) -> tuple[HypothesisSeed, ...]:
            return (
                HypothesisSeed(
                    hypothesis_id="hypothesis-blocked",
                    proposal_ref=_ref("hypothesis-blocked"),
                ),
                HypothesisSeed(
                    hypothesis_id="hypothesis-complete",
                    proposal_ref=_ref("hypothesis-complete"),
                ),
            )

    def runner(
        store: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        _static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        handlers: dict[SimpleStage, Any] = {}
        for stage in tuple(SimpleStage)[2:]:

            async def handle(
                _checkpoint: StageCheckpoint,
                _prior: Mapping[SimpleStage, StageCheckpoint],
                *,
                current: SimpleStage = stage,
            ) -> StageResult:
                if (
                    identity.hypothesis_id == "hypothesis-blocked"
                    and current is SimpleStage.PRO_CON_DONE
                ):
                    blocked_calls.append(current)
                    raise StageBlocked(
                        StageFailure(
                            code="PROVIDER_TEMPORARY_FAILURE",
                            retryable=True,
                            safe_message="try this hypothesis later",
                        )
                    )
                return StageResult(
                    output_refs=(_ref(f"{identity.hypothesis_id}-{current.value}"),),
                    verdict=(
                        "FALSE"
                        if current is SimpleStage.VERIFICATION_FINAL_DONE
                        else None
                    ),
                )

            handlers[stage] = handle
        return SimpleRuntimeRunner(
            store,
            handlers,
            recovery=recovery(identity),
        )

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=TwoHypotheses(),
        runner_factory=runner,
        recovery_factory=recovery,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )

    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert outcome.status == "BLOCKED"
    blocked = outcome.identity.model_copy(
        update={"hypothesis_id": "hypothesis-blocked"}
    )
    exhausted = store.require(blocked, SimpleStage.PRO_CON_DONE)
    assert len(blocked_calls) == 3
    assert exhausted.error_code == "RECOVERY_EXHAUSTED"
    assert exhausted.retryable is False
    completed = outcome.identity.model_copy(
        update={"hypothesis_id": "hypothesis-complete"}
    )
    assert (
        store.require(
            completed,
            SimpleStage.VERIFICATION_FINAL_DONE,
        ).verdict
        == "FALSE"
    )


def test_chaining_child_is_added_once_to_durable_analysis_queue(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
    )
    identity = application_identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    chaining_ref = artifacts.put_json(
        {
            "kind": "simple_chaining_result",
            "children": [
                {
                    "title": "compound finding",
                    "parent_hypothesis_ids": ["hypothesis-1", "hypothesis-2"],
                }
            ],
        }
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.CHAINING_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(chaining_ref,),
        )
    )
    run = SimpleAnalysisRun(
        analysis_id="analysis-1",
        display_analysis_id="A-001",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        repository="repo",
        hypothesis_ids=("hypothesis-1", "hypothesis-2"),
    )
    static = StaticBootstrapResult(
        repository_profile_ref=_ref("repository-profile"),
        static_bundle_ref=_ref("static-bundle"),
        workspace_path=tmp_path / "workspace",
    )

    updated = application._register_chain_children(run, application_identity, static)
    repeated = application._register_chain_children(
        updated,
        application_identity,
        static,
    )

    assert len(updated.hypothesis_ids) == 3
    assert repeated.hypothesis_ids == updated.hypothesis_ids
    child_id = updated.hypothesis_ids[-1]
    assert updated.chain_depths[child_id] == 1


@pytest.mark.parametrize(
    ("exit_code", "timed_out", "outcome", "stale", "expected_promotions"),
    [
        (0, False, "INCONCLUSIVE", False, 1),
        (0, False, "INCONCLUSIVE", True, 0),
        (1, False, "INCONCLUSIVE", False, 0),
        (2, False, "INCONCLUSIVE", False, 0),
        (0, True, "INCONCLUSIVE", False, 0),
        (0, False, "SUPPORTED", False, 0),
    ],
)
def test_resume_promotes_only_verified_legacy_poc_inconclusive_exhaustion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
    timed_out: bool,
    outcome: str,
    stale: bool,
    expected_promotions: int,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-legacy",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-legacy",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "exit_code": exit_code,
            "timed_out": timed_out,
            "attempt_id": "attempt-3",
        }
    )
    interpretation_ref = artifacts.put_json(
        {
            "kind": "simple_dynamic_interpretation",
            "execution_ref": execution_ref.model_dump(mode="json"),
            "result": {"outcome": outcome},
        }
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.POC_EXECUTION_DONE,
            stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
            status=StageStatus.BLOCKED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(execution_ref, interpretation_ref),
            error_code="RECOVERY_EXHAUSTED",
            attempt_number=3,
            attempt_id="attempt-3",
        )
    )
    if stale:

        def _stale(_checkpoint: StageCheckpoint) -> None:
            raise ValueError("POC_INCONCLUSIVE_PROMOTION_STALE")

        monkeypatch.setattr(store, "promote_inconclusive_execution", _stale)

    promoted = application._promote_legacy_inconclusive_pocs("analysis-legacy")

    assert promoted == expected_promotions
    checkpoint = store.require(identity, SimpleStage.POC_EXECUTION_DONE)
    assert checkpoint.status is (
        StageStatus.SUCCEEDED if expected_promotions else StageStatus.BLOCKED
    )
    assert checkpoint.verdict == ("HOLD" if expected_promotions else None)
    assert checkpoint.validated_poc_ref is None
    assert checkpoint.output_refs == (execution_ref, interpretation_ref)
