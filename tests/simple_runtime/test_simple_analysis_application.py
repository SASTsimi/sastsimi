from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

import pytest

from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    ChainingEvidenceInvalid,
    HypothesisSeed,
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
    SimpleAnalysisRun,
    StaticBootstrapResult,
    StaticEvidenceInvalid,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectStaticBootstrap,
    ProcessResult,
    StaticCoverageBlocked,
)
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


def _admitted_primitive(
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    identity: CheckpointIdentity,
    *,
    required: tuple[str, ...] = (),
    provided: tuple[str, ...] = (),
) -> StoredDataRef:
    ref = artifacts.put_json(
        {
            "kind": "simple_primitive",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "source_hypothesis_id": identity.hypothesis_id,
            "required_capabilities": required,
            "provided_capabilities": provided,
        }
    )
    existing = store.get(identity, SimpleStage.PRIMITIVE_ADMISSION_DONE)
    store.save_checkpoint(
        existing.model_copy(update={"output_refs": (ref,)})
        if existing is not None
        else StageCheckpoint(
            identity=identity,
            stage=SimpleStage.PRIMITIVE_ADMISSION_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(ref,),
        )
    )
    return ref


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
    *,
    final_verdict: Literal["FALSE", "HOLD"] = "FALSE",
    data_dir: Path | None = None,
) -> SimpleRuntimeRunner:
    del _static
    chaining_ref = None
    if final_verdict == "HOLD":
        assert data_dir is not None
        chaining_ref = SimpleArtifactRepository(data_dir, identity).put_json(
            {
                "kind": "simple_chaining_result",
                "analysis_id": identity.analysis_id,
                "source_hypothesis_id": identity.hypothesis_id,
                "considered_primitive_refs": [],
                "status": "NO_MATERIAL_CHILD",
                "children": [],
            }
        )
    handlers: dict[SimpleStage, Any] = {}
    for stage in tuple(SimpleStage)[2:]:

        async def handle(
            _checkpoint: StageCheckpoint,
            _prior: Mapping[SimpleStage, StageCheckpoint],
            *,
            current: SimpleStage = stage,
        ) -> StageResult:
            return StageResult(
                output_refs=(
                    (chaining_ref,)
                    if current is SimpleStage.CHAINING_DONE and chaining_ref is not None
                    else (_ref(current.value.lower()),)
                ),
                verdict=final_verdict
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


@pytest.mark.parametrize("parsed_files", [0, 1])
def test_opengrep_unavailable_static_evidence_requires_independent_proof(
    tmp_path: Path, parsed_files: int
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-opengrep-unavailable",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "f" * 64,
            "expected_count": 0,
            "verified_count": 0,
            "gaps": [],
            "unsupported": [],
            "unavailable": True,
            "unavailable_paths": [
                {"path": "app.py", "reason": "OPENGREP_EXECUTION_FAILED"}
            ],
            "ast_parsed_file_count": parsed_files,
        }
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
            "ast_summary": {"parsed_file_count": parsed_files, "facts": []},
            "codeql_executed": False,
        }
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
    )
    static = StaticBootstrapResult(
        repository_profile_ref=_ref("repository-profile"),
        static_bundle_ref=bundle_ref,
        static_coverage_ref=coverage_ref,
        static_disposition="PARTIAL",
        workspace_path=tmp_path / "workspaces" / identity.workspace_id,
    )
    if parsed_files:
        application._validate_static_evidence(static, identity)
    else:
        with pytest.raises(StaticEvidenceInvalid):
            application._validate_static_evidence(static, identity)


@pytest.mark.parametrize(
    "damage", ["missing_file", "missing_format", "missing_manifest"]
)
def test_full_static_evidence_rejects_damaged_ast_manifest(
    tmp_path: Path, damage: str
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-ast-missing",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("f()\n", encoding="utf-8")
    ast_summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=100
    )
    if damage == "missing_file":
        manifest = json.loads(
            artifacts.read(StoredDataRef.model_validate(ast_summary["manifest_ref"]))
        )
        manifest["entries"][0]["ref"]["content_hash"] = "0" * 64
        ast_summary["manifest_ref"] = artifacts.put_json(manifest).model_dump(
            mode="json"
        )
    elif damage == "missing_format":
        ast_summary.pop("format_version")
    else:
        ast_summary.pop("manifest_ref")
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "f" * 64,
            "expected_count": 1,
            "verified_count": 1,
            "gaps": [],
            "unsupported": [],
            "ast_parsed_file_count": 1,
        }
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
            "ast_summary": ast_summary,
        }
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3"),
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
    )
    static = StaticBootstrapResult(
        repository_profile_ref=_ref("repository-profile"),
        static_bundle_ref=bundle_ref,
        static_coverage_ref=coverage_ref,
        static_disposition="FULL",
        workspace_path=workspace,
    )

    with pytest.raises(StaticEvidenceInvalid):
        application._validate_static_evidence(static, identity)


@pytest.mark.parametrize("with_sarif_ref", [False, True])
def test_opengrep_unavailable_accepts_only_durable_codeql_proof(
    tmp_path: Path, with_sarif_ref: bool
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-codeql-proof",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "f" * 64,
            "expected_count": 0,
            "verified_count": 0,
            "gaps": [],
            "unsupported": [],
            "unavailable": True,
            "unavailable_paths": [
                {"path": "app.py", "reason": "OPENGREP_EXECUTION_FAILED"}
            ],
            "ast_parsed_file_count": 0,
            "codeql_executed": True,
        }
    )
    tool_refs = [
        artifacts.put_json({"kind": "ast"}).model_dump(mode="json"),
        artifacts.put_json({"results": []}).model_dump(mode="json"),
    ]
    if with_sarif_ref:
        tool_refs.append(artifacts.put_json({"runs": []}).model_dump(mode="json"))
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
            "ast_summary": {"parsed_file_count": 0, "facts": []},
            "codeql_executed": True,
            "tool_result_refs": tool_refs,
        }
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
    )
    static = StaticBootstrapResult(
        repository_profile_ref=_ref("repository-profile"),
        static_bundle_ref=bundle_ref,
        static_coverage_ref=coverage_ref,
        static_disposition="PARTIAL",
        workspace_path=tmp_path / "workspaces" / identity.workspace_id,
    )
    if with_sarif_ref:
        application._validate_static_evidence(static, identity)
    else:
        with pytest.raises(StaticEvidenceInvalid):
            application._validate_static_evidence(static, identity)


@pytest.mark.asyncio
async def test_verified_partial_static_evidence_runs_agents_but_never_completes(
    tmp_path: Path,
) -> None:
    class PartialStatic:
        async def run(
            self,
            request: SimpleAnalysisRequest,
            identity: CheckpointIdentity,
        ) -> StaticBootstrapResult:
            artifacts = SimpleArtifactRepository(request.data_dir, identity)
            coverage_ref = artifacts.put_json(
                {
                    "kind": "simple_static_coverage_v1",
                    "analysis_id": identity.analysis_id,
                    "workspace_id": identity.workspace_id,
                    "commit_id": identity.commit_id,
                    "fingerprint": "f" * 64,
                    "expected_count": 2,
                    "verified_count": 1,
                    "gaps": [
                        {
                            "path": "src/unreadable.py",
                            "rule_id": "python.rule",
                            "reason": "parse_or_scan_error",
                        }
                    ],
                    "unsupported": [],
                    "unsupported_files": [],
                    "unavailable": False,
                }
            )
            bundle_ref = artifacts.put_json(
                {
                    "kind": "simple_static_fact_bundle",
                    "analysis_id": identity.analysis_id,
                    "workspace_id": identity.workspace_id,
                    "commit_id": identity.commit_id,
                    "static_coverage_ref": coverage_ref.model_dump(mode="json"),
                    "opengrep_findings": [],
                }
            )
            return StaticBootstrapResult(
                repository_profile_ref=_ref("repository-profile"),
                static_bundle_ref=bundle_ref,
                static_coverage_ref=coverage_ref,
                static_disposition="PARTIAL",
                workspace_path=request.data_dir / "workspaces" / identity.workspace_id,
            )

    class PartialHypotheses:
        async def propose(
            self,
            identity: CheckpointIdentity,
            static: StaticBootstrapResult,
        ) -> tuple[HypothesisSeed, ...]:
            assert static.static_disposition == "PARTIAL"
            assert static.static_coverage_ref is not None
            return (
                HypothesisSeed(
                    hypothesis_id="hypothesis-1", proposal_ref=_ref("hypothesis")
                ),
            )

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=PartialStatic(),
        hypothesis_bootstrap=PartialHypotheses(),
        runner_factory=_runner,
        id_factory=iter(("analysis-partial", "workspace-1")).__next__,
    )

    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert outcome.status == "PARTIAL"
    run = store.require_analysis_run("analysis-partial")
    assert run.static_disposition == "PARTIAL"
    assert run.static_coverage_ref is not None
    assert (
        store.require(outcome.identity, SimpleStage.STATIC_DONE).status
        is StageStatus.SUCCEEDED
    )
    assert (
        store.require(
            outcome.identity.model_copy(update={"hypothesis_id": "hypothesis-1"}),
            SimpleStage.VERIFICATION_FINAL_DONE,
        ).status
        is StageStatus.SUCCEEDED
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "interruption",
    [
        "pending",
        "stale",
        "hold_before_chaining",
        "unregistered_chain_child",
        "untrusted_chaining_output",
    ],
    ids=[
        "pending",
        "stale",
        "hold-before-chaining",
        "unregistered-chain-child",
        "untrusted-chaining-output",
    ],
)
async def test_partial_resume_advances_unfinished_agent_before_retrying_static(
    tmp_path: Path,
    interruption: Literal[
        "pending",
        "stale",
        "hold_before_chaining",
        "unregistered_chain_child",
        "untrusted_chaining_output",
    ],
) -> None:
    class PartialStatic:
        calls = 0

        async def run(
            self, request: SimpleAnalysisRequest, identity: CheckpointIdentity
        ) -> StaticBootstrapResult:
            self.calls += 1
            if (
                interruption
                in {
                    "unregistered_chain_child",
                    "untrusted_chaining_output",
                }
                and self.calls > 1
            ):
                raise RuntimeError("STATIC_RETRY_BEFORE_CHAIN_CHILD")
            artifacts = SimpleArtifactRepository(request.data_dir, identity)
            coverage_ref = artifacts.put_json(
                {
                    "kind": "simple_static_coverage_v1",
                    "analysis_id": identity.analysis_id,
                    "workspace_id": identity.workspace_id,
                    "commit_id": identity.commit_id,
                    "fingerprint": "f" * 64,
                    "expected_count": 2,
                    "verified_count": 1,
                    "gaps": [
                        {
                            "path": "app.py",
                            "rule_id": "python.rule",
                            "reason": "not_attempted_budget",
                        }
                    ],
                    "unsupported": [],
                    "unsupported_files": [],
                    "unavailable": False,
                }
            )
            bundle_ref = artifacts.put_json(
                {
                    "kind": "simple_static_fact_bundle",
                    "analysis_id": identity.analysis_id,
                    "workspace_id": identity.workspace_id,
                    "commit_id": identity.commit_id,
                    "static_coverage_ref": coverage_ref.model_dump(mode="json"),
                }
            )
            return StaticBootstrapResult(
                repository_profile_ref=_ref("repository-profile"),
                static_bundle_ref=bundle_ref,
                static_coverage_ref=coverage_ref,
                static_disposition="PARTIAL",
                workspace_path=request.data_dir / "workspaces" / identity.workspace_id,
            )

    class PartialHypotheses:
        async def propose(
            self, identity: CheckpointIdentity, static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            assert static.static_disposition == "PARTIAL"
            artifacts = SimpleArtifactRepository(tmp_path, identity)
            proposal_ref = artifacts.put_json(
                {
                    "kind": "simple_hypothesis_proposal",
                    "hypothesis_id": "hypothesis-1",
                    "static_bundle_ref": static.static_bundle_ref.model_dump(
                        mode="json"
                    ),
                    "proposal": {"title": "partial resume"},
                }
            )
            seeds = [
                HypothesisSeed(hypothesis_id="hypothesis-1", proposal_ref=proposal_ref)
            ]
            if interruption == "unregistered_chain_child":
                second_ref = artifacts.put_json(
                    {
                        "kind": "simple_hypothesis_proposal",
                        "hypothesis_id": "hypothesis-2",
                        "static_bundle_ref": static.static_bundle_ref.model_dump(
                            mode="json"
                        ),
                        "proposal": {"title": "second chain parent"},
                    }
                )
                seeds.append(
                    HypothesisSeed(
                        hypothesis_id="hypothesis-2", proposal_ref=second_ref
                    )
                )
            return tuple(seeds)

    static = PartialStatic()
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=PartialHypotheses(),
        runner_factory=lambda current_store, child, bootstrap: _runner(
            current_store,
            child,
            bootstrap,
            final_verdict="HOLD"
            if interruption
            in {
                "hold_before_chaining",
                "unregistered_chain_child",
                "untrusted_chaining_output",
            }
            else "FALSE",
            data_dir=tmp_path,
        ),
        id_factory=iter(("analysis-partial-pending-agent", "workspace-1")).__next__,
    )
    first = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )
    static_checkpoint = store.require(first.identity, SimpleStage.STATIC_DONE)
    assert first.status == "PARTIAL"
    assert static_checkpoint.status is StageStatus.SUCCEEDED
    assert static.calls == 1
    child = first.identity.model_copy(update={"hypothesis_id": "hypothesis-1"})
    if interruption == "stale":
        prior_agent = store.require(child, SimpleStage.VERIFICATION_INITIAL_DONE)
        terminal = store.require(child, SimpleStage.VERIFICATION_FINAL_DONE)
        assert prior_agent.stage_version == STAGE_VERSION[prior_agent.stage]
        old_version = str(int(prior_agent.stage_version) - 1)
        store.save_checkpoint(
            prior_agent.model_copy(update={"stage_version": old_version})
        )
        assert store.require(child, SimpleStage.VERIFICATION_FINAL_DONE) == terminal
    elif interruption == "hold_before_chaining":
        final = store.require(child, SimpleStage.VERIFICATION_FINAL_DONE)
        prior_agent = store.require(child, SimpleStage.PRIMITIVE_ADMISSION_DONE)
        assert final.verdict == "HOLD"
        assert (
            store.require(child, SimpleStage.CHAINING_DONE).status
            is StageStatus.SUCCEEDED
        )
        store.invalidate_from(
            child,
            SimpleStage.PRIMITIVE_ADMISSION_DONE,
            new_inputs=(),
            force=True,
        )
        assert store.get(child, SimpleStage.PRIMITIVE_ADMISSION_DONE) is None
        assert store.get(child, SimpleStage.CHAINING_DONE) is None
    elif interruption == "unregistered_chain_child":
        prior_agent = store.require(child, SimpleStage.CHAINING_DONE)
        artifacts = SimpleArtifactRepository(tmp_path, child)
        second_parent = child.model_copy(update={"hypothesis_id": "hypothesis-2"})
        upstream_ref = _admitted_primitive(
            store, artifacts, child, provided=("route_access",)
        )
        downstream_ref = _admitted_primitive(
            store, artifacts, second_parent, required=("route_access",)
        )
        chained_ref = artifacts.put_json(
            {
                "kind": "simple_chaining_result",
                "analysis_id": child.analysis_id,
                "source_hypothesis_id": child.hypothesis_id,
                "status": "MATERIAL_CHILD",
                "considered_primitive_refs": [
                    upstream_ref.model_dump(mode="json"),
                    downstream_ref.model_dump(mode="json"),
                ],
                "children": [
                    {
                        "upstream_primitive_hash": upstream_ref.content_hash,
                        "downstream_primitive_hash": downstream_ref.content_hash,
                        "title": "compound finding",
                        "vulnerability_type": "compound",
                        "summary": "A second primitive extends the first",
                        "rationale": "Matching capabilities",
                        "code_locations": ["app.py:1"],
                        "parent_hypothesis_ids": ["hypothesis-1", "hypothesis-2"],
                        "parent_primitive_refs": [
                            upstream_ref.model_dump(mode="json"),
                            downstream_ref.model_dump(mode="json"),
                        ],
                    }
                ],
            }
        )
        store.save_checkpoint(
            prior_agent.model_copy(update={"output_refs": (chained_ref,)})
        )
        assert store.require_analysis_run(
            first.identity.analysis_id
        ).hypothesis_ids == (
            "hypothesis-1",
            "hypothesis-2",
        )
    elif interruption == "untrusted_chaining_output":
        prior_agent = store.require(child, SimpleStage.CHAINING_DONE)
        malformed_ref = SimpleArtifactRepository(tmp_path, child).put_bytes(
            b"{", "application/json"
        )
        store.save_checkpoint(
            prior_agent.model_copy(update={"output_refs": (malformed_ref,)})
        )
    else:
        prior_agent = store.require(child, SimpleStage.PRO_CON_DONE)
        store.replace_from(
            StageCheckpoint(
                identity=child,
                stage=SimpleStage.PRO_CON_DONE,
                status=StageStatus.PENDING,
                input_refs=prior_agent.input_refs,
                input_hash=input_reference_hash(prior_agent.input_refs),
            )
        )

    resumed = await application.resume(first.display_analysis_id)

    assert static.calls == 1
    if interruption == "untrusted_chaining_output":
        assert (resumed.status, resumed.error_code) == (
            "BLOCKED",
            "CHAINING_EVIDENCE_INVALID",
        )
        blocked = store.require(child, SimpleStage.CHAINING_DONE)
        assert blocked.status is StageStatus.BLOCKED
        assert blocked.output_refs == (malformed_ref,)
        assert SimpleArtifactRepository(tmp_path, child).read(malformed_ref) == b"{"
        return
    assert resumed.status == "PARTIAL", resumed.error_code
    if interruption == "unregistered_chain_child":
        run = store.require_analysis_run(first.identity.analysis_id)
        assert len(run.hypothesis_ids) == 3
        chained_child = child.model_copy(
            update={"hypothesis_id": run.hypothesis_ids[2]}
        )
        assert (
            store.require(chained_child, SimpleStage.VERIFICATION_FINAL_DONE).status
            is StageStatus.SUCCEEDED
        )
    else:
        replayed = store.require(child, prior_agent.stage)
        assert replayed.status is StageStatus.SUCCEEDED
        assert replayed.stage_version == prior_agent.stage_version
        assert replayed.attempt_id != prior_agent.attempt_id
    assert store.require(first.identity, SimpleStage.STATIC_DONE) == static_checkpoint
    if interruption == "hold_before_chaining":
        assert store.require(child, SimpleStage.VERIFICATION_FINAL_DONE) == final
        assert (
            store.require(child, SimpleStage.CHAINING_DONE).status
            is StageStatus.SUCCEEDED
        )
        await application.resume(first.display_analysis_id)
        assert static.calls == 2


@pytest.mark.asyncio
async def test_partial_resume_retries_static_and_reuses_completed_agents(
    tmp_path: Path,
) -> None:
    class ImprovingStatic:
        calls = 0
        bundles: list[StoredDataRef] = []

        async def run(
            self, request: SimpleAnalysisRequest, identity: CheckpointIdentity
        ) -> StaticBootstrapResult:
            self.calls += 1
            artifacts = SimpleArtifactRepository(request.data_dir, identity)
            partial = self.calls == 1
            coverage_ref = artifacts.put_json(
                {
                    "kind": "simple_static_coverage_v1",
                    "analysis_id": identity.analysis_id,
                    "workspace_id": identity.workspace_id,
                    "commit_id": identity.commit_id,
                    "fingerprint": "f" * 64,
                    "expected_count": 2,
                    "verified_count": 1 if partial else 2,
                    "gaps": (
                        [
                            {
                                "path": "app.py",
                                "rule_id": "rule",
                                "reason": "scan_timeout",
                            }
                        ]
                        if partial
                        else []
                    ),
                    "unsupported": [],
                    "unsupported_files": [],
                    "unavailable": False,
                }
            )
            bundle_ref = artifacts.put_json(
                {
                    "kind": "simple_static_fact_bundle",
                    "analysis_id": identity.analysis_id,
                    "workspace_id": identity.workspace_id,
                    "commit_id": identity.commit_id,
                    "static_coverage_ref": coverage_ref.model_dump(mode="json"),
                    "ast_summary": {"facts": []},
                    "opengrep_findings": (
                        [] if partial else [{"path": "app.py", "check_id": "rule"}]
                    ),
                    "codeql_findings": [],
                }
            )
            self.bundles.append(bundle_ref)
            return StaticBootstrapResult(
                repository_profile_ref=_ref("repository-profile"),
                static_bundle_ref=bundle_ref,
                static_coverage_ref=coverage_ref,
                static_disposition="PARTIAL" if partial else "FULL",
                workspace_path=request.data_dir / "workspaces" / identity.workspace_id,
            )

    class GrowingHypotheses:
        calls = 0

        async def propose(
            self, identity: CheckpointIdentity, static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            self.calls += 1
            artifacts = SimpleArtifactRepository(tmp_path, identity)
            result = []
            titles = ("one",) if self.calls == 1 else ("one", "two")
            for title in titles:
                proposal_ref = artifacts.put_json(
                    {
                        "kind": "simple_hypothesis_proposal",
                        "hypothesis_id": f"hypothesis-{title}-{self.calls}",
                        "proposal": {"title": title},
                    }
                )
                result.append(
                    HypothesisSeed(
                        hypothesis_id=f"hypothesis-{title}-{self.calls}",
                        proposal_ref=proposal_ref,
                    )
                )
            return tuple(result)

    static = ImprovingStatic()
    hypotheses = GrowingHypotheses()
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    visited: list[tuple[str, StoredDataRef]] = []

    def runner_factory(
        current_store: SimpleCheckpointStore,
        child: CheckpointIdentity,
        bootstrap: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        assert child.hypothesis_id is not None
        visited.append((child.hypothesis_id, bootstrap.static_bundle_ref))
        return _runner(current_store, child, bootstrap)

    app = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=hypotheses,
        runner_factory=runner_factory,
        id_factory=iter(("analysis-partial-resume", "workspace-1")).__next__,
    )
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )
    assert first.status == "PARTIAL"
    old_child = store.require_analysis_run(first.identity.analysis_id).hypothesis_ids[0]
    old_identity = first.identity.model_copy(update={"hypothesis_id": old_child})
    old_checkpoint = store.require(old_identity, SimpleStage.PRO_CON_DONE)

    resumed = await app.resume(first.identity.analysis_id)

    assert resumed.status == "COMPLETE"
    assert static.calls == 2
    assert hypotheses.calls == 2
    run = store.require_analysis_run(first.identity.analysis_id)
    assert len(run.hypothesis_ids) == 2
    assert run.static_disposition == "FULL"
    assert store.require(old_identity, SimpleStage.PRO_CON_DONE) == old_checkpoint
    assert visited[-2:] == [
        (old_child, static.bundles[0]),
        (run.hypothesis_ids[1], static.bundles[1]),
    ]


@pytest.mark.asyncio
async def test_resume_reconciles_hypothesis_checkpoint_after_interruption(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-interrupted-append",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "f" * 64,
            "expected_count": 1,
            "verified_count": 1,
            "gaps": [],
            "unsupported": [],
        }
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
        }
    )
    proposal_refs = tuple(
        artifacts.put_json(
            {
                "kind": "simple_hypothesis_proposal",
                "hypothesis_id": hypothesis_id,
                "static_bundle_ref": bundle_ref.model_dump(mode="json"),
                "proposal": {"title": hypothesis_id},
            }
        )
        for hypothesis_id in ("hypothesis-one", "hypothesis-two")
    )
    display = AnalysisDisplayIdStore(store.database_path).get_or_allocate(
        identity.analysis_id
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id=display,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            workspace_path=tmp_path / "workspaces" / identity.workspace_id,
            repository_profile_ref=_ref("repository-profile"),
            static_bundle_ref=bundle_ref,
            static_coverage_ref=coverage_ref,
            static_disposition="FULL",
            hypothesis_ids=("hypothesis-one",),
        )
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(bundle_ref,),
            input_hash=input_reference_hash((bundle_ref,)),
            output_refs=proposal_refs,
        )
    )
    first_child = identity.model_copy(update={"hypothesis_id": "hypothesis-one"})
    first_inputs = (proposal_refs[0], bundle_ref)
    store.save_checkpoint(
        StageCheckpoint(
            identity=first_child,
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.PENDING,
            input_refs=first_inputs,
            input_hash=input_reference_hash(first_inputs),
        )
    )
    app = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
    )

    resumed = await app.resume(identity.analysis_id)

    assert resumed.status == "COMPLETE"
    assert store.require_analysis_run(identity.analysis_id).hypothesis_ids == (
        "hypothesis-one",
        "hypothesis-two",
    )
    second_child = identity.model_copy(update={"hypothesis_id": "hypothesis-two"})
    assert (
        store.require(second_child, SimpleStage.PRO_CON_DONE).status
        is StageStatus.SUCCEEDED
    )


@pytest.mark.asyncio
async def test_failed_hypothesis_refresh_cannot_complete_old_children(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-failed-refresh",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    display = AnalysisDisplayIdStore(store.database_path).get_or_allocate(
        identity.analysis_id
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id=display,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            workspace_path=tmp_path / "workspaces" / identity.workspace_id,
            repository_profile_ref=_ref("repository-profile"),
            static_bundle_ref=_ref("static-bundle"),
            hypothesis_ids=("hypothesis-1",),
        )
    )
    inputs = (_ref("static-bundle"),)
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.BLOCKED,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
            error_code="HYPOTHESIS_EVIDENCE_INVALID",
            retryable=False,
        )
    )
    app = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
    )

    resumed = await app.resume(identity.analysis_id)

    assert resumed.status == "BLOCKED"
    assert resumed.current_stage is SimpleStage.HYPOTHESIS_DONE
    assert resumed.error_code == "HYPOTHESIS_EVIDENCE_INVALID"


@pytest.mark.asyncio
async def test_duplicate_proposals_in_one_batch_run_only_one_child(
    tmp_path: Path,
) -> None:
    class DuplicatingHypotheses:
        async def propose(
            self, identity: CheckpointIdentity, static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            artifacts = SimpleArtifactRepository(tmp_path, identity)
            seeds = []
            for hypothesis_id in ("hypothesis-one", "hypothesis-two"):
                proposal_ref = artifacts.put_json(
                    {
                        "kind": "simple_hypothesis_proposal",
                        "hypothesis_id": hypothesis_id,
                        "static_bundle_ref": static.static_bundle_ref.model_dump(
                            mode="json"
                        ),
                        "proposal": {"title": "same finding"},
                    }
                )
                seeds.append(
                    HypothesisSeed(
                        hypothesis_id=hypothesis_id,
                        proposal_ref=proposal_ref,
                    )
                )
            return tuple(seeds)

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    app = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=DuplicatingHypotheses(),
        runner_factory=_runner,
        id_factory=iter(("analysis-dedup", "workspace-1")).__next__,
    )

    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert outcome.status == "COMPLETE"
    assert store.require_analysis_run("analysis-dedup").hypothesis_ids == (
        "hypothesis-one",
    )
    assert (
        store.get(
            outcome.identity.model_copy(update={"hypothesis_id": "hypothesis-two"}),
            SimpleStage.PRO_CON_DONE,
        )
        is None
    )


@pytest.mark.asyncio
async def test_failed_hypothesis_checkpoint_write_keeps_seed_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    original_complete = store.complete
    failed_once = False

    def flaky_complete(
        checkpoint: StageCheckpoint,
        result: StageResult,
        *,
        analysis_run: SimpleAnalysisRun | None = None,
    ) -> StageCheckpoint:
        nonlocal failed_once
        if checkpoint.stage is SimpleStage.HYPOTHESIS_DONE and not failed_once:
            failed_once = True
            raise OSError("temporary checkpoint write failure")
        return original_complete(checkpoint, result, analysis_run=analysis_run)

    monkeypatch.setattr(store, "complete", flaky_complete)
    app = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
        recovery_factory=_RecoveryFactory(tmp_path),
        id_factory=iter(("analysis-retry-seed", "workspace-1")).__next__,
    )

    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert failed_once
    assert outcome.status == "COMPLETE"
    assert store.require_analysis_run("analysis-retry-seed").hypothesis_ids == (
        "hypothesis-1",
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


@pytest.mark.asyncio
async def test_static_snapshot_is_pinned_if_process_stops_after_static_commit(
    tmp_path: Path,
) -> None:
    class ChangingStatic:
        calls = 0

        async def run(
            self, request: SimpleAnalysisRequest, identity: CheckpointIdentity
        ) -> StaticBootstrapResult:
            self.calls += 1
            return StaticBootstrapResult(
                repository_profile_ref=_ref("repository-profile"),
                static_bundle_ref=_ref("static-bundle"),
                workspace_path=request.data_dir / "workspaces" / identity.workspace_id,
                policy_snapshot_ref=_ref(f"policy-snapshot-{self.calls}"),
            )

    class StopAfterStaticCommit(SimpleCheckpointStore):
        def complete(
            self,
            checkpoint: StageCheckpoint,
            result: StageResult,
            *,
            analysis_run: SimpleAnalysisRun | None = None,
        ) -> StageCheckpoint:
            if analysis_run is None:
                completed = super().complete(checkpoint, result)
            else:
                completed = super().complete(
                    checkpoint, result, analysis_run=analysis_run
                )
            if checkpoint.stage is SimpleStage.STATIC_DONE:
                raise RuntimeError("simulated post-commit crash")
            return completed

    database_path = tmp_path / "db" / "sastsimi.sqlite3"
    static = ChangingStatic()
    interrupted = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=StopAfterStaticCommit(database_path),
        static_bootstrap=static,
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )

    with pytest.raises(RuntimeError, match="simulated post-commit crash"):
        await interrupted.analyze(
            SimpleAnalysisRequest(
                data_dir=tmp_path,
                repository="https://example.invalid/repo.git",
                commit="a" * 40,
            )
        )

    store = SimpleCheckpointStore(database_path)
    persisted = store.require_analysis_run("analysis-1")
    assert persisted.policy_snapshot_ref == _ref("policy-snapshot-1")
    assert persisted.workspace_path == tmp_path / "workspaces" / "workspace-1"
    static_checkpoint = store.list_checkpoints("analysis-1")[0]
    assert static_checkpoint.stage is SimpleStage.STATIC_DONE
    assert static_checkpoint.status is StageStatus.SUCCEEDED
    assert _ref("policy-snapshot-1") in static_checkpoint.output_refs
    seen_snapshots: list[StoredDataRef | None] = []

    def runner_factory(
        current_store: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        bootstrap: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        seen_snapshots.append(bootstrap.policy_snapshot_ref)
        return _runner(current_store, identity, bootstrap)

    resumed = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=runner_factory,
    )
    outcome = await resumed.resume("analysis-1")

    assert outcome.status == "COMPLETE"
    assert static.calls == 1
    assert seen_snapshots == [_ref("policy-snapshot-1")]


def test_static_completion_rolls_back_if_run_update_fails(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = SimpleAnalysisRun(
        analysis_id="analysis-1",
        display_analysis_id="A-001",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        repository="https://example.invalid/repo.git",
    )
    store.save_analysis_run(run)
    identity = CheckpointIdentity(
        analysis_id=run.analysis_id,
        workspace_id=run.workspace_id,
        commit_id=run.commit_id,
        hypothesis_id=None,
    )
    checkpoint = store.mark_running(
        identity, SimpleStage.STATIC_DONE, (), attempt_id="attempt-1"
    )
    updated = run.model_copy(
        update={
            "workspace_path": tmp_path / "workspaces" / "workspace-1",
            "repository_profile_ref": _ref("repository-profile"),
            "static_bundle_ref": _ref("static-bundle"),
            "policy_snapshot_ref": _ref("policy-snapshot-1"),
        }
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_static_run_update
            BEFORE UPDATE ON simple_analysis_runs
            WHEN json_extract(NEW.run_json, '$.policy_snapshot_ref') IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'simulated run write failure');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="simulated run write failure"):
        store.complete(
            checkpoint,
            StageResult(
                output_refs=(
                    _ref("repository-profile"),
                    _ref("static-bundle"),
                    _ref("policy-snapshot-1"),
                )
            ),
            analysis_run=updated,
        )

    assert (
        store.require(identity, SimpleStage.STATIC_DONE).status is StageStatus.RUNNING
    )
    assert store.require_analysis_run("analysis-1").policy_snapshot_ref is None


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
async def test_partial_opengrep_scan_runs_agents_without_claiming_complete(
    tmp_path: Path,
) -> None:
    tool = tmp_path / "tool"
    tool.write_bytes(b"tool")
    binding = SimpleToolBinding(
        executable_path=tool,
        version="1.0",
        executable_sha256=hashlib.sha256(b"tool").hexdigest(),
    )
    profile = SimpleExecutionProfile(
        provider_profile_ref="local",
        provider="openai",
        model="test-model",
        auth_mode="SUBSCRIPTION_LOGIN",
        credential_ref="OFFICIAL_CLIENT_SESSION",
        data_dir=tmp_path,
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        tools={"git": binding, "opengrep": binding},
    )
    rules = tmp_path / "materials" / "opengrep" / "rules.yml"
    rules.parent.mkdir(parents=True)
    rules.write_text(
        "rules:\n"
        + "".join(
            f"  - id: rule.{index}\n"
            "    languages: [python]\n"
            "    message: test\n"
            "    severity: INFO\n"
            "    pattern: foo(...)\n"
            for index in range(4)
        ),
        encoding="utf-8",
    )

    class SecondBatchTimeout:
        scans = 0

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            del timeout_seconds
            if argv[1] == "clone":
                root = Path(argv[-1])
                root.mkdir(parents=True)
                (root / "app.py").write_text("foo(user)\n", encoding="utf-8")
            elif argv[1:3] == ("rev-parse", "HEAD"):
                return ProcessResult(0, ("a" * 40).encode(), b"")
            elif argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py\0", b"")
            elif argv[1] == "scan":
                self.scans += 1
                if self.scans == 2:
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [
                                {
                                    "check_id": "rule.0",
                                    "path": str(Path(cwd or argv[-1]) / "app.py"),
                                    "start": {"line": 1},
                                }
                            ],
                            "errors": [],
                            "paths": {"scanned": ["app.py"], "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
            return ProcessResult(0, b"", b"")

    class PartialHypotheses:
        async def propose(
            self, identity: CheckpointIdentity, static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            assert static.static_disposition == "PARTIAL"
            proposal_ref = SimpleArtifactRepository(tmp_path, identity).put_json(
                {
                    "kind": "simple_hypothesis_proposal",
                    "hypothesis_id": "hypothesis-partial",
                    "static_bundle_ref": static.static_bundle_ref.model_dump(
                        mode="json"
                    ),
                    "proposal": {"title": "partial"},
                }
            )
            return (
                HypothesisSeed(
                    hypothesis_id="hypothesis-partial",
                    proposal_ref=proposal_ref,
                ),
            )

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    process = SecondBatchTimeout()
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=DirectStaticBootstrap(
            profile=profile,
            process=process,
            store=store,
            static_material_root=tmp_path / "materials",
        ),
        hypothesis_bootstrap=PartialHypotheses(),
        runner_factory=_runner,
        id_factory=iter(("analysis-partial", "workspace-1")).__next__,
    )

    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert (outcome.status, outcome.error_code) == ("PARTIAL", None)
    assert store.require(outcome.identity, SimpleStage.STATIC_DONE).status is (
        StageStatus.SUCCEEDED
    )
    run = store.require_analysis_run(outcome.identity.analysis_id)
    assert run.static_bundle_ref is not None
    assert run.static_coverage_ref is not None
    assert process.scans == 2
    artifacts = SimpleArtifactRepository(tmp_path, outcome.identity)
    coverage = json.loads(artifacts.read(run.static_coverage_ref))
    assert coverage["verified_count"] > 0
    assert coverage["gaps"]
    attempts = store.list_static_scan_attempts(
        outcome.identity,
        "https://example.invalid/repo.git",
        coverage["fingerprint"],
    )
    assert any(
        item.tool == "opengrep"
        and item.status == "SUCCEEDED"
        and item.raw_ref is not None
        for item in attempts
    )


@pytest.mark.parametrize(
    "error_code",
    (
        "STATIC_COVERAGE_INCOMPLETE",
        "SEMGREP_TOOL_UNAVAILABLE",
        "SEMGREP_RESULT_INVALID",
    ),
)
@pytest.mark.asyncio
async def test_same_coverage_fingerprint_resume_keeps_evidence_without_retry(
    tmp_path: Path,
    error_code: str,
) -> None:
    class DeterministicGap:
        calls = 0
        fingerprint = "coverage-one"

        async def coverage_fingerprint(
            self, _request: SimpleAnalysisRequest, _identity: CheckpointIdentity
        ) -> str:
            return self.fingerprint

        async def run(
            self, _request: SimpleAnalysisRequest, identity: CheckpointIdentity
        ) -> StaticBootstrapResult:
            self.calls += 1
            artifacts = SimpleArtifactRepository(tmp_path, identity)
            coverage = artifacts.put_json(
                {
                    "kind": "simple_static_coverage_v1",
                    "fingerprint": self.fingerprint,
                    "expected_count": 1,
                    "verified_count": 0,
                    "gaps": [
                        {
                            "path": "app.py",
                            "rule_id": "rule.one",
                            "reason": "parse_or_scan_error",
                        }
                    ],
                }
            )
            bundle = artifacts.put_json({"kind": "simple_static_fact_bundle"})
            raise StaticCoverageBlocked(error_code, coverage, bundle, retryable=False)

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    static = DeterministicGap()
    recovery = _RecoveryFactory(tmp_path)
    app = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
        recovery_factory=recovery,
        id_factory=iter(("analysis-coverage-gap", "workspace-gap")).__next__,
    )
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )
    checkpoint = store.require(first.identity, SimpleStage.STATIC_DONE)
    assert first.status == "BLOCKED"
    assert len(checkpoint.output_refs) == 2
    assert static.calls == 1
    assert recovery.calls == []
    resumed = await app.resume(first.identity.analysis_id)
    assert resumed.status == "BLOCKED"
    assert static.calls == 1
    static.fingerprint = "coverage-two"
    changed = await app.resume(first.identity.analysis_id)
    assert changed.status == "BLOCKED"
    assert static.calls == 2


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
async def test_nonretryable_scope_error_without_evidence_stays_blocked(
    tmp_path: Path,
) -> None:
    class ScopeError(ValueError):
        retryable = False

    class InvalidScopeStatic:
        calls = 0

        async def run(
            self,
            _request: SimpleAnalysisRequest,
            _identity: CheckpointIdentity,
        ) -> StaticBootstrapResult:
            self.calls += 1
            raise ScopeError("STATIC_SCOPE_MANIFEST_UNVERIFIED")

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    static = InvalidScopeStatic()
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

    assert outcome.status == "BLOCKED"
    assert outcome.error_code == "STATIC_SCOPE_MANIFEST_UNVERIFIED"
    assert static.calls == 1
    assert not recovery.calls
    assert store.require(outcome.identity, SimpleStage.STATIC_DONE).retryable is False
    resumed = await application.resume(outcome.identity.analysis_id)
    assert resumed.status == "BLOCKED"
    assert resumed.error_code == "STATIC_SCOPE_MANIFEST_UNVERIFIED"
    assert static.calls == 1


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
async def test_resume_rejects_completed_static_evidence_from_another_scope(
    tmp_path: Path,
) -> None:
    class ScopedStatic:
        fingerprint = "product-scope-one"
        calls = 0

        async def coverage_fingerprint(
            self, _request: SimpleAnalysisRequest, _identity: CheckpointIdentity
        ) -> str:
            return self.fingerprint

        async def run(
            self, request: SimpleAnalysisRequest, identity: CheckpointIdentity
        ) -> StaticBootstrapResult:
            self.calls += 1
            artifacts = SimpleArtifactRepository(tmp_path, identity)
            coverage = artifacts.put_json(
                {
                    "kind": "simple_static_coverage_v1",
                    "fingerprint": self.fingerprint,
                    "expected_count": 1,
                    "verified_count": 1,
                    "gaps": [],
                }
            )
            bundle = artifacts.put_json(
                {
                    "kind": "simple_static_fact_bundle",
                    "static_coverage_ref": coverage.model_dump(mode="json"),
                }
            )
            return StaticBootstrapResult(
                repository_profile_ref=artifacts.put_json({"kind": "profile"}),
                static_bundle_ref=bundle,
                workspace_path=request.data_dir / "workspaces" / identity.workspace_id,
            )

    class AcceptingHypotheses:
        calls = 0

        async def propose(
            self, _identity: CheckpointIdentity, _static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            self.calls += 1
            return (
                HypothesisSeed(
                    hypothesis_id="hypothesis-1", proposal_ref=_ref("hypothesis")
                ),
            )

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    static = ScopedStatic()
    hypotheses = AcceptingHypotheses()
    app = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=hypotheses,
        runner_factory=_runner,
        id_factory=iter(("analysis-product-scope", "workspace-1")).__next__,
    )
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )
    assert first.status == "COMPLETE"
    original_bundle = store.require_analysis_run(
        first.identity.analysis_id
    ).static_bundle_ref
    static.fingerprint = "product-scope-two"

    with pytest.raises(ValueError, match="STATIC_SCOPE_CHANGED_NEW_ANALYSIS_REQUIRED"):
        await app.resume(first.identity.analysis_id)

    assert static.calls == 1
    assert hypotheses.calls == 1
    assert (
        store.require_analysis_run(first.identity.analysis_id).static_bundle_ref
        == original_bundle
    )


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
@pytest.mark.parametrize(
    "failure_code",
    ["LLM_TOKEN_BUDGET_EXHAUSTED", "LLM_TOKEN_USAGE_UNAVAILABLE"],
)
@pytest.mark.parametrize(
    ("max_tokens", "expected_status"),
    [("unlimited", "COMPLETE"), (5, "FAILED")],
)
async def test_resume_reopens_token_failures_only_without_cumulative_token_limit(
    tmp_path: Path,
    failure_code: str,
    max_tokens: int | Literal["unlimited"],
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
        max_tokens=max_tokens,
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
    checkpoint = store.require(child, SimpleStage.PRO_CON_DONE)
    store.save_checkpoint(
        checkpoint.model_copy(
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
        status=(
            "TIMED_OUT"
            if failure_code == "LLM_TOKEN_USAGE_UNAVAILABLE"
            else "SUCCEEDED"
        ),
        elapsed_ms=100,
        input_tokens=None if failure_code == "LLM_TOKEN_USAGE_UNAVAILABLE" else 8,
        output_tokens=None if failure_code == "LLM_TOKEN_USAGE_UNAVAILABLE" else 2,
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


@pytest.mark.parametrize("invalid_tail", [False, True])
@pytest.mark.parametrize("candidate_pipeline", [False, True])
def test_chaining_child_is_added_once_to_durable_analysis_queue(
    tmp_path: Path,
    invalid_tail: bool,
    candidate_pipeline: bool,
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
    second_parent = identity.model_copy(update={"hypothesis_id": "hypothesis-2"})
    upstream_ref = _admitted_primitive(
        store, artifacts, identity, provided=("route_access",)
    )
    downstream_ref = _admitted_primitive(
        store, artifacts, second_parent, required=("route_access",)
    )
    valid_child = {
        "upstream_primitive_hash": upstream_ref.content_hash,
        "downstream_primitive_hash": downstream_ref.content_hash,
        "title": "compound finding",
        "vulnerability_type": "compound",
        "summary": "A second primitive extends the first",
        "rationale": "Matching capabilities",
        "code_locations": ["app.py:1"],
        "parent_hypothesis_ids": ["hypothesis-1", "hypothesis-2"],
        "parent_primitive_refs": [
            upstream_ref.model_dump(mode="json"),
            downstream_ref.model_dump(mode="json"),
        ],
    }
    children = [valid_child]
    if invalid_tail:
        children.append(
            {
                **valid_child,
                "title": "invalid second child",
                "parent_hypothesis_ids": ["hypothesis-1", "unknown-parent"],
            }
        )
    chaining_ref = artifacts.put_json(
        {
            "kind": "simple_chaining_result",
            "analysis_id": identity.analysis_id,
            "source_hypothesis_id": identity.hypothesis_id,
            "considered_primitive_refs": [
                upstream_ref.model_dump(mode="json"),
                downstream_ref.model_dump(mode="json"),
            ],
            "status": "MATERIAL_CHILD",
            "children": children,
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
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    if candidate_pipeline:
        for hypothesis_id in (
            "hypothesis-1",
            "hypothesis-2",
            *(f"hypothesis-existing-{index}" for index in range(31)),
        ):
            store.upsert_hypothesis(root_identity, hypothesis_id)
    run = SimpleAnalysisRun(
        analysis_id="analysis-1",
        display_analysis_id="A-001",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        repository="repo",
        candidate_pipeline_version=1 if candidate_pipeline else None,
        hypothesis_ids=() if candidate_pipeline else ("hypothesis-1", "hypothesis-2"),
    )
    static = StaticBootstrapResult(
        repository_profile_ref=_ref("repository-profile"),
        static_bundle_ref=_ref("static-bundle"),
        workspace_path=tmp_path / "workspace",
    )

    if invalid_tail:
        with pytest.raises(ChainingEvidenceInvalid):
            application._register_chain_children(run, application_identity, static)
        assert not any(
            checkpoint.identity.hypothesis_id.startswith("hypothesis-chain-")
            for checkpoint in store.list_checkpoints(identity.analysis_id)
            if checkpoint.identity.hypothesis_id is not None
        )
        return

    updated = application._register_chain_children(run, application_identity, static)
    repeated = application._register_chain_children(
        updated,
        application_identity,
        static,
    )

    if candidate_pipeline:
        assert updated.hypothesis_ids == repeated.hypothesis_ids == ()
        assert store.hypothesis_count(root_identity) == 34
        child_id = next(
            hypothesis_id
            for hypothesis_id in store.list_hypotheses(root_identity, limit=40)
            if hypothesis_id.startswith("hypothesis-chain-")
        )
        assert store.hypothesis_metadata(root_identity, child_id) == (
            1,
            ("hypothesis-1", "hypothesis-2"),
        )
    else:
        assert len(updated.hypothesis_ids) == 3
        assert repeated.hypothesis_ids == updated.hypothesis_ids
        child_id = updated.hypothesis_ids[-1]
        assert updated.chain_depths[child_id] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalidity",
    [
        "empty",
        "unreadable",
        "malformed_json",
        "malformed_children",
        "partial_children",
        "unbound_child",
    ],
)
async def test_successful_chaining_requires_trusted_output_before_completion(
    tmp_path: Path, invalidity: str
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-invalid-chain",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    if invalidity == "empty":
        invalid_refs: tuple[StoredDataRef, ...] = ()
    elif invalidity == "unreadable":
        invalid_refs = (_ref("missing-chaining"),)
    elif invalidity == "malformed_json":
        invalid_refs = (artifacts.put_bytes(b"{", "application/json"),)
    elif invalidity == "malformed_children":
        invalid_refs = (
            artifacts.put_json(
                {"kind": "simple_chaining_result", "children": {"not": "a list"}}
            ),
        )
    elif invalidity == "unbound_child":
        invalid_refs = (
            artifacts.put_json(
                {
                    "kind": "simple_chaining_result",
                    "analysis_id": identity.analysis_id,
                    "source_hypothesis_id": identity.hypothesis_id,
                    "considered_primitive_refs": [],
                    "status": "MATERIAL_CHILD",
                    "children": [
                        {
                            "upstream_primitive_hash": "a" * 64,
                            "downstream_primitive_hash": "b" * 64,
                            "title": "unbound child",
                            "vulnerability_type": "compound",
                            "summary": "No admitted primitive supports this child",
                            "rationale": "Claimed matching capabilities",
                            "code_locations": ["app.py:1"],
                            "parent_hypothesis_ids": ["hypothesis-1"],
                            "parent_primitive_refs": [],
                        }
                    ],
                }
            ),
        )
    else:
        invalid_refs = (
            artifacts.put_json(
                {
                    "kind": "simple_chaining_result",
                    "analysis_id": identity.analysis_id,
                    "source_hypothesis_id": identity.hypothesis_id,
                    "considered_primitive_refs": [],
                    "status": "MATERIAL_CHILD",
                    "children": [
                        {
                            "upstream_primitive_hash": "a" * 64,
                            "downstream_primitive_hash": "b" * 64,
                            "title": "valid child",
                            "vulnerability_type": "compound",
                            "summary": "Valid candidate",
                            "rationale": "Matching capabilities",
                            "code_locations": ["app.py:1"],
                            "parent_hypothesis_ids": ["hypothesis-1"],
                            "parent_primitive_refs": [],
                        },
                        {"title": "incomplete child"},
                    ],
                }
            ),
        )

    async def invalid_chaining(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        del checkpoint, prior
        return StageResult(output_refs=invalid_refs)

    def runner_factory(
        current_store: SimpleCheckpointStore,
        child: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        baseline = _runner(
            current_store, child, static, final_verdict="HOLD", data_dir=tmp_path
        )
        return SimpleRuntimeRunner(
            current_store,
            {**baseline.handlers, SimpleStage.CHAINING_DONE: invalid_chaining},
        )

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=runner_factory,
        id_factory=iter(("analysis-invalid-chain", "workspace-1")).__next__,
    )

    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert (outcome.status, outcome.error_code) == (
        "BLOCKED",
        "CHAINING_EVIDENCE_INVALID",
    )
    checkpoint = store.require(identity, SimpleStage.CHAINING_DONE)
    assert checkpoint.status is StageStatus.BLOCKED
    assert checkpoint.output_refs == invalid_refs
    assert store.require_analysis_run(identity.analysis_id).hypothesis_ids == (
        "hypothesis-1",
    )
    if invalidity == "malformed_json":
        assert artifacts.read(invalid_refs[0]) == b"{"


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


@pytest.mark.asyncio
async def test_interrupted_static_resume_retries_without_llm_recovery(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    display = AnalysisDisplayIdStore(store.database_path).get_or_allocate("analysis-1")
    run = SimpleAnalysisRun(
        analysis_id="analysis-1",
        display_analysis_id=display,
        workspace_id="workspace-1",
        commit_id="a" * 40,
        repository="https://example.invalid/repo.git",
    )
    store.save_analysis_run(run)
    identity = CheckpointIdentity(
        analysis_id=run.analysis_id,
        workspace_id=run.workspace_id,
        commit_id=run.commit_id,
        hypothesis_id=None,
    )
    store.mark_running(identity, SimpleStage.STATIC_DONE, (), attempt_id="attempt-1")
    recovery = _RecoveryFactory(tmp_path)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
        recovery_factory=recovery,
    )

    outcome = await application.resume("analysis-1")

    assert outcome.status == "COMPLETE"
    checkpoint = store.require(identity, SimpleStage.STATIC_DONE)
    assert checkpoint.status is StageStatus.SUCCEEDED
    assert checkpoint.attempt_number == 2
    assert recovery.calls == []
