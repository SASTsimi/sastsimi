"""A v2 resume keeps the static evidence that supplied its candidates."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.application import (
    HypothesisSeed,
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.store import SimpleCheckpointStore


@pytest.mark.asyncio
async def test_v2_partial_same_id_resume_keeps_static_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-v2-partial",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    source_hash = "b" * 64
    ast_file = artifacts.put_json(
        {
            "kind": "simple_python_ast_file_v2",
            "path": "app.py",
            "source_sha256": source_hash,
            "facts": [],
        }
    )
    manifest = artifacts.put_json(
        {
            "kind": "simple_python_ast_manifest_v2",
            "entries": [
                {
                    "path": "app.py",
                    "fact_count": 0,
                    "source_sha256": source_hash,
                    "ref": ast_file.model_dump(mode="json"),
                }
            ],
            "fact_count": 0,
            "parsed_file_count": 1,
        }
    )
    sources = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": ["app.py"]}
    )
    coverage = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "c" * 64,
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
            "unavailable": False,
            "ast_parsed_file_count": 1,
            "ast_parse_errors": [],
            "ast_parse_error_count": 0,
            "ast_oversize_paths": [],
            "ast_oversize_count": 0,
            "ast_truncated": False,
        }
    )
    bundle = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": coverage.model_dump(mode="json"),
            "source_manifest_ref": sources.model_dump(mode="json"),
            "ast_summary": {
                "kind": "simple_python_ast",
                "format_version": 3,
                "manifest_ref": manifest.model_dump(mode="json"),
                "fact_count": 0,
                "parsed_file_count": 1,
                "parse_errors": [],
                "parse_error_count": 0,
                "oversize_paths": [],
                "oversize_count": 0,
                "truncated": False,
            },
        }
    )
    profile = artifacts.put_json({"kind": "repository_profile"})
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.STATIC_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(profile, bundle),
    )
    store.save_checkpoint(checkpoint)

    class NoStaticRetry:
        async def run(
            self, request: SimpleAnalysisRequest, current: CheckpointIdentity
        ) -> StaticBootstrapResult:
            raise AssertionError("v2 resume reran static analysis")

    class NoHypothesisProposal:
        async def propose(
            self, current: CheckpointIdentity, static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            raise AssertionError("v2 resume entered the legacy hypothesis path")

    def no_runner(
        current_store: SimpleCheckpointStore,
        current: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        raise AssertionError("v2 resume entered the legacy child path")

    application = SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=NoStaticRetry(),
        hypothesis_bootstrap=NoHypothesisProposal(),
        runner_factory=no_runner,
        candidate_pipeline_enabled=True,
        candidate_pipeline_version=2,
    )
    display_id = application._display.get_or_allocate(identity.analysis_id)
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id=display_id,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            repository_profile_ref=profile,
            static_bundle_ref=bundle,
            static_coverage_ref=coverage,
            static_disposition="PARTIAL",
            workspace_path=data_dir / "workspaces" / identity.workspace_id,
            candidate_pipeline_version=2,
        )
    )

    async def candidate_pipeline(
        run: SimpleAnalysisRun,
        current: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisOutcome:
        assert run.analysis_id == identity.analysis_id
        assert static.static_bundle_ref == bundle
        assert static.static_coverage_ref == coverage
        assert static.static_disposition == "PARTIAL"
        return SimpleAnalysisOutcome(
            identity=current,
            display_analysis_id=run.display_analysis_id,
            status="PARTIAL",
            current_stage=SimpleStage.HYPOTHESIS_DONE,
        )

    monkeypatch.setattr(application, "_run_candidate_pipeline", candidate_pipeline)

    outcome = await application.resume(identity.analysis_id)

    assert outcome.status == "PARTIAL"
    assert store.require(identity, SimpleStage.STATIC_DONE) == checkpoint
    assert (
        store.require_analysis_run(identity.analysis_id).static_coverage_ref == coverage
    )
