"""Python-only static completeness must retain exact scope and run evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding
from sastsimi.reporting.bilingual_bundle import coverage_report_lines
from sastsimi.reporting.coverage_disclosure import coverage_disclosure
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectStaticBootstrap,
    ProcessResult,
)
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.opengrep_rule_batches import RuleBatchPlan
from sastsimi.simple_runtime.run_lease import analysis_run_lease
from sastsimi.simple_runtime.static_coverage import CoverageSlice, StaticCoveragePlan
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.static_analysis.file_scope import out_of_scope_limits_python_coverage


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="python-scope-analysis",
        workspace_id="python-scope-workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )


def _coverage(
    identity: CheckpointIdentity,
    *,
    out_of_scope: list[dict[str, str]] | None = None,
    gaps: list[dict[str, str]] | None = None,
    engine_errors: list[str] | None = None,
) -> dict[str, object]:
    pending = gaps or []
    return {
        "kind": "simple_static_coverage_v1",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "fingerprint": "f" * 64,
        "expected_count": 1,
        "verified_count": 1 - len(pending),
        "gaps": pending,
        "unsupported": [],
        "unsupported_files": [],
        "unavailable_paths": [],
        "ast_parsed_file_count": 1,
        "ast_parse_error_count": 0,
        "ast_parse_errors": [],
        "ast_oversize_count": 0,
        "ast_oversize_paths": [],
        "ast_truncated": False,
        "codeql_error": None,
        "engine_errors": engine_errors or [],
        "out_of_scope_product_files": out_of_scope or [],
        "excluded_test_files": [],
    }


class _ScopeProcess:
    def __init__(self, extra_path: str) -> None:
        self.extra_path = extra_path

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
            (root / "app.py").write_text(
                "def ready():\n    return True\n", encoding="utf-8"
            )
            (root / self.extra_path).write_text(
                "// excluded source\n", encoding="utf-8"
            )
        elif argv[1:3] == ("rev-parse", "HEAD"):
            return ProcessResult(0, ("a" * 40).encode(), b"")
        elif argv[1:3] == ("ls-files", "-z"):
            return ProcessResult(0, f"app.py\0{self.extra_path}\0".encode(), b"")
        elif argv[1] == "scan":
            raise AssertionError("the test supplies a verified scanner slice")
        return ProcessResult(0, b"", b"")


@pytest.mark.asyncio
@pytest.mark.parametrize("extra_path", ("runtime.js", "launch.sh"))
async def test_static_bootstrap_reports_full_python_scope_with_non_python_exclusions(
    tmp_path: Path, extra_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = tmp_path / "opengrep" / "rules.yml"
    rules.parent.mkdir()
    rules.write_text(
        "rules:\n"
        "  - id: python.ready\n"
        "    languages: [python]\n"
        "    message: test\n"
        "    severity: INFO\n"
        "    pattern: ready(...)\n",
        encoding="utf-8",
    )
    executable = tmp_path / "tool"
    executable.write_bytes(b"tool")
    binding = SimpleToolBinding(
        executable_path=executable,
        version="1.0",
        executable_sha256=hashlib.sha256(b"tool").hexdigest(),
    )
    profile = SimpleExecutionProfile(
        provider_profile_ref="local",
        provider="openai",
        model="test-model",
        auth_mode="SUBSCRIPTION_LOGIN",
        credential_ref="OFFICIAL_CLIENT_SESSION",
        data_dir=tmp_path / "data",
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        tools={"git": binding, "opengrep": binding},
    )
    identity = _identity()
    store = SimpleCheckpointStore(profile.data_dir / "db" / "sastsimi.sqlite3")
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=_ScopeProcess(extra_path),
        store=store,
        static_material_root=tmp_path,
    )

    async def verified_scan(
        workspace: Path,
        request: SimpleAnalysisRequest,
        current: CheckpointIdentity,
        rule_plan: RuleBatchPlan,
        coverage_plan: StaticCoveragePlan,
        tracked: object,
        scope_fingerprint: str,
        artifacts: SimpleArtifactRepository,
        budget: object,
        slices: list[CoverageSlice],
        refs: list[object],
        errors: list[str],
    ) -> None:
        del workspace, request, current, tracked, scope_fingerprint, budget, errors
        raw: dict[str, object] = {
            "results": [],
            "errors": [],
            "paths": {"scanned": ["app.py"], "skipped": []},
        }
        raw_ref = artifacts.put_bytes(json.dumps(raw).encode(), "application/json")
        batch = rule_plan.batches[0]
        slices.append(
            CoverageSlice(
                engine="opengrep",
                batch_key=batch.key,
                rule_ids=batch.rule_ids,
                verified_pairs=coverage_plan.expected_pairs,
                gap_reasons=(),
                parsed=raw,
                normalized_results=(),
                raw_ref=raw_ref,
            )
        )
        refs.append(raw_ref)

    monkeypatch.setattr(bootstrap, "_collect_opengrep", verified_scan)
    result = await bootstrap.run(
        SimpleAnalysisRequest(
            data_dir=profile.data_dir,
            repository="https://example.invalid/repo.git",
            commit=identity.commit_id,
        ),
        identity,
    )
    assert result.static_disposition == "FULL"
    assert result.static_coverage_ref is not None
    coverage = json.loads(
        SimpleArtifactRepository(profile.data_dir, identity).read(
            result.static_coverage_ref
        )
    )
    assert coverage["verified_count"] == coverage["expected_count"] == 1
    assert coverage["out_of_scope_product_files"] == [
        {"path": extra_path, "reason": "non_python_product_source"}
    ]


def test_full_python_scope_report_still_discloses_non_python_exclusions(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    data = _coverage(
        identity,
        out_of_scope=[
            {"path": "web/app.js", "reason": "non_python_product_source"},
            {"path": "scripts/launch.sh", "reason": "non_python_product_source"},
        ],
    )
    ref = artifacts.put_json(data)
    disclosure = coverage_disclosure(
        data,
        ref,
        analysis_id=identity.analysis_id,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        disposition="FULL",
    )
    english = "\n".join(coverage_report_lines(disclosure, korean=False))
    korean = "\n".join(coverage_report_lines(disclosure, korean=True))
    english_status = next(
        line for line in english.splitlines() if line.startswith("- Static scan status")
    )
    korean_status = next(
        line for line in korean.splitlines() if line.startswith("- 정적 분석 상태")
    )
    assert disclosure.partial is False
    assert disclosure.out_of_scope_product_count == 2
    assert "Python" in english_status and "`FULL`" in english_status
    assert "Python" in korean_status and "`FULL`" in korean_status
    assert "Out-of-scope product files: 2" in english
    assert "web/app.js" in english and "scripts/launch.sh" in english


@pytest.mark.parametrize(
    "row",
    [
        {"path": "api/types.pyi", "reason": "python_stub_not_scanned"},
        {"path": "api/types.pyi", "reason": "declared_non_python_entry"},
        {"path": "examples/app.py", "reason": "manifest_unverified_possible_product"},
        {"path": "web/app.ts", "reason": "manifest_unverified_possible_product"},
        {"path": "web/app.js", "reason": "unknown_exclusion_reason"},
        {"path": "web/app.txt", "reason": "non_python_product_source"},
    ],
)
def test_full_python_scope_rejects_unverified_or_uncertain_product(
    tmp_path: Path, row: dict[str, str]
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    data = _coverage(identity, out_of_scope=[row])
    with pytest.raises(ValueError, match="REPORT_STATIC_COVERAGE_DISPOSITION_INVALID"):
        coverage_disclosure(
            data,
            artifacts.put_json(data),
            analysis_id=identity.analysis_id,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            disposition="FULL",
        )


@pytest.mark.parametrize(
    ("path", "reason", "limits"),
    [
        ("web/app.js", "non_python_product_source", False),
        ("scripts/launch.sh", "non_python_product_source", False),
        ("bin/entry.ts", "declared_non_python_entry", False),
        ("api/types.pyi", "declared_non_python_entry", True),
        ("web/app.ts", "manifest_unverified_possible_product", True),
        ("api/app.py", "non_python_product_source", True),
        ("web/app.txt", "non_python_product_source", True),
    ],
)
def test_python_scope_limit_classification_is_conservative(
    path: str, reason: str, limits: bool
) -> None:
    assert out_of_scope_limits_python_coverage(path, reason) is limits


def test_unpreviewed_python_scope_exclusion_still_prevents_full(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    out_of_scope = [
        {"path": f"web/app{index}.js", "reason": "non_python_product_source"}
        for index in range(8)
    ]
    out_of_scope.append({"path": "api/types.pyi", "reason": "python_stub_not_scanned"})
    data = _coverage(identity, out_of_scope=out_of_scope)
    with pytest.raises(ValueError, match="REPORT_STATIC_COVERAGE_DISPOSITION_INVALID"):
        coverage_disclosure(
            data,
            artifacts.put_json(data),
            analysis_id=identity.analysis_id,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            disposition="FULL",
        )


@pytest.mark.parametrize(
    "change",
    [
        {"gaps": [{"path": "app.py", "rule_id": "python.ready", "reason": "timeout"}]},
        {"engine_errors": ["OPENGREP_EXECUTION_FAILED"]},
        {"expected_count": 0, "verified_count": 0},
        {"codeql_error": "CODEQL_EXECUTION_FAILED"},
        {"ast_parse_error_count": 1},
        {"ast_truncated": True},
        {"unsupported_files": [{"path": "app.py", "reason": "unsupported_language"}]},
    ],
)
def test_full_python_scope_rejects_unverified_scan_evidence(
    tmp_path: Path, change: dict[str, object]
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    data = _coverage(identity)
    data.update(change)
    if "gaps" in change:
        data["verified_count"] = 0
    with pytest.raises(ValueError, match="REPORT_STATIC_COVERAGE_DISPOSITION_INVALID"):
        coverage_disclosure(
            data,
            artifacts.put_json(data),
            analysis_id=identity.analysis_id,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            disposition="FULL",
        )


class _SavedStatic:
    def __init__(self, fingerprint: str) -> None:
        self.fingerprint = fingerprint

    async def coverage_fingerprint(
        self, request: SimpleAnalysisRequest, identity: CheckpointIdentity
    ) -> str:
        del request, identity
        return self.fingerprint

    async def run(
        self, request: SimpleAnalysisRequest, identity: CheckpointIdentity
    ) -> StaticBootstrapResult:
        del request, identity
        raise AssertionError("saved v2 static evidence must not be rerun")


class _NoHypotheses:
    async def propose(self, *args: object) -> tuple[()]:
        del args
        raise AssertionError("saved candidate work must not be reproposed")


def _saved_v2_run(
    tmp_path: Path, *, coverage_change: dict[str, object] | None = None
) -> tuple[
    SimpleAnalysisApplication,
    SimpleCheckpointStore,
    CheckpointIdentity,
    StageCheckpoint,
    _SavedStatic,
]:
    data_dir = tmp_path / "data"
    identity = _identity()
    workspace = data_dir / "workspaces" / identity.workspace_id
    workspace.mkdir(parents=True)
    (workspace / "app.py").write_text(
        "def ready():\n    return True\n", encoding="utf-8"
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    summary = collect_python_ast(
        workspace, ("app.py",), artifacts, max_source_bytes=32_768
    )
    coverage = _coverage(
        identity,
        out_of_scope=[{"path": "web/app.js", "reason": "non_python_product_source"}],
    )
    coverage.update(coverage_change or {})
    coverage_ref = artifacts.put_json(coverage)
    source_ref = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": ["app.py"]}
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
            "source_manifest_ref": source_ref.model_dump(mode="json"),
            "ast_summary": summary,
        }
    )
    profile_ref = artifacts.put_json({"kind": "repository_profile"})
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.STATIC_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(profile_ref, bundle_ref),
    )
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    store.save_checkpoint(checkpoint)
    saved_static = _SavedStatic(str(coverage["fingerprint"]))
    app = SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=saved_static,
        hypothesis_bootstrap=_NoHypotheses(),
        runner_factory=lambda *_: (_ for _ in ()).throw(AssertionError("child rerun")),
        candidate_pipeline_enabled=True,
        candidate_pipeline_version=2,
    )
    display_id = app._display.get_or_allocate(identity.analysis_id)
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id=display_id,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            workspace_path=workspace,
            repository_profile_ref=profile_ref,
            static_bundle_ref=bundle_ref,
            static_coverage_ref=coverage_ref,
            static_disposition="PARTIAL",
            candidate_pipeline_version=2,
        )
    )
    return app, store, identity, checkpoint, saved_static


def test_verified_non_python_exclusions_are_valid_full_static_evidence(
    tmp_path: Path,
) -> None:
    app, store, identity, _, _ = _saved_v2_run(tmp_path)
    run = store.require_analysis_run(identity.analysis_id)
    assert run.repository_profile_ref is not None
    assert run.static_bundle_ref is not None
    assert run.static_coverage_ref is not None
    assert run.workspace_path is not None
    app._validate_static_evidence(
        StaticBootstrapResult(
            repository_profile_ref=run.repository_profile_ref,
            static_bundle_ref=run.static_bundle_ref,
            static_coverage_ref=run.static_coverage_ref,
            static_disposition="FULL",
            workspace_path=run.workspace_path,
        ),
        identity,
    )


@pytest.mark.asyncio
async def test_same_id_resume_reclassifies_only_verified_python_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, identity, checkpoint, _ = _saved_v2_run(tmp_path)
    original = store.require_analysis_run(identity.analysis_id)

    async def stop_before_candidate_work(
        run: SimpleAnalysisRun,
        current: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisOutcome:
        assert static.static_disposition == "FULL"
        return SimpleAnalysisOutcome(
            identity=current,
            display_analysis_id=run.display_analysis_id,
            status="PARTIAL",
            current_stage=SimpleStage.HYPOTHESIS_DONE,
        )

    monkeypatch.setattr(app, "_run_candidate_pipeline", stop_before_candidate_work)
    outcome = await app.resume(identity.analysis_id)
    saved = store.require_analysis_run(identity.analysis_id)

    assert outcome.status == "PARTIAL"  # Static FULL does not force terminal COMPLETE.
    assert saved.static_disposition == "FULL"
    assert saved.analysis_id == original.analysis_id
    assert saved.static_coverage_ref == original.static_coverage_ref
    assert saved.static_bundle_ref == original.static_bundle_ref
    assert store.require(identity, SimpleStage.STATIC_DONE) == checkpoint


@pytest.mark.asyncio
async def test_same_id_resume_preserves_partial_after_downstream_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, identity, static_checkpoint, _ = _saved_v2_run(tmp_path)
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=static_checkpoint.output_refs,
            input_hash=input_reference_hash(static_checkpoint.output_refs),
        )
    )

    async def stop_before_candidate_work(
        run: SimpleAnalysisRun,
        current: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisOutcome:
        assert run.static_disposition == "PARTIAL"
        assert static.static_disposition == "PARTIAL"
        return SimpleAnalysisOutcome(
            identity=current,
            display_analysis_id=run.display_analysis_id,
            status="PARTIAL",
            current_stage=SimpleStage.HYPOTHESIS_DONE,
        )

    monkeypatch.setattr(app, "_run_candidate_pipeline", stop_before_candidate_work)
    outcome = await app.resume(identity.analysis_id)
    assert outcome.status == "PARTIAL"
    assert (
        store.require_analysis_run(identity.analysis_id).static_disposition == "PARTIAL"
    )


@pytest.mark.asyncio
async def test_same_id_reclassification_respects_active_lease(tmp_path: Path) -> None:
    app, store, identity, checkpoint, _ = _saved_v2_run(tmp_path)
    with analysis_run_lease(tmp_path / "data", identity.analysis_id):
        outcome = await app.resume(identity.analysis_id)
    assert outcome.status == "RUNNING"
    assert outcome.error_code == "ANALYSIS_ALREADY_RUNNING"
    assert (
        store.require_analysis_run(identity.analysis_id).static_disposition == "PARTIAL"
    )
    assert store.require(identity, SimpleStage.STATIC_DONE) == checkpoint


@pytest.mark.asyncio
async def test_same_id_reclassification_rejects_changed_scope_hash(
    tmp_path: Path,
) -> None:
    app, store, identity, _, saved_static = _saved_v2_run(tmp_path)
    saved_static.fingerprint = "0" * 64
    with pytest.raises(ValueError, match="STATIC_SCOPE_CHANGED_NEW_ANALYSIS_REQUIRED"):
        await app.resume(identity.analysis_id)
    assert (
        store.require_analysis_run(identity.analysis_id).static_disposition == "PARTIAL"
    )


@pytest.mark.asyncio
async def test_same_id_reclassification_rejects_corrupt_cas_reference(
    tmp_path: Path,
) -> None:
    app, store, identity, _, _ = _saved_v2_run(tmp_path)
    run = store.require_analysis_run(identity.analysis_id)
    assert run.static_coverage_ref is not None
    damaged = run.static_coverage_ref.model_copy(update={"content_hash": "0" * 64})
    store.save_analysis_run(run.model_copy(update={"static_coverage_ref": damaged}))

    outcome = await app.resume(identity.analysis_id)

    assert outcome.status == "BLOCKED"
    assert outcome.error_code == "STATIC_EVIDENCE_INVALID"
    assert (
        store.require_analysis_run(identity.analysis_id).static_disposition == "PARTIAL"
    )


@pytest.mark.asyncio
async def test_same_id_reclassification_rejects_unverified_python_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, identity, _, _ = _saved_v2_run(
        tmp_path,
        coverage_change={
            "verified_count": 0,
            "gaps": [
                {"path": "app.py", "rule_id": "python.ready", "reason": "timeout"}
            ],
        },
    )

    async def stop_before_candidate_work(
        run: SimpleAnalysisRun,
        current: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisOutcome:
        assert static.static_disposition == "PARTIAL"
        return SimpleAnalysisOutcome(
            identity=current,
            display_analysis_id=run.display_analysis_id,
            status="PARTIAL",
            current_stage=SimpleStage.HYPOTHESIS_DONE,
        )

    monkeypatch.setattr(app, "_run_candidate_pipeline", stop_before_candidate_work)
    await app.resume(identity.analysis_id)
    assert (
        store.require_analysis_run(identity.analysis_id).static_disposition == "PARTIAL"
    )
