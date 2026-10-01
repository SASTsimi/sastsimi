from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime import bootstrap_stages as static_module
from sastsimi.simple_runtime import semgrep_fallback as semgrep_module
from sastsimi.simple_runtime.application import (
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attempt_owner import AttemptOwner, PromptByteCounts
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectHypothesisBootstrap,
    DirectStaticBootstrap,
    ProcessResult,
    StaticCoverageBlocked,
)
from sastsimi.simple_runtime.candidates import ingest_static_candidates
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.opengrep_rule_batches import (
    RuleBatchPlan,
    plan_rule_batches,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.semgrep_fallback_plan import plan_semgrep_target_chunks
from sastsimi.simple_runtime.static_coverage import (
    CoverageSlice,
    StaticCandidateBudget,
    StaticCoveragePlan,
    finish_coverage,
    merge_static_candidates,
    plan_static_coverage,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.static_analysis.file_scope import build_static_file_scope


@pytest.mark.asyncio
@pytest.mark.parametrize("engine", ("opengrep", "semgrep"))
async def test_resume_replays_each_partial_execution_after_same_key_timeout(
    tmp_path: Path, engine: str
) -> None:
    process = _AdaptiveSemgrepProcess(lambda _targets, _command: TimeoutError())
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=3)
    bootstrap, profile, identity, batches, coverage, workspace, rules = fixture
    batch = batches.batches[0]
    targets = ("file-000.py", "file-001.py", "file-002.py")
    if engine == "opengrep":
        kind = "opengrep_scan_request_v1"
        key_data: dict[str, object] = {
            "kind": kind,
            "batch_key": batch.key,
            "rule_ids": batch.rule_ids,
            "targets": targets,
        }
    else:
        kind = "semgrep_scan_request_v1"
        key_data = {
            "adaptive": 1,
            "batch": batch.key,
            "rules": batch.rule_ids,
            "targets": targets,
        }
    run_key = hashlib.sha256(canonical_bytes(key_data)).hexdigest()
    request_data: dict[str, object] = {
        "kind": kind,
        "batch_key": batch.key,
        "rule_ids": list(batch.rule_ids),
        "targets": list(targets),
    }
    if engine == "semgrep":
        request_data["per_file_timeout_seconds"] = None
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    store = _store(profile)
    repository = _request(profile).repository

    for path in targets[:2]:
        raw_ref = artifacts.put_bytes(
            json.dumps(
                {
                    "results": [],
                    "errors": [],
                    "paths": {"scanned": [path], "skipped": []},
                }
            ).encode(),
            "application/json",
        )
        request_ref = artifacts.put_json(
            {**request_data, "raw_content_hash": raw_ref.content_hash}
        )
        store.record_static_scan_execution(
            identity,
            repository,
            coverage.fingerprint,
            engine,
            run_key,
            "BLOCKED",
            raw_ref,
            f"{engine.upper()}_PARTIAL_SCAN",
            request_ref,
            timeout_seconds=120,
        )
        store.save_static_scan_attempt(
            identity,
            repository,
            coverage.fingerprint,
            engine,
            run_key,
            "BLOCKED",
            raw_ref,
            None,
            f"{engine.upper()}_PARTIAL_SCAN",
            request_ref,
        )

    timeout_request = artifacts.put_json(request_data)
    store.record_static_scan_execution(
        identity,
        repository,
        coverage.fingerprint,
        engine,
        run_key,
        "BLOCKED",
        None,
        "EXTERNAL_TOOL_TIMEOUT",
        timeout_request,
        timeout_seconds=120,
    )
    store.save_static_scan_attempt(
        identity,
        repository,
        coverage.fingerprint,
        engine,
        run_key,
        "BLOCKED",
        None,
        None,
        "EXTERNAL_TOOL_TIMEOUT",
        timeout_request,
    )
    assert (
        store.list_static_scan_attempts(identity, repository, coverage.fingerprint)[
            0
        ].raw_ref
        is None
    )

    if engine == "opengrep":
        output_root = tmp_path / "opengrep-output"
        output_root.mkdir()
        slices, _, _ = await bootstrap._recover_opengrep_timeout_chunks(
            workspace,
            _request(profile),
            identity,
            coverage,
            batch,
            coverage.expected_pairs,
            rules,
            output_root,
            artifacts,
            {
                run_key: store.list_static_scan_attempts(
                    identity, repository, coverage.fingerprint
                )[0]
            },
            store.list_static_scan_replay_attempts(
                identity, repository, coverage.fingerprint, tool="opengrep"
            ),
            StaticCandidateBudget(),
            frozenset(),
        )
    else:
        slices, _, _ = await _run_adaptive_semgrep(fixture)

    report = finish_coverage(coverage, slices)
    assert report.verified_count == 2
    assert {(gap.path, gap.rule_id) for gap in report.gaps} == {
        ("file-002.py", "python.sql")
    }
    assert process.calls
    assert all(targets == ("file-002.py",) for targets, _ in process.calls)


@pytest.mark.asyncio
async def test_opengrep_resume_unions_complementary_partial_rule_proofs(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess(lambda _targets, _command: TimeoutError())
    fixture = _adaptive_semgrep_fixture(
        tmp_path, process, count=1, rule_ids=("python.a", "python.b")
    )
    bootstrap, profile, identity, batches, coverage, workspace, rules = fixture
    batch = batches.batches[0]
    targets = ("file-000.py",)
    run_key = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "opengrep_scan_request_v1",
                "batch_key": batch.key,
                "rule_ids": batch.rule_ids,
                "targets": targets,
            }
        )
    ).hexdigest()
    descriptor: dict[str, object] = {
        "kind": "opengrep_scan_request_v1",
        "batch_key": batch.key,
        "rule_ids": list(batch.rule_ids),
        "targets": list(targets),
    }
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    store = _store(profile)
    repository = _request(profile).repository
    for skipped_rule in batch.rule_ids:
        raw_ref = artifacts.put_bytes(
            json.dumps(
                {
                    "results": [],
                    "errors": [],
                    "paths": {"scanned": list(targets), "skipped": []},
                    "skipped_rules": [skipped_rule],
                }
            ).encode(),
            "application/json",
        )
        request_ref = artifacts.put_json(
            {**descriptor, "raw_content_hash": raw_ref.content_hash}
        )
        store.record_static_scan_execution(
            identity,
            repository,
            coverage.fingerprint,
            "opengrep",
            run_key,
            "BLOCKED",
            raw_ref,
            "OPENGREP_PARTIAL_SCAN",
            request_ref,
            timeout_seconds=120,
        )
        store.save_static_scan_attempt(
            identity,
            repository,
            coverage.fingerprint,
            "opengrep",
            run_key,
            "BLOCKED",
            raw_ref,
            None,
            "OPENGREP_PARTIAL_SCAN",
            request_ref,
        )

    attempts = store.list_static_scan_attempts(
        identity, repository, coverage.fingerprint
    )
    output_root = tmp_path / "opengrep-output"
    output_root.mkdir()
    slices, _, errors = await bootstrap._recover_opengrep_timeout_chunks(
        workspace,
        _request(profile),
        identity,
        coverage,
        batch,
        coverage.expected_pairs,
        rules,
        output_root,
        artifacts,
        {item.run_key: item for item in attempts},
        store.list_static_scan_replay_attempts(
            identity, repository, coverage.fingerprint, tool="opengrep"
        ),
        StaticCandidateBudget(),
        frozenset(),
    )

    assert finish_coverage(coverage, slices).verified_count == 2
    assert errors == []
    assert process.calls == []


def test_bounded_static_output_rejects_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "scan.json"
    output.write_bytes(b"1234")
    monkeypatch.setattr(
        static_module, "_MAX_STATIC_SCAN_OUTPUT_BYTES", 3, raising=False
    )

    with pytest.raises(RuntimeError, match="^STATIC_SCAN_OUTPUT_TOO_LARGE$"):
        static_module._read_static_scan_output(output)


@pytest.mark.asyncio
async def test_truncated_git_file_list_cannot_become_complete_coverage(
    tmp_path: Path,
) -> None:
    class TruncatedListProcess(_Process):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1:3] == ("ls-files", "-z"):
                return cast(
                    ProcessResult,
                    SimpleNamespace(
                        returncode=0,
                        stdout=b"app.py\0",
                        stderr=b"",
                        stdout_truncated=True,
                        stderr_truncated=False,
                    ),
                )
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _profile(tmp_path)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=TruncatedListProcess(),
        store=_store(profile),
        static_material_root=tmp_path,
    )

    with pytest.raises(RuntimeError, match="^GIT_TRACKED_FILES_FAILED$"):
        await bootstrap._tracked_files(tmp_path)


@pytest.mark.asyncio
async def test_incomplete_git_file_list_without_terminator_is_rejected(
    tmp_path: Path,
) -> None:
    class IncompleteListProcess(_Process):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _profile(tmp_path)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=IncompleteListProcess(),
        store=_store(profile),
        static_material_root=tmp_path,
    )

    with pytest.raises(RuntimeError, match="^GIT_TRACKED_FILES_FAILED$"):
        await bootstrap._tracked_files(tmp_path)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("truncated_command", "expected_code"),
    [
        ("status", "GIT_STATUS_FAILED"),
        ("ignored", "GIT_IGNORED_FILES_FAILED"),
    ],
)
async def test_truncated_git_cleanliness_output_is_rejected(
    tmp_path: Path, truncated_command: str, expected_code: str
) -> None:
    class TruncatedCleanlinessProcess(_Process):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            is_status = argv[1] == "status"
            is_ignored = argv[1:4] == ("ls-files", "--others", "--ignored")
            if (truncated_command == "status" and is_status) or (
                truncated_command == "ignored" and is_ignored
            ):
                return cast(
                    ProcessResult,
                    SimpleNamespace(
                        returncode=0,
                        stdout=b"",
                        stderr=b"",
                        stdout_truncated=True,
                        stderr_truncated=False,
                    ),
                )
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _profile(tmp_path)
    request = _request(profile)
    workspace = _ready_workspace(tmp_path, request)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=TruncatedCleanlinessProcess(),
        store=_store(profile),
        static_material_root=tmp_path,
    )

    with pytest.raises(RuntimeError, match=f"^{expected_code}$"):
        await bootstrap._verify_opengrep_workspace(workspace, request)


@pytest.mark.asyncio
async def test_completed_static_scope_fingerprint_rejects_dirty_checkout(
    tmp_path: Path,
) -> None:
    class DirtyResumeProcess(_Process):
        dirty = False

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if self.dirty and argv[1:3] == ("status", "--porcelain=v1"):
                return ProcessResult(0, b" M app.py\0", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _profile(tmp_path).model_copy(update={"workspace_root": tmp_path})
    request = _request(profile)
    _ready_workspace(tmp_path, request)
    identity = CheckpointIdentity(
        analysis_id="analysis-dirty-resume",
        workspace_id="checkout",
        commit_id=request.commit,
        hypothesis_id=None,
    )
    process = DirtyResumeProcess()
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )

    assert await bootstrap.coverage_fingerprint(request, identity)
    process.dirty = True
    with pytest.raises(RuntimeError, match="^WORKSPACE_DIRTY$"):
        await bootstrap.coverage_fingerprint(request, identity)


class _Process:
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
                "def query(user):\n    return db.execute(user)\n",
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("", encoding="utf-8")
        elif argv[1:3] == ("rev-parse", "HEAD"):
            return ProcessResult(0, ("a" * 40).encode(), b"")
        elif argv[1:3] == ("ls-files", "-z"):
            return ProcessResult(0, b"app.py\0requirements.txt\0", b"")
        elif argv[1] == "scan":
            output = Path(argv[argv.index("--output") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "python.sql",
                                "path": str(Path(cwd or argv[-1]) / "app.py"),
                                "start": {"line": 2},
                            }
                        ],
                        "errors": [],
                        "paths": {"scanned": ["app.py"], "skipped": []},
                    }
                ),
                encoding="utf-8",
            )
        elif argv[1:3] == ("database", "create"):
            database = Path(argv[3])
            database.mkdir(parents=True, exist_ok=True)
            (database / "codeql-database.yml").write_text("ok", encoding="utf-8")
        elif argv[1:3] == ("database", "analyze"):
            output_arg = next(value for value in argv if value.startswith("--output="))
            output = Path(output_arg[9:])
            output.write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "results": [
                                    {
                                        "ruleId": "py/sql-injection",
                                        "message": {"text": "unsafe query"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "app.py"
                                                    },
                                                    "region": {"startLine": 2},
                                                }
                                            }
                                        ],
                                    }
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
        return ProcessResult(0, b"", b"")


class _RecordingProcess(_Process):
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: int,
    ) -> ProcessResult:
        self.commands.append(tuple(argv))
        return await super().run(
            argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
        )


def test_engine_raw_sources_union_verified_pairs_without_merging_engines(
    tmp_path: Path,
) -> None:
    identity = _identity("raw-source-pair-union")
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    raw_ref = artifacts.put_bytes(b'{"results":[]}', "application/json")
    slices = (
        CoverageSlice(
            engine="opengrep",
            batch_key="a",
            rule_ids=("python.sql",),
            verified_pairs=frozenset({("app.py", "python.sql")}),
            gap_reasons=(),
            parsed={},
            normalized_results=(),
            raw_ref=raw_ref,
        ),
        CoverageSlice(
            engine="opengrep",
            batch_key="b",
            rule_ids=("python.sql",),
            verified_pairs=frozenset({("good.py", "python.sql")}),
            gap_reasons=(),
            parsed={},
            normalized_results=(),
            raw_ref=raw_ref,
        ),
        CoverageSlice(
            engine="semgrep",
            batch_key="c",
            rule_ids=("python.sql",),
            verified_pairs=frozenset({("good.py", "python.sql")}),
            gap_reasons=(),
            parsed={},
            normalized_results=(),
            raw_ref=raw_ref,
        ),
    )

    assert static_module._engine_raw_sources(slices) == [
        {
            "ref": raw_ref.model_dump(mode="json"),
            "engine": "opengrep",
            "verified_pairs": [
                {"path": "app.py", "rule_id": "python.sql"},
                {"path": "good.py", "rule_id": "python.sql"},
            ],
        },
        {
            "ref": raw_ref.model_dump(mode="json"),
            "engine": "semgrep",
            "verified_pairs": [{"path": "good.py", "rule_id": "python.sql"}],
        },
    ]


@pytest.mark.asyncio
async def test_unverified_scan_hit_stays_out_of_candidates_and_in_coverage_gaps(
    tmp_path: Path,
) -> None:
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, _CoverageProcess(parse_warning=True), codeql=False
    )
    identity = _identity("unverified-raw-hit")

    result = await bootstrap.run(_request(profile), identity)

    assert result.static_disposition == "PARTIAL"
    assert result.static_bundle_ref is not None
    coverage = _coverage_from_ref(profile, identity, result.static_coverage_ref)
    assert any(
        gap["path"] == "app.py" and gap["rule_id"] == "python.sql"
        for gap in coverage["gaps"]
    )
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    source = bundle["engine_raw_sources"][0]
    raw = json.loads(artifacts.read(StoredDataRef.model_validate(source["ref"])))
    assert {hit["path"] for hit in raw["results"]} == {"app.py", "good.py"}
    assert source["verified_pairs"] == [{"path": "good.py", "rule_id": "python.sql"}]

    ingest_static_candidates(
        identity,
        coverage["fingerprint"],
        result.static_bundle_ref,
        artifacts,
        store,
        workspace=result.workspace_path,
    )
    candidates = store.list_candidates(identity, coverage["fingerprint"])
    assert {candidate.path for candidate in candidates} == {"good.py"}


@pytest.mark.asyncio
async def test_product_scope_drives_ast_scan_manifest_and_coverage(
    tmp_path: Path,
) -> None:
    class ProductScopeProcess(_Process):
        def __init__(self) -> None:
            self.scan_commands: list[tuple[str, ...]] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "clone":
                result = await super().run(
                    argv, cwd=cwd, timeout_seconds=timeout_seconds
                )
                target = Path(argv[-1]) / "tests" / "test_broken.py"
                target.parent.mkdir()
                target.write_text("def broken(:\n", encoding="utf-8")
                return result
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py\0tests/test_broken.py\0", b"")
            if argv[1] == "scan":
                self.scan_commands.append(tuple(argv))
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {"scanned": ["app.py"], "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _without_codeql(_profile(tmp_path))
    identity = _identity("product-scope")
    process = ProductScopeProcess()
    result = await DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    ).run(_request(profile), identity)

    assert process.scan_commands
    assert all("app.py" in command for command in process.scan_commands)
    assert all(
        "tests/test_broken.py" not in command for command in process.scan_commands
    )
    assert all(
        str(profile.workspace_root / identity.workspace_id) not in command
        for command in process.scan_commands
    )
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    bundle = json.loads(artifacts.read(result.static_bundle_ref))
    manifest = json.loads(
        artifacts.read(StoredDataRef.model_validate(bundle["source_manifest_ref"]))
    )
    poc_manifest = json.loads(
        artifacts.read(StoredDataRef.model_validate(bundle["poc_source_manifest_ref"]))
    )
    coverage = json.loads(
        artifacts.read(StoredDataRef.model_validate(bundle["static_coverage_ref"]))
    )
    assert manifest["paths"] == ["app.py"]
    assert poc_manifest["paths"] == ["app.py"]
    assert bundle["ast_summary"]["parse_error_count"] == 0
    assert coverage["expected_count"] == coverage["verified_count"] == 1
    assert coverage["excluded_test_files"] == [
        {"path": "tests/test_broken.py", "reason": "test-directory:tests"}
    ]
    assert coverage["out_of_scope_product_files"] == []
    assert bundle["engine_raw_sources"] == [
        {
            "ref": ref,
            "engine": "opengrep",
            "verified_pairs": [{"path": "app.py", "rule_id": "python.sql"}],
        }
        for ref in bundle["engine_raw_refs"]
    ]
    assert bundle["engine_raw_sources"]
    for saved in (bundle, manifest, poc_manifest):
        assert "tests/test_broken.py" not in json.dumps(saved, sort_keys=True)


@pytest.mark.asyncio
async def test_declared_product_entry_in_test_tree_stays_in_scan_and_poc_manifests(
    tmp_path: Path,
) -> None:
    class DeclaredProductProcess(_Process):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "clone":
                result = await super().run(
                    argv, cwd=cwd, timeout_seconds=timeout_seconds
                )
                root = Path(argv[-1])
                (root / "pyproject.toml").write_text(
                    '[project.scripts]\napp = "tests.app:main"\n', encoding="utf-8"
                )
                (root / "tests").mkdir()
                (root / "tests" / "app.py").write_text(
                    "def main(): pass\n", encoding="utf-8"
                )
                (root / "tests" / "test_app.py").write_text(
                    "def test_app(): pass\n", encoding="utf-8"
                )
                return result
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(
                    0,
                    b"app.py\0requirements.txt\0pyproject.toml\0"
                    b"tests/app.py\0tests/test_app.py\0",
                    b"",
                )
            if argv[1] == "scan":
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {
                                "scanned": ["app.py", "tests/app.py"],
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _without_codeql(_profile(tmp_path))
    identity = _identity("declared-product-in-test-tree")
    result = await DirectStaticBootstrap(
        profile=profile,
        process=DeclaredProductProcess(),
        store=_store(profile),
        static_material_root=tmp_path,
    ).run(_request(profile), identity)
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    bundle = json.loads(artifacts.read(result.static_bundle_ref))
    source_ref = StoredDataRef.model_validate(bundle["source_manifest_ref"])
    poc_ref = StoredDataRef.model_validate(bundle["poc_source_manifest_ref"])
    source = json.loads(artifacts.read(source_ref))
    poc = json.loads(artifacts.read(poc_ref))
    assert "tests/app.py" in source["paths"]
    assert "tests/app.py" in poc["paths"]
    assert "tests/test_app.py" not in source["paths"]
    assert "tests/test_app.py" not in poc["paths"]


@pytest.mark.asyncio
async def test_test_only_checkout_cannot_succeed_with_zero_product_pairs(
    tmp_path: Path,
) -> None:
    class TestOnlyProcess(_Process):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "clone":
                root = Path(argv[-1])
                (root / "tests").mkdir(parents=True)
                (root / "README.md").write_text("Test fixture\n", encoding="utf-8")
                (root / "tests" / "test_app.py").write_text(
                    "def test_app(): pass\n", encoding="utf-8"
                )
                return ProcessResult(0, b"", b"")
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"README.md\0tests/test_app.py\0", b"")
            if argv[1] == "scan":
                pytest.fail("test-only checkout must not launch a scanner")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _without_codeql(_profile(tmp_path))
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=TestOnlyProcess(),
        store=_store(profile),
        static_material_root=tmp_path,
    )
    with pytest.raises(StaticCoverageBlocked, match="NO_PYTHON_SOURCE"):
        await bootstrap.run(_request(profile), _identity("test-only-checkout"))


@pytest.mark.asyncio
async def test_non_python_product_file_is_outside_python_coverage(
    tmp_path: Path,
) -> None:
    class MixedProductProcess(_Process):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "clone":
                result = await super().run(
                    argv, cwd=cwd, timeout_seconds=timeout_seconds
                )
                (Path(argv[-1]) / "main.go").write_text(
                    "package main\nfunc main() {}\n", encoding="utf-8"
                )
                return result
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py\0main.go\0", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _without_codeql(_profile(tmp_path))
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=MixedProductProcess(),
        store=_store(profile),
        static_material_root=tmp_path,
    )
    identity = _identity("unsupported-product")
    result = await bootstrap.run(_request(profile), identity)
    assert result.static_disposition == "PARTIAL"
    coverage = _coverage_from_ref(profile, identity, result.static_coverage_ref)
    assert coverage["verified_count"] == coverage["expected_count"] == 1
    assert coverage["unsupported_files"] == []
    assert coverage["out_of_scope_product_files"] == [
        {"path": "main.go", "reason": "non_python_product_source"}
    ]


@pytest.mark.asyncio
async def test_mixed_python_typescript_scope_keeps_out_of_scope_reason(
    tmp_path: Path,
) -> None:
    class MixedProductProcess(_Process):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "clone":
                result = await super().run(
                    argv, cwd=cwd, timeout_seconds=timeout_seconds
                )
                root = Path(argv[-1])
                (root / "ui").mkdir()
                (root / "ui" / "main.ts").write_text(
                    "export const ready = true;\n", encoding="utf-8"
                )
                (root / "ui" / "main.test.ts").write_text(
                    "import { test } from 'vitest';\ntest('ready', () => {});\n",
                    encoding="utf-8",
                )
                return result
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py\0ui/main.ts\0ui/main.test.ts\0", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _without_codeql(_profile(tmp_path))
    identity = _identity("mixed-python-typescript-scope")
    result = await DirectStaticBootstrap(
        profile=profile,
        process=MixedProductProcess(),
        store=_store(profile),
        static_material_root=tmp_path,
    ).run(_request(profile), identity)

    coverage = _coverage_from_ref(profile, identity, result.static_coverage_ref)
    assert result.static_disposition == "PARTIAL"
    assert coverage["out_of_scope_product_files"] == [
        {"path": "ui/main.ts", "reason": "non_python_product_source"}
    ]
    assert coverage["excluded_test_files"] == [
        {
            "path": "ui/main.test.ts",
            "reason": "test-basename+content:javascript-typescript",
        }
    ]


def _profile(tmp_path: Path) -> SimpleExecutionProfile:
    _write_rules(tmp_path, ("python.sql",))
    executable = tmp_path / "tool"
    executable.write_bytes(b"tool")
    binding = SimpleToolBinding(
        executable_path=executable,
        version="1.0",
        executable_sha256=hashlib.sha256(b"tool").hexdigest(),
    )
    return SimpleExecutionProfile(
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
        tools={"git": binding, "opengrep": binding, "codeql": binding},
    )


def _write_rules(root: Path, rule_ids: Sequence[str]) -> None:
    rules = root / "opengrep" / "rules.yml"
    rules.parent.mkdir(parents=True, exist_ok=True)
    rules.write_text(
        "rules:\n"
        + "".join(
            f"  - id: {rule_id}\n"
            "    languages: [python]\n"
            "    message: test\n"
            "    severity: INFO\n"
            "    pattern: db.execute(...)\n"
            for rule_id in rule_ids
        ),
        encoding="utf-8",
    )


def _identity(analysis_id: str = "analysis-1") -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id=analysis_id,
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )


def _request(profile: SimpleExecutionProfile) -> SimpleAnalysisRequest:
    return SimpleAnalysisRequest(
        data_dir=profile.data_dir,
        repository="https://example.invalid/repo.git",
        commit="a" * 40,
    )


def _store(profile: SimpleExecutionProfile) -> SimpleCheckpointStore:
    return SimpleCheckpointStore(profile.data_dir / "db" / "sastsimi.sqlite3")


def _ready_workspace(tmp_path: Path, request: SimpleAnalysisRequest) -> Path:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("db.execute(user)\n", encoding="utf-8")
    (workspace / ".sastsimi-ready.json").write_text(
        json.dumps({"repository": request.repository, "commit": request.commit}),
        encoding="utf-8",
    )
    return workspace


def _without_codeql(profile: SimpleExecutionProfile) -> SimpleExecutionProfile:
    return profile.model_copy(
        update={
            "tools": {
                name: tool for name, tool in profile.tools.items() if name != "codeql"
            }
        }
    )


class _BatchProcess(_Process):
    def __init__(
        self, rule_ids: Sequence[str], *, fail_second_once: bool = False
    ) -> None:
        self.rule_ids = tuple(rule_ids)
        self.fail_second_once = fail_second_once
        self.failed = False
        self.scans: list[tuple[tuple[str, ...], Path | None, int]] = []

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: int,
    ) -> ProcessResult:
        if argv[1] != "scan":
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)
        self.scans.append((tuple(argv), cwd, timeout_seconds))
        if self.fail_second_once and len(self.scans) == 2 and not self.failed:
            self.failed = True
            raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
        excluded = {
            argv[index + 1]
            for index, value in enumerate(argv[:-1])
            if value == "--exclude-rule"
        }
        output = Path(argv[argv.index("--output") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": rule_id,
                            "path": str(Path(cwd or argv[-1]) / "app.py"),
                            "start": {"line": 2},
                        }
                        for rule_id in self.rule_ids
                        if rule_id not in excluded
                    ],
                    "errors": [],
                    "paths": {"scanned": ["app.py"], "skipped": []},
                }
            ),
            encoding="utf-8",
        )
        return ProcessResult(0, b"", b"")


@pytest.mark.asyncio
async def test_all_batches_use_original_config_and_product_target(
    tmp_path: Path,
) -> None:
    profile = _without_codeql(_profile(tmp_path))
    rule_ids = tuple(f"python.rule{index}" for index in range(7))
    _write_rules(tmp_path, rule_ids)
    process = _BatchProcess(rule_ids)
    identity = _identity()
    result = await DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    ).run(_request(profile), identity)

    assert len(process.scans) == 3
    assert len({argv[argv.index("--output") + 1] for argv, _, _ in process.scans}) == 3
    expected_batches = (rule_ids[:3], rule_ids[3:6], rule_ids[6:])
    for (argv, cwd, _timeout), selected in zip(
        process.scans, expected_batches, strict=True
    ):
        assert argv[argv.index("--config") + 1] == str(
            tmp_path / "opengrep" / "rules.yml"
        )
        assert argv[-1] == "app.py"
        assert cwd == profile.workspace_root / identity.workspace_id
        assert "--no-rewrite-rule-ids" in argv
        excluded = {
            argv[index + 1]
            for index, value in enumerate(argv[:-1])
            if value == "--exclude-rule"
        }
        assert excluded == set(rule_ids) - set(selected)

    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    bundle = json.loads(artifacts.read(result.static_bundle_ref))
    aggregate = json.loads(
        artifacts.read(StoredDataRef.model_validate(bundle["tool_result_refs"][1]))
    )
    assert {item["check_id"] for item in aggregate["results"]} == set(rule_ids)
    assert len(aggregate["batches"]) == 3


@pytest.mark.asyncio
async def test_timeout_resume_reuses_first_batch(tmp_path: Path) -> None:
    profile = _without_codeql(_profile(tmp_path))
    rule_ids = tuple(f"python.rule{index}" for index in range(4))
    _write_rules(tmp_path, rule_ids)
    process = _BatchProcess(rule_ids, fail_second_once=True)
    store = _store(profile)
    identity = _identity("analysis-timeout")
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=store,
        static_material_root=tmp_path,
    )
    first = await bootstrap.run(_request(profile), identity)
    assert first.static_disposition == "PARTIAL"
    coverage = _coverage_from_ref(profile, identity, first.static_coverage_ref)
    assert 0 < coverage["verified_count"] < coverage["expected_count"]
    attempts = store.list_static_scan_attempts(
        identity, _request(profile).repository, coverage["fingerprint"]
    )
    assert len(attempts) == 2
    assert (
        sum(
            item.status == "SUCCEEDED" and item.raw_ref is not None for item in attempts
        )
        == 1
    )
    assert sum(item.error_code == "EXTERNAL_TOOL_TIMEOUT" for item in attempts) == 1

    result = await bootstrap.run(_request(profile), identity)
    assert result.static_bundle_ref is not None
    assert len(process.scans) == 3
    first_output = process.scans[0][0][process.scans[0][0].index("--output") + 1]
    assert (
        sum(
            argv[argv.index("--output") + 1] == first_output
            for argv, _, _ in process.scans
        )
        == 1
    )


@pytest.mark.asyncio
async def test_legacy_pass_deadline_does_not_stop_later_batches(tmp_path: Path) -> None:
    profile = _without_codeql(_profile(tmp_path)).model_copy(
        update={"max_elapsed_seconds": "unlimited", "static_scan_pass_seconds": 1}
    )
    rule_ids = tuple(f"python.rule{index}" for index in range(4))
    _write_rules(tmp_path, rule_ids)
    process = _BatchProcess(rule_ids)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )

    result = await bootstrap.run(_request(profile), _identity("analysis-deadline"))
    assert result.static_disposition == "FULL"
    assert len(process.scans) == 2
    assert [timeout for _argv, _cwd, timeout in process.scans] == [120, 120]


@pytest.mark.asyncio
async def test_opengrep_rejects_changed_workspace_before_cache_use(
    tmp_path: Path,
) -> None:
    class DirtyProcess(_BatchProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1:3] == ("status", "--porcelain=v1"):
                return ProcessResult(0, b" M app.py\0", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _without_codeql(_profile(tmp_path))
    process = DirtyProcess(("python.sql",))
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )

    with pytest.raises(RuntimeError, match="^WORKSPACE_DIRTY$"):
        await bootstrap.run(_request(profile), _identity("analysis-dirty"))
    assert process.scans == []


@pytest.mark.asyncio
async def test_opengrep_rejects_changed_executable_before_cache_use(
    tmp_path: Path,
) -> None:
    profile = _without_codeql(_profile(tmp_path))
    process = _BatchProcess(("python.sql",))
    identity = _identity("analysis-tool-change")
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )
    await bootstrap.run(_request(profile), identity)
    profile.tools["opengrep"].executable_path.write_bytes(b"changed tool")

    with pytest.raises(RuntimeError, match="^OPENGREP_TOOL_CHANGED$"):
        await bootstrap.run(_request(profile), identity)
    assert len(process.scans) == 1


@pytest.mark.asyncio
async def test_opengrep_rejects_ignored_scanner_control_before_cache_use(
    tmp_path: Path,
) -> None:
    class IgnoredControlProcess(_BatchProcess):
        ignored = False

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1:4] == ("ls-files", "--others", "--ignored"):
                return ProcessResult(
                    0, b".semgrepignore\0" if self.ignored else b"", b""
                )
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _without_codeql(_profile(tmp_path))
    process = IgnoredControlProcess(("python.sql",))
    identity = _identity("analysis-ignore-change")
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )
    await bootstrap.run(_request(profile), identity)
    process.ignored = True

    with pytest.raises(RuntimeError, match="^WORKSPACE_DIRTY$"):
        await bootstrap.run(_request(profile), identity)
    assert len(process.scans) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["delete", "corrupt"])
async def test_corrupt_cache_reexecutes_only_that_batch(
    tmp_path: Path, damage: str
) -> None:
    profile = _without_codeql(_profile(tmp_path))
    rule_ids = tuple(f"python.rule{index}" for index in range(4))
    _write_rules(tmp_path, rule_ids)
    process = _BatchProcess(rule_ids)
    store = _store(profile)
    identity = _identity("analysis-corrupt")
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=store,
        static_material_root=tmp_path,
    )
    first = await bootstrap.run(_request(profile), identity)
    first_bundle = _coverage_from_ref(profile, identity, first.static_bundle_ref)
    first_coverage = _coverage_from_ref(
        profile,
        identity,
        StoredDataRef.model_validate(first_bundle["static_coverage_ref"]),
    )
    attempts = store.list_static_scan_attempts(
        identity, _request(profile).repository, first_coverage["fingerprint"]
    )
    first_attempt = next(item for item in attempts if item.tool == "opengrep")
    ref = first_attempt.raw_ref
    assert ref is not None
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    path = artifacts.artifacts.path_for(ref.content_hash)
    if damage == "delete":
        path.unlink()
    else:
        path.write_bytes(b"corrupt")

    await bootstrap.run(_request(profile), identity)

    assert len(process.scans) == 3
    replayed = store.list_static_scan_attempts(
        identity, _request(profile).repository, first_coverage["fingerprint"]
    )
    replayed_attempt = next(
        item for item in replayed if item.run_key == first_attempt.run_key
    )
    assert replayed_attempt.raw_ref is not None
    assert json.loads(artifacts.read(replayed_attempt.raw_ref))["errors"] == []


@pytest.mark.asyncio
async def test_clone_disables_host_autocrlf_for_container_workspaces(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path)
    process = _RecordingProcess()
    identity = CheckpointIdentity(
        analysis_id="analysis-line-endings",
        workspace_id="workspace-line-endings",
        commit_id="a" * 40,
        hypothesis_id=None,
    )

    await DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    ).run(
        SimpleAnalysisRequest(
            data_dir=profile.data_dir,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        ),
        identity,
    )

    clone = next(command for command in process.commands if command[1] == "clone")
    assert clone[1:-2] == (
        "clone",
        "--no-checkout",
        "--config",
        "core.autocrlf=false",
        "--",
    )


@pytest.mark.asyncio
async def test_checkout_enables_git_long_paths_for_windows_repositories(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path)
    process = _RecordingProcess()
    request = _request(profile)
    workspace = tmp_path / "long-path-checkout"
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )

    await bootstrap._prepare_repository(request, workspace)

    checkout = next(command for command in process.commands if "checkout" in command)
    assert checkout[1:] == (
        "-c",
        "core.longpaths=true",
        "checkout",
        "--detach",
        "a" * 40,
    )
    assert (workspace / ".sastsimi-ready.json").is_file()


class _Client:
    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
        owner: AttemptOwner | None = None,
        prompt_bytes: PromptByteCounts | None = None,
        invocation_id: str | None = None,
    ) -> SimpleLLMCallResult:
        del prompt, output_schema, timeout_ms, agent_name, owner, prompt_bytes
        del invocation_id
        return SimpleLLMCallResult(
            value={
                "hypotheses": [
                    {
                        "title": "SQL injection",
                        "vulnerability_type": "SQLI",
                        "summary": "user reaches query",
                        "code_locations": ["app.py:2"],
                        "source": "user",
                        "sink": "db.execute",
                        "rationale": "no sanitizer",
                    }
                ]
            },
            prompt_digest="prompt",
            output_digest="output",
        )


@pytest.mark.asyncio
async def test_real_static_tools_feed_exact_hypothesis_input(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    result = await DirectStaticBootstrap(
        profile=profile,
        process=_Process(),
        store=_store(profile),
        static_material_root=tmp_path,
    ).run(
        SimpleAnalysisRequest(
            data_dir=profile.data_dir,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        ),
        identity,
    )
    bundle = json.loads(
        SimpleArtifactRepository(profile.data_dir, identity).read(
            result.static_bundle_ref
        )
    )

    assert bundle["opengrep_findings"][0]["path"] == "app.py"
    assert bundle["codeql_findings"][0]["rule_id"] == "py/sql-injection"
    manifest = json.loads(
        SimpleArtifactRepository(profile.data_dir, identity).read(
            StoredDataRef.model_validate(bundle["source_manifest_ref"])
        )
    )
    assert manifest["paths"] == ["app.py"]
    poc_manifest = json.loads(
        SimpleArtifactRepository(profile.data_dir, identity).read(
            StoredDataRef.model_validate(bundle["poc_source_manifest_ref"])
        )
    )
    assert poc_manifest["paths"] == ["app.py", "requirements.txt"]

    seeds = await DirectHypothesisBootstrap(
        data_dir=profile.data_dir,
        client_factory=lambda _identity, _artifacts: _Client(),
    ).propose(identity, result)

    assert not isinstance(seeds, StageFailure)
    assert len(seeds) == 1
    assert seeds[0].hypothesis_id.startswith("hypothesis-")


@pytest.mark.asyncio
async def test_codeql_database_create_sees_only_selected_product_source(
    tmp_path: Path,
) -> None:
    class ProductScopeProcess(_Process):
        def __init__(self) -> None:
            self.created_paths: tuple[str, ...] | None = None
            self.codeql_timeouts: list[int] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py\0tests/test_app.py\0", b"")
            if argv[1:3] == ("database", "create"):
                self.codeql_timeouts.append(timeout_seconds)
                source_arg = next(
                    value for value in argv if value.startswith("--source-root=")
                )
                source = Path(source_arg.partition("=")[2])
                self.created_paths = tuple(
                    path.relative_to(source).as_posix()
                    for path in sorted(source.rglob("*"))
                    if path.is_file()
                )
            if argv[1:3] == ("database", "analyze"):
                self.codeql_timeouts.append(timeout_seconds)
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _profile(tmp_path).model_copy(
        update={"max_elapsed_seconds": "unlimited", "static_scan_pass_seconds": 1}
    )
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('app')\n", encoding="utf-8")
    (workspace / "tests").mkdir()
    (workspace / "tests" / "test_app.py").write_text(
        "def test_app():\n    assert True\n", encoding="utf-8"
    )
    (workspace / ".sastsimi-ready.json").write_text(
        json.dumps(
            {
                "repository": "https://example.invalid/project.git",
                "commit": "a" * 40,
            }
        ),
        encoding="utf-8",
    )
    process = ProductScopeProcess()
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )

    await bootstrap._run_codeql(
        workspace,
        profile.data_dir,
        "https://example.invalid/project.git",
        "a" * 40,
        "product-only",
    )

    assert process.created_paths == ("app.py",)
    assert process.codeql_timeouts == [1800, 1800]


@pytest.mark.asyncio
async def test_codeql_create_and_analyze_bound_memory_with_one_thread(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path)
    request = _request(profile)
    workspace = _ready_workspace(tmp_path, request)
    process = _RecordingProcess()
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )

    await bootstrap._run_codeql(
        workspace,
        profile.data_dir,
        request.repository,
        request.commit,
        "bounded-codeql",
    )

    codeql_commands = [
        command
        for command in process.commands
        if command[1:3] in {("database", "create"), ("database", "analyze")}
    ]
    assert [command[1:3] for command in codeql_commands] == [
        ("database", "create"),
        ("database", "analyze"),
    ]
    for command in codeql_commands:
        assert [
            argument
            for argument in command
            if argument.startswith(("--threads=", "--ram="))
        ] == ["--threads=1", "--ram=2048"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dataset_present", "first_analyze_fails"),
    [(False, False), (True, False), (False, True)],
)
async def test_codeql_rebuilds_incomplete_cached_database_without_overwriting_it(
    tmp_path: Path, dataset_present: bool, first_analyze_fails: bool
) -> None:
    class IncompleteDatabaseProcess(_Process):
        def __init__(self, incomplete: Path, fail_first_analyze: bool) -> None:
            self.incomplete = incomplete
            self.fail_first_analyze = fail_first_analyze
            self.created: list[Path] = []
            self.analyzed: list[Path] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py\0", b"")
            if argv[1:3] == ("resolve", "database"):
                database = Path(argv[-1])
                return ProcessResult(
                    0,
                    json.dumps({"datasetFolder": str(database / "db-python")}).encode(),
                    b"",
                )
            if argv[1:3] == ("database", "create"):
                database = Path(argv[3])
                self.created.append(database)
                result = await super().run(
                    argv, cwd=cwd, timeout_seconds=timeout_seconds
                )
                (database / "db-python").mkdir()
                return result
            if argv[1:3] == ("database", "analyze"):
                database = Path(argv[3])
                self.analyzed.append(database)
                if database == self.incomplete:
                    return ProcessResult(2, b"", b"database needs to be finalized")
                if self.fail_first_analyze and len(self.analyzed) == 1:
                    return ProcessResult(2, b"", b"query failed")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _profile(tmp_path)
    repository = "https://example.invalid/project.git"
    commit = "a" * 40
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('app')\n", encoding="utf-8")
    (workspace / ".sastsimi-ready.json").write_text(
        json.dumps({"repository": repository, "commit": commit}), encoding="utf-8"
    )
    scope = build_static_file_scope(workspace, ("app.py",))
    key = hashlib.sha256(
        f"{repository}\0{commit}\0{scope.fingerprint}".encode()
    ).hexdigest()[:24]
    incomplete = profile.data_dir / "codeql" / key / "database"
    incomplete.mkdir(parents=True)
    (incomplete / "codeql-database.yml").write_text("ok", encoding="utf-8")
    (incomplete / "working").mkdir()
    if dataset_present:
        (incomplete / "db-python").mkdir()
    process = IncompleteDatabaseProcess(incomplete, first_analyze_fails)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )

    if first_analyze_fails:
        with pytest.raises(RuntimeError, match="^CODEQL_ANALYZE_FAILED$"):
            await bootstrap._run_codeql(
                workspace, profile.data_dir, repository, commit, "retry-incomplete"
            )
    raw = await bootstrap._run_codeql(
        workspace, profile.data_dir, repository, commit, "retry-incomplete"
    )

    assert json.loads(raw)["runs"]
    assert (incomplete / "working").is_dir()
    assert (incomplete / "codeql-database.yml").is_file()
    assert len(process.created) == 1
    assert process.created[0] != incomplete
    assert process.analyzed == process.created * (2 if first_analyze_fails else 1)


@pytest.mark.asyncio
async def test_codeql_rejects_sarif_finding_outside_selected_product_scope(
    tmp_path: Path,
) -> None:
    class OutOfScopeProcess(_Process):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py\0tests/test_app.py\0", b"")
            if argv[1:3] == ("database", "analyze"):
                argument = next(
                    value for value in argv if value.startswith("--output=")
                )
                Path(argument.partition("=")[2]).write_text(
                    json.dumps(
                        {
                            "runs": [
                                {
                                    "results": [
                                        {
                                            "locations": [
                                                {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": "tests/test_app.py"
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    profile = _profile(tmp_path)
    repository = "https://example.invalid/project.git"
    commit = "a" * 40
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('app')\n", encoding="utf-8")
    (workspace / "tests").mkdir()
    (workspace / "tests" / "test_app.py").write_text(
        "def test_app():\n    assert True\n", encoding="utf-8"
    )
    (workspace / ".sastsimi-ready.json").write_text(
        json.dumps({"repository": repository, "commit": commit}), encoding="utf-8"
    )
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=OutOfScopeProcess(),
        store=_store(profile),
        static_material_root=tmp_path,
    )

    with pytest.raises(RuntimeError, match="^CODEQL_SOURCE_SCOPE_INVALID$"):
        await bootstrap._run_codeql(
            workspace, profile.data_dir, repository, commit, "out-of-scope"
        )


@pytest.mark.asyncio
async def test_codeql_retry_rejects_stale_sarif(tmp_path: Path) -> None:
    class NoOutputProcess:
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            del cwd, timeout_seconds
            if argv[1:3] == ("rev-parse", "HEAD"):
                return ProcessResult(0, ("a" * 40).encode(), b"")
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py\0", b"")
            return ProcessResult(0, b"", b"")

    profile = _profile(tmp_path)
    repository = "https://example.invalid/project.git"
    commit = "a" * 40
    analysis_id = "analysis-retry"
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('app')\n", encoding="utf-8")
    (workspace / ".sastsimi-ready.json").write_text(
        json.dumps({"repository": repository, "commit": commit}), encoding="utf-8"
    )
    scope = build_static_file_scope(workspace, ("app.py",))
    key = hashlib.sha256(
        f"{repository}\0{commit}\0{scope.fingerprint}".encode()
    ).hexdigest()[:24]
    analysis_key = hashlib.sha256(analysis_id.encode()).hexdigest()[:24]
    root = profile.data_dir / "codeql" / key
    database = root / "database"
    database.mkdir(parents=True)
    (database / "codeql-database.yml").write_text("ok", encoding="utf-8")
    output = root / f"results-{analysis_key}.sarif"
    output.write_text('{"runs":[{"stale":true}]}', encoding="utf-8")
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=NoOutputProcess(),
        store=_store(profile),
        static_material_root=tmp_path,
    )

    with pytest.raises(RuntimeError, match="^CODEQL_ANALYZE_FAILED$"):
        await bootstrap._run_codeql(
            workspace,
            profile.data_dir,
            repository,
            commit,
            analysis_id,
        )

    assert not output.exists()


@pytest.mark.asyncio
async def test_codeql_output_has_finite_size_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _profile(tmp_path)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=_Process(),
        store=_store(profile),
        static_material_root=tmp_path,
    )
    monkeypatch.setattr(static_module, "_MAX_STATIC_SCAN_OUTPUT_BYTES", 32)
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('app')\n", encoding="utf-8")
    (workspace / "requirements.txt").write_text("", encoding="utf-8")
    (workspace / ".sastsimi-ready.json").write_text(
        json.dumps(
            {
                "repository": "https://example.invalid/project.git",
                "commit": "a" * 40,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="^STATIC_SCAN_OUTPUT_TOO_LARGE$"):
        await bootstrap._run_codeql(
            workspace,
            profile.data_dir,
            "https://example.invalid/project.git",
            "a" * 40,
            "oversized-codeql",
        )


@pytest.mark.asyncio
async def test_codeql_sarif_is_analysis_scoped(tmp_path: Path) -> None:
    class OutputProcess:
        def __init__(self) -> None:
            self.outputs: list[Path] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            del cwd, timeout_seconds
            if argv[1:3] == ("rev-parse", "HEAD"):
                return ProcessResult(0, ("a" * 40).encode(), b"")
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"app.py\0", b"")
            if argv[1:3] == ("database", "analyze"):
                argument = next(
                    value for value in argv if value.startswith("--output=")
                )
                output = Path(argument.partition("=")[2])
                output.write_text('{"runs":[]}', encoding="utf-8")
                self.outputs.append(output)
            return ProcessResult(0, b"", b"")

    profile = _profile(tmp_path)
    repository = "https://example.invalid/project.git"
    commit = "a" * 40
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('app')\n", encoding="utf-8")
    (workspace / ".sastsimi-ready.json").write_text(
        json.dumps({"repository": repository, "commit": commit}), encoding="utf-8"
    )
    scope = build_static_file_scope(workspace, ("app.py",))
    key = hashlib.sha256(
        f"{repository}\0{commit}\0{scope.fingerprint}".encode()
    ).hexdigest()[:24]
    database = profile.data_dir / "codeql" / key / "database"
    database.mkdir(parents=True)
    (database / "codeql-database.yml").write_text("ok", encoding="utf-8")
    process = OutputProcess()
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )

    await bootstrap._run_codeql(
        workspace, profile.data_dir, repository, commit, "analysis-one"
    )
    await bootstrap._run_codeql(
        workspace, profile.data_dir, repository, commit, "analysis-two"
    )

    assert len(process.outputs) == 2
    assert process.outputs[0] != process.outputs[1]
    assert all(path.is_file() for path in process.outputs)


class _CoverageProcess(_Process):
    """Small checkout with one parser-warning file and one clean file."""

    def __init__(
        self,
        *,
        fallback_fails: bool = False,
        codeql_fails: bool = False,
        parse_warning: bool = True,
        invalid_python: bool = False,
    ) -> None:
        self.fallback_fails = fallback_fails
        self.codeql_fails = codeql_fails
        self.parse_warning = parse_warning
        self.invalid_python = invalid_python
        self.opengrep_calls = 0
        self.fallback_calls: list[tuple[str, ...]] = []
        self.codeql_calls = 0
        self._query_root: Path | None = None

    async def run(
        self, argv: Sequence[str], *, cwd: Path | None = None, timeout_seconds: int
    ) -> ProcessResult:
        if argv[1:3] == ("resolve", "queries"):
            root = Path(argv[-1]).parent
            self._query_root = root
            if not (root / "qlpack.yml").is_file():
                return ProcessResult(2, b"", b"missing qlpack")
            return ProcessResult(
                0, json.dumps([str(root / "security.ql")]).encode(), b""
            )
        if argv[1:3] == ("resolve", "packs"):
            assert self._query_root is not None
            root = self._query_root
            if not (root / "qlpack.yml").is_file():
                return ProcessResult(2, b"", b"missing qlpack")
            import yaml  # type: ignore[import-untyped]

            manifest = yaml.safe_load((root / "qlpack.yml").read_text(encoding="utf-8"))
            pack = {"version": manifest["version"], "path": str(root / "qlpack.yml")}
            listing = {"steps": [{"found": {manifest["name"]: pack}}]}
            return ProcessResult(0, json.dumps(listing).encode(), b"")
        if argv[1] == "clone":
            root = Path(argv[-1])
            root.mkdir(parents=True)
            (root / "app.py").write_text(
                "def broken(:\n"
                if self.invalid_python
                else "def query(user):\n    return db.execute(user)\n",
                encoding="utf-8",
            )
            (root / "good.py").write_text(
                "def good():\n    return 1\n", encoding="utf-8"
            )
            return ProcessResult(0, b"", b"")
        if argv[1:3] == ("ls-files", "-z"):
            return ProcessResult(0, b"app.py\0good.py\0", b"")
        if argv[1] == "scan" and "--metrics=off" in argv:
            self.fallback_calls.append(tuple(argv))
            output = Path(argv[argv.index("--output") + 1])
            if self.fallback_fails:
                output.write_bytes(b"bad")
                return ProcessResult(2, b"bad", b"failed")
            output.write_bytes(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "python.sql",
                                "path": "app.py",
                                "start": {"line": 1},
                            }
                        ],
                        "errors": [],
                        "paths": {"scanned": ["app.py"], "skipped": []},
                    }
                ).encode()
            )
            return ProcessResult(0, b"", b"")
        if argv[1] == "scan":
            self.opengrep_calls += 1
            targets = tuple(path for path in ("app.py", "good.py") if path in argv)
            assert targets
            output = Path(argv[argv.index("--output") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "python.sql",
                                "path": path,
                                "start": {"line": 1},
                            }
                            for path in targets
                        ],
                        "errors": (
                            [{"type": "PartialParsing", "path": "app.py"}]
                            if self.parse_warning and "app.py" in targets
                            else []
                        ),
                        "paths": {"scanned": list(targets), "skipped": []},
                    }
                ),
                encoding="utf-8",
            )
            return ProcessResult(0, b"", b"")
        if argv[1:3] == ("database", "analyze"):
            self.codeql_calls += 1
            if self.codeql_fails:
                return ProcessResult(2, b"", b"failed")
        return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)


@pytest.mark.asyncio
async def test_candidate_limit_blocks_without_discarding_ast_and_codeql(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap, profile, _store = _coverage_bootstrap(
        tmp_path, _CoverageProcess(parse_warning=False), codeql=True
    )
    monkeypatch.setattr(
        static_module,
        "StaticCandidateBudget",
        lambda: StaticCandidateBudget(max_results=1),
        raising=False,
    )
    identity = _identity("candidate-memory-cap")

    with pytest.raises(
        StaticCoverageBlocked, match="STATIC_CANDIDATES_TOO_LARGE"
    ) as blocked:
        await bootstrap.run(_request(profile), identity)

    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    bundle = json.loads(artifacts.read(blocked.value.bundle_ref))
    coverage = json.loads(
        artifacts.read(StoredDataRef.model_validate(bundle["static_coverage_ref"]))
    )
    assert bundle["ast_summary"]["kind"] == "simple_python_ast"
    assert bundle["ast_summary"]["fact_count"] > 0
    assert bundle["ast_summary"]["manifest_ref"]
    assert bundle["codeql_executed"] is True
    assert bundle["codeql_findings"]
    assert "STATIC_CANDIDATES_TOO_LARGE" in coverage["engine_errors"]
    assert coverage["verified_count"] < coverage["expected_count"]


class _AdaptiveSemgrepProcess:
    def __init__(self, response: object | None = None) -> None:
        self.response = response
        self.calls: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
        self.timeouts: list[int] = []

    async def run(
        self, argv: Sequence[str], *, cwd: Path | None = None, timeout_seconds: int
    ) -> ProcessResult:
        del cwd
        command = tuple(argv)
        targets = tuple(arg for arg in command if arg.startswith("file-"))
        self.calls.append((targets, command))
        self.timeouts.append(timeout_seconds)
        if callable(self.response):
            response = self.response(targets, command)
        else:
            response = None
        if isinstance(response, BaseException):
            raise response
        if response is None:
            response = {
                "results": [],
                "errors": [],
                "paths": {"scanned": list(targets), "skipped": []},
            }
        Path(command[command.index("--output") + 1]).write_bytes(
            json.dumps(response).encode()
        )
        return ProcessResult(0, b"", b"")


def _adaptive_semgrep_fixture(
    tmp_path: Path,
    process: _AdaptiveSemgrepProcess,
    count: int = 129,
    rule_ids: tuple[str, ...] = ("python.sql",),
) -> tuple[
    DirectStaticBootstrap,
    SimpleExecutionProfile,
    CheckpointIdentity,
    RuleBatchPlan,
    StaticCoveragePlan,
    Path,
    Path,
]:
    profile = _profile(tmp_path)
    profile = profile.model_copy(
        update={
            "semgrep_fallback": True,
            "tools": {**profile.tools, "semgrep": profile.tools["opengrep"]},
        }
    )
    identity = _identity("adaptive-semgrep")
    workspace = profile.workspace_root / identity.workspace_id
    workspace.mkdir(parents=True)
    files = [f"file-{index:03d}.py" for index in range(count)]
    for name in files:
        (workspace / name).write_text("x = 1\n", encoding="utf-8")
    _write_rules(tmp_path, rule_ids)
    rules = tmp_path / "opengrep" / "rules.yml"
    binding = profile.tools["opengrep"]
    batches = plan_rule_batches(
        rules.read_bytes(),
        tool_version=binding.version,
        executable_sha256=binding.executable_sha256,
    )
    coverage = plan_static_coverage(workspace, files, identity.commit_id, batches)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )
    return bootstrap, profile, identity, batches, coverage, workspace, rules


async def _run_adaptive_semgrep(
    fixture: tuple[
        DirectStaticBootstrap,
        SimpleExecutionProfile,
        CheckpointIdentity,
        RuleBatchPlan,
        StaticCoveragePlan,
        Path,
        Path,
    ],
) -> tuple[list[CoverageSlice], list[StoredDataRef], list[str]]:
    bootstrap, profile, identity, batches, coverage, workspace, rules = fixture
    return await bootstrap._collect_semgrep(
        workspace,
        _request(profile),
        identity,
        batches,
        coverage,
        [],
        rules,
        SimpleArtifactRepository(profile.data_dir, identity),
    )


@pytest.mark.asyncio
async def test_adaptive_semgrep_uses_128_target_roots_and_replays_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified_targets = [0]
    original_verify = semgrep_module._verified_target

    def counting_verify(workspace: Path, raw: str) -> str:
        verified_targets[0] += 1
        return original_verify(workspace, raw)

    monkeypatch.setattr(semgrep_module, "_verified_target", counting_verify)
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process)
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == []
    assert tuple(len(targets) for targets, _ in process.calls) == (128, 1)
    assert all(
        len(subprocess.list2cmdline(command).encode("utf-16-le")) // 2 <= 24_000
        for _, command in process.calls
    )
    assert finish_coverage(fixture[4], slices).verified_count == 129
    resumed, _refs, resumed_errors = await _run_adaptive_semgrep(fixture)
    assert resumed_errors == []
    assert len(process.calls) == 2
    assert finish_coverage(fixture[4], resumed).verified_count == 129
    assert verified_targets[0] <= 129


@pytest.mark.asyncio
async def test_semgrep_resume_splits_previously_timed_out_parent_without_rerun(
    tmp_path: Path,
) -> None:
    singleton_attempts: dict[str, int] = {}

    def timeout_parent_then_recover_children(
        targets: tuple[str, ...], _command: tuple[str, ...]
    ) -> BaseException | None:
        if len(targets) > 1:
            return TimeoutError()
        target = targets[0]
        singleton_attempts[target] = singleton_attempts.get(target, 0) + 1
        if singleton_attempts[target] == 1:
            return RuntimeError("transient child failure")
        return None

    process = _AdaptiveSemgrepProcess(timeout_parent_then_recover_children)
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=2)
    first, _refs, _errors = await _run_adaptive_semgrep(fixture)
    assert finish_coverage(fixture[4], first).verified_count == 0
    assert {gap.path for gap in finish_coverage(fixture[4], first).gaps} == {
        "file-000.py",
        "file-001.py",
    }
    _, profile, identity, _batches, coverage, _workspace, _rules = fixture
    parent_attempt = next(
        attempt
        for attempt in _store(profile).list_static_scan_attempts(
            identity, _request(profile).repository, coverage.fingerprint
        )
        if attempt.tool == "semgrep" and attempt.error_code == "EXTERNAL_TOOL_TIMEOUT"
    )
    assert parent_attempt.raw_ref is None
    assert tuple(targets for targets, _ in process.calls) == (
        ("file-000.py", "file-001.py"),
        ("file-000.py",),
        ("file-001.py",),
    )

    resumed, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == []
    assert tuple(targets for targets, _ in process.calls[3:]) == (
        ("file-000.py",),
        ("file-001.py",),
    )
    assert len([targets for targets, _ in process.calls if len(targets) == 2]) == 1
    assert finish_coverage(fixture[4], resumed).verified_count == 2
    assert finish_coverage(fixture[4], resumed).gaps == ()


@pytest.mark.asyncio
async def test_semgrep_resume_reuses_proof_after_missing_pair_changes(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process)
    first, _refs, first_errors = await _run_adaptive_semgrep(fixture)
    assert first_errors == []
    assert finish_coverage(fixture[4], first).verified_count == 129
    assert len(process.calls) == 2

    bootstrap, profile, identity, batches, coverage, workspace, rules = fixture
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    store = _store(profile)
    coverage_ref = artifacts.put_json({"kind": "test_coverage_snapshot"})
    for attempt in store.list_static_scan_attempts(
        identity, _request(profile).repository, coverage.fingerprint
    ):
        store.save_static_scan_attempt(
            identity,
            _request(profile).repository,
            coverage.fingerprint,
            attempt.tool,
            attempt.run_key,
            attempt.status,
            attempt.raw_ref,
            coverage_ref,
            attempt.error_code,
        )
    opengrep_proof = CoverageSlice(
        engine="opengrep",
        batch_key=batches.batches[0].key,
        rule_ids=batches.batches[0].rule_ids,
        verified_pairs=frozenset({("file-000.py", "python.sql")}),
        gap_reasons=(),
        parsed={"results": [], "errors": [], "paths": {}},
        normalized_results=(),
    )
    resumed, _refs, errors = await bootstrap._collect_semgrep(
        workspace,
        _request(profile),
        identity,
        batches,
        coverage,
        [opengrep_proof],
        rules,
        artifacts,
    )

    assert errors == []
    assert len(process.calls) == 2
    assert finish_coverage(coverage, [opengrep_proof, *resumed]).verified_count == 129


@pytest.mark.asyncio
async def test_semgrep_resume_does_not_credit_corrupt_saved_raw(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process)
    await _run_adaptive_semgrep(fixture)
    bootstrap, profile, identity, batches, coverage, workspace, rules = fixture
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    attempts = _store(profile).list_static_scan_attempts(
        identity, _request(profile).repository, coverage.fingerprint
    )
    first_chunk = next(
        attempt
        for attempt in attempts
        if attempt.raw_ref is not None
        and len(json.loads(artifacts.read(attempt.raw_ref))["paths"]["scanned"]) == 128
    )
    assert first_chunk.raw_ref is not None
    artifacts.artifacts.path_for(first_chunk.raw_ref.content_hash).write_bytes(
        b"corrupt"
    )
    opengrep_proof = CoverageSlice(
        engine="opengrep",
        batch_key=batches.batches[0].key,
        rule_ids=batches.batches[0].rule_ids,
        verified_pairs=frozenset({("file-000.py", "python.sql")}),
        gap_reasons=(),
        parsed={"results": [], "errors": [], "paths": {}},
        normalized_results=(),
    )

    resumed, _refs, errors = await bootstrap._collect_semgrep(
        workspace,
        _request(profile),
        identity,
        batches,
        coverage,
        [opengrep_proof],
        rules,
        artifacts,
    )

    assert errors == []
    assert len(process.calls) == 3
    assert process.calls[-1][0] == tuple(
        f"file-{index:03d}.py" for index in range(1, 128)
    )
    assert finish_coverage(coverage, [opengrep_proof, *resumed]).verified_count == 129


@pytest.mark.asyncio
async def test_semgrep_resume_ignores_unbound_summary_when_execution_is_valid(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process)
    await _run_adaptive_semgrep(fixture)
    bootstrap, profile, identity, batches, coverage, workspace, rules = fixture
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    store = _store(profile)
    first_chunk = next(
        attempt
        for attempt in store.list_static_scan_attempts(
            identity, _request(profile).repository, coverage.fingerprint
        )
        if attempt.raw_ref is not None
        and len(json.loads(artifacts.read(attempt.raw_ref))["paths"]["scanned"]) == 128
    )
    assert first_chunk.raw_ref is not None
    assert first_chunk.request_ref is not None
    alternate_raw = json.dumps(
        json.loads(artifacts.read(first_chunk.raw_ref)), indent=2
    ).encode()
    alternate_ref = artifacts.put_bytes(alternate_raw, "application/json")
    assert alternate_ref != first_chunk.raw_ref
    store.save_static_scan_attempt(
        identity,
        _request(profile).repository,
        coverage.fingerprint,
        first_chunk.tool,
        first_chunk.run_key,
        first_chunk.status,
        alternate_ref,
        first_chunk.coverage_ref,
        first_chunk.error_code,
        first_chunk.request_ref,
    )
    opengrep_proof = CoverageSlice(
        engine="opengrep",
        batch_key=batches.batches[0].key,
        rule_ids=batches.batches[0].rule_ids,
        verified_pairs=frozenset({("file-000.py", "python.sql")}),
        gap_reasons=(),
        parsed={"results": [], "errors": [], "paths": {}},
        normalized_results=(),
    )
    resumed, refs, errors = await bootstrap._collect_semgrep(
        workspace,
        _request(profile),
        identity,
        batches,
        coverage,
        [opengrep_proof],
        rules,
        artifacts,
    )
    assert errors == []
    assert len(process.calls) == 2
    assert first_chunk.raw_ref in refs
    assert alternate_ref not in refs
    assert finish_coverage(coverage, [opengrep_proof, *resumed]).verified_count == 129


@pytest.mark.asyncio
async def test_semgrep_resume_rejects_mismatched_request_ref(tmp_path: Path) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process)
    await _run_adaptive_semgrep(fixture)
    bootstrap, profile, identity, batches, coverage, workspace, rules = fixture
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    store = _store(profile)
    first_chunk = next(
        attempt
        for attempt in store.list_static_scan_attempts(
            identity, _request(profile).repository, coverage.fingerprint
        )
        if attempt.raw_ref is not None
        and len(json.loads(artifacts.read(attempt.raw_ref))["paths"]["scanned"]) == 128
    )
    assert first_chunk.request_ref is not None
    descriptor = json.loads(artifacts.read(first_chunk.request_ref))
    descriptor["rule_ids"] = ["different.rule"]
    changed_request_ref = artifacts.put_json(descriptor)
    store.save_static_scan_attempt(
        identity,
        _request(profile).repository,
        coverage.fingerprint,
        first_chunk.tool,
        first_chunk.run_key,
        first_chunk.status,
        first_chunk.raw_ref,
        first_chunk.coverage_ref,
        first_chunk.error_code,
        changed_request_ref,
    )
    execution = store.list_static_scan_executions(
        identity,
        _request(profile).repository,
        coverage.fingerprint,
        tool="semgrep",
        run_key=first_chunk.run_key,
    )[0]
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_static_scan_executions SET request_ref_json = ? "
            "WHERE execution_id = ?",
            (changed_request_ref.model_dump_json(), execution.execution_id),
        )
    resumed, _refs, errors = await bootstrap._collect_semgrep(
        workspace,
        _request(profile),
        identity,
        batches,
        coverage,
        [],
        rules,
        artifacts,
    )
    assert errors == []
    assert len(process.calls) == 3
    assert finish_coverage(coverage, resumed).verified_count == 129


@pytest.mark.asyncio
async def test_adaptive_semgrep_replays_legacy_32_target_success(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=97)
    _, profile, identity, batches, coverage, _, _ = fixture
    targets = tuple(f"file-{index:03d}.py" for index in range(32))
    original = batches.batches[0]
    run_key = hashlib.sha256(
        canonical_bytes(
            {"batch": original.key, "rules": original.rule_ids, "targets": targets}
        )
    ).hexdigest()
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    raw = json.dumps(
        {"results": [], "errors": [], "paths": {"scanned": targets, "skipped": []}}
    ).encode()
    ref = artifacts.put_bytes(raw, "application/json")
    _store(profile).save_static_scan_attempt(
        identity,
        _request(profile).repository,
        coverage.fingerprint,
        "semgrep",
        run_key,
        "SUCCEEDED",
        ref,
        None,
        None,
    )
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == []
    assert tuple(len(targets) for targets, _ in process.calls) == (65,)
    assert finish_coverage(coverage, slices).verified_count == 97


@pytest.mark.asyncio
async def test_legacy_semgrep_proof_survives_changed_missing_boundaries(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=97)
    bootstrap, profile, identity, batches, coverage, workspace, rules = fixture
    targets = tuple(f"file-{index:03d}.py" for index in range(32))
    original = batches.batches[0]
    run_key = hashlib.sha256(
        canonical_bytes(
            {"batch": original.key, "rules": original.rule_ids, "targets": targets}
        )
    ).hexdigest()
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    raw = json.dumps(
        {"results": [], "errors": [], "paths": {"scanned": targets, "skipped": []}}
    ).encode()
    _store(profile).save_static_scan_attempt(
        identity,
        _request(profile).repository,
        coverage.fingerprint,
        "semgrep",
        run_key,
        "SUCCEEDED",
        artifacts.put_bytes(raw, "application/json"),
        None,
        None,
    )
    opengrep_proof = CoverageSlice(
        engine="opengrep",
        batch_key=original.key,
        rule_ids=original.rule_ids,
        verified_pairs=frozenset({("file-000.py", "python.sql")}),
        gap_reasons=(),
        parsed={"results": [], "errors": [], "paths": {}},
        normalized_results=(),
    )
    resumed, _refs, errors = await bootstrap._collect_semgrep(
        workspace,
        _request(profile),
        identity,
        batches,
        coverage,
        [opengrep_proof],
        rules,
        artifacts,
    )
    assert errors == []
    assert tuple(len(targets) for targets, _ in process.calls) == (65,)
    assert finish_coverage(coverage, [opengrep_proof, *resumed]).verified_count == 97


@pytest.mark.asyncio
async def test_legacy_semgrep_proof_recovers_unsorted_rule_selection(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(
        tmp_path, process, count=2, rule_ids=("z.rule", "a.rule")
    )
    bootstrap, profile, identity, batches, coverage, workspace, rules = fixture
    targets = ("file-000.py", "file-001.py")
    selected = tuple(sorted(batches.batches[0].rule_ids))
    run_key = hashlib.sha256(
        canonical_bytes(
            {"batch": batches.batches[0].key, "rules": selected, "targets": targets}
        )
    ).hexdigest()
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    raw = json.dumps(
        {"results": [], "errors": [], "paths": {"scanned": targets, "skipped": []}}
    ).encode()
    _store(profile).save_static_scan_attempt(
        identity,
        _request(profile).repository,
        coverage.fingerprint,
        "semgrep",
        run_key,
        "SUCCEEDED",
        artifacts.put_bytes(raw, "application/json"),
        None,
        None,
    )
    opengrep_proof = CoverageSlice(
        engine="opengrep",
        batch_key=batches.batches[0].key,
        rule_ids=batches.batches[0].rule_ids,
        verified_pairs=frozenset(
            {("file-000.py", "z.rule"), ("file-000.py", "a.rule")}
        ),
        gap_reasons=(),
        parsed={"results": [], "errors": [], "paths": {}},
        normalized_results=(),
    )
    slices, _refs, errors = await bootstrap._collect_semgrep(
        workspace,
        _request(profile),
        identity,
        batches,
        coverage,
        [opengrep_proof],
        rules,
        artifacts,
    )
    assert errors == []
    assert process.calls == []
    assert finish_coverage(coverage, [opengrep_proof, *slices]).verified_count == 4


@pytest.mark.asyncio
async def test_legacy_singleton_timeout_proof_survives_changed_chunk(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=2)
    bootstrap, profile, identity, batches, coverage, workspace, rules = fixture
    original = batches.batches[0]
    run_key = hashlib.sha256(
        canonical_bytes(
            {
                "batch": original.key,
                "rules": original.rule_ids,
                "targets": ("file-000.py",),
                "adaptive": 1,
                "per_file_timeout_seconds": 30,
            }
        )
    ).hexdigest()
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    raw = json.dumps(
        {
            "results": [],
            "errors": [],
            "paths": {"scanned": ["file-000.py"], "skipped": []},
        }
    ).encode()
    _store(profile).save_static_scan_attempt(
        identity,
        _request(profile).repository,
        coverage.fingerprint,
        "semgrep",
        run_key,
        "SUCCEEDED",
        artifacts.put_bytes(raw, "application/json"),
        None,
        None,
    )
    slices, _refs, errors = await bootstrap._collect_semgrep(
        workspace,
        _request(profile),
        identity,
        batches,
        coverage,
        [],
        rules,
        artifacts,
    )
    assert errors == []
    assert tuple(targets for targets, _ in process.calls) == (("file-001.py",),)
    assert finish_coverage(coverage, slices).verified_count == 2


@pytest.mark.asyncio
async def test_adaptive_semgrep_splits_only_unverified_pair_and_deduplicates_hit(
    tmp_path: Path,
) -> None:
    hit = {
        "check_id": "python.sql",
        "path": "file-000.py",
        "start": {"line": 1},
    }

    def partial(
        targets: tuple[str, ...], _command: tuple[str, ...]
    ) -> dict[str, object]:
        if len(targets) == 128:
            return {
                "results": [hit],
                "errors": [{"type": "Syntax error", "path": "file-000.py"}],
                "paths": {"scanned": list(targets), "skipped": []},
            }
        return {
            "results": [hit] if "file-000.py" in targets else [],
            "errors": [],
            "paths": {"scanned": list(targets), "skipped": []},
        }

    process = _AdaptiveSemgrepProcess(partial)
    fixture = _adaptive_semgrep_fixture(tmp_path, process)
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == []
    assert tuple(targets for targets, _ in process.calls) == (
        tuple(f"file-{index:03d}.py" for index in range(128)),
        ("file-000.py",),
        ("file-128.py",),
    )
    assert finish_coverage(fixture[4], slices).verified_count == 129
    merged = json.loads(merge_static_candidates(fixture[3], slices))
    assert len(merged["results"]) == 1


@pytest.mark.asyncio
async def test_cached_partial_is_revalidated_without_parent_rerun_or_ref_loss(
    tmp_path: Path,
) -> None:
    def parse_error(
        targets: tuple[str, ...], _command: tuple[str, ...]
    ) -> dict[str, object]:
        return {
            "results": [],
            "errors": (
                [{"type": "Syntax error", "path": "file-000.py"}]
                if "file-000.py" in targets
                else []
            ),
            "paths": {"scanned": list(targets), "skipped": []},
        }

    process = _AdaptiveSemgrepProcess(parse_error)
    fixture = _adaptive_semgrep_fixture(tmp_path, process)
    first, _refs, _errors = await _run_adaptive_semgrep(fixture)
    assert finish_coverage(fixture[4], first).verified_count == 128
    _, profile, identity, batches, coverage, _, _ = fixture
    key = hashlib.sha256(
        canonical_bytes(
            {
                "adaptive": 1,
                "batch": batches.batches[0].key,
                "rules": batches.batches[0].rule_ids,
                "targets": tuple(f"file-{index:03d}.py" for index in range(128)),
            }
        )
    ).hexdigest()
    before = next(
        attempt
        for attempt in _store(profile).list_static_scan_attempts(
            identity, _request(profile).repository, coverage.fingerprint
        )
        if attempt.tool == "semgrep" and attempt.run_key == key
    )
    assert before.raw_ref is not None
    count = len(process.calls)
    second, _refs, _errors = await _run_adaptive_semgrep(fixture)
    after = next(
        attempt
        for attempt in _store(profile).list_static_scan_attempts(
            identity, _request(profile).repository, coverage.fingerprint
        )
        if attempt.tool == "semgrep" and attempt.run_key == key
    )
    assert len(process.calls) == count + 1
    assert after.raw_ref == before.raw_ref
    assert finish_coverage(coverage, second).verified_count == 128
    assert finish_coverage(coverage, second).gaps[0].path == "file-000.py"


@pytest.mark.asyncio
async def test_single_file_timeout_gets_one_bounded_retry(tmp_path: Path) -> None:
    attempts = [0]

    def timeout_then_success(
        _targets: tuple[str, ...], _command: tuple[str, ...]
    ) -> BaseException | None:
        attempts[0] += 1
        return TimeoutError() if attempts[0] == 1 else None

    process = _AdaptiveSemgrepProcess(timeout_then_success)
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=1)
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == []
    assert len(process.calls) == 2
    assert "--timeout" not in process.calls[0][1]
    assert process.calls[1][1][process.calls[1][1].index("--timeout") + 1] == "30"
    assert finish_coverage(fixture[4], slices).verified_count == 1


@pytest.mark.asyncio
async def test_timeout_retry_rechecks_windows_command_length(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = [0]

    def time_out_once(
        _targets: tuple[str, ...], _command: tuple[str, ...]
    ) -> BaseException | None:
        attempts[0] += 1
        return TimeoutError() if attempts[0] == 1 else None

    process = _AdaptiveSemgrepProcess(time_out_once)
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=1)
    monkeypatch.setattr(
        static_module,
        "semgrep_command_utf16_units",
        lambda argv: 24_001 if "--timeout" in argv else 1,
        raising=False,
    )
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert len(process.calls) == 1
    assert errors == ["SEMGREP_COMMAND_TOO_LONG"]
    assert finish_coverage(fixture[4], slices).gaps[0].reason == (
        "SEMGREP_COMMAND_TOO_LONG"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["execution", "invalid_json"])
async def test_resume_retries_transient_semgrep_failure(
    tmp_path: Path, failure: str
) -> None:
    calls = [0]

    def fail_once(
        _targets: tuple[str, ...], _command: tuple[str, ...]
    ) -> BaseException | dict[str, object] | None:
        calls[0] += 1
        if calls[0] > 1:
            return None
        if failure == "execution":
            return RuntimeError("transient process failure")
        return {"results": [], "errors": [], "paths": []}

    process = _AdaptiveSemgrepProcess(fail_once)
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=1)
    first, _refs, first_errors = await _run_adaptive_semgrep(fixture)
    assert len(process.calls) == 1
    assert first_errors == [
        (
            "SEMGREP_EXECUTION_FAILED"
            if failure == "execution"
            else "SEMGREP_RESULT_INVALID"
        )
    ]
    assert finish_coverage(fixture[4], first).verified_count == 0

    resumed, _refs, resumed_errors = await _run_adaptive_semgrep(fixture)
    assert resumed_errors == []
    assert len(process.calls) == 2
    assert finish_coverage(fixture[4], resumed).verified_count == 1


@pytest.mark.asyncio
async def test_single_file_json_timeout_gets_one_bounded_retry(tmp_path: Path) -> None:
    def timeout_then_success(
        targets: tuple[str, ...], command: tuple[str, ...]
    ) -> dict[str, object]:
        return {
            "results": [],
            "errors": (
                []
                if "--timeout" in command
                else [{"type": "Timeout", "path": targets[0]}]
            ),
            "paths": {"scanned": list(targets), "skipped": []},
        }

    process = _AdaptiveSemgrepProcess(timeout_then_success)
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=1)
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == []
    assert len(process.calls) == 2
    assert "--timeout" not in process.calls[0][1]
    assert process.calls[1][1][process.calls[1][1].index("--timeout") + 1] == "30"
    assert finish_coverage(fixture[4], slices).verified_count == 1


@pytest.mark.asyncio
async def test_cached_single_file_json_timeout_retries_without_parent_rerun(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=1)
    _, profile, identity, batches, coverage, _, _ = fixture
    original = batches.batches[0]
    target = ("file-000.py",)
    key = hashlib.sha256(
        canonical_bytes(
            {
                "adaptive": 1,
                "batch": original.key,
                "rules": original.rule_ids,
                "targets": target,
            }
        )
    ).hexdigest()
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    raw = json.dumps(
        {
            "results": [],
            "errors": [{"type": "Timeout", "path": target[0]}],
            "paths": {"scanned": list(target), "skipped": []},
        }
    ).encode()
    ref = artifacts.put_bytes(raw, "application/json")
    _store(profile).save_static_scan_attempt(
        identity,
        _request(profile).repository,
        coverage.fingerprint,
        "semgrep",
        key,
        "BLOCKED",
        ref,
        None,
        "SEMGREP_PARTIAL_SCAN",
    )
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == []
    assert len(process.calls) == 1
    assert process.calls[0][1][process.calls[0][1].index("--timeout") + 1] == "30"
    assert finish_coverage(coverage, slices).verified_count == 1


@pytest.mark.asyncio
async def test_repeated_json_timeout_stays_a_gap_without_retry_loop(
    tmp_path: Path,
) -> None:
    def always_timeout(
        targets: tuple[str, ...], _command: tuple[str, ...]
    ) -> dict[str, object]:
        return {
            "results": [],
            "errors": [{"type": "Timeout", "path": targets[0]}],
            "paths": {"scanned": list(targets), "skipped": []},
        }

    process = _AdaptiveSemgrepProcess(always_timeout)
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=1)
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == ["SEMGREP_PARTIAL_SCAN"]
    assert len(process.calls) == 2
    assert finish_coverage(fixture[4], slices).gaps[0].reason == "scan_timeout"
    resumed, _refs, resumed_errors = await _run_adaptive_semgrep(fixture)
    assert resumed_errors == ["SEMGREP_PARTIAL_SCAN"]
    assert len(process.calls) == 4
    assert finish_coverage(fixture[4], resumed).gaps[0].reason == "scan_timeout"


@pytest.mark.asyncio
async def test_semgrep_source_chunks_respect_512_kib_and_attempt_large_file(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=3)
    workspace = fixture[5]
    (workspace / "file-000.py").write_bytes(b"x" * 300_000)
    (workspace / "file-001.py").write_bytes(b"x" * 300_000)
    (workspace / "file-002.py").write_bytes(b"x" * 600_000)

    slices, _refs, errors = await _run_adaptive_semgrep(fixture)

    assert errors == []
    assert tuple(targets for targets, _ in process.calls) == (
        ("file-000.py",),
        ("file-001.py",),
        ("file-002.py",),
    )
    assert finish_coverage(fixture[4], slices).verified_count == 3


@pytest.mark.asyncio
async def test_slow_semgrep_chunk_has_bounded_wall_time_and_splits(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess(
        lambda targets, _command: TimeoutError() if len(targets) > 1 else None
    )
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=4)
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == []
    assert tuple(len(targets) for targets, _ in process.calls) == (
        4,
        2,
        1,
        1,
        2,
        1,
        1,
    )
    assert all(1 <= timeout <= 120 for timeout in process.timeouts)
    assert finish_coverage(fixture[4], slices).verified_count == 4


@pytest.mark.asyncio
async def test_adaptive_semgrep_cancellation_escapes_split_queue(
    tmp_path: Path,
) -> None:
    process = _AdaptiveSemgrepProcess(
        lambda _targets, _command: asyncio.CancelledError()
    )
    fixture = _adaptive_semgrep_fixture(tmp_path, process)
    with pytest.raises(asyncio.CancelledError):
        await _run_adaptive_semgrep(fixture)
    assert len(process.calls) == 1


@pytest.mark.asyncio
async def test_unplannable_target_returns_explicit_coverage_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=1)

    def reject_target(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("SEMGREP_COMMAND_TOO_LONG")

    monkeypatch.setattr(static_module, "plan_semgrep_target_chunks", reject_target)
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == ["SEMGREP_COMMAND_TOO_LONG"]
    assert finish_coverage(fixture[4], slices).gaps[0].reason == (
        "SEMGREP_COMMAND_TOO_LONG"
    )
    assert process.calls == []


@pytest.mark.asyncio
async def test_unplannable_target_does_not_skip_other_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _AdaptiveSemgrepProcess()
    fixture = _adaptive_semgrep_fixture(tmp_path, process, count=2)
    original_planner = plan_semgrep_target_chunks

    def reject_one(
        targets: Sequence[str],
        command_for: Callable[[tuple[str, ...]], Sequence[str]],
    ) -> tuple[tuple[str, ...], ...]:
        if "file-001.py" in targets:
            raise RuntimeError("SEMGREP_COMMAND_TOO_LONG")
        return original_planner(targets, command_for)

    monkeypatch.setattr(static_module, "plan_semgrep_target_chunks", reject_one)
    slices, _refs, errors = await _run_adaptive_semgrep(fixture)
    assert errors == ["SEMGREP_COMMAND_TOO_LONG"]
    assert tuple(targets for targets, _ in process.calls) == (("file-000.py",),)
    result = finish_coverage(fixture[4], slices)
    assert result.verified_count == 1
    assert {gap.path for gap in result.gaps} == {"file-001.py"}


def _coverage_bootstrap(
    tmp_path: Path,
    process: _CoverageProcess,
    *,
    semgrep: bool = False,
    codeql: bool = True,
) -> tuple[DirectStaticBootstrap, SimpleExecutionProfile, SimpleCheckpointStore]:
    profile = _profile(tmp_path)
    tools = dict(profile.tools)
    if semgrep:
        tools["semgrep"] = tools["opengrep"]
    if not codeql:
        tools.pop("codeql")
    profile = profile.model_copy(update={"tools": tools, "semgrep_fallback": semgrep})
    store = _store(profile)
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    return bootstrap, profile, store


def _enable_semgrep_fallback(profile: SimpleExecutionProfile) -> SimpleExecutionProfile:
    return profile.model_copy(
        update={
            "semgrep_fallback": True,
            "tools": {**profile.tools, "semgrep": profile.tools["opengrep"]},
        }
    )


def test_prior_fallback_fingerprints_do_not_rescan_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _enable_semgrep_fallback(_profile(tmp_path))
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=_Process(),
        store=_store(profile),
        static_material_root=tmp_path,
    )
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("db.execute(user)\n", encoding="utf-8")
    binding = profile.tools["opengrep"]
    rule_plan = plan_rule_batches(
        (tmp_path / "opengrep" / "rules.yml").read_bytes(),
        tool_version=binding.version,
        executable_sha256=binding.executable_sha256,
    )
    original_resolve = Path.resolve
    root_resolutions = 0

    def counting_resolve(self: Path, strict: bool = False) -> Path:
        nonlocal root_resolutions
        if self == workspace:
            root_resolutions += 1
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", counting_resolve)
    old_fingerprints = bootstrap._prior_fallback_coverage_fingerprints(
        workspace, ["app.py"], "a" * 40, rule_plan
    )

    assert old_fingerprints == frozenset()
    assert root_resolutions == 0


@pytest.mark.asyncio
async def test_semgrep_opt_in_caps_each_opengrep_batch_before_fallback(
    tmp_path: Path,
) -> None:
    class SlowOpenGrep(_CoverageProcess):
        def __init__(self) -> None:
            super().__init__()
            self.opengrep_timeouts: list[int] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                self.opengrep_calls += 1
                self.opengrep_timeouts.append(timeout_seconds)
                raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = SlowOpenGrep()
    bootstrap, profile, _store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    result = await bootstrap.run(_request(profile), _identity("bounded-opengrep"))
    assert result.static_disposition in {"FULL", "PARTIAL"}
    assert process.opengrep_timeouts
    assert all(0 < seconds <= 120 for seconds in process.opengrep_timeouts)
    assert process.fallback_calls


@pytest.mark.asyncio
async def test_opengrep_timeout_recovers_in_bounded_chunks_and_reuses_proof(
    tmp_path: Path,
) -> None:
    class ChunkedOpenGrep(_CoverageProcess):
        def __init__(self) -> None:
            super().__init__(parse_warning=False)
            self.chunks: list[tuple[str, ...]] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "clone":
                result = await super().run(
                    argv, cwd=cwd, timeout_seconds=timeout_seconds
                )
                root = Path(argv[-1])
                for index in range(129):
                    (root / f"file-{index:03d}.py").write_text(
                        "value = 1\n", encoding="utf-8"
                    )
                return result
            if argv[1:3] == ("ls-files", "-z"):
                names = ("app.py", "good.py", *(f"file-{i:03d}.py" for i in range(129)))
                return ProcessResult(0, "\0".join(names).encode() + b"\0", b"")
            if argv[1] == "scan" and "--metrics=off" not in argv:
                targets = tuple(
                    item
                    for item in argv
                    if item in {"app.py", "good.py"} or item.startswith("file-")
                )
                self.chunks.append(targets)
                if len(targets) == 64:
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {"scanned": list(targets), "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = ChunkedOpenGrep()
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    profile = profile.model_copy(
        update={"max_elapsed_seconds": "unlimited", "static_scan_pass_seconds": 1}
    )
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    identity = _identity("opengrep-chunk-resume")
    request = _request(profile)
    result = await bootstrap.run(request, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    coverage = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert coverage["verified_count"] == coverage["expected_count"] == 131
    assert tuple(map(len, process.chunks)) == (64, 32, 32, 64, 32, 32, 3)
    assert process.fallback_calls == []
    chunk_attempts = [
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, coverage["fingerprint"]
        )
        if item.tool == "opengrep" and item.request_ref is not None
    ]
    assert len(chunk_attempts) == 7
    assert (
        sum(
            item.status == "SUCCEEDED" and item.raw_ref is not None
            for item in chunk_attempts
        )
        == 5
    )
    assert (
        sum(item.error_code == "EXTERNAL_TOOL_TIMEOUT" for item in chunk_attempts) == 2
    )

    await bootstrap.run(request, identity)
    assert tuple(map(len, process.chunks)) == (64, 32, 32, 64, 32, 32, 3)


@pytest.mark.asyncio
async def test_opengrep_timeout_pre_splits_large_source_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ByteChunkOpenGrep(_CoverageProcess):
        def __init__(self) -> None:
            super().__init__(parse_warning=False)
            self.chunks: list[tuple[str, ...]] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                if cwd is not None and argv[-1] == str(cwd):
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                targets = tuple(path for path in ("app.py", "good.py") if path in argv)
                self.chunks.append(targets)
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {"scanned": list(targets), "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = ByteChunkOpenGrep()
    bootstrap, profile, _store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    monkeypatch.setattr(static_module, "_OPENGREP_RECOVERY_MAX_SOURCE_BYTES", 1)

    await bootstrap.run(_request(profile), _identity("opengrep-source-bytes"))

    assert process.chunks == [("app.py",), ("good.py",)]
    assert process.fallback_calls == []


@pytest.mark.asyncio
async def test_opengrep_overlong_target_does_not_abandon_short_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class TimedOutFullScan(_CoverageProcess):
        def __init__(self) -> None:
            super().__init__(parse_warning=False)
            self.chunks: list[tuple[str, ...]] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                if cwd is not None and argv[-1] == str(cwd):
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                targets = tuple(path for path in ("app.py", "good.py") if path in argv)
                self.chunks.append(targets)
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {"scanned": list(targets), "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    original_planner = plan_semgrep_target_chunks

    def reject_good(
        targets: Sequence[str],
        command_for: Callable[[tuple[str, ...]], Sequence[str]],
        **kwargs: Any,
    ) -> tuple[tuple[str, ...], ...]:
        if "good.py" in targets:
            raise RuntimeError("SEMGREP_COMMAND_TOO_LONG")
        return original_planner(targets, command_for, **kwargs)

    monkeypatch.setattr(static_module, "plan_semgrep_target_chunks", reject_good)
    process = TimedOutFullScan()
    bootstrap, profile, _store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("opengrep-overlong-sibling")

    result = await bootstrap.run(_request(profile), identity)
    assert result.static_disposition == "PARTIAL"
    coverage = _coverage_from_ref(profile, identity, result.static_coverage_ref)
    assert process.chunks == [("app.py",)]
    assert coverage["verified_count"] == 1
    assert any(gap["path"] == "good.py" for gap in coverage["gaps"])


@pytest.mark.asyncio
async def test_opengrep_timed_out_chunk_splits_and_records_child_proof(
    tmp_path: Path,
) -> None:
    class SplittingOpenGrep(_CoverageProcess):
        def __init__(self) -> None:
            super().__init__(parse_warning=False)
            self.chunks: list[tuple[str, ...]] = []
            self.timeouts: list[int] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                if cwd is not None and argv[-1] == str(cwd):
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                targets = tuple(path for path in ("app.py", "good.py") if path in argv)
                self.chunks.append(targets)
                self.timeouts.append(timeout_seconds)
                if len(targets) > 1:
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {"scanned": list(targets), "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = SplittingOpenGrep()
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("opengrep-adaptive-chunks")
    request = _request(profile)
    result = await bootstrap.run(request, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    coverage = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert coverage["verified_count"] == coverage["expected_count"] == 2
    assert process.chunks == [("app.py", "good.py"), ("app.py",), ("good.py",)]
    assert all(0 < seconds <= 120 for seconds in process.timeouts)
    assert process.fallback_calls == []

    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    chunks = [
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, coverage["fingerprint"]
        )
        if item.tool == "opengrep" and item.request_ref is not None
    ]
    assert len(chunks) == 3
    by_targets = {
        tuple(json.loads(artifacts.read(item.request_ref))["targets"]): item
        for item in chunks
        if item.request_ref is not None
    }
    parent = by_targets[("app.py", "good.py")]
    assert parent.status == "BLOCKED"
    assert parent.error_code == "EXTERNAL_TOOL_TIMEOUT"
    assert parent.raw_ref is None
    for target in ("app.py", "good.py"):
        child = by_targets[(target,)]
        assert child.status == "SUCCEEDED"
        assert child.raw_ref is not None
        assert child.coverage_ref is not None
        assert child.request_ref is not None
        descriptor = json.loads(artifacts.read(child.request_ref))
        assert descriptor["raw_content_hash"] == child.raw_ref.content_hash


@pytest.mark.asyncio
async def test_opengrep_chunk_partial_sends_only_unproved_file_to_semgrep(
    tmp_path: Path,
) -> None:
    class PartialChunk(_CoverageProcess):
        def __init__(self) -> None:
            super().__init__(parse_warning=False)
            self.chunk_calls = 0

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                if cwd is not None and argv[-1] == str(cwd):
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                self.chunk_calls += 1
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [{"type": "Syntax error", "path": "app.py"}],
                            "paths": {
                                "scanned": ["app.py", "good.py"],
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = PartialChunk()
    bootstrap, profile, _store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("opengrep-chunk-partial")
    request = _request(profile)
    result = await bootstrap.run(request, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    coverage = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert coverage["verified_count"] == coverage["expected_count"] == 2
    assert process.chunk_calls == 1
    assert len(process.fallback_calls) == 1
    assert "app.py" in process.fallback_calls[0]
    assert "good.py" not in process.fallback_calls[0]
    await bootstrap.run(request, identity)
    assert process.chunk_calls == 1
    assert len(process.fallback_calls) == 1


@pytest.mark.asyncio
async def test_opengrep_singleton_timeouts_stop_until_explicit_resume(
    tmp_path: Path,
) -> None:
    class TimedOutChunk(_CoverageProcess):
        def __init__(self) -> None:
            super().__init__(parse_warning=False, fallback_fails=True)
            self.chunks: list[tuple[str, ...]] = []
            self.singleton_attempts: dict[str, int] = {}
            self.timeouts: list[int] = []
            self.store: SimpleCheckpointStore | None = None
            self.identity: CheckpointIdentity | None = None
            self.repository: str | None = None

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                if cwd is not None and argv[-1] == str(cwd):
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                assert self.store is not None
                assert self.identity is not None
                assert self.repository is not None
                history = self.store.list_static_scan_executions(
                    self.identity, self.repository, tool="opengrep"
                )
                assert history[-1].status == "STARTED"
                targets = tuple(path for path in ("app.py", "good.py") if path in argv)
                self.chunks.append(targets)
                self.timeouts.append(timeout_seconds)
                if len(targets) > 1:
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                target = targets[0]
                self.singleton_attempts[target] = (
                    self.singleton_attempts.get(target, 0) + 1
                )
                if self.singleton_attempts[target] == 1:
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {
                                "scanned": [target],
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = TimedOutChunk()
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("opengrep-chunk-timeout")
    request = _request(profile)
    process.store = store
    process.identity = identity
    process.repository = request.repository
    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"
    initial = _coverage_from_ref(profile, identity, first.static_coverage_ref)
    assert initial["verified_count"] == 0
    assert process.chunks == [("app.py", "good.py"), ("app.py",), ("good.py",)]
    assert all(0 < seconds <= 120 for seconds in process.timeouts)
    assert process.fallback_calls
    first_opengrep = store.list_static_scan_executions(
        identity, request.repository, initial["fingerprint"], tool="opengrep"
    )
    assert len(first_opengrep) == 3
    assert all(item.error_code == "EXTERNAL_TOOL_TIMEOUT" for item in first_opengrep)
    for gap in initial["gaps"]:
        target = gap["path"]
        fallback_attempts = sum(target in argv for argv in process.fallback_calls)
        assert gap["attempt_count"] == 2 + fallback_attempts
        assert gap["history_complete"] is True
        assert gap["latest_error_ref"] is not None

    fallback_calls = len(process.fallback_calls)
    result = await bootstrap.run(request, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    coverage = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert coverage["verified_count"] == coverage["expected_count"] == 2
    assert process.chunks == [
        ("app.py", "good.py"),
        ("app.py",),
        ("good.py",),
        ("app.py",),
        ("good.py",),
    ]
    assert len(process.fallback_calls) == fallback_calls
    replayed = SimpleCheckpointStore(profile.data_dir / "db" / "sastsimi.sqlite3")
    all_opengrep = replayed.list_static_scan_executions(
        identity, request.repository, initial["fingerprint"], tool="opengrep"
    )
    assert len(all_opengrep) == 5
    assert [item.error_code for item in all_opengrep[-2:]] == [None, None]


@pytest.mark.asyncio
async def test_opengrep_resume_reuses_successful_child_after_sibling_timeout(
    tmp_path: Path,
) -> None:
    class RecoveringSibling(_CoverageProcess):
        def __init__(self) -> None:
            super().__init__(parse_warning=False, fallback_fails=True)
            self.chunks: list[tuple[str, ...]] = []
            self.good_attempts = 0

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                if cwd is not None and argv[-1] == str(cwd):
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                targets = tuple(path for path in ("app.py", "good.py") if path in argv)
                self.chunks.append(targets)
                if len(targets) > 1:
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                if targets == ("good.py",):
                    self.good_attempts += 1
                    if self.good_attempts == 1:
                        raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {"scanned": list(targets), "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = RecoveringSibling()
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("opengrep-child-resume")
    request = _request(profile)
    partial = await bootstrap.run(request, identity)
    assert partial.static_disposition == "PARTIAL"
    first = _coverage_from_ref(profile, identity, partial.static_coverage_ref)
    assert first["verified_count"] == 1
    assert process.chunks == [("app.py", "good.py"), ("app.py",), ("good.py",)]
    attempts = store.list_static_scan_attempts(
        identity, request.repository, first["fingerprint"]
    )
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    successful = next(
        item
        for item in attempts
        if item.tool == "opengrep"
        and item.request_ref is not None
        and json.loads(artifacts.read(item.request_ref))["targets"] == ["app.py"]
    )
    assert successful.raw_ref is not None
    assert successful.coverage_ref is not None

    result = await bootstrap.run(request, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    coverage = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert coverage["verified_count"] == coverage["expected_count"] == 2
    assert process.chunks == [
        ("app.py", "good.py"),
        ("app.py",),
        ("good.py",),
        ("good.py",),
    ]


class _CorruptReplayOpenGrep(_CoverageProcess):
    def __init__(self, *, first_success: frozenset[str]) -> None:
        super().__init__(parse_warning=False, fallback_fails=True)
        self.first_success = first_success
        self.chunks: list[tuple[str, ...]] = []
        self.singleton_attempts: dict[str, int] = {}

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: int,
    ) -> ProcessResult:
        if argv[1] == "scan" and "--metrics=off" not in argv:
            if cwd is not None and argv[-1] == str(cwd):
                raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
            targets = tuple(path for path in ("app.py", "good.py") if path in argv)
            self.chunks.append(targets)
            if len(targets) > 1:
                raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
            target = targets[0]
            self.singleton_attempts[target] = self.singleton_attempts.get(target, 0) + 1
            if (
                target not in self.first_success
                and self.singleton_attempts[target] == 1
            ):
                raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
            output = Path(argv[argv.index("--output") + 1])
            output.write_text(
                json.dumps(
                    {
                        "results": [],
                        "errors": [],
                        "paths": {"scanned": [target], "skipped": []},
                    }
                ),
                encoding="utf-8",
            )
            return ProcessResult(0, b"", b"")
        return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)


@pytest.mark.asyncio
async def test_opengrep_corrupt_timed_out_parent_request_is_recreated_on_resume(
    tmp_path: Path,
) -> None:
    process = _CorruptReplayOpenGrep(first_success=frozenset())
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("opengrep-corrupt-parent-request")
    request = _request(profile)
    partial = await bootstrap.run(request, identity)
    assert partial.static_disposition == "PARTIAL"
    first = _coverage_from_ref(profile, identity, partial.static_coverage_ref)
    assert first["verified_count"] == 0
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    parent = next(
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, first["fingerprint"]
        )
        if item.tool == "opengrep"
        and item.request_ref is not None
        and json.loads(artifacts.read(item.request_ref))["targets"]
        == ["app.py", "good.py"]
    )
    assert parent.request_ref is not None
    artifacts.artifacts.path_for(parent.request_ref.content_hash).write_bytes(
        b"corrupt"
    )

    result = await bootstrap.run(request, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    coverage = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert coverage["verified_count"] == coverage["expected_count"] == 2
    assert process.chunks == [
        ("app.py", "good.py"),
        ("app.py",),
        ("good.py",),
        ("app.py", "good.py"),
        ("app.py",),
        ("good.py",),
    ]
    assert json.loads(artifacts.read(parent.request_ref))["targets"] == [
        "app.py",
        "good.py",
    ]
    quarantined = list(artifacts.paths.quarantine.iterdir())
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == b"corrupt"


@pytest.mark.asyncio
async def test_opengrep_corrupt_successful_child_raw_is_recreated_on_resume(
    tmp_path: Path,
) -> None:
    process = _CorruptReplayOpenGrep(first_success=frozenset({"app.py"}))
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("opengrep-corrupt-child-raw")
    request = _request(profile)
    partial = await bootstrap.run(request, identity)
    assert partial.static_disposition == "PARTIAL"
    first = _coverage_from_ref(profile, identity, partial.static_coverage_ref)
    assert first["verified_count"] == 1
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    child = next(
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, first["fingerprint"]
        )
        if item.tool == "opengrep"
        and item.request_ref is not None
        and json.loads(artifacts.read(item.request_ref))["targets"] == ["app.py"]
    )
    assert child.raw_ref is not None
    artifacts.artifacts.path_for(child.raw_ref.content_hash).write_bytes(b"corrupt")

    result = await bootstrap.run(request, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    coverage = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert coverage["verified_count"] == coverage["expected_count"] == 2
    assert process.chunks == [
        ("app.py", "good.py"),
        ("app.py",),
        ("good.py",),
        ("app.py",),
        ("good.py",),
    ]
    assert json.loads(artifacts.read(child.raw_ref))["paths"]["scanned"] == ["app.py"]
    quarantined = list(artifacts.paths.quarantine.iterdir())
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == b"corrupt"


@pytest.mark.asyncio
async def test_opengrep_chunk_rejects_changed_request_descriptor(
    tmp_path: Path,
) -> None:
    class CompleteChunk(_CoverageProcess):
        def __init__(self) -> None:
            super().__init__(parse_warning=False)
            self.chunk_calls = 0

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                if cwd is not None and argv[-1] == str(cwd):
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                self.chunk_calls += 1
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {
                                "scanned": ["app.py", "good.py"],
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = CompleteChunk()
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("opengrep-chunk-tamper")
    request = _request(profile)
    result = await bootstrap.run(request, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    coverage = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    chunk = next(
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, coverage["fingerprint"]
        )
        if item.tool == "opengrep" and item.request_ref is not None
    )
    assert chunk.raw_ref is not None
    assert chunk.request_ref is not None
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    descriptor = json.loads(artifacts.read(chunk.request_ref))
    descriptor["targets"] = ["good.py"]
    forged = artifacts.put_json(descriptor)
    store.save_static_scan_attempt(
        identity,
        request.repository,
        coverage["fingerprint"],
        "opengrep",
        chunk.run_key,
        "SUCCEEDED",
        chunk.raw_ref,
        None,
        None,
        forged,
    )
    execution = store.list_static_scan_executions(
        identity,
        request.repository,
        coverage["fingerprint"],
        tool="opengrep",
        run_key=chunk.run_key,
    )[0]
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_static_scan_executions SET request_ref_json = ? "
            "WHERE execution_id = ?",
            (forged.model_dump_json(), execution.execution_id),
        )

    await bootstrap.run(request, identity)
    assert process.chunk_calls == 2
    assert list(artifacts.paths.quarantine.iterdir()) == []


@pytest.mark.asyncio
async def test_missing_semgrep_keeps_bounded_opengrep_batch_deadline(
    tmp_path: Path,
) -> None:
    class RecordingOpenGrep(_CoverageProcess):
        def __init__(self) -> None:
            super().__init__(parse_warning=False)
            self.opengrep_timeouts: list[int] = []

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                self.opengrep_timeouts.append(timeout_seconds)
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = RecordingOpenGrep()
    bootstrap, profile, _store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    opengrep = profile.tools["opengrep"]
    missing_semgrep = opengrep.model_copy(
        update={"executable_path": tmp_path / "missing-semgrep"}
    )
    profile = profile.model_copy(
        update={
            "max_elapsed_seconds": 7200,
            "tools": {**profile.tools, "semgrep": missing_semgrep},
        }
    )
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store,
        static_material_root=tmp_path,
    )
    await bootstrap.run(_request(profile), _identity("missing-semgrep-deadline"))
    assert process.opengrep_timeouts
    assert process.opengrep_timeouts[0] == 120


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error_type", "expected_retryable"),
    [
        ("Syntax error", True),
        ("OutOfMemory", True),
        ("Syntax error then OutOfMemory", True),
    ],
)
async def test_no_verified_semgrep_parser_gaps_remain_retryable_after_timeout(
    tmp_path: Path,
    error_type: str,
    expected_retryable: bool,
) -> None:
    class ParserOnlyFallback(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
            if argv[1] == "scan" and "--metrics=off" in argv:
                targets = [arg for arg in argv if arg in {"app.py", "good.py"}]
                actual_error = (
                    "Syntax error"
                    if error_type == "Syntax error then OutOfMemory"
                    and len(targets) > 1
                    else "OutOfMemory"
                    if error_type == "Syntax error then OutOfMemory"
                    else error_type
                )
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [
                                {"type": actual_error, "path": target}
                                for target in targets
                            ],
                            "paths": {"scanned": targets, "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = ParserOnlyFallback()
    bootstrap, profile, _store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    result = await bootstrap.run(_request(profile), _identity("parser-after-timeout"))
    assert result.static_disposition == "PARTIAL"
    assert expected_retryable is True
    coverage = _coverage_from_ref(
        profile, _identity("parser-after-timeout"), result.static_coverage_ref
    )
    assert {gap["reason"] for gap in coverage["gaps"]} == {"parse_or_scan_error"}


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["semgrep_child", "codeql"])
async def test_parser_gap_with_later_engine_failure_remains_retryable(
    tmp_path: Path, failure: str
) -> None:
    class FailingAfterParser(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if (
                argv[1] == "scan"
                and "--metrics=off" not in argv
                and failure != "codeql"
            ):
                raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
            if argv[1:3] == ("database", "analyze") and failure == "codeql":
                raise RuntimeError("CODEQL_EXECUTION_FAILED")
            if argv[1] == "scan" and "--metrics=off" in argv:
                targets = [arg for arg in argv if arg in {"app.py", "good.py"}]
                if len(targets) == 1 and failure == "semgrep_child":
                    raise RuntimeError("SEMGREP_EXECUTION_FAILED")
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [
                                {"type": "Syntax error", "path": target}
                                for target in targets
                            ],
                            "paths": {"scanned": targets, "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = FailingAfterParser()
    bootstrap, profile, _store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=failure == "codeql"
    )
    identity = _identity("parser-with-engine-failure")
    if failure == "codeql":
        partial = await bootstrap.run(_request(profile), identity)
        assert partial.static_disposition == "PARTIAL"
        coverage = _coverage_from_ref(profile, identity, partial.static_coverage_ref)
        assert coverage["codeql_error"] == "CODEQL_EXECUTION_FAILED"
        assert coverage["verified_count"] > 0
    else:
        partial = await bootstrap.run(_request(profile), identity)
        assert partial.static_disposition == "PARTIAL"
        coverage = _coverage_from_ref(profile, identity, partial.static_coverage_ref)
        assert coverage["verified_count"] == 0
        assert coverage["gaps"]


async def _seed_old_partial(
    tmp_path: Path, process: _CoverageProcess, analysis_id: str
) -> tuple[
    SimpleExecutionProfile,
    SimpleCheckpointStore,
    CheckpointIdentity,
    StaticBootstrapResult,
]:
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity(analysis_id)
    result = await bootstrap.run(_request(profile), identity)
    assert result.static_disposition == "PARTIAL"
    assert process.opengrep_calls == 1
    return profile, store, identity, result


@pytest.mark.asyncio
async def test_fallback_opt_in_revalidates_old_partial_without_opengrep_rerun(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess()
    old_profile, store, identity, old_blocked = await _seed_old_partial(
        tmp_path, process, "reuse-old-partial"
    )
    old_report = _coverage_from_ref(
        old_profile, identity, old_blocked.static_coverage_ref
    )
    assert old_report["verified_count"] == 1
    profile = _enable_semgrep_fallback(old_profile)
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    completed = await bootstrap.run(_request(profile), identity)
    assert process.opengrep_calls == 2
    assert len(process.fallback_calls) == 1
    report = _coverage_from_ref(
        profile,
        identity,
        StoredDataRef.model_validate(
            _coverage_from_ref(profile, identity, completed.static_bundle_ref)[
                "static_coverage_ref"
            ]
        ),
    )
    assert report["expected_count"] == report["verified_count"] == 2
    assert report["gaps"] == []


@pytest.mark.asyncio
async def test_fallback_opt_in_counts_compatible_prior_execution_history(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess(fallback_fails=True)
    old_profile, store, identity, old_blocked = await _seed_old_partial(
        tmp_path, process, "count-prior-invocations"
    )
    prior = _coverage_from_ref(old_profile, identity, old_blocked.static_coverage_ref)
    assert (
        store.count_static_scan_executions(
            identity,
            _request(old_profile).repository,
            prior["fingerprint"],
            tool="opengrep",
        )
        == 1
    )

    profile = _enable_semgrep_fallback(old_profile)
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    partial = await bootstrap.run(_request(profile), identity)
    assert partial.static_disposition == "PARTIAL"
    report = _coverage_from_ref(profile, identity, partial.static_coverage_ref)
    assert report["gaps"]
    for gap in report["gaps"]:
        assert gap["known_attempts_by_engine"] == {"opengrep": 2, "semgrep": 1}
        assert gap["known_attempt_count"] == gap["attempt_count"] == 3
        assert gap["history_complete"] is True


@pytest.mark.asyncio
async def test_cross_fingerprint_corrupt_partial_is_quarantined_and_rescanned(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess()
    old_profile, store, identity, old_blocked = await _seed_old_partial(
        tmp_path, process, "corrupt-old-partial"
    )
    old_report = _coverage_from_ref(
        old_profile, identity, old_blocked.static_coverage_ref
    )
    old_attempt = next(
        item
        for item in store.list_static_scan_attempts(
            identity, _request(old_profile).repository, old_report["fingerprint"]
        )
        if item.tool == "opengrep"
    )
    assert old_attempt.raw_ref is not None
    artifacts = SimpleArtifactRepository(old_profile.data_dir, identity)
    artifacts.artifacts.path_for(old_attempt.raw_ref.content_hash).write_bytes(b"bad")
    profile = _enable_semgrep_fallback(old_profile)
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    await bootstrap.run(_request(profile), identity)
    assert process.opengrep_calls == 2
    assert any(artifacts.paths.quarantine.iterdir())


@pytest.mark.asyncio
async def test_cross_fingerprint_numeric_coverage_without_raw_never_counts(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess()
    old_profile, store, identity, old_blocked = await _seed_old_partial(
        tmp_path, process, "count-without-proof"
    )
    old_report = _coverage_from_ref(
        old_profile, identity, old_blocked.static_coverage_ref
    )
    old_attempt = next(
        item
        for item in store.list_static_scan_attempts(
            identity, _request(old_profile).repository, old_report["fingerprint"]
        )
        if item.tool == "opengrep"
    )
    store.save_static_scan_attempt(
        identity,
        _request(old_profile).repository,
        old_report["fingerprint"],
        "opengrep",
        old_attempt.run_key,
        "BLOCKED",
        None,
        old_blocked.static_coverage_ref,
        "OPENGREP_PARTIAL_SCAN",
    )
    profile = _enable_semgrep_fallback(old_profile)
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    await bootstrap.run(_request(profile), identity)
    assert process.opengrep_calls == 2


@pytest.mark.asyncio
async def test_cross_fingerprint_partial_requires_clean_checkout(
    tmp_path: Path,
) -> None:
    class DirtyOnResume(_CoverageProcess):
        dirty = False

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if self.dirty and argv[1] == "status":
                return ProcessResult(0, b" M app.py\0", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = DirtyOnResume()
    old_profile, store, identity, _ = await _seed_old_partial(
        tmp_path, process, "dirty-old-partial"
    )
    process.dirty = True
    profile = _enable_semgrep_fallback(old_profile)
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    with pytest.raises(RuntimeError, match="WORKSPACE_DIRTY"):
        await bootstrap.run(_request(profile), identity)
    assert process.opengrep_calls == 1


@pytest.mark.asyncio
async def test_cross_fingerprint_rejects_changed_opengrep_executable(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess()
    old_profile, store, identity, _ = await _seed_old_partial(
        tmp_path, process, "changed-old-tool"
    )
    profile = _enable_semgrep_fallback(old_profile)
    replacement = tmp_path / "changed-opengrep"
    replacement.write_bytes(b"changed-tool")
    changed_binding = SimpleToolBinding(
        executable_path=replacement,
        version="changed",
        executable_sha256=hashlib.sha256(b"changed-tool").hexdigest(),
    )
    profile = profile.model_copy(
        update={"tools": {**profile.tools, "opengrep": changed_binding}}
    )
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    await bootstrap.run(_request(profile), identity)
    assert process.opengrep_calls == 2


def _coverage_from_ref(
    profile: SimpleExecutionProfile,
    identity: CheckpointIdentity,
    ref: StoredDataRef | None,
) -> dict[str, Any]:
    assert ref is not None
    return cast(
        dict[str, Any],
        json.loads(SimpleArtifactRepository(profile.data_dir, identity).read(ref)),
    )


@pytest.mark.asyncio
async def test_product_language_without_applicable_rules_blocks_before_scan(
    tmp_path: Path,
) -> None:
    class NoApplicableSource(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "clone":
                root = Path(argv[-1])
                root.mkdir(parents=True)
                (root / "main.go").write_text("package main\n", encoding="utf-8")
                return ProcessResult(0, b"", b"")
            if argv[1:3] == ("ls-files", "-z"):
                return ProcessResult(0, b"main.go\0", b"")
            if argv[1] == "scan":
                raise AssertionError("unsupported Go source must not be scanned")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    bootstrap, profile, _store_ = _coverage_bootstrap(
        tmp_path, NoApplicableSource(), codeql=True
    )
    (tmp_path / "opengrep" / "rules.yml").write_text(
        "not a rule catalog", encoding="utf-8"
    )
    identity = _identity("empty-rule-failure")
    with pytest.raises(StaticCoverageBlocked, match="NO_PYTHON_SOURCE") as blocked:
        await bootstrap.run(_request(profile), identity)
    bundle = _coverage_from_ref(profile, identity, blocked.value.bundle_ref)
    coverage = _coverage_from_ref(profile, identity, blocked.value.coverage_ref)
    assert bundle["codeql_executed"] is False
    assert coverage["codeql_error"] is None


@pytest.mark.asyncio
async def test_python_source_with_only_javascript_rules_is_not_complete(
    tmp_path: Path,
) -> None:
    profile = _without_codeql(_profile(tmp_path))
    (tmp_path / "opengrep" / "rules.yml").write_text(
        "rules:\n"
        "  - id: javascript.only\n"
        "    languages: [javascript]\n"
        "    message: test\n"
        "    severity: INFO\n"
        "    pattern: $APP.use($AUTH)\n",
        encoding="utf-8",
    )
    identity = _identity("python-no-rules")
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=_Process(),
        store=_store(profile),
        static_material_root=tmp_path,
    )

    result = await bootstrap.run(_request(profile), identity)

    assert result.static_disposition == "PARTIAL"
    coverage = _coverage_from_ref(profile, identity, result.static_coverage_ref)
    assert coverage["expected_count"] == coverage["verified_count"] == 0
    assert coverage["unavailable_paths"] == [
        {"path": path, "reason": "NO_PYTHON_RULES"} for path in ("app.py",)
    ]


@pytest.mark.asyncio
async def test_dirty_checkout_cannot_be_completed_by_semgrep_fallback(
    tmp_path: Path,
) -> None:
    class DirtyProcess(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "status":
                return ProcessResult(0, b" M app.py\0", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = DirtyProcess()
    bootstrap, profile, _store_ = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    with pytest.raises(RuntimeError, match="WORKSPACE_DIRTY"):
        await bootstrap.run(_request(profile), _identity("dirty-fallback"))
    assert process.fallback_calls == []


@pytest.mark.asyncio
async def test_checkout_changed_after_preflight_skips_untrusted_fallback(
    tmp_path: Path,
) -> None:
    class DirtyAfterPreflight(_CoverageProcess):
        status_calls = 0

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "status":
                self.status_calls += 1
                return ProcessResult(
                    0, b" M app.py\0" if self.status_calls > 1 else b"", b""
                )
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = DirtyAfterPreflight()
    bootstrap, profile, _store_ = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    with pytest.raises(RuntimeError, match="WORKSPACE_DIRTY"):
        await bootstrap.run(_request(profile), _identity("late-dirty-fallback"))
    assert process.status_calls >= 2
    assert process.fallback_calls == []


@pytest.mark.asyncio
async def test_nonzero_opengrep_output_is_not_reused_as_success(
    tmp_path: Path,
) -> None:
    class FailedThenSuccessful(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--output" in argv:
                self.opengrep_calls += 1
                targets = [path for path in ("app.py", "good.py") if path in argv]
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {
                                "scanned": targets,
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(2 if self.opengrep_calls == 1 else 0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = FailedThenSuccessful(parse_warning=False)
    bootstrap, profile, _store_ = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("nonzero-cache")
    first = await bootstrap.run(_request(profile), identity)
    assert first.static_disposition == "PARTIAL"
    coverage = _coverage_from_ref(profile, identity, first.static_coverage_ref)
    assert coverage["verified_count"] == 0
    assert coverage["expected_count"] == 2
    assert {(gap["path"], gap["rule_id"]) for gap in coverage["gaps"]} == {
        ("app.py", "python.sql"),
        ("good.py", "python.sql"),
    }
    second = await bootstrap.run(_request(profile), identity)
    assert second.static_disposition == "FULL"
    assert process.opengrep_calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_kind", ["timeout", "nonzero"])
async def test_opengrep_retry_failure_preserves_previous_verified_pairs(
    tmp_path: Path, failure_kind: str
) -> None:
    class PartialThenFailure(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--output" in argv:
                self.opengrep_calls += 1
                if self.opengrep_calls == 1:
                    output = Path(argv[argv.index("--output") + 1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(
                        json.dumps(
                            {
                                "results": [],
                                "errors": [],
                                "paths": {"scanned": ["good.py"], "skipped": []},
                            }
                        ),
                        encoding="utf-8",
                    )
                    return ProcessResult(0, b"", b"")
                if failure_kind == "timeout":
                    raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {
                                "scanned": ["app.py", "good.py"],
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(2, b"", b"failed")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = PartialThenFailure()
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("partial-then-timeout")
    request = _request(profile)
    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"
    first_report = _coverage_from_ref(profile, identity, first.static_coverage_ref)
    assert first_report["verified_count"] == 1
    previous = next(
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, first_report["fingerprint"]
        )
        if item.tool == "opengrep"
    )
    assert previous.raw_ref is not None

    second = await bootstrap.run(request, identity)
    assert second.static_disposition == "PARTIAL"
    second_report = _coverage_from_ref(profile, identity, second.static_coverage_ref)
    assert process.opengrep_calls == 2
    assert second_report["verified_count"] == 1
    assert second_report["gaps"][0]["path"] == "app.py"
    attempts = [
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, second_report["fingerprint"]
        )
        if item.tool == "opengrep"
    ]
    assert len(attempts) == 2
    retained = next(item for item in attempts if item.run_key == previous.run_key)
    assert retained.raw_ref == previous.raw_ref
    assert any(
        item.run_key != previous.run_key and item.status == "BLOCKED"
        for item in attempts
    )


@pytest.mark.asyncio
async def test_opengrep_partial_retry_preserves_previous_verified_pairs(
    tmp_path: Path,
) -> None:
    class AlternatingPartial(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--output" in argv:
                self.opengrep_calls += 1
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {
                                "scanned": [
                                    "good.py" if self.opengrep_calls == 1 else "app.py"
                                ],
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = AlternatingPartial()
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("alternating-partial")
    request = _request(profile)
    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"
    first_report = _coverage_from_ref(profile, identity, first.static_coverage_ref)
    previous = next(
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, first_report["fingerprint"]
        )
        if item.tool == "opengrep"
    )
    result = await bootstrap.run(request, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    coverage = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert process.opengrep_calls == 2
    assert coverage["verified_count"] == coverage["expected_count"] == 2
    assert len(bundle["engine_raw_refs"]) == 2
    assert previous.raw_ref is not None
    assert previous.raw_ref.model_dump(mode="json") in bundle["engine_raw_refs"]
    attempts = [
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, coverage["fingerprint"]
        )
        if item.tool == "opengrep"
    ]
    assert len(attempts) == 2
    retained = next(item for item in attempts if item.run_key == previous.run_key)
    assert retained.raw_ref == previous.raw_ref
    assert any(
        item.run_key != previous.run_key
        and item.status == "SUCCEEDED"
        and item.raw_ref is not None
        for item in attempts
    )
    resumed = await bootstrap.run(request, identity)
    resumed_bundle = _coverage_from_ref(profile, identity, resumed.static_bundle_ref)
    resumed_coverage = _coverage_from_ref(
        profile,
        identity,
        StoredDataRef.model_validate(resumed_bundle["static_coverage_ref"]),
    )
    assert process.opengrep_calls == 2
    assert resumed_coverage["verified_count"] == 2


@pytest.mark.asyncio
async def test_opengrep_resume_unions_timeout_and_clean_partial_proofs(
    tmp_path: Path,
) -> None:
    class TimeoutThenComplementary(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--output" in argv:
                self.opengrep_calls += 1
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                first = self.opengrep_calls == 1
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": (
                                [{"type": "Timeout", "path": "app.py"}] if first else []
                            ),
                            "paths": {
                                "scanned": (
                                    ["app.py", "good.py"] if first else ["app.py"]
                                ),
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = TimeoutThenComplementary()
    bootstrap, profile, _store = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("timeout-then-complementary")
    request = _request(profile)
    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"
    second = await bootstrap.run(request, identity)
    second_bundle = _coverage_from_ref(profile, identity, second.static_bundle_ref)
    second_coverage = _coverage_from_ref(
        profile,
        identity,
        StoredDataRef.model_validate(second_bundle["static_coverage_ref"]),
    )
    assert second_coverage["verified_count"] == 2
    assert len(second_bundle["engine_raw_refs"]) == 2
    resumed = await bootstrap.run(request, identity)
    resumed_bundle = _coverage_from_ref(profile, identity, resumed.static_bundle_ref)
    resumed_coverage = _coverage_from_ref(
        profile,
        identity,
        StoredDataRef.model_validate(resumed_bundle["static_coverage_ref"]),
    )
    assert process.opengrep_calls == 2
    assert resumed_coverage["verified_count"] == 2
    assert len(resumed_bundle["engine_raw_refs"]) == 2


@pytest.mark.asyncio
async def test_unknown_located_opengrep_error_is_retried_on_resume(
    tmp_path: Path,
) -> None:
    class UnknownErrorThenSuccess(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--output" in argv:
                self.opengrep_calls += 1
                targets = [path for path in ("app.py", "good.py") if path in argv]
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": (
                                [{"type": "OutOfMemory", "path": "app.py"}]
                                if self.opengrep_calls == 1
                                else []
                            ),
                            "paths": {
                                "scanned": targets,
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = UnknownErrorThenSuccess()
    bootstrap, profile, _store = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("unknown-located-error")
    request = _request(profile)
    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"
    await bootstrap.run(request, identity)
    assert process.opengrep_calls == 2


def test_reusable_parse_warning_rejects_nonstring_type_without_crashing() -> None:
    slice_ = CoverageSlice(
        engine="opengrep",
        batch_key="batch",
        rule_ids=("python.sql",),
        verified_pairs=frozenset(),
        gap_reasons=(("app.py", "python.sql", "parse_or_scan_error"),),
        parsed={"errors": [{"type": ["Unexpected"], "path": "app.py"}]},
        normalized_results=(),
    )
    assert not DirectStaticBootstrap._reusable_parse_warning(
        slice_, frozenset({("app.py", "python.sql")})
    )


@pytest.mark.asyncio
async def test_resume_reuses_located_list_form_partial_and_retries_unscanned_file(
    tmp_path: Path,
) -> None:
    class ListFormPartial(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            result = await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)
            if argv[1] == "scan" and "--metrics=off" not in argv:
                output = Path(argv[argv.index("--output") + 1])
                parsed = json.loads(output.read_text(encoding="utf-8"))
                if "app.py" in argv:
                    parsed["errors"][0]["type"] = ["PartialParsing", [{"line": 1}]]
                    parsed["paths"]["scanned"] = ["app.py"]
                    output.write_text(json.dumps(parsed), encoding="utf-8")
            return result

    process = ListFormPartial(fallback_fails=True)
    bootstrap, profile, _ = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("list-form-partial-reuse")
    request = _request(profile)
    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"
    report = _coverage_from_ref(profile, identity, first.static_coverage_ref)
    assert report["expected_count"] == 2
    assert report["verified_count"] == 0
    assert {gap["path"] for gap in report["gaps"]} == {"app.py", "good.py"}
    assert any(
        "app.py" in call and "good.py" in call for call in process.fallback_calls
    )
    second = await bootstrap.run(request, identity)
    assert second.static_disposition == "PARTIAL"
    assert process.opengrep_calls == 2


@pytest.mark.asyncio
async def test_locked_retry_output_preserves_previous_partial_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class PartialFirst(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--output" in argv:
                self.opengrep_calls += 1
                scanned = ["good.py"] if self.opengrep_calls == 1 else ["app.py"]
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {"scanned": scanned, "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = PartialFirst()
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("locked-retry-output")
    request = _request(profile)
    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"
    first_report = _coverage_from_ref(profile, identity, first.static_coverage_ref)
    previous = next(
        item
        for item in store.list_static_scan_attempts(
            identity, request.repository, first_report["fingerprint"]
        )
        if item.tool == "opengrep"
    )
    original_unlink = Path.unlink

    def locked_unlink(path: Path, missing_ok: bool = False) -> None:
        if path.name.startswith("opengrep-"):
            raise PermissionError("locked scanner output")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", locked_unlink)
    result = await bootstrap.run(request, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    second_report = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert second_report["verified_count"] == second_report["expected_count"] == 2
    assert process.opengrep_calls == 2
    attempts = store.list_static_scan_attempts(
        identity, request.repository, second_report["fingerprint"]
    )
    retained = next(item for item in attempts if item.run_key == previous.run_key)
    assert retained.raw_ref == previous.raw_ref


@pytest.mark.asyncio
async def test_nonzero_opengrep_keeps_parseable_hit_as_provisional(
    tmp_path: Path,
) -> None:
    class FailedWithHit(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--output" in argv:
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps(
                        {
                            "results": [
                                {
                                    "check_id": "python.sql",
                                    "path": "app.py",
                                    "start": {"line": 1, "col": 1},
                                }
                            ],
                            "errors": [],
                            "paths": {
                                "scanned": ["app.py", "good.py"],
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(2, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    bootstrap, profile, _store_ = _coverage_bootstrap(
        tmp_path, FailedWithHit(), codeql=False
    )
    identity = _identity("nonzero-provisional-hit")
    result = await bootstrap.run(_request(profile), identity)
    assert result.static_disposition == "PARTIAL"
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    assert bundle["opengrep_findings"] == []


@pytest.mark.asyncio
async def test_codeql_runs_after_opengrep_partial_parse(tmp_path: Path) -> None:
    process = _CoverageProcess()
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-after-warning")
    result = await bootstrap.run(_request(profile), identity)
    assert result.static_disposition == "PARTIAL"
    assert result.static_coverage_ref is not None
    assert process.codeql_calls == 1
    report = _coverage_from_ref(profile, identity, result.static_coverage_ref)
    assert report["expected_count"] == 2
    assert report["verified_count"] == 1
    assert report["gaps"][0]["path"] == "app.py"
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    assert bundle["codeql_executed"] is True
    assert bundle["ast_summary"]["kind"] == "simple_python_ast"


def _cacheable_codeql_materials(tmp_path: Path) -> Path:
    root = tmp_path / "codeql"
    root.mkdir()
    (root / "python-security.qls").write_text("- queries: security\n", encoding="utf-8")
    (root / "qlpack.yml").write_text(
        "name: test/security\nversion: 1.0.0\n", encoding="utf-8"
    )
    (root / "security.ql").write_text("select 1\n", encoding="utf-8")
    return root


@pytest.mark.asyncio
async def test_partial_resume_reuses_verified_codeql_sarif(tmp_path: Path) -> None:
    _cacheable_codeql_materials(tmp_path)
    process = _CoverageProcess()
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-cache")
    request = _request(profile)

    first = await bootstrap.run(request, identity)
    second = await bootstrap.run(request, identity)

    assert first.static_disposition == second.static_disposition == "PARTIAL"
    assert process.codeql_calls == 1
    first_bundle = _coverage_from_ref(profile, identity, first.static_bundle_ref)
    second_bundle = _coverage_from_ref(profile, identity, second.static_bundle_ref)
    assert second_bundle["tool_result_refs"][2] == first_bundle["tool_result_refs"][2]


@pytest.mark.asyncio
async def test_codeql_cache_rejects_changed_local_qlpack(tmp_path: Path) -> None:
    query_root = _cacheable_codeql_materials(tmp_path)
    qlpack = query_root / "qlpack.yml"
    process = _CoverageProcess()
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-local-pack-changed")
    request = _request(profile)

    await bootstrap.run(request, identity)
    qlpack.write_text("name: test/security\nversion: 2.0.0\n", encoding="utf-8")
    await bootstrap.run(request, identity)

    assert process.codeql_calls == 2


@pytest.mark.asyncio
async def test_codeql_cache_rejects_changed_resolved_pack_content(
    tmp_path: Path,
) -> None:
    query_root = _cacheable_codeql_materials(tmp_path)
    process = _CoverageProcess()
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-resolved-pack-changed")
    request = _request(profile)

    await bootstrap.run(request, identity)
    (query_root / "security.ql").write_text("select 2\n", encoding="utf-8")
    await bootstrap.run(request, identity)

    assert process.codeql_calls == 2


@pytest.mark.asyncio
async def test_codeql_cache_disabled_without_resolved_pack_proof(
    tmp_path: Path,
) -> None:
    _cacheable_codeql_materials(tmp_path)

    class UnresolvedPack(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1:3] == ("resolve", "packs"):
                return ProcessResult(2, b"", b"unavailable")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = UnresolvedPack()
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-pack-unresolved")
    request = _request(profile)

    await bootstrap.run(request, identity)
    await bootstrap.run(request, identity)

    assert process.codeql_calls == 2
    with sqlite3.connect(store.database_path) as connection:
        cached = connection.execute(
            "SELECT COUNT(*) FROM simple_static_scan_attempts WHERE tool = 'codeql'"
        ).fetchone()
    assert cached == (0,)


@pytest.mark.asyncio
async def test_codeql_cache_rejects_changed_query_suite_and_corrupt_sarif(
    tmp_path: Path,
) -> None:
    query_suite = _cacheable_codeql_materials(tmp_path) / "python-security.qls"
    process = _CoverageProcess()
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-cache-changed")
    request = _request(profile)

    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"
    query_suite.write_text("- queries: extended-security\n", encoding="utf-8")
    second = await bootstrap.run(request, identity)
    assert process.codeql_calls == 2
    second_bundle = _coverage_from_ref(profile, identity, second.static_bundle_ref)
    sarif_ref = StoredDataRef.model_validate(second_bundle["tool_result_refs"][2])
    SimpleArtifactRepository(profile.data_dir, identity).artifacts.path_for(
        sarif_ref.content_hash
    ).write_bytes(b"corrupt")

    third = await bootstrap.run(request, identity)
    assert third.static_disposition == "PARTIAL"
    assert process.codeql_calls == 3


@pytest.mark.asyncio
async def test_codeql_cache_rejects_corrupt_request_descriptor(tmp_path: Path) -> None:
    _cacheable_codeql_materials(tmp_path)
    process = _CoverageProcess()
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-request-corrupt")
    request = _request(profile)
    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"
    # The CodeQL result uses its own identity fingerprint, independent of the
    # OpenGrep coverage plan, so locate its descriptor through the store.
    with sqlite3.connect(store.database_path) as connection:
        row = connection.execute(
            "SELECT request_ref_json FROM simple_static_scan_attempts "
            "WHERE analysis_id = ? AND tool = 'codeql'",
            (identity.analysis_id,),
        ).fetchone()
    assert row is not None
    descriptor_ref = StoredDataRef.model_validate_json(row[0])
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    artifacts.artifacts.path_for(descriptor_ref.content_hash).write_bytes(b"corrupt")

    second = await bootstrap.run(request, identity)
    assert second.static_disposition == "PARTIAL"
    assert process.codeql_calls == 2
    second_bundle = _coverage_from_ref(profile, identity, second.static_bundle_ref)
    assert second_bundle["codeql_executed"] is True
    await bootstrap.run(request, identity)
    assert process.codeql_calls == 2


@pytest.mark.asyncio
async def test_codeql_cache_rejects_changed_executable_digest(tmp_path: Path) -> None:
    _cacheable_codeql_materials(tmp_path)
    process = _CoverageProcess()
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-new-tool")
    request = _request(profile)
    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"

    replacement = tmp_path / "new-codeql-tool"
    replacement.write_bytes(b"new-codeql-tool")
    profile = profile.model_copy(
        update={
            "tools": {
                **profile.tools,
                "codeql": SimpleToolBinding(
                    executable_path=replacement,
                    version="2.0",
                    executable_sha256=hashlib.sha256(b"new-codeql-tool").hexdigest(),
                ),
            },
        }
    )
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    second = await bootstrap.run(_request(profile), identity)
    assert second.static_disposition == "PARTIAL"
    assert process.codeql_calls == 2


@pytest.mark.asyncio
async def test_corrupt_execution_history_keeps_gap_artifact_on_resume(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess()
    bootstrap, profile, _store = _coverage_bootstrap(
        tmp_path, process, semgrep=False, codeql=False
    )
    identity = _identity("analysis-corrupt-execution-history")
    request = _request(profile)
    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"

    database = profile.data_dir / "db" / "sastsimi.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE simple_static_scan_executions SET error_ref_json = ? "
            "WHERE analysis_id = ?",
            ("not-json", identity.analysis_id),
        )

    with pytest.raises(StaticCoverageBlocked) as caught:
        await bootstrap.run(request, identity)
    report = _coverage_from_ref(profile, identity, caught.value.coverage_ref)
    assert report["gaps"]
    assert all(gap["attempt_count"] is None for gap in report["gaps"])
    assert all(gap["history_complete"] is False for gap in report["gaps"])
    assert all(gap["history_status"] == "INVALID" for gap in report["gaps"])
    assert "STATIC_SCAN_EXECUTION_HISTORY_INVALID" in report["engine_errors"]


@pytest.mark.asyncio
async def test_opengrep_execution_is_durable_before_process_dispatch(
    tmp_path: Path,
) -> None:
    class ObserveStarted(_CoverageProcess):
        store: SimpleCheckpointStore
        identity: CheckpointIdentity
        repository: str

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                history = self.store.list_static_scan_executions(
                    self.identity, self.repository, tool="opengrep"
                )
                assert len(history) == 1
                assert history[0].status == "STARTED"
                assert history[0].request_ref is not None
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = ObserveStarted()
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=False, codeql=False
    )
    identity = _identity("analysis-durable-dispatch")
    request = _request(profile)
    process.store = store
    process.identity = identity
    process.repository = request.repository

    first = await bootstrap.run(request, identity)
    assert first.static_disposition == "PARTIAL"
    history = store.list_static_scan_executions(identity, request.repository)
    assert len(history) == 1
    assert history[0].status == "BLOCKED"


@pytest.mark.asyncio
async def test_unfinished_execution_prevents_exact_gap_count_on_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _CoverageProcess()
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=False, codeql=False
    )
    identity = _identity("analysis-unfinished-execution")
    request = _request(profile)

    def fail_finish(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated-ledger-finalization-failure")

    monkeypatch.setattr(
        store, "finish_static_scan_execution", fail_finish, raising=False
    )
    with pytest.raises(StaticCoverageBlocked):
        await bootstrap.run(request, identity)
    monkeypatch.undo()

    history = store.list_static_scan_executions(identity, request.repository)
    assert len(history) == 1
    assert history[0].status == "STARTED"
    resumed = await bootstrap.run(request, identity)
    assert resumed.static_disposition == "PARTIAL"
    assert resumed.static_coverage_ref is not None
    report = _coverage_from_ref(profile, identity, resumed.static_coverage_ref)
    assert report["gaps"]
    assert all(gap["attempt_count"] is None for gap in report["gaps"])
    assert all(gap["history_complete"] is False for gap in report["gaps"])
    assert all(gap["history_status"] == "INTERRUPTED" for gap in report["gaps"])


@pytest.mark.asyncio
async def test_semgrep_closes_only_failed_file_rule_pairs(tmp_path: Path) -> None:
    process = _CoverageProcess()
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("analysis-fallback-closed")
    result = await bootstrap.run(_request(profile), identity)
    assert len(process.fallback_calls) == 1
    assert "app.py" in process.fallback_calls[0]
    assert "good.py" not in process.fallback_calls[0]
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    report = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert report["expected_count"] == report["verified_count"] == 2
    assert report["gaps"] == []
    assert report["engine_verified_counts"] == {"opengrep": 1, "semgrep": 1}
    executions = store.list_static_scan_executions(
        identity, _request(profile).repository, report["fingerprint"], tool="semgrep"
    )
    assert len(executions) == 1
    assert executions[0].status == "SUCCEEDED"
    assert executions[0].request_ref is not None
    assert {hit["engine"] for hit in bundle["opengrep_findings"]} == {
        "opengrep",
        "semgrep",
    }


@pytest.mark.asyncio
async def test_semgrep_execution_is_durable_before_process_dispatch(
    tmp_path: Path,
) -> None:
    class ObserveSemgrepStarted(_CoverageProcess):
        store: SimpleCheckpointStore
        identity: CheckpointIdentity
        repository: str

        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" in argv:
                history = self.store.list_static_scan_executions(
                    self.identity, self.repository, tool="semgrep"
                )
                assert history
                assert history[-1].status == "STARTED"
                assert history[-1].request_ref is not None
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = ObserveSemgrepStarted()
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("analysis-semgrep-durable-dispatch")
    request = _request(profile)
    process.store = store
    process.identity = identity
    process.repository = request.repository
    await bootstrap.run(request, identity)
    history = store.list_static_scan_executions(
        identity, request.repository, tool="semgrep"
    )
    assert history
    assert all(item.status == "SUCCEEDED" for item in history)


@pytest.mark.asyncio
async def test_codeql_survives_fallback_failure(tmp_path: Path) -> None:
    process = _CoverageProcess(fallback_fails=True)
    bootstrap, profile, store = _coverage_bootstrap(tmp_path, process, semgrep=True)
    identity = _identity("analysis-fallback-failed")
    result = await bootstrap.run(_request(profile), identity)
    assert result.static_disposition == "PARTIAL"
    assert process.codeql_calls == 1
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    assert bundle["codeql_executed"] is True
    assert len(bundle["tool_result_refs"]) >= 3
    report = _coverage_from_ref(profile, identity, result.static_coverage_ref)
    assert report["gaps"][0]["path"] == "app.py"
    attempt = next(
        item
        for item in store.list_static_scan_attempts(
            identity, _request(profile).repository, report["fingerprint"]
        )
        if item.tool == "semgrep"
    )
    assert attempt.status == "BLOCKED"
    assert attempt.raw_ref is not None
    executions = store.list_static_scan_executions(
        identity, _request(profile).repository, report["fingerprint"], tool="semgrep"
    )
    assert len(executions) == 1
    assert executions[0].status == "BLOCKED"
    assert executions[0].error_code == "SEMGREP_EXECUTION_FAILED"
    assert executions[0].error_ref == attempt.raw_ref
    assert (
        SimpleArtifactRepository(profile.data_dir, identity).read(attempt.raw_ref)
        == b"bad"
    )


@pytest.mark.asyncio
async def test_codeql_failure_retains_ast_and_opengrep_evidence(tmp_path: Path) -> None:
    process = _CoverageProcess(parse_warning=False, codeql_fails=True)
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process)
    identity = _identity("analysis-codeql-failed")
    result = await bootstrap.run(_request(profile), identity)
    assert result.static_disposition == "PARTIAL"
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    assert bundle["ast_summary"]["fact_count"] > 0
    assert bundle["ast_summary"]["manifest_ref"]
    assert bundle["opengrep_findings"]
    assert bundle["codeql_executed"] is False
    assert len(bundle["tool_result_refs"]) >= 2


@pytest.mark.parametrize("call_count", (10_000, 10_001))
def test_ast_saves_all_facts_by_file_without_total_cap(
    tmp_path: Path, call_count: int
) -> None:
    (tmp_path / "a.py").write_text("f()\n" * 10_000, encoding="utf-8")
    (tmp_path / "empty.py").write_text("# no AST facts\n", encoding="utf-8")
    if call_count > 10_000:
        (tmp_path / "z.py").write_text("g()\n", encoding="utf-8")
    profile = _profile(tmp_path)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=_Process(),
        store=_store(profile),
        static_material_root=tmp_path,
    )
    artifacts = SimpleArtifactRepository(
        profile.data_dir, _identity(f"analysis-ast-{call_count}")
    )
    paths = (
        ("a.py", "empty.py", "z.py")
        if call_count > 10_000
        else (
            "a.py",
            "empty.py",
        )
    )

    summary = bootstrap._python_ast(tmp_path, paths, artifacts)

    assert summary["fact_count"] == call_count
    assert summary["truncated"] is False
    assert "facts" not in summary
    manifest = json.loads(
        artifacts.read(StoredDataRef.model_validate(summary["manifest_ref"]))
    )
    assert manifest["fact_count"] == call_count
    assert [item["path"] for item in manifest["entries"]] == list(paths)
    assert [item["fact_count"] for item in manifest["entries"]] == (
        [10_000, 0, 1] if call_count > 10_000 else [10_000, 0]
    )
    first = json.loads(
        artifacts.read(StoredDataRef.model_validate(manifest["entries"][0]["ref"]))
    )
    assert len(first["facts"]) == 10_000
    assert first["facts"][-1] == {
        "kind": "Call",
        "path": "a.py",
        "line": 10_000,
        "name": "f",
    }


@pytest.mark.asyncio
async def test_ast_parse_errors_are_disclosed_even_when_rule_coverage_succeeds(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess(parse_warning=False, invalid_python=True)
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("analysis-ast-errors")
    result = await bootstrap.run(_request(profile), identity)
    assert result.static_disposition == "PARTIAL"
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    report = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert report["ast_parse_error_count"] == 1
    assert report["ast_truncated"] is False
    assert report["verified_count"] == report["expected_count"] == 2


@pytest.mark.asyncio
async def test_ast_facts_are_not_truncated_for_valid_scan(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess(parse_warning=False)
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("analysis-ast-valid")

    result = await bootstrap.run(_request(profile), identity)

    assert result.static_disposition == "FULL"
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    report = _coverage_from_ref(
        profile, identity, StoredDataRef.model_validate(bundle["static_coverage_ref"])
    )
    assert report["ast_truncated"] is False
    assert report["ast_parse_error_count"] == 0


def test_ast_continues_parsing_files_after_first_parse_error(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.py").write_text("def a(): pass\n", encoding="utf-8")
    (tmp_path / "z.py").write_text("def broken(:\n", encoding="utf-8")
    profile = _profile(tmp_path)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=_Process(),
        store=_store(profile),
        static_material_root=tmp_path,
    )

    identity = _identity("ast-parse-after-error")
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    result = bootstrap._python_ast(tmp_path, ("a.py", "z.py"), artifacts)

    assert result["parse_error_count"] == 1
    assert result["parse_errors"] == ["z.py"]
    assert result["parsed_file_count"] == 1


def test_ast_retains_every_unparsed_product_path(tmp_path: Path) -> None:
    paths = tuple(f"file_{index:03d}.py" for index in range(105))
    for relative in paths:
        (tmp_path / relative).write_text("def broken(:\n", encoding="utf-8")
    profile = _profile(tmp_path)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=_Process(),
        store=_store(profile),
        static_material_root=tmp_path,
    )

    identity = _identity("ast-all-unparsed")
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    result = bootstrap._python_ast(tmp_path, paths, artifacts)

    assert result["parse_error_count"] == len(paths)
    assert result["parse_errors"] == list(paths)


def test_ast_parses_selected_python_stub_source(tmp_path: Path) -> None:
    (tmp_path / "api.pyi").write_text(
        "def parse(value: str) -> bool: ...\n", encoding="utf-8"
    )
    profile = _profile(tmp_path)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=_Process(),
        store=_store(profile),
        static_material_root=tmp_path,
    )

    identity = _identity("ast-stub-source")
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    result = bootstrap._python_ast(tmp_path, ("api.pyi",), artifacts)

    assert result["parsed_file_count"] == 1
    assert result["parse_error_count"] == 0
    manifest = json.loads(
        artifacts.read(StoredDataRef.model_validate(result["manifest_ref"]))
    )
    assert manifest["entries"][0]["path"] == "api.pyi"
    assert manifest["entries"][0]["fact_count"] > 0


def test_ast_does_not_read_symlink_outside_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    external = tmp_path / "external.py"
    external.write_text("def outside_secret(): pass\n", encoding="utf-8")
    try:
        (workspace / "leak.py").symlink_to(external)
    except OSError:
        # Standard Windows users may lack symlink privileges. Simulate the
        # reparse-path signal while still proving the source is never parsed.
        (workspace / "leak.py").write_bytes(external.read_bytes())
        original_is_symlink = Path.is_symlink
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda path: path == workspace / "leak.py" or original_is_symlink(path),
        )
    profile = _profile(tmp_path)
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=_Process(),
        store=_store(profile),
        static_material_root=tmp_path,
    )

    identity = _identity("ast-symlink")
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    result = bootstrap._python_ast(workspace, ("leak.py",), artifacts)

    assert result["parsed_file_count"] == 0
    assert result["parse_errors"] == ["leak.py"]
    assert result["fact_count"] == 0


@pytest.mark.parametrize("extension", (".mjs", ".cjs", ".mts", ".cts"))
def test_repository_profile_discards_extended_js_ts_source(extension: str) -> None:
    profile = DirectStaticBootstrap._repository_profile((f"src/main{extension}",))

    assert profile["languages"] == ()
    assert profile["needs_confirmation"] is True


@pytest.mark.asyncio
async def test_ast_oversize_product_file_is_partial_with_path_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _CoverageProcess(parse_warning=False)
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process, codeql=False)
    monkeypatch.setattr(static_module, "_MAX_SOURCE_BYTES", 1)
    identity = _identity("analysis-ast-oversize")

    result = await bootstrap.run(_request(profile), identity)
    assert result.static_disposition == "PARTIAL"
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    assert bundle["ast_summary"]["oversize_count"] == 2
    assert bundle["ast_summary"]["oversize_paths"] == ["app.py", "good.py"]


@pytest.mark.asyncio
async def test_resume_reuses_verified_batches_without_duplicate_findings(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess()
    bootstrap, profile, _ = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("analysis-resume-static")
    first = await bootstrap.run(_request(profile), identity)
    second = await bootstrap.run(_request(profile), identity)
    assert process.opengrep_calls == 1
    assert len(process.fallback_calls) == 1
    bundle = _coverage_from_ref(profile, identity, second.static_bundle_ref)
    assert len(bundle["opengrep_findings"]) == 2
    first_bundle = _coverage_from_ref(profile, identity, first.static_bundle_ref)
    assert first_bundle["opengrep_findings"] == bundle["opengrep_findings"]


@pytest.mark.asyncio
async def test_resume_retries_partial_batch_when_file_was_not_scanned(
    tmp_path: Path,
) -> None:
    class TemporarilyUnscanned(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--output" in argv and self.opengrep_calls == 0:
                self.opengrep_calls += 1
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {"scanned": ["good.py"], "skipped": []},
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = TemporarilyUnscanned(parse_warning=False)
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("resume-unscanned")
    first = await bootstrap.run(_request(profile), identity)
    assert first.static_disposition == "PARTIAL"
    await bootstrap.run(_request(profile), identity)
    assert process.opengrep_calls == 2


@pytest.mark.asyncio
async def test_resume_retries_opengrep_parser_gap(tmp_path: Path) -> None:
    process = _CoverageProcess(parse_warning=True)
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("resume-parser-gap")

    first = await bootstrap.run(_request(profile), identity)
    assert first.static_disposition == "PARTIAL"
    await bootstrap.run(_request(profile), identity)

    assert process.opengrep_calls == 2


@pytest.mark.asyncio
async def test_cached_semgrep_coverage_requires_same_executable(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess()
    bootstrap, profile, store = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    semgrep_path = tmp_path / "semgrep-test"
    semgrep_path.write_bytes(b"semgrep-tool")
    profile = profile.model_copy(
        update={
            "tools": {
                **profile.tools,
                "semgrep": SimpleToolBinding(
                    executable_path=semgrep_path,
                    version="test",
                    executable_sha256=hashlib.sha256(b"semgrep-tool").hexdigest(),
                ),
            }
        }
    )
    bootstrap = DirectStaticBootstrap(
        profile=profile, process=process, store=store, static_material_root=tmp_path
    )
    identity = _identity("semgrep-tool-changed")
    await bootstrap.run(_request(profile), identity)
    assert len(process.fallback_calls) == 1
    semgrep_path.write_bytes(b"changed-semgrep-tool")
    partial = await bootstrap.run(_request(profile), identity)
    assert partial.static_disposition == "PARTIAL"
    assert len(process.fallback_calls) == 1


@pytest.mark.asyncio
async def test_semgrep_fallback_chunks_continue_past_aggregate_elapsed_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [100.0]
    call_timeouts: list[int] = []

    class AdvancingFallback(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" in argv:
                self.fallback_calls.append(tuple(argv))
                call_timeouts.append(timeout_seconds)
                targets = [arg for arg in argv if arg.startswith("file-")]
                clock[0] += 3601
                Path(argv[argv.index("--output") + 1]).write_bytes(
                    json.dumps(
                        {
                            "results": [],
                            "errors": [],
                            "paths": {"scanned": targets, "skipped": []},
                        }
                    ).encode()
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = AdvancingFallback()
    bootstrap, profile, _ = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    profile = profile.model_copy(
        update={"max_elapsed_seconds": "unlimited", "static_scan_pass_seconds": 1}
    )
    bootstrap = DirectStaticBootstrap(
        profile=profile,
        process=process,
        store=_store(profile),
        static_material_root=tmp_path,
    )
    identity = _identity("fallback-shared-deadline")
    workspace = profile.workspace_root / identity.workspace_id
    workspace.mkdir(parents=True)
    files = [f"file-{index:03d}.py" for index in range(129)]
    for file in files:
        (workspace / file).write_text("x = 1\n", encoding="utf-8")
    rules = tmp_path / "opengrep" / "rules.yml"
    binding = profile.tools["opengrep"]
    batches = plan_rule_batches(
        rules.read_bytes(),
        tool_version=binding.version,
        executable_sha256=binding.executable_sha256,
    )
    coverage = plan_static_coverage(workspace, files, identity.commit_id, batches)
    monkeypatch.setattr(
        static_module,
        "time",
        SimpleNamespace(monotonic=lambda: clock[0]),
        raising=False,
    )
    slices, _refs, errors = await bootstrap._collect_semgrep(
        workspace,
        _request(profile),
        identity,
        batches,
        coverage,
        [],
        rules,
        SimpleArtifactRepository(profile.data_dir, identity),
    )
    assert len(process.fallback_calls) == 2
    assert len(slices) == 2
    assert len(slices[1].verified_pairs) == 1
    assert errors == []
    assert call_timeouts == [120, 120]


@pytest.mark.asyncio
async def test_changed_fingerprint_does_not_reuse_old_coverage(tmp_path: Path) -> None:
    process = _CoverageProcess()
    bootstrap, profile, _ = _coverage_bootstrap(
        tmp_path, process, semgrep=True, codeql=False
    )
    identity = _identity("analysis-changed-rule")
    first = await bootstrap.run(_request(profile), identity)
    rules = tmp_path / "opengrep" / "rules.yml"
    rules.write_text(
        rules.read_text(encoding="utf-8").replace(
            "pattern: db.execute(...)\n", "pattern: foo(...)\n"
        ),
        encoding="utf-8",
    )
    second = await bootstrap.run(_request(profile), identity)
    assert process.opengrep_calls == 2
    assert len(process.fallback_calls) == 2
    first_bundle = _coverage_from_ref(profile, identity, first.static_bundle_ref)
    second_bundle = _coverage_from_ref(profile, identity, second.static_bundle_ref)
    assert first_bundle["static_coverage_ref"] != second_bundle["static_coverage_ref"]


@pytest.mark.asyncio
async def test_invalid_opengrep_rules_preserve_ast_and_codeql_partial_evidence(
    tmp_path: Path,
) -> None:
    process = _CoverageProcess(parse_warning=False)
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process, codeql=True)
    (tmp_path / "opengrep" / "rules.yml").write_text(
        "not a rule catalog", encoding="utf-8"
    )
    identity = _identity("invalid-opengrep-catalog")

    result = await bootstrap.run(_request(profile), identity)

    assert result.static_disposition == "PARTIAL"
    assert process.opengrep_calls == 0
    assert process.codeql_calls == 1
    coverage = _coverage_from_ref(profile, identity, result.static_coverage_ref)
    assert coverage["unavailable"] is True
    expected_scope = build_static_file_scope(
        profile.workspace_root / identity.workspace_id, ("app.py", "good.py")
    )
    assert coverage["fingerprint"] == expected_scope.fingerprint
    assert coverage["expected_count"] == 0
    assert coverage["verified_count"] == 0
    assert coverage["engine_errors"] == ["OPENGREP_RULE_CATALOG_INVALID"]
    assert coverage["unavailable_paths"] == [
        {"path": path, "reason": "OPENGREP_RULE_CATALOG_INVALID"}
        for path in ("app.py", "good.py")
    ]
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    assert bundle["ast_summary"]["parsed_file_count"] == 2
    assert bundle["codeql_executed"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("codeql", [False, True])
async def test_opengrep_total_failure_requires_an_independent_verified_engine(
    tmp_path: Path, codeql: bool
) -> None:
    class AllInvalidSourceAndFailedScan(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan":
                self.opengrep_calls += 1
                return ProcessResult(2, b"", b"failed")
            result = await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)
            if argv[1] == "clone":
                root = Path(argv[-1])
                for path in ("app.py", "good.py"):
                    (root / path).write_text("def broken(:\n", encoding="utf-8")
            return result

    process = AllInvalidSourceAndFailedScan()
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process, codeql=codeql)
    identity = _identity(f"total-failure-codeql-{codeql}")
    if not codeql:
        with pytest.raises(
            StaticCoverageBlocked, match="STATIC_COVERAGE_NO_VERIFIED_RESULTS"
        ) as blocked:
            await bootstrap.run(_request(profile), identity)
        coverage_ref = blocked.value.coverage_ref
    else:
        result = await bootstrap.run(_request(profile), identity)
        assert result.static_disposition == "PARTIAL"
        assert result.static_coverage_ref is not None
        coverage_ref = result.static_coverage_ref
        bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
        assert bundle["codeql_executed"] is True
        assert bundle["ast_summary"]["parsed_file_count"] == 0
    coverage = _coverage_from_ref(profile, identity, coverage_ref)
    assert coverage["verified_count"] == 0
    assert coverage["expected_count"] == 2
    assert len(coverage["gaps"]) == 2


@pytest.mark.asyncio
async def test_static_bootstrap_previews_but_preserves_all_raw_hits(
    tmp_path: Path,
) -> None:
    class ManyHits(_CoverageProcess):
        async def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout_seconds: int,
        ) -> ProcessResult:
            if argv[1] == "scan" and "--metrics=off" not in argv:
                self.opengrep_calls += 1
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                hits = [
                    {
                        "check_id": "python.sql",
                        "path": "app.py",
                        "start": {"line": 1, "col": column},
                    }
                    for column in range(1, 602)
                ]
                hits.append(
                    {
                        "check_id": "python.sql",
                        "path": "good.py",
                        "start": {"line": 1, "col": 1},
                    }
                )
                output.write_text(
                    json.dumps(
                        {
                            "results": hits,
                            "errors": [],
                            "paths": {
                                "scanned": ["app.py", "good.py"],
                                "skipped": [],
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"", b"")
            return await super().run(argv, cwd=cwd, timeout_seconds=timeout_seconds)

    process = ManyHits(parse_warning=False)
    bootstrap, profile, _ = _coverage_bootstrap(tmp_path, process, codeql=False)
    identity = _identity("bounded-preview-full-raw")

    result = await bootstrap.run(_request(profile), identity)

    assert result.static_disposition == "FULL"
    artifacts = SimpleArtifactRepository(profile.data_dir, identity)
    bundle = _coverage_from_ref(profile, identity, result.static_bundle_ref)
    preview_ref = StoredDataRef.model_validate(bundle["tool_result_refs"][1])
    preview = json.loads(artifacts.read(preview_ref))
    assert len(preview["results"]) == 500
    assert preview["candidate_snippets_truncated"] is True
    assert len(bundle["opengrep_findings"]) <= 500
    raw_ref = StoredDataRef.model_validate(bundle["engine_raw_sources"][0]["ref"])
    raw = json.loads(artifacts.read(raw_ref))
    assert len(raw["results"]) == 602
